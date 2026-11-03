/*
 * ring.c — ring buffer SPSC lock-free.                      [TUẦN 3]
 *
 * Test: tests/test_ring.cpp (kể cả test 2 thread). Chạy thêm với
 * ThreadSanitizer: cmake -B build-tsan -DCMAKE_C_FLAGS=-fsanitize=thread
 *                  -DCMAKE_CXX_FLAGS=-fsanitize=thread
 *
 * KHÁI NIỆM
 *   Hai chỉ số tăng mãi (không quay về 0), kiểu size_t:
 *     head: vị trí producer sẽ ghi tiếp   — CHỈ producer ghi
 *     tail: vị trí consumer sẽ đọc tiếp   — CHỈ consumer ghi
 *   Số phần tử = head - tail (phép trừ unsigned vẫn đúng khi tràn số).
 *   Slot thực tế = index & (capacity - 1)  -> vì vậy capacity là lũy thừa 2.
 *   Rỗng: head == tail.   Đầy: head - tail == capacity.
 *
 *   Mỗi biến chỉ có một luồng ghi -> không có tranh chấp ghi, không cần lock.
 *   Vấn đề còn lại là THỨ TỰ BỘ NHỚ:
 *
 *   push (producer):
 *     h = load(head, relaxed)          biến của chính mình
 *     t = load(tail, ACQUIRE)          xem consumer đã giải phóng slot chưa
 *     đầy -> return false
 *     slots[h & mask] = item           ghi dữ liệu
 *     store(head, h + 1, RELEASE)      "công bố": mọi ghi phía trên phải
 *                                      được thấy trước khi head mới được thấy
 *   pop (consumer): đối xứng
 *     t = load(tail, relaxed)
 *     h = load(head, ACQUIRE)          cặp với RELEASE của producer
 *     rỗng -> return false
 *     *item = slots[t & mask]
 *     store(tail, t + 1, RELEASE)      cho producer biết slot đã trống
 *
 *   Nếu dùng relaxed cho tất cả: trên ARM (memory model yếu), consumer có thể
 *   thấy head mới TRƯỚC khi thấy dữ liệu trong slot -> đọc rác. Trên x86 lỗi
 *   này hiếm khi lộ ra, nên phải hiểu chứ không thử là thấy.
 *
 *   False sharing: head và tail bị hai core khác nhau ghi liên tục. Nếu
 *   chúng nằm trên cùng cache line (64 byte), hai core tranh nhau cache line
 *   đó -> chậm hẳn. Tách bằng _Alignas(64) cho từng biến.
 *
 *   Tối ưu nâng cao (sau khi bản cơ bản chạy đúng): producer giữ bản cache
 *   cục bộ của tail, chỉ load lại tail thật khi bản cache báo đầy. Đo
 *   trước/sau bằng benchmark.
 *
 * Gợi ý struct:
 *
 *   struct ring {
 *       _Alignas(64) _Atomic size_t head;
 *       _Alignas(64) _Atomic size_t tail;
 *       _Alignas(64) size_t mask;        capacity - 1
 *       void **slots;
 *   };
 *
 *   Cấp phát struct có _Alignas(64): malloc chỉ đảm bảo căn lề
 *   alignof(max_align_t) (thường 16). Dùng aligned_alloc(64, size) của C11
 *   — size phải là bội của 64 — hoặc tự kiểm tra rồi ghi chú lý do.
 */
#include "ring.h"

#include <stdalign.h>  /* alignas, alignof */
#include <stdatomic.h> /* _Atomic, atomic_load_explicit, atomic_store_explicit,
                          memory_order_acquire / release / relaxed */
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>    /* aligned_alloc, calloc, free */

/* Cache line 64 byte trên x86-64 và phần lớn ARM64. head, tail và phần
 * chỉ-đọc (mask, slots) mỗi thứ một line: producer ghi head, consumer ghi
 * tail, hai core không tranh nhau cùng một line. */
#define RING_CACHE_LINE 64

/* tail_cache / head_cache: bản sao cục bộ chỉ số của bên kia, nằm chung line
 * với chỉ số của chính mình. Chỉ load chỉ số thật (kéo cache line từ core
 * kia về) khi bản sao báo đầy/rỗng, thay vì mỗi gói một lần. */
struct ring {
    _Alignas(RING_CACHE_LINE) _Atomic size_t head;  /* chỉ producer ghi */
    size_t tail_cache;                              /* producer riêng */
    _Alignas(RING_CACHE_LINE) _Atomic size_t tail;  /* chỉ consumer ghi */
    size_t head_cache;                              /* consumer riêng */
    _Alignas(RING_CACHE_LINE) size_t mask;          /* capacity - 1 */
    void **slots;
};

/* ring_create: kiểm tra capacity >= 2 và (capacity & (capacity - 1)) == 0. */
struct ring *ring_create(size_t capacity)
{
    struct ring *r;

    if (capacity < 2u || (capacity & (capacity - 1u)) != 0)
        return NULL;

    /* malloc chỉ bảo đảm alignof(max_align_t); struct có _Alignas(64) phải
     * cấp bằng aligned_alloc. sizeof đã là bội của 64 vì alignment của
     * struct là 64, đúng điều kiện size của aligned_alloc. */
    r = aligned_alloc(alignof(struct ring), sizeof *r);
    if (r == NULL)
        return NULL;
    r->slots = calloc(capacity, sizeof *r->slots);
    if (r->slots == NULL)
    {
        free(r);
        return NULL;
    }
    atomic_init(&r->head, 0);
    atomic_init(&r->tail, 0);
    r->tail_cache = 0;
    r->head_cache = 0;
    r->mask = capacity - 1u;
    return r;
}

/* ring_destroy: NULL-safe; free slots và struct. Không free các item. */
void ring_destroy(struct ring *r)
{
    if (r == NULL)
        return;
    free(r->slots);
    free(r);
}

/* ring_push: xem pseudo-code ở đầu file. */
bool ring_push(struct ring *r, void *item)
{
    size_t h = atomic_load_explicit(&r->head, memory_order_relaxed);

    if (h - r->tail_cache > r->mask)
    {
        /* acquire: cặp với release trong ring_pop. Consumer đọc xong slot
         * rồi mới công bố tail mới, nên ghi đè slot đó ở đây là an toàn.
         * tail_cache cũ hơn tail thật nên chỉ có thể báo đầy sai, không
         * bao giờ cho ghi đè slot chưa đọc. */
        r->tail_cache = atomic_load_explicit(&r->tail, memory_order_acquire);
        if (h - r->tail_cache > r->mask)
            return false;
    }
    r->slots[h & r->mask] = item;
    /* release: ghi slot phía trên phải được thấy trước head mới. */
    atomic_store_explicit(&r->head, h + 1u, memory_order_release);
    return true;
}

/* ring_pop: xem pseudo-code ở đầu file. */
bool ring_pop(struct ring *r, void **item)
{
    size_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);

    if (t == r->head_cache)
    {
        /* acquire cặp với release của producer; head_cache chỉ lưu giá trị
         * đã acquire nên slot trước nó chắc chắn đã được ghi xong. */
        r->head_cache = atomic_load_explicit(&r->head, memory_order_acquire);
        if (t == r->head_cache)
            return false;
    }
    *item = r->slots[t & r->mask];
    atomic_store_explicit(&r->tail, t + 1u, memory_order_release);
    return true;
}

/* ring_count: head - tail, cả hai load relaxed. */
size_t ring_count(const struct ring *r)
{
    /* Load tail trước: tail chỉ tăng nên tail cũ <= head đọc sau, hiệu
     * không bao giờ "âm". Đọc head trước có thể ra số khổng lồ. */
    size_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    size_t h = atomic_load_explicit(&r->head, memory_order_relaxed);

    return h - t;
}
