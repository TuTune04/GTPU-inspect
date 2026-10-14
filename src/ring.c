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

/* ring_create: kiểm tra capacity >= 2 và (capacity & (capacity - 1)) == 0. */
struct ring *ring_create(size_t capacity)
{
    /* TODO: xóa stub và viết code của bạn */
    (void)capacity;
    return NULL;
}

/* ring_destroy: NULL-safe; free slots và struct. Không free các item. */
void ring_destroy(struct ring *r)
{
    /* TODO */
    (void)r;
}

/* ring_push: xem pseudo-code ở đầu file. */
bool ring_push(struct ring *r, void *item)
{
    /* TODO */
    (void)r;
    (void)item;
    return false;
}

/* ring_pop: xem pseudo-code ở đầu file. */
bool ring_pop(struct ring *r, void **item)
{
    /* TODO */
    (void)r;
    (void)item;
    return false;
}

/* ring_count: head - tail, cả hai load relaxed. */
size_t ring_count(const struct ring *r)
{
    /* TODO */
    (void)r;
    return 0;
}
