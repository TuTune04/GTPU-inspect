/*
 * mempool.c — memory pool kích thước cố định, free list.    [TUẦN 3]
 *
 * Test: tests/test_mempool.cpp
 *
 * KHÁI NIỆM
 *   Một khối nhớ lớn chia thành count ô bằng nhau. Ô nào đang rảnh thì
 *   dùng chính vùng nhớ của nó để lưu con trỏ tới ô rảnh kế tiếp
 *   ("intrusive free list") -> không tốn thêm bộ nhớ quản lý.
 *
 *     free_head -> [ô 3] -> [ô 0] -> [ô 7] -> NULL
 *
 *   alloc: lấy free_head, free_head = next của nó.
 *   free : ghi next của obj = free_head, free_head = obj.
 *
 *   Vì sao tốt hơn malloc trên đường xử lý gói:
 *     - O(1) cố định, không lock nội bộ, không syscall, không phân mảnh
 *     - biết trước tổng bộ nhớ; hết pool = tín hiệu backpressure rõ ràng
 *     - các buffer nằm gần nhau, tốt cho cache
 *
 * CHI TIẾT KỸ THUẬT CẦN CẨN THẬN
 *   - obj_size phải >= sizeof(void *) để chứa con trỏ next, và làm tròn lên
 *     bội của alignof(max_align_t) (hoặc 64 nếu muốn mỗi buffer một cache
 *     line). Công thức làm tròn: (n + a - 1) / a * a.
 *   - Kiểm tra tràn: obj_size * count có thể tràn size_t. Kiểm tra
 *     count > SIZE_MAX / obj_size trước khi nhân.
 *   - Đọc/ghi con trỏ next trong ô: dùng memcpy(&next, obj, sizeof next)
 *     thay vì *(void **)obj. Đúng tinh thần quy tắc "không ép kiểu con trỏ
 *     buffer" và tránh vấn đề strict aliasing.
 *   - Debug (tùy chọn): trong mempool_free kiểm tra obj nằm trong
 *     [base, base + obj_size * count) và (obj - base) % obj_size == 0.
 *     So sánh con trỏ thuộc hai mảng khác nhau là UB -> đổi sang uintptr_t
 *     (<stdint.h>) rồi mới so.
 *
 * Gợi ý struct:
 *
 *   struct mempool {
 *       unsigned char *base;      khối nhớ lớn
 *       size_t         obj_size;  đã làm tròn
 *       size_t         count;
 *       size_t         available;
 *       void          *free_head;
 *   };
 */
#include "mempool.h"

#include <assert.h>
#include <stddef.h>    /* max_align_t, size_t */
#include <stdint.h>    /* SIZE_MAX, uintptr_t */
#include <stdlib.h>    /* malloc, aligned_alloc, free */
#include <string.h>    /* memcpy */

/* Mỗi ô một bội của cache line: buffer gói của hai worker không bao giờ
 * chung một line, và 64 cũng là bội của alignof(max_align_t). */
#define POOL_ALIGN 64u

struct mempool {
    unsigned char *base;      /* khối nhớ lớn */
    size_t         obj_size;  /* đã làm tròn */
    size_t         count;
    size_t         available;
    void          *free_head;
};

/* Đọc/ghi con trỏ next nằm trong ô rảnh bằng memcpy, không *(void **)obj. */
static void *next_of(const void *obj)
{
    void *next;

    memcpy(&next, obj, sizeof next);
    return next;
}

static void set_next(void *obj, void *next)
{
    memcpy(obj, &next, sizeof next);
}

/*
 * mempool_create
 *   1. Làm tròn obj_size, kiểm tra tràn.
 *   2. Cấp struct + khối base.
 *   3. Xâu mọi ô vào free list (duyệt i = count-1 .. 0 để ô 0 ở đầu).
 */
struct mempool *mempool_create(size_t obj_size, size_t count)
{
    struct mempool *p;
    size_t i;

    if (count == 0)
        return NULL;
    if (obj_size < sizeof(void *))
        obj_size = sizeof(void *);
    if (obj_size > SIZE_MAX - (POOL_ALIGN - 1u))
        return NULL;
    obj_size = (obj_size + POOL_ALIGN - 1u) / POOL_ALIGN * POOL_ALIGN;
    if (count > SIZE_MAX / obj_size)
        return NULL;

    p = malloc(sizeof *p);
    if (p == NULL)
        return NULL;
    /* obj_size * count là bội của POOL_ALIGN, đúng điều kiện aligned_alloc. */
    p->base = aligned_alloc(POOL_ALIGN, obj_size * count);
    if (p->base == NULL)
    {
        free(p);
        return NULL;
    }
    p->obj_size = obj_size;
    p->count = count;
    p->available = count;
    p->free_head = NULL;
    for (i = count; i-- > 0;)
    {
        void *obj = p->base + i * obj_size;

        set_next(obj, p->free_head);
        p->free_head = obj;
    }
    return p;
}

/* mempool_destroy: NULL-safe; free base rồi free struct. */
void mempool_destroy(struct mempool *p)
{
    if (p == NULL)
        return;
    free(p->base);
    free(p);
}

void *mempool_alloc(struct mempool *p)
{
    void *obj = p->free_head;

    if (obj == NULL)
        return NULL;
    p->free_head = next_of(obj);
    p->available--;
    return obj;
}

void mempool_free(struct mempool *p, void *obj)
{
    if (obj == NULL)
        return;
#ifndef NDEBUG
    {
        /* So con trỏ khác mảng là UB nên so bằng uintptr_t. Bắt lỗi trả nhầm
         * pool hoặc con trỏ lệch vào giữa ô — free list hỏng thì rất khó dò. */
        uintptr_t b = (uintptr_t)p->base;
        uintptr_t o = (uintptr_t)obj;

        assert(o >= b && o - b < p->obj_size * p->count);
        assert((o - b) % p->obj_size == 0);
        assert(p->available < p->count);
    }
#endif
    set_next(obj, p->free_head);
    p->free_head = obj;
    p->available++;
}

size_t mempool_available(const struct mempool *p)
{
    return p->available;
}
