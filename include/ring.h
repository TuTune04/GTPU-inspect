/*
 * ring.h — ring buffer SPSC lock-free.                       [TUẦN 3]
 *
 * SPSC = Single Producer, Single Consumer: đúng MỘT luồng gọi ring_push và
 * đúng MỘT luồng (khác) gọi ring_pop. Với ràng buộc này không cần mutex,
 * chỉ cần biến atomic với memory ordering đúng.
 *
 * Phần tử là con trỏ void* (thường trỏ tới buffer gói lấy từ mempool), nên
 * ring không copy dữ liệu gói.
 *
 * Kiểu opaque: struct ring định nghĩa trong ring.c, nơi dùng <stdatomic.h>.
 * Không để _Atomic trong header vì header này còn được include từ C++ (test).
 */
#ifndef GTPU_RING_H
#define GTPU_RING_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ring;

/* capacity phải là lũy thừa của 2 (>= 2); sai -> NULL. */
struct ring *ring_create(size_t capacity);
void         ring_destroy(struct ring *r);

/* Producer. Đầy -> false (không chặn, không ghi đè). */
bool ring_push(struct ring *r, void *item);

/* Consumer. Rỗng -> false. */
bool ring_pop(struct ring *r, void **item);

/* Theo lô (v2): một lần cập nhật head/tail cho cả lô, nên chi phí đồng bộ
 * giữa hai core chia đều cho n phần tử. Push được bao nhiêu thì trả về bấy
 * nhiêu (0..n, theo thứ tự, phần còn lại người gọi thử lại). Pop tối đa max
 * phần tử, trả số đã lấy. */
size_t ring_push_bulk(struct ring *r, void *const *items, size_t n);
size_t ring_pop_bulk(struct ring *r, void **items, size_t max);

/* Số phần tử ước lượng — chỉ dùng để quan sát/debug, không dùng để đồng bộ. */
size_t ring_count(const struct ring *r);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_RING_H */
