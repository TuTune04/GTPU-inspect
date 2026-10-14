/*
 * mempool.h — memory pool kích thước cố định.                [TUẦN 3]
 *
 * Cấp trước `count` buffer, mỗi buffer `obj_size` byte, trong MỘT lần
 * malloc. alloc/free chỉ là lấy/trả phần tử ở đầu free list: O(1), không
 * gọi malloc, không phân mảnh, thời gian ổn định.
 *
 * Pool KHÔNG thread-safe: chỉ một luồng được gọi alloc/free. Trong pipeline
 * tuần 3, reader alloc còn worker xong việc phải TRẢ buffer — xem
 * pipeline.c về cách trả buffer qua một ring ngược (worker -> reader).
 */
#ifndef GTPU_MEMPOOL_H
#define GTPU_MEMPOOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mempool;

/* obj_size được làm tròn lên bội của alignment. NULL nếu hết bộ nhớ. */
struct mempool *mempool_create(size_t obj_size, size_t count);
void            mempool_destroy(struct mempool *p);

/* Hết buffer -> NULL (không malloc thêm). */
void *mempool_alloc(struct mempool *p);

/* obj phải là con trỏ lấy từ CHÍNH pool này. NULL -> không làm gì. */
void mempool_free(struct mempool *p, void *obj);

size_t mempool_available(const struct mempool *p);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_MEMPOOL_H */
