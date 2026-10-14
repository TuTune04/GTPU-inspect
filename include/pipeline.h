/*
 * pipeline.h — 1 luồng đọc + N luồng worker.                 [TUẦN 3]
 *
 *  .pcap -> [reader] -- hash(TEID) % N --> ring[i] --> [worker i]
 *               ^                                         |
 *               +------------- free_ring[i] <-------------+  (trả buffer)
 *
 * Mỗi worker có struct stats và session_table RIÊNG; sau khi mọi worker
 * kết thúc, luồng chính gộp stats bằng stats_merge.
 */
#ifndef GTPU_PIPELINE_H
#define GTPU_PIPELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "session_table.h"
#include "stats.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PIPELINE_MAX_WORKERS 64u

struct pipeline_config {
    const char *path;
    unsigned    n_workers;      /* 1..PIPELINE_MAX_WORKERS */
    size_t      ring_capacity;  /* lũy thừa 2, ví dụ 1024 */
    size_t      pool_size;      /* số buffer mỗi worker, ví dụ 4096 */
    bool        use_mempool;    /* false: malloc/free mỗi gói (để so sánh) */
};

struct pipeline_result {
    struct stats           total;                       /* đã gộp */
    unsigned               n_workers;
    struct session_table  *tables[PIPELINE_MAX_WORKERS]; /* mỗi worker một bảng */
    uint64_t               per_worker_packets[PIPELINE_MAX_WORKERS];
    double                 elapsed_sec;
};

/* 0 nếu thành công. Khi thành công, gọi pipeline_result_free sau khi dùng. */
int  pipeline_run(const struct pipeline_config *cfg, struct pipeline_result *res);
void pipeline_result_free(struct pipeline_result *res);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_PIPELINE_H */
