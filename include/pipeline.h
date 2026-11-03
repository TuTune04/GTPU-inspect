/*
 * pipeline.h — 1 luồng đọc + N luồng worker.             [TUẦN 3, v2]
 *
 *  .pcap (mmap) -> [reader] -- hash(TEID) % N --> ring[i] --> [worker i]
 *                                 offset record           đọc thẳng từ map
 *
 * Mỗi worker có struct stats và session_table RIÊNG; sau khi mọi worker
 * kết thúc, luồng chính gộp stats bằng stats_merge.
 */
#ifndef GTPU_PIPELINE_H
#define GTPU_PIPELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pcap.h"
#include "session_table.h"
#include "stats.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PIPELINE_MAX_WORKERS 64u
#define PIPELINE_MAX_BATCH   256u

struct pipeline_config {
    const char *path;
    unsigned    n_workers;      /* 1..PIPELINE_MAX_WORKERS */
    size_t      ring_capacity;  /* lũy thừa 2, ví dụ 1024 */
    size_t      batch;          /* số gói mỗi lần push, 0/1 = từng gói;
                                   <= PIPELINE_MAX_BATCH và <= ring_capacity */
    bool        shared_nothing; /* true: không reader, mỗi worker một đoạn file;
                                   phiên phải gộp bằng session_merge */
};

struct pipeline_result {
    struct stats           total;                       /* đã gộp */
    unsigned               n_workers;
    struct session_table  *tables[PIPELINE_MAX_WORKERS]; /* mỗi worker một bảng */
    uint64_t               per_worker_packets[PIPELINE_MAX_WORKERS];
    uint64_t               dropped_sessions;  /* stats_record trả -1 */
    enum pcap_status       read_status;       /* PCAP_EOF nếu đọc hết file */
    double                 elapsed_sec;       /* tạo worker -> join xong */
    double                 reader_sec;        /* vòng đọc của reader; shared-
                                                 nothing: thời gian chia file */
    double                 per_worker_cpu_sec[PIPELINE_MAX_WORKERS];
};

/* 0 nếu thành công (kể cả khi file hỏng giữa chừng: xem read_status, stats
 * vẫn chứa các gói đã đọc). pcap_map_open lỗi -> -1 và read_status là lỗi đó.
 * Khi thành công, gọi pipeline_result_free sau khi dùng. */
int  pipeline_run(const struct pipeline_config *cfg, struct pipeline_result *res);
void pipeline_result_free(struct pipeline_result *res);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_PIPELINE_H */
