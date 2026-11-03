/*
 * stats.h — thống kê tổng và báo cáo cuối chương trình.      [TUẦN 2]
 */
#ifndef GTPU_STATS_H
#define GTPU_STATS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>    /* FILE */

#include "parse_result.h"
#include "parser.h"
#include "session_table.h"

#ifdef __cplusplus
extern "C" {
#endif

struct stats {
    uint64_t packets;                        /* mọi gói đọc từ pcap   */
    uint64_t bytes;                          /* tổng orig_len         */
    uint64_t by_result[PARSE_RESULT_COUNT];  /* ok / ignored / err    */
    uint64_t by_msg_type[256];               /* chỉ gói PARSE_OK      */
    uint64_t by_qfi[64];                     /* chỉ gói có QFI        */
};

void stats_init(struct stats *st);

/*
 * Ghi nhận một gói:
 *   - luôn: packets++, bytes += wire_len, by_result[res]++
 *   - nếu res == PARSE_OK: by_msg_type, by_qfi, và cập nhật phiên trong
 *     bảng sessions (nếu sessions != NULL) bằng session_account().
 * Trả -1 nếu không thêm được phiên (bảng đầy), 0 nếu bình thường.
 */
int stats_record(struct stats *st, struct session_table *sessions,
                 enum parse_result res, const struct pkt_info *info,
                 uint32_t wire_len, uint64_t ts_ns);

/* Cộng dồn src vào dst — tuần 3, gộp kết quả các worker. */
void stats_merge(struct stats *dst, const struct stats *src);

/* Cập nhật counter của một phiên và luồng inner tương ứng. */
void session_account(struct session *s, const struct pkt_info *info,
                     uint32_t wire_len, uint64_t ts_ns);

/*
 * Gộp src vào dst cho CÙNG một phiên, với src là phần đến SAU trong file
 * (v2, chế độ shared-nothing: mỗi worker một đoạn file, gộp theo thứ tự
 * đoạn). Tổng gói/byte, first/last ts và last_qfi luôn đúng như chạy tuần
 * tự. Trả false khi chi tiết theo luồng có thể lệch: src có gói rơi vào
 * flows_overflow (không còn biết thuộc luồng nào) trong khi dst đã theo dõi
 * luồng, nên các gói đó có thể thuộc một luồng của dst.
 */
bool session_merge(struct session *dst, const struct session *src);

/* In báo cáo: tổng, theo message type, theo lý do lỗi, top N phiên. */
void stats_print(const struct stats *st, const struct session_table *sessions,
                 size_t top_n, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_STATS_H */
