/*
 * stats.c — thống kê và báo cáo.                            [TUẦN 2]
 */
#include "stats.h"

#include <inttypes.h> /* PRIu64, PRIx32: in uint64_t/uint32_t đúng chuẩn */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>   /* memset */

#include "gtpu.h"     /* gtpu_msg_type_str, GTPU_MSG_GPDU */

/* stats_init: memset(st, 0, sizeof *st). */
void stats_init(struct stats *st)
{
    /* TODO: xóa stub và viết code của bạn */
    (void)st;
}

/*
 * stats_record
 *   Lưu ý: info chỉ có nghĩa khi res == PARSE_OK.
 *   Key phiên: { info->gtp.teid, info->outer_dst_ip }.
 *   Echo Request/Response có TEID 0 — bạn có muốn chúng thành một "phiên"
 *   không? Quyết định và ghi lý do (gợi ý: chỉ G-PDU và End Marker mới gắn
 *   với phiên người dùng).
 */
int stats_record(struct stats *st, struct session_table *sessions,
                 enum parse_result res, const struct pkt_info *info,
                 uint32_t wire_len, uint64_t ts_ns)
{
    /* TODO */
    (void)st;
    (void)sessions;
    (void)res;
    (void)info;
    (void)wire_len;
    (void)ts_ns;
    return 0;
}

/* stats_merge: cộng từng field, kể cả từng phần tử mảng. */
void stats_merge(struct stats *dst, const struct stats *src)
{
    /* TODO */
    (void)dst;
    (void)src;
}

/*
 * session_account
 *   1. packets++, bytes += wire_len; first_ts_ns (nếu packets trước đó = 0),
 *      last_ts_ns; last_qfi nếu info->gtp.has_qfi.
 *   2. Nếu info->has_inner: tìm trong flows[0..n_flows) luồng có cùng
 *      5-tuple (so từng field). Thấy -> cộng counter. Không thấy và
 *      n_flows < SESSION_MAX_FLOWS -> thêm mới. Đầy -> flows_overflow++.
 *   Tìm tuyến tính trên 8 phần tử là đủ nhanh — không cần hash cho mảng nhỏ.
 */
void session_account(struct session *s, const struct pkt_info *info,
                     uint32_t wire_len, uint64_t ts_ns)
{
    /* TODO */
    (void)s;
    (void)info;
    (void)wire_len;
    (void)ts_ns;
}

/*
 * stats_print — ví dụ bố cục:
 *
 *   Packets: 44   Bytes: 12345
 *
 *   Result                       Count
 *   ok                              21
 *   ignored:not_udp                  1
 *   err:gtp_truncated                1
 *
 *   Message type                 Count
 *   G-PDU (255)                     17
 *   Echo Request (1)                 1
 *
 *   Top 10 sessions by bytes
 *   TEID        Endpoint         Packets   Bytes   Flows  QFI
 *   0x00001001  192.168.20.1           5    2000       1    -
 *
 *   In IP từ uint32_t host order: (ip >> 24) & 0xff, (ip >> 16) & 0xff, ...
 *   In uint64_t: fprintf(out, "%" PRIu64, x);  TEID: "0x%08" PRIx32
 *   sessions == NULL -> bỏ qua phần top N.
 */
void stats_print(const struct stats *st, const struct session_table *sessions,
                 size_t top_n, FILE *out)
{
    /* TODO */
    (void)st;
    (void)sessions;
    (void)top_n;
    (void)out;
}
