/*
 * stats.c — thống kê và báo cáo.                            [TUẦN 2]
 */
#include "stats.h"

#include <inttypes.h> /* PRIu64, PRIx32: in uint64_t/uint32_t đúng chuẩn */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>   /* malloc, free */
#include <string.h>   /* memset */

#include "gtpu.h"     /* gtpu_msg_type_str, GTPU_MSG_GPDU */

/* stats_init: memset(st, 0, sizeof *st). */
void stats_init(struct stats *st)
{
    memset(st, 0, sizeof *st);
}

/*
 * Phiên người dùng chỉ gắn với G-PDU và End Marker: hai loại này mang TEID
 * của một tunnel thật. Echo có TEID 0 (path management giữa hai node, không
 * thuộc phiên nào) và Error Indication mang TEID trong IE chứ không phải
 * header, nên cả hai chỉ được đếm theo message type, không tạo phiên.
 */
static bool belongs_to_session(uint8_t msg_type)
{
    return msg_type == GTPU_MSG_GPDU || msg_type == GTPU_MSG_END_MARKER;
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
    st->packets++;
    st->bytes += wire_len;
    if ((size_t)res < PARSE_RESULT_COUNT)
        st->by_result[res]++;

    if (res != PARSE_OK)
        return 0;

    st->by_msg_type[info->gtp.msg_type]++;
    if (info->gtp.has_qfi && info->gtp.qfi < 64u)
        st->by_qfi[info->gtp.qfi]++;

    if (sessions != NULL && belongs_to_session(info->gtp.msg_type))
    {
        struct session_key key;
        struct session *s;

        key.teid = info->gtp.teid;
        key.endpoint_ip = info->outer_dst_ip;
        s = session_table_upsert(sessions, &key);
        if (s == NULL)
            return -1;
        session_account(s, info, wire_len, ts_ns);
    }
    return 0;
}

/* stats_merge: cộng từng field, kể cả từng phần tử mảng. */
void stats_merge(struct stats *dst, const struct stats *src)
{
    size_t i;

    dst->packets += src->packets;
    dst->bytes += src->bytes;
    for (i = 0; i < PARSE_RESULT_COUNT; i++)
        dst->by_result[i] += src->by_result[i];
    for (i = 0; i < 256; i++)
        dst->by_msg_type[i] += src->by_msg_type[i];
    for (i = 0; i < 64; i++)
        dst->by_qfi[i] += src->by_qfi[i];
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
    struct inner_flow *f = NULL;
    size_t i;

    if (s->packets == 0)
        s->first_ts_ns = ts_ns;
    s->packets++;
    s->bytes += wire_len;
    s->last_ts_ns = ts_ns;
    /* last_qfi = 0 nghĩa là chưa thấy QFI: QFI hợp lệ là 1..63. */
    if (info->gtp.has_qfi)
        s->last_qfi = info->gtp.qfi;

    if (!info->has_inner)
        return;

    for (i = 0; i < s->n_flows; i++)
    {
        struct inner_flow *c = &s->flows[i];

        if (c->src_ip == info->inner_src_ip && c->dst_ip == info->inner_dst_ip &&
            c->sport == info->inner_sport && c->dport == info->inner_dport &&
            c->proto == info->inner_proto)
        {
            f = c;
            break;
        }
    }
    if (f == NULL)
    {
        if (s->n_flows >= SESSION_MAX_FLOWS)
        {
            s->flows_overflow++;
            return;
        }
        f = &s->flows[s->n_flows++];
        memset(f, 0, sizeof *f);
        f->src_ip = info->inner_src_ip;
        f->dst_ip = info->inner_dst_ip;
        f->sport = info->inner_sport;
        f->dport = info->inner_dport;
        f->proto = info->inner_proto;
    }
    f->packets++;
    f->bytes += wire_len;
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
static void fmt_ip(char *buf, size_t cap, uint32_t ip)
{
    snprintf(buf, cap, "%u.%u.%u.%u", (unsigned)((ip >> 24) & 0xffu),
             (unsigned)((ip >> 16) & 0xffu), (unsigned)((ip >> 8) & 0xffu),
             (unsigned)(ip & 0xffu));
}

void stats_print(const struct stats *st, const struct session_table *sessions,
                 size_t top_n, FILE *out)
{
    size_t i;

    fprintf(out, "Packets: %" PRIu64 "   Bytes: %" PRIu64 "\n\n", st->packets,
            st->bytes);

    fprintf(out, "%-28s %10s\n", "Result", "Count");
    for (i = 0; i < PARSE_RESULT_COUNT; i++)
    {
        if (st->by_result[i] > 0)
            fprintf(out, "%-28s %10" PRIu64 "\n",
                    parse_result_str((enum parse_result)i), st->by_result[i]);
    }

    fprintf(out, "\n%-28s %10s\n", "Message type", "Count");
    for (i = 0; i < 256; i++)
    {
        char name[48];

        if (st->by_msg_type[i] == 0)
            continue;
        snprintf(name, sizeof name, "%s (%u)", gtpu_msg_type_str((uint8_t)i),
                 (unsigned)i);
        fprintf(out, "%-28s %10" PRIu64 "\n", name, st->by_msg_type[i]);
    }

    {
        bool header = false;

        for (i = 0; i < 64; i++)
        {
            if (st->by_qfi[i] == 0)
                continue;
            if (!header)
            {
                fprintf(out, "\n%-28s %10s\n", "QFI", "Count");
                header = true;
            }
            fprintf(out, "%-28zu %10" PRIu64 "\n", i, st->by_qfi[i]);
        }
    }

    if (sessions == NULL || top_n == 0)
        return;

    {
        size_t cap = session_table_size(sessions);
        const struct session **top;
        size_t n;

        if (cap > top_n)
            cap = top_n;
        if (cap == 0)
            return;
        top = malloc(cap * sizeof *top);
        if (top == NULL)
            return;
        n = session_table_top_n(sessions, top, cap);

        fprintf(out, "\nTop %zu sessions by bytes\n", top_n);
        fprintf(out, "%-10s  %-15s %8s %10s %6s  %s\n", "TEID", "Endpoint",
                "Packets", "Bytes", "Flows", "QFI");
        for (i = 0; i < n; i++)
        {
            const struct session *s = top[i];
            char ip[16], qfi[8];

            fmt_ip(ip, sizeof ip, s->key.endpoint_ip);
            if (s->last_qfi != 0)
                snprintf(qfi, sizeof qfi, "%u", (unsigned)s->last_qfi);
            else
                snprintf(qfi, sizeof qfi, "-");
            fprintf(out, "0x%08" PRIx32 "  %-15s %8" PRIu64 " %10" PRIu64
                         " %6u  %s\n",
                    s->key.teid, ip, s->packets, s->bytes,
                    (unsigned)s->n_flows, qfi);
        }
        free(top);
    }
}
