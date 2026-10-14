/*
 * parser.h — parse một frame: Ethernet -> IPv4 -> UDP -> GTP-U -> inner IPv4
 *            -> inner TCP/UDP.                              [TUẦN 1]
 */
#ifndef GTPU_PARSER_H
#define GTPU_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gtpu.h"
#include "parse_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_HEADER_LEN   14u
#define ETHERTYPE_IPV4   0x0800u
#define IPV4_MIN_HDR_LEN 20u
#define UDP_HEADER_LEN   8u
#define IPPROTO_NUM_TCP  6u    /* tránh trùng tên IPPROTO_TCP của <netinet/in.h> */
#define IPPROTO_NUM_UDP  17u

/* Mọi địa chỉ IP và cổng lưu ở HOST order (đã qua rd_be16/rd_be32). */
struct pkt_info {
    /* outer */
    uint32_t outer_src_ip, outer_dst_ip;
    uint16_t outer_sport, outer_dport;

    /* GTP-U */
    struct gtpu_hdr gtp;

    /* inner (chỉ có khi gtp.msg_type == G-PDU) */
    bool           has_inner;
    const uint8_t *inner;           /* trỏ vào buffer gốc, không copy */
    size_t         inner_len;
    uint32_t       inner_src_ip, inner_dst_ip;
    uint8_t        inner_proto;     /* 6 TCP, 17 UDP, 1 ICMP...       */
    uint16_t       inner_sport, inner_dport;   /* 0 nếu không TCP/UDP */
};

/*
 * Parse frame Ethernet [buf, buf + len). len là caplen, không phải orig_len.
 * Trả PARSE_OK và điền *out, hoặc trả lý do bỏ qua / lỗi (khi đó nội dung
 * *out không xác định).
 */
enum parse_result parse_packet(const uint8_t *buf, size_t len,
                               struct pkt_info *out);

/* "ok", "ignored:not_udp", "err:gtp_truncated"... khớp file .expected. */
const char *parse_result_str(enum parse_result r);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_PARSER_H */
