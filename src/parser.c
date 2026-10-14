/*
 * parser.c — Ethernet -> IPv4 -> UDP -> GTP-U -> inner IPv4 -> TCP/UDP.
 *                                                            [TUẦN 1]
 *
 * Test: tests/test_parser.cpp (data-driven trên các file .pcap trong tests/data/).
 *
 * NGUYÊN TẮC VÀNG: mỗi lần đọc một trường, NGAY TRƯỚC ĐÓ phải kiểm tra
 * "còn đủ byte không". Không tin bất kỳ trường độ dài nào trong gói.
 * Gặp gói không thỏa -> trả đúng enum lý do, KHÔNG đọc tiếp.
 *
 * MÔ HÌNH ĐỀ XUẤT: mỗi lớp là một hàm static nhận vùng byte (p, len) của
 * chính lớp đó, điền phần của mình vào struct pkt_info, và trả qua tham số
 * out vùng byte của lớp kế tiếp (con trỏ + độ dài). parse_packet() chỉ việc
 * gọi lần lượt và dừng ở lớp đầu tiên không trả PARSE_OK.
 *
 * Mẫu khai báo (bỏ comment khi bạn bắt đầu viết hàm đó — khai báo static
 * mà chưa dùng sẽ bị clang báo -Wunused-function và -Werror biến thành lỗi):
 *
 *   static enum parse_result parse_eth(const uint8_t *p, size_t len,
 *                                      const uint8_t **next, size_t *next_len);
 *   static enum parse_result parse_ipv4(const uint8_t *p, size_t len,
 *                                       struct pkt_info *out,
 *                                       const uint8_t **next, size_t *next_len);
 *   static enum parse_result parse_udp(const uint8_t *p, size_t len,
 *                                      struct pkt_info *out,
 *                                      const uint8_t **next, size_t *next_len);
 *   static enum parse_result parse_inner(const uint8_t *p, size_t len,
 *                                        struct pkt_info *out);
 *
 * Phần GTP-U nằm riêng trong gtpu.c (gtpu_parse) để test được độc lập.
 */
#include "parser.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>   /* memset nếu cần xóa *out */

#include "bytes.h"    /* rd_be16, rd_be32 */
#include "gtpu.h"     /* gtpu_parse, GTPU_PORT, GTPU_MSG_GPDU */

/*
 * ---------------------------------------------------------------------------
 * parse_eth — Ethernet II (14 byte)
 *
 *   off 0  : dst MAC (6)
 *   off 6  : src MAC (6)
 *   off 12 : EtherType (2, big-endian)
 *
 *   len < ETH_HEADER_LEN          -> PARSE_ERR_ETH_TRUNCATED
 *   EtherType != ETHERTYPE_IPV4   -> PARSE_IGN_NOT_IPV4
 *   next = p + 14, next_len = len - 14
 *
 * Mở rộng (không bắt buộc): VLAN tag 0x8100 chèn thêm 4 byte trước EtherType.
 *
 * ---------------------------------------------------------------------------
 * parse_ipv4 — IPv4 header (20..60 byte)
 *
 *   off 0  : version (4 bit cao) | IHL (4 bit thấp, đơn vị 4 byte)
 *   off 2  : total length (2)     = header + payload
 *   off 6  : flags(3) | fragment offset(13)   ; MF là bit 0x2000
 *   off 9  : protocol (1)
 *   off 12 : src IP (4)
 *   off 16 : dst IP (4)
 *
 *   Thứ tự kiểm tra (khớp malformed.expected):
 *     len < 20                          -> PARSE_ERR_IP_TRUNCATED
 *     version != 4                      -> PARSE_ERR_IP_BAD_VERSION
 *     IHL < 5                           -> PARSE_ERR_IP_BAD_IHL
 *     len < IHL*4                       -> PARSE_ERR_IP_TRUNCATED
 *     total < IHL*4 || total > len      -> PARSE_ERR_IP_LEN_MISMATCH
 *     MF set || frag offset != 0        -> PARSE_IGN_IP_FRAGMENT
 *     protocol != 17                    -> PARSE_IGN_NOT_UDP
 *
 *   QUAN TRỌNG: sau khi kiểm tra, coi độ dài gói là `total`, KHÔNG phải len.
 *   Frame Ethernet tối thiểu 60 byte nên gói nhỏ có byte padding ở cuối;
 *   nếu dùng len thì UDP/GTP length sẽ "không khớp" sai.
 *   next = p + IHL*4, next_len = total - IHL*4
 *
 *   Kiểu dữ liệu: IHL*4 tính bằng size_t để so với len không bị
 *   -Wsign-compare / -Wconversion.
 *
 * ---------------------------------------------------------------------------
 * parse_udp — UDP header (8 byte)
 *
 *   off 0 : src port   off 2 : dst port   off 4 : length (gồm cả 8 byte header)
 *
 *     len < 8                           -> PARSE_ERR_UDP_TRUNCATED
 *     ulen < 8 || ulen > len            -> PARSE_ERR_UDP_LEN_MISMATCH
 *     dst port != GTPU_PORT             -> PARSE_IGN_NOT_GTPU_PORT
 *         (xét CỔNG ĐÍCH: gói GTP-C trong non_gtpu.pcap có src port 2152
 *          nhưng dst port 2123)
 *   next = p + 8, next_len = ulen - 8
 *
 * ---------------------------------------------------------------------------
 * parse_inner — inner IPv4 + TCP/UDP port (chỉ gọi khi msg_type == G-PDU)
 *
 *     len < 20                          -> PARSE_ERR_INNER_TRUNCATED
 *     version != 4 || IHL < 5           -> PARSE_ERR_INNER_BAD_IHL
 *   Lấy src/dst IP, protocol. Nếu TCP hoặc UDP và còn đủ 4 byte sau IHL*4
 *   thì đọc sport/dport; không đủ thì để 0 (không coi là lỗi).
 *   (Echo/Error Indication/End Marker: has_inner = false, không gọi hàm này.)
 * ---------------------------------------------------------------------------
 */

/* Offset các trường dùng trong từng lớp. */
#define ETH_OFF_ETHERTYPE 12u
#define IPV4_OFF_TOTAL_LEN 2u
#define IPV4_OFF_FRAG 6u
#define IPV4_OFF_PROTO 9u
#define IPV4_OFF_SRC 12u
#define IPV4_OFF_DST 16u
#define IPV4_FLAG_MF 0x2000u      /* More Fragments */
#define IPV4_FRAG_OFF_MASK 0x1fffu
#define UDP_OFF_SPORT 0u
#define UDP_OFF_DPORT 2u
#define UDP_OFF_LEN 4u
#define L4_PORTS_LEN 4u           /* sport + dport, đủ cho cả TCP lẫn UDP */

static enum parse_result parse_eth(const uint8_t *p, size_t len,
                                   const uint8_t **next, size_t *next_len)
{
    if (len < ETH_HEADER_LEN)
        return PARSE_ERR_ETH_TRUNCATED;
    if (rd_be16(p + ETH_OFF_ETHERTYPE) != ETHERTYPE_IPV4)
        return PARSE_IGN_NOT_IPV4;
    *next = p + ETH_HEADER_LEN;
    *next_len = len - ETH_HEADER_LEN;
    return PARSE_OK;
}

static enum parse_result parse_ipv4(const uint8_t *p, size_t len,
                                    struct pkt_info *out,
                                    const uint8_t **next, size_t *next_len)
{
    unsigned version, ihl;
    size_t hdr_len, total;
    uint16_t frag;

    if (len < IPV4_MIN_HDR_LEN)
        return PARSE_ERR_IP_TRUNCATED;

    version = (unsigned)(p[0] >> 4);
    ihl = (unsigned)(p[0] & 0x0fu);
    if (version != 4u)
        return PARSE_ERR_IP_BAD_VERSION;
    if (ihl < 5u)
        return PARSE_ERR_IP_BAD_IHL;
    hdr_len = (size_t)ihl * 4u;
    if (len < hdr_len)
        return PARSE_ERR_IP_TRUNCATED;

    total = rd_be16(p + IPV4_OFF_TOTAL_LEN);
    if (total < hdr_len || total > len)
        return PARSE_ERR_IP_LEN_MISMATCH;

    frag = rd_be16(p + IPV4_OFF_FRAG);
    if ((frag & IPV4_FLAG_MF) != 0u || (frag & IPV4_FRAG_OFF_MASK) != 0u)
        return PARSE_IGN_IP_FRAGMENT;
    if (p[IPV4_OFF_PROTO] != IPPROTO_NUM_UDP)
        return PARSE_IGN_NOT_UDP;

    out->outer_src_ip = rd_be32(p + IPV4_OFF_SRC);
    out->outer_dst_ip = rd_be32(p + IPV4_OFF_DST);
    /* Từ đây coi độ dài gói là `total`: bỏ byte padding của Ethernet. */
    *next = p + hdr_len;
    *next_len = total - hdr_len;
    return PARSE_OK;
}

static enum parse_result parse_udp(const uint8_t *p, size_t len,
                                   struct pkt_info *out,
                                   const uint8_t **next, size_t *next_len)
{
    size_t ulen;

    if (len < UDP_HEADER_LEN)
        return PARSE_ERR_UDP_TRUNCATED;
    ulen = rd_be16(p + UDP_OFF_LEN);
    if (ulen < UDP_HEADER_LEN || ulen > len)
        return PARSE_ERR_UDP_LEN_MISMATCH;

    out->outer_sport = rd_be16(p + UDP_OFF_SPORT);
    out->outer_dport = rd_be16(p + UDP_OFF_DPORT);
    if (out->outer_dport != GTPU_PORT)
        return PARSE_IGN_NOT_GTPU_PORT;

    *next = p + UDP_HEADER_LEN;
    *next_len = ulen - UDP_HEADER_LEN;
    return PARSE_OK;
}

static enum parse_result parse_inner(const uint8_t *p, size_t len,
                                     struct pkt_info *out)
{
    unsigned ihl;
    size_t hdr_len;

    if (len < IPV4_MIN_HDR_LEN)
        return PARSE_ERR_INNER_TRUNCATED;
    ihl = (unsigned)(p[0] & 0x0fu);
    if ((p[0] >> 4) != 4 || ihl < 5u)
        return PARSE_ERR_INNER_BAD_IHL;
    hdr_len = (size_t)ihl * 4u;
    if (len < hdr_len)
        return PARSE_ERR_INNER_TRUNCATED;

    out->inner_proto = p[IPV4_OFF_PROTO];
    out->inner_src_ip = rd_be32(p + IPV4_OFF_SRC);
    out->inner_dst_ip = rd_be32(p + IPV4_OFF_DST);
    /* Cổng: chỉ TCP/UDP, và chỉ khi còn đủ 4 byte; thiếu thì để 0, không lỗi. */
    if ((out->inner_proto == IPPROTO_NUM_TCP ||
         out->inner_proto == IPPROTO_NUM_UDP) &&
        len - hdr_len >= L4_PORTS_LEN)
    {
        out->inner_sport = rd_be16(p + hdr_len);
        out->inner_dport = rd_be16(p + hdr_len + 2u);
    }
    return PARSE_OK;
}

/*
 * parse_packet
 *
 *   1. memset(out, 0, sizeof *out) để field không dùng tới có giá trị rõ ràng.
 *   2. parse_eth -> parse_ipv4 -> parse_udp, dừng ngay khi != PARSE_OK.
 *   3. gtpu_parse(udp_payload, udp_payload_len, &out->gtp, &off).
 *   4. Nếu out->gtp.msg_type == GTPU_MSG_GPDU:
 *        out->inner = udp_payload + off; out->inner_len = ... ;
 *        parse_inner(...)
 *   5. return PARSE_OK.
 */
enum parse_result parse_packet(const uint8_t *buf, size_t len,
                               struct pkt_info *out)
{
    const uint8_t *p = buf;
    const uint8_t *next;
    size_t plen = len, next_len, payload_off;
    enum parse_result res;

    memset(out, 0, sizeof *out);

    res = parse_eth(p, plen, &next, &next_len);
    if (res != PARSE_OK)
        return res;
    p = next;
    plen = next_len;

    res = parse_ipv4(p, plen, out, &next, &next_len);
    if (res != PARSE_OK)
        return res;
    p = next;
    plen = next_len;

    res = parse_udp(p, plen, out, &next, &next_len);
    if (res != PARSE_OK)
        return res;
    p = next;
    plen = next_len;

    res = gtpu_parse(p, plen, &out->gtp, &payload_off);
    if (res != PARSE_OK)
        return res;

    if (out->gtp.msg_type == GTPU_MSG_GPDU)
    {
        out->inner = p + payload_off;
        out->inner_len = plen - payload_off;
        res = parse_inner(out->inner, out->inner_len, out);
        if (res != PARSE_OK)
            return res;
        out->has_inner = true;
    }
    return PARSE_OK;
}

/*
 * parse_result_str
 *
 * switch trả chuỗi hằng, khớp cột verdict trong các file .expected trong tests/data/:
 *   PARSE_OK                   -> "ok"
 *   PARSE_IGN_NOT_IPV4         -> "ignored:not_ipv4"
 *   PARSE_ERR_GTP_EXT_BAD_LEN  -> "err:gtp_ext_bad_len"
 *   ... (đủ mọi giá trị trong parse_result.h)
 *
 * Cách khác gọn hơn: một mảng `static const char *const names[] =
 * { [PARSE_OK] = "ok", ... };` (designated initializer, có từ C99), rồi
 * kiểm tra r < PARSE_RESULT_COUNT trước khi tra mảng.
 */
const char *parse_result_str(enum parse_result r)
{
    static const char *const names[PARSE_RESULT_COUNT] = {
        [PARSE_OK] = "ok",
        [PARSE_IGN_NOT_IPV4] = "ignored:not_ipv4",
        [PARSE_IGN_NOT_UDP] = "ignored:not_udp",
        [PARSE_IGN_NOT_GTPU_PORT] = "ignored:not_gtpu_port",
        [PARSE_IGN_IP_FRAGMENT] = "ignored:ip_fragment",
        [PARSE_ERR_ETH_TRUNCATED] = "err:eth_truncated",
        [PARSE_ERR_IP_TRUNCATED] = "err:ip_truncated",
        [PARSE_ERR_IP_BAD_IHL] = "err:ip_bad_ihl",
        [PARSE_ERR_IP_BAD_VERSION] = "err:ip_bad_version",
        [PARSE_ERR_IP_LEN_MISMATCH] = "err:ip_len_mismatch",
        [PARSE_ERR_UDP_TRUNCATED] = "err:udp_truncated",
        [PARSE_ERR_UDP_LEN_MISMATCH] = "err:udp_len_mismatch",
        [PARSE_ERR_GTP_TRUNCATED] = "err:gtp_truncated",
        [PARSE_ERR_GTP_BAD_VERSION] = "err:gtp_bad_version",
        [PARSE_ERR_GTP_BAD_PT] = "err:gtp_bad_pt",
        [PARSE_ERR_GTP_LEN_MISMATCH] = "err:gtp_len_mismatch",
        [PARSE_ERR_GTP_OPT_TRUNCATED] = "err:gtp_opt_truncated",
        [PARSE_ERR_GTP_EXT_BAD_LEN] = "err:gtp_ext_bad_len",
        [PARSE_ERR_GTP_EXT_TRUNCATED] = "err:gtp_ext_truncated",
        [PARSE_ERR_GTP_EXT_TOO_MANY] = "err:gtp_ext_too_many",
        [PARSE_ERR_INNER_TRUNCATED] = "err:inner_truncated",
        [PARSE_ERR_INNER_BAD_IHL] = "err:inner_bad_ihl",
    };

    if ((unsigned)r >= (unsigned)PARSE_RESULT_COUNT || names[r] == NULL)
        return "unknown";
    return names[r];
}
