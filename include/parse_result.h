/*
 * parse_result.h — kết quả parse một gói.                    [TUẦN 1 + 2]
 *
 * Tách riêng để parser.h và gtpu.h cùng dùng mà không include vòng nhau.
 *
 * Mỗi giá trị tương ứng một verdict trong các file .expected trong tests/data/:
 *   PARSE_OK                -> "ok"
 *   PARSE_IGN_<X>           -> "ignored:<x>"   (không phải lỗi, chỉ bỏ qua)
 *   PARSE_ERR_<X>           -> "err:<x>"       (gói hỏng, đếm theo lý do)
 * parse_result_str() trong parser.c làm phép đổi này.
 */
#ifndef GTPU_PARSE_RESULT_H
#define GTPU_PARSE_RESULT_H

#ifdef __cplusplus
extern "C" {
#endif

enum parse_result {
    PARSE_OK = 0,

    /* --- bỏ qua --- */
    PARSE_IGN_NOT_IPV4,         /* EtherType != 0x0800 (ARP, IPv6...)      */
    PARSE_IGN_NOT_UDP,          /* IPv4 protocol != 17                      */
    PARSE_IGN_NOT_GTPU_PORT,    /* UDP dst port != 2152                     */
    PARSE_IGN_IP_FRAGMENT,      /* MF=1 hoặc fragment offset != 0           */

    /* --- lỗi lớp 2/3/4 (tuần 1) --- */
    PARSE_ERR_ETH_TRUNCATED,    /* < 14 byte                                */
    PARSE_ERR_IP_TRUNCATED,     /* < 20 byte hoặc < IHL*4                   */
    PARSE_ERR_IP_BAD_IHL,       /* IHL < 5                                  */
    PARSE_ERR_IP_BAD_VERSION,   /* version != 4                             */
    PARSE_ERR_IP_LEN_MISMATCH,  /* total length < IHL*4 hoặc > byte có thật */
    PARSE_ERR_UDP_TRUNCATED,    /* < 8 byte                                 */
    PARSE_ERR_UDP_LEN_MISMATCH, /* UDP length < 8 hoặc > IP payload         */

    /* --- lỗi GTP-U (tuần 1) --- */
    PARSE_ERR_GTP_TRUNCATED,    /* < 8 byte header bắt buộc                 */
    PARSE_ERR_GTP_BAD_VERSION,  /* version != 1                             */
    PARSE_ERR_GTP_BAD_PT,       /* PT != 1                                  */
    PARSE_ERR_GTP_LEN_MISMATCH, /* 8 + length != UDP payload length         */
    PARSE_ERR_GTP_OPT_TRUNCATED,/* cờ E/S/PN bật nhưng thiếu 4 byte         */

    /* --- lỗi extension header (tuần 2) --- */
    PARSE_ERR_GTP_EXT_BAD_LEN,  /* extension length = 0                     */
    PARSE_ERR_GTP_EXT_TRUNCATED,/* extension vượt quá gói                   */
    PARSE_ERR_GTP_EXT_TOO_MANY, /* chuỗi dài hơn GTPU_MAX_EXT_HEADERS       */

    /* --- lỗi inner IPv4 (tuần 1) --- */
    PARSE_ERR_INNER_TRUNCATED,  /* inner < 20 byte                          */
    PARSE_ERR_INNER_BAD_IHL,    /* inner IHL < 5 / version sai              */

    PARSE_RESULT_COUNT          /* số phần tử, dùng làm kích thước mảng đếm */
};

#ifdef __cplusplus
}
#endif

#endif /* GTPU_PARSE_RESULT_H */
