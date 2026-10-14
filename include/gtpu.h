/*
 * gtpu.h — header GTP-U theo 3GPP TS 29.281.                 [TUẦN 1 + 2]
 *
 *  Header bắt buộc (8 byte):
 *    byte 0   : | version(3) | PT(1) | (*)(1) | E(1) | S(1) | PN(1) |
 *    byte 1   : message type
 *    byte 2-3 : length   = số byte SAU 8 byte đầu (gồm cả 4 byte tùy chọn
 *                          và các extension header)
 *    byte 4-7 : TEID
 *
 *  Phần tùy chọn (4 byte, có mặt khi E, S hoặc PN bật — dù chỉ một cờ):
 *    byte 8-9 : sequence number   (chỉ có nghĩa khi S=1)
 *    byte 10  : N-PDU number      (chỉ có nghĩa khi PN=1)
 *    byte 11  : next extension header type (chỉ có nghĩa khi E=1)
 *
 *  Extension header (tuần 2), mỗi cái:
 *    byte 0          : length, đơn vị 4 byte (0 là không hợp lệ)
 *    byte 1..4n-2    : nội dung
 *    byte 4n-1       : next extension header type (0 = hết chuỗi)
 *
 *  PDU Session Container (type 0x85, TS 38.415):
 *    byte 1 : PDU type ở 4 bit cao (0 = DL, 1 = UL)
 *    byte 2 : DL: PPP(1) RQI(1) QFI(6)  /  UL: (2 bit khác) QFI(6)
 *             -> QFI luôn là 6 bit thấp của byte 2
 */
#ifndef GTPU_GTPU_H
#define GTPU_GTPU_H

#include <stdbool.h>
#include <stddef.h>   /* size_t */
#include <stdint.h>

#include "parse_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GTPU_PORT            2152u
#define GTPU_HEADER_LEN      8u
#define GTPU_OPT_LEN         4u

/* Bit trong byte flags (byte 0) */
#define GTPU_FLAG_PN         0x01u
#define GTPU_FLAG_S          0x02u
#define GTPU_FLAG_E          0x04u

/* Message type */
#define GTPU_MSG_ECHO_REQ    1u
#define GTPU_MSG_ECHO_RESP   2u
#define GTPU_MSG_ERROR_IND   26u
#define GTPU_MSG_END_MARKER  254u
#define GTPU_MSG_GPDU        255u

/* Extension header type */
#define GTPU_EXT_NONE        0x00u
#define GTPU_EXT_UDP_PORT    0x40u
#define GTPU_EXT_PDU_SESSION 0x85u
/* Giới hạn số extension trong một gói, chống chuỗi dài bất thường. */
#define GTPU_MAX_EXT_HEADERS 16u

struct gtpu_hdr {
    /* --- tuần 1 --- */
    uint8_t  version;       /* 3 bit cao byte 0, phải = 1 */
    uint8_t  pt;            /* protocol type, phải = 1    */
    uint8_t  flags;         /* nguyên byte 0, tra bằng GTPU_FLAG_*          */
    uint8_t  msg_type;
    uint16_t length;        /* host order */
    uint32_t teid;          /* host order */
    bool     has_opt;       /* có 4 byte tùy chọn hay không */
    uint16_t seq;
    uint8_t  npdu;
    uint8_t  next_ext;      /* type extension ĐẦU TIÊN (byte 11) */

    /* --- tuần 2 --- */
    uint8_t  n_ext;         /* số extension header đã duyệt   */
    bool     has_qfi;       /* có PDU Session Container không */
    uint8_t  qfi;           /* 0..63 */
    uint8_t  pdu_type;      /* 0 = DL, 1 = UL */
};

/*
 * Parse header GTP-U trong vùng [p, p + len) — đúng bằng UDP payload.
 * Thành công: điền *h, *payload_off = offset bắt đầu T-PDU (inner IP) tính
 * từ p, trả PARSE_OK. Không bao giờ đọc ra ngoài [p, p + len).
 */
enum parse_result gtpu_parse(const uint8_t *p, size_t len,
                             struct gtpu_hdr *h, size_t *payload_off);

/* "G-PDU", "Echo Request", ... ; type lạ -> "Unknown". */
const char *gtpu_msg_type_str(uint8_t msg_type);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_GTPU_H */
