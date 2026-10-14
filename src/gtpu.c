/*
 * gtpu.c — parse header GTP-U (TS 29.281 mục 5).            [TUẦN 1 + 2]
 *
 * Test: tests/test_gtpu.cpp (buffer dựng tay) và tests/test_parser.cpp.
 * Bố cục byte xem comment đầu include/gtpu.h.
 */
#include "gtpu.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bytes.h"    /* rd_be16, rd_be32 */

/*
 * ---------------------------------------------------------------------------
 * [TUẦN 2] gtpu_parse_ext — duyệt chuỗi extension header
 *
 * Mẫu khai báo (bỏ comment khi bắt đầu viết):
 *
 *   static enum parse_result gtpu_parse_ext(const uint8_t *p, size_t len,
 *                                           size_t *off, uint8_t first_type,
 *                                           struct gtpu_hdr *h);
 *
 *   p, len    : toàn bộ vùng GTP-U (đã cắt theo 8 + length)
 *   *off      : vào = 12 (sau 4 byte tùy chọn); ra = offset đầu T-PDU
 *   first_type: h->next_ext (byte 11)
 *
 * Vòng lặp, khi type != GTPU_EXT_NONE:
 *   1. Đếm n_ext; vượt GTPU_MAX_EXT_HEADERS   -> PARSE_ERR_GTP_EXT_TOO_MANY
 *   2. Còn < 1 byte                           -> PARSE_ERR_GTP_EXT_TRUNCATED
 *   3. ext_len = p[*off] * 4 (byte). = 0      -> PARSE_ERR_GTP_EXT_BAD_LEN
 *      (length 0 làm vòng lặp không tiến -> lặp vô hạn. Đây là lý do số 1
 *       phải kiểm tra.)
 *   4. *off + ext_len > len                   -> PARSE_ERR_GTP_EXT_TRUNCATED
 *   5. Nếu type == GTPU_EXT_PDU_SESSION:
 *        pdu_type = p[*off + 1] >> 4;  qfi = p[*off + 2] & 0x3F;
 *        has_qfi = true
 *      Type khác: bỏ qua nội dung.
 *   6. type = p[*off + ext_len - 1]  (byte cuối của extension = next type)
 *   7. *off += ext_len
 *
 * Tự đọc TS 29.281 mục 5.2.1: hai bit cao của type cho biết bên nhận có
 * BẮT BUỘC phải hiểu extension đó không. Bạn quyết định xử lý type lạ thế
 * nào và ghi lý do vào comment.
 * ---------------------------------------------------------------------------
 */

/*
 * gtpu_parse                                                   [TUẦN 1]
 *
 * Các bước:
 *   1. len < GTPU_HEADER_LEN                     -> PARSE_ERR_GTP_TRUNCATED
 *   2. flags = p[0]; version = flags >> 5; pt = (flags >> 4) & 1
 *        version != 1                            -> PARSE_ERR_GTP_BAD_VERSION
 *        pt != 1                                 -> PARSE_ERR_GTP_BAD_PT
 *   3. msg_type = p[1]; length = rd_be16(p + 2); teid = rd_be32(p + 4)
 *   4. has_opt = flags & (E|S|PN)
 *        nếu có: len < 12                        -> PARSE_ERR_GTP_OPT_TRUNCATED
 *        seq = rd_be16(p + 8); npdu = p[10]; next_ext = p[11]
 *      off = has_opt ? 12 : 8
 *   5. GTPU_HEADER_LEN + length != len           -> PARSE_ERR_GTP_LEN_MISMATCH
 *      (fixture có cả trường hợp length lớn hơn và NHỎ HƠN thực tế)
 *      Bước 4 phải đứng TRƯỚC bước 5 để gói thiếu byte tùy chọn được báo
 *      đúng lý do opt_truncated thay vì len_mismatch.
 *   6. [TUẦN 1] Nếu cờ E bật: chưa duyệt chain, tạm thời coi T-PDU bắt đầu
 *      ngay sau 12 byte (fixture gtpu_5g_ext sẽ fail tới tuần 2 — bình thường).
 *      [TUẦN 2] Gọi gtpu_parse_ext(p, len, &off, h->next_ext, h).
 *   7. *payload_off = off; return PARSE_OK
 *
 * Lưu ý -Wconversion: `flags >> 5` có kiểu int; gán vào uint8_t cần ép
 * (uint8_t) tường minh. Đây là ép kiểu GIÁ TRỊ, hoàn toàn hợp lệ — khác
 * với ép kiểu CON TRỎ buffer sang struct (bị cấm).
 *
 * Câu hỏi: Echo Request phải có TEID = 0 và cờ S = 1 theo spec. Có nên coi
 * vi phạm là lỗi parse, hay chỉ đếm riêng thành "bất thường"?
 */
enum parse_result gtpu_parse(const uint8_t *p, size_t len,
                             struct gtpu_hdr *h, size_t *payload_off)
{
    /* TODO: xóa stub và viết code của bạn */
    (void)p;
    (void)len;
    (void)h;
    (void)payload_off;
    return PARSE_ERR_GTP_TRUNCATED;
}

/*
 * gtpu_msg_type_str
 *
 * switch: 1 "Echo Request", 2 "Echo Response", 26 "Error Indication",
 * 254 "End Marker", 255 "G-PDU", còn lại "Unknown".
 * Tên giống Wireshark để dễ đối chiếu output.
 */
const char *gtpu_msg_type_str(uint8_t msg_type)
{
    /* TODO */
    (void)msg_type;
    return "Unknown";
}
