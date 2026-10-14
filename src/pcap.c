/*
 * pcap.c — pcap reader.                                      [TUẦN 1]
 *
 * Test: tests/test_pcap.cpp. Dữ liệu: tests/data/pcap_*.pcap,
 * tests/data/bad_pcap_*.pcap, kết quả đúng trong các file .expected cùng tên.
 */
#include "pcap.h"

#include <stdbool.h>  /* bool */
#include <stdio.h>    /* FILE, fopen, fread, fclose */
#include <stdlib.h>   /* malloc, calloc, free */
#include <string.h>   /* memcpy */

#include "bytes.h"    /* rd_le32, rd_be32, rd_le16, rd_be16 */

/*
 * struct pcap_reader — bạn tự định nghĩa. Gợi ý các field cần có:
 *
 *   FILE     *fp;
 *   bool      swapped;    file big-endian? -> đọc trường bằng rd_be32
 *   bool      nanosec;    magic nano giây? -> ts_frac là ns, không phải us
 *   uint32_t  snaplen;
 *   uint8_t  *buf;        buffer chứa data của gói hiện tại, cấp MỘT lần
 *   size_t    buf_cap;    trong pcap_open, tái sử dụng cho mọi gói
 *
 * Câu hỏi tự trả lời: buf_cap nên bằng snaplen trong file hay PCAP_MAX_CAPLEN?
 * Nếu snaplen trong file = 0xffffffff thì sao?
 *
 * Gợi ý: viết một hàm static nhỏ đọc trường u32 theo r->swapped, ví dụ
 *   static uint32_t field32(const struct pcap_reader *r, const uint8_t *p);
 * để không phải if/else ở mọi chỗ.
 * (Chỉ khai báo hàm static khi đã dùng nó, nếu không clang báo
 *  -Wunused-function và -Werror biến nó thành lỗi.)
 */

/*
 * pcap_open
 *
 * Các bước:
 *   1. fopen(path, "rb"). Thất bại -> PCAP_ERR_IO.
 *   2. fread 24 byte vào mảng uint8_t hdr[PCAP_GLOBAL_HEADER_LEN].
 *      Đọc được < 24 byte -> PCAP_ERR_TRUNCATED_GLOBAL_HEADER.
 *   3. magic = rd_le32(hdr). So với 4 giá trị (xem pcap.h) để biết
 *      swapped/nanosec. Không khớp -> PCAP_ERR_BAD_MAGIC.
 *   4. Đọc snaplen (offset 16) và linktype (offset 20) theo endianness vừa
 *      biết. linktype != PCAP_LINKTYPE_ETHERNET -> PCAP_ERR_UNSUPPORTED_LINKTYPE.
 *   5. calloc struct reader, malloc buffer.
 *   6. *out = reader; return PCAP_OK.
 *
 * Mọi nhánh lỗi: fclose/free những gì đã mở/cấp, đặt *out = NULL.
 * Mẹo C kinh điển cho việc dọn dẹp nhiều bước: một nhãn `fail:` cuối hàm
 * và `goto fail;`. Đây là cách Linux kernel làm, không phải code xấu.
 *
 * Test liên quan: bad_pcap_magic, bad_pcap_short_header, bad_pcap_linktype,
 * pcap_big_endian, pcap_nanosec.
 */
enum pcap_status pcap_open(const char *path, struct pcap_reader **out)
{
    /* TODO: xóa stub và viết code của bạn */
    (void)path;
    *out = NULL;
    return PCAP_ERR_IO;
}

/*
 * pcap_next
 *
 * Các bước:
 *   1. fread 16 byte record header.
 *        - đọc được 0 byte  -> PCAP_EOF (hết file bình thường)
 *        - đọc được 1..15   -> PCAP_ERR_TRUNCATED_RECORD
 *   2. Lấy ts_sec, ts_frac, caplen, orig_len (offset 0, 4, 8, 12) theo
 *      endianness của file.
 *   3. KHÔNG TIN caplen: nếu caplen > PCAP_MAX_CAPLEN hoặc > dung lượng
 *      buffer -> PCAP_ERR_CAPLEN_TOO_LARGE. (bad_pcap_caplen_huge.pcap có
 *      caplen = 2^31 - 1: nếu bạn malloc theo nó là sai thiết kế.)
 *   4. fread caplen byte vào buffer. Thiếu byte -> PCAP_ERR_TRUNCATED_RECORD.
 *   5. Điền pkt: data = buffer, caplen, orig_len,
 *      ts_ns = ts_sec * 1000000000 + (nanosec ? ts_frac : ts_frac * 1000).
 *      Cẩn thận tràn số: ép sang uint64_t TRƯỚC khi nhân.
 *
 * Câu hỏi: orig_len < caplen thì có phải lỗi không? (Gợi ý: Wireshark báo
 * gì? Bạn quyết định và ghi lại lý do.)
 *
 * Test liên quan: bad_pcap_truncated_record (lỗi sau 1 gói),
 * bad_pcap_caplen_huge (lỗi sau 1 gói), pcap_empty (EOF ngay).
 */
enum pcap_status pcap_next(struct pcap_reader *r, struct pcap_packet *pkt)
{
    /* TODO */
    (void)r;
    (void)pkt;
    return PCAP_EOF;
}

/*
 * pcap_close
 *
 * if (r == NULL) return;  rồi fclose, free buffer, free reader.
 * Valgrind trong CI sẽ báo nếu thiếu bước nào.
 */
void pcap_close(struct pcap_reader *r)
{
    /* TODO */
    (void)r;
}

/*
 * pcap_status_str
 *
 * Một switch trả chuỗi hằng. Tên phải khớp cột verdict trong .expected
 * (bỏ tiền tố "err:"): PCAP_ERR_BAD_MAGIC -> "bad_magic", ...
 * Để default trả "unknown". Nếu bỏ default và liệt kê đủ case, -Wall
 * (-Wswitch) sẽ cảnh báo khi bạn thêm giá trị enum mới mà quên xử lý.
 */
const char *pcap_status_str(enum pcap_status s)
{
    /* TODO */
    (void)s;
    return "unknown";
}
