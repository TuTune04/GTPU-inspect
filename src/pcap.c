/*
 * pcap.c — pcap reader.                                      [TUẦN 1]
 *
 * Test: tests/test_pcap.cpp. Dữ liệu: tests/data/pcap_*.pcap,
 * tests/data/bad_pcap_*.pcap, kết quả đúng trong các file .expected cùng tên.
 */
#include "pcap.h"

#include <stdbool.h> /* bool */
#include <stdio.h>   /* FILE, fopen, fread, fclose */
#include <stdlib.h>  /* malloc, calloc, free */
#include <string.h>  /* memcpy */

#include "bytes.h" /* rd_le32, rd_be32, rd_le16, rd_be16 */

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
/* Đọc một trường 32 bit theo endianness của file. */
static uint32_t rd32(bool big_endian, const uint8_t *p)
{
    return big_endian ? rd_be32(p) : rd_le32(p);
}

/* Định nghĩa đầy đủ ở đây, người dùng ngoài file này chỉ thấy con trỏ. */
struct pcap_reader
{
    FILE *fp;
    uint8_t *buf;          /* PCAP_MAX_CAPLEN byte, dùng lại cho mọi gói */
    bool big_endian;       /* các trường của file theo BE? */
    bool nanosec;          /* ts_frac là nano giây (ngược lại: micro) */
    uint32_t snaplen;      /* chỉ để tham khảo, không dùng để chặn */
    enum pcap_status last; /* trạng thái dính, cho pcap_next */
};

enum pcap_status pcap_open(const char *path, struct pcap_reader **out)
{
    FILE *fp = NULL;
    struct pcap_reader *r = NULL;
    uint8_t *buf = NULL;
    uint8_t hdr[PCAP_GLOBAL_HEADER_LEN];
    bool big_endian = false, nanosec = false;
    uint32_t snaplen, linktype;
    size_t n;
    enum pcap_status st;

    *out = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL)
    {
        st = PCAP_ERR_IO;
        goto fail;
    }

    n = fread(hdr, 1, sizeof hdr, fp);
    if (n < sizeof hdr)
    {
        /* Đọc thiếu: do lỗi I/O hay do file ngắn thật? */
        st = ferror(fp) ? PCAP_ERR_IO : PCAP_ERR_TRUNCATED_GLOBAL_HEADER;
        goto fail;
    }

    /* Đọc magic kiểu little-endian rồi so với cả 4 giá trị có thể. */
    switch (rd_le32(hdr))
    {
    case PCAP_MAGIC_US:
        big_endian = false;
        nanosec = false;
        break;
    case PCAP_MAGIC_NS:
        big_endian = false;
        nanosec = true;
        break;
    case PCAP_MAGIC_US_SWAPPED:
        big_endian = true;
        nanosec = false;
        break;
    case PCAP_MAGIC_NS_SWAPPED:
        big_endian = true;
        nanosec = true;
        break;
    default:
        st = PCAP_ERR_BAD_MAGIC;
        goto fail;
    }

    snaplen = rd32(big_endian, hdr + PCAP_GH_OFF_SNAPLEN);
    linktype = rd32(big_endian, hdr + PCAP_GH_OFF_LINKTYPE);
    if (linktype != PCAP_LINKTYPE_ETHERNET)
    {
        st = PCAP_ERR_UNSUPPORTED_LINKTYPE;
        goto fail;
    }

    r = calloc(1, sizeof *r);
    buf = malloc(PCAP_MAX_CAPLEN);
    if (r == NULL || buf == NULL)
    {
        st = PCAP_ERR_NOMEM;
        goto fail;
    }

    r->fp = fp; /* từ đây reader sở hữu fp và buf */
    r->buf = buf;
    r->big_endian = big_endian;
    r->nanosec = nanosec;
    r->snaplen = snaplen;
    r->last = PCAP_OK;
    *out = r;
    return PCAP_OK;

fail:
    free(buf); /* free(NULL) an toàn */
    free(r);
    if (fp != NULL)
        fclose(fp);
    return st; /* *out vẫn là NULL */
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
/* Ghi lại trạng thái cuối và trả về nó: từ đây reader ở trạng thái "dính". */
static enum pcap_status set_last(struct pcap_reader *r, enum pcap_status st)
{
    r->last = st;
    return st;
}

enum pcap_status pcap_next(struct pcap_reader *r, struct pcap_packet *pkt)
{
    uint8_t rec[PCAP_RECORD_HEADER_LEN];
    uint32_t ts_sec, ts_frac, caplen, orig_len;
    size_t n;

    /* Đã gặp EOF hoặc lỗi trước đó: trả lại đúng trạng thái, không đọc nữa. */
    if (r->last != PCAP_OK)
        return r->last;

    /* 1. Record header. */
    n = fread(rec, 1, sizeof rec, r->fp);
    if (n < sizeof rec)
    {
        if (ferror(r->fp))
            return set_last(r, PCAP_ERR_IO);
        if (n == 0)
            return set_last(r, PCAP_EOF); /* hết file bình thường */
        return set_last(r, PCAP_ERR_TRUNCATED_RECORD);
    }

    /* 2. Các trường theo endianness của file. */
    ts_sec = rd32(r->big_endian, rec + PCAP_REC_OFF_TS_SEC);
    ts_frac = rd32(r->big_endian, rec + PCAP_REC_OFF_TS_FRAC);
    caplen = rd32(r->big_endian, rec + PCAP_REC_OFF_CAPLEN);
    orig_len = rd32(r->big_endian, rec + PCAP_REC_OFF_ORIG_LEN);

    /* 3. Không tin caplen: buffer chỉ có PCAP_MAX_CAPLEN byte. */
    if (caplen > PCAP_MAX_CAPLEN)
        return set_last(r, PCAP_ERR_CAPLEN_TOO_LARGE);

    /* 4. Dữ liệu gói. */
    n = fread(r->buf, 1, caplen, r->fp);
    if (n < caplen)
    {
        return set_last(r, ferror(r->fp) ? PCAP_ERR_IO
                                         : PCAP_ERR_TRUNCATED_RECORD);
    }

    /* 5. Điền kết quả. Ép uint64_t TRƯỚC khi nhân để không tràn 32 bit. */
    pkt->data = r->buf;
    pkt->caplen = caplen;
    pkt->orig_len = orig_len;
    pkt->ts_ns = (uint64_t)ts_sec * PCAP_NS_PER_SEC +
                 (r->nanosec ? (uint64_t)ts_frac
                             : (uint64_t)ts_frac * PCAP_NS_PER_US);
    return PCAP_OK;
}

/*
 * pcap_close
 *
 * if (r == NULL) return;  rồi fclose, free buffer, free reader.
 * Valgrind trong CI sẽ báo nếu thiếu bước nào.
 */
void pcap_close(struct pcap_reader *r)
{
    if (r == NULL)
        return;

    if (r->fp != NULL)
        fclose(r->fp);
    free(r->buf);
    free(r);
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
    switch (s)
    {
    case PCAP_OK:
        return "ok";
    case PCAP_EOF:
        return "eof";
    case PCAP_ERR_IO:
        return "io_error";
    case PCAP_ERR_NOMEM:
        return "no_memory";
    case PCAP_ERR_BAD_MAGIC:
        return "bad_magic";
    case PCAP_ERR_TRUNCATED_GLOBAL_HEADER:
        return "truncated_global_header";
    case PCAP_ERR_UNSUPPORTED_LINKTYPE:
        return "unsupported_linktype";
    case PCAP_ERR_TRUNCATED_RECORD:
        return "truncated_record";
    case PCAP_ERR_CAPLEN_TOO_LARGE:
        return "caplen_too_large";
    }
    return "unknown"; /* giá trị ngoài enum */
}