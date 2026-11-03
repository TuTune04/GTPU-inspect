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
#include <fcntl.h>     /* open, O_RDONLY */
#include <sys/mman.h>  /* mmap, munmap, posix_madvise */
#include <sys/stat.h>  /* fstat, S_ISREG */
#include <unistd.h>    /* close */

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

/* Kiểm tra global header 24 byte. Dùng chung cho reader stream và reader
 * mmap để hai bên trả đúng cùng một lỗi cho cùng một file. */
static enum pcap_status parse_global_header(const uint8_t *hdr,
                                            bool *big_endian, bool *nanosec,
                                            uint32_t *snaplen)
{
    /* Đọc magic kiểu little-endian rồi so với cả 4 giá trị có thể. */
    switch (rd_le32(hdr))
    {
    case PCAP_MAGIC_US:
        *big_endian = false;
        *nanosec = false;
        break;
    case PCAP_MAGIC_NS:
        *big_endian = false;
        *nanosec = true;
        break;
    case PCAP_MAGIC_US_SWAPPED:
        *big_endian = true;
        *nanosec = false;
        break;
    case PCAP_MAGIC_NS_SWAPPED:
        *big_endian = true;
        *nanosec = true;
        break;
    default:
        return PCAP_ERR_BAD_MAGIC;
    }

    *snaplen = rd32(*big_endian, hdr + PCAP_GH_OFF_SNAPLEN);
    if (rd32(*big_endian, hdr + PCAP_GH_OFF_LINKTYPE) != PCAP_LINKTYPE_ETHERNET)
        return PCAP_ERR_UNSUPPORTED_LINKTYPE;
    return PCAP_OK;
}

/* Record header 16 byte -> caplen, orig_len, ts_ns (chưa đụng tới data). */
static void decode_record(bool big_endian, bool nanosec, const uint8_t *rec,
                          struct pcap_packet *pkt)
{
    uint32_t ts_sec = rd32(big_endian, rec + PCAP_REC_OFF_TS_SEC);
    uint32_t ts_frac = rd32(big_endian, rec + PCAP_REC_OFF_TS_FRAC);

    pkt->caplen = rd32(big_endian, rec + PCAP_REC_OFF_CAPLEN);
    pkt->orig_len = rd32(big_endian, rec + PCAP_REC_OFF_ORIG_LEN);
    /* Ép uint64_t TRƯỚC khi nhân để không tràn 32 bit. */
    pkt->ts_ns = (uint64_t)ts_sec * PCAP_NS_PER_SEC +
                 (nanosec ? (uint64_t)ts_frac
                          : (uint64_t)ts_frac * PCAP_NS_PER_US);
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
    uint32_t snaplen;
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

    st = parse_global_header(hdr, &big_endian, &nanosec, &snaplen);
    if (st != PCAP_OK)
        goto fail;

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
    decode_record(r->big_endian, r->nanosec, rec, pkt);

    /* 3. Không tin caplen: buffer chỉ có PCAP_MAX_CAPLEN byte. */
    if (pkt->caplen > PCAP_MAX_CAPLEN)
        return set_last(r, PCAP_ERR_CAPLEN_TOO_LARGE);

    /* 4. Dữ liệu gói. */
    n = fread(r->buf, 1, pkt->caplen, r->fp);
    if (n < pkt->caplen)
    {
        return set_last(r, ferror(r->fp) ? PCAP_ERR_IO
                                         : PCAP_ERR_TRUNCATED_RECORD);
    }
    pkt->data = r->buf;
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
/*
 * Reader mmap (v2)
 *
 * Vì sao: reader stream chép mỗi gói hai lần (kernel -> buffer stdio ->
 * r->buf), và pipeline v1 chép thêm lần nữa vào buffer pool. Với mmap, page
 * cache được ánh xạ thẳng vào địa chỉ của process: không chép, và nhiều
 * luồng đọc chung được vì vùng map chỉ đọc.
 */
struct pcap_map
{
    const uint8_t *base;
    size_t size;
    bool big_endian;
    bool nanosec;
};

enum pcap_status pcap_map_open(const char *path, struct pcap_map **out)
{
    struct pcap_map *m = NULL;
    struct stat sb;
    void *base;
    bool big_endian = false, nanosec = false;
    uint32_t snaplen;
    enum pcap_status st;
    size_t size;
    int fd;

    *out = NULL;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return PCAP_ERR_IO;
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode))
    {
        close(fd);
        return PCAP_ERR_IO;
    }
    if ((uintmax_t)sb.st_size < PCAP_GLOBAL_HEADER_LEN)
    {
        close(fd);
        return PCAP_ERR_TRUNCATED_GLOBAL_HEADER;
    }
    if ((uintmax_t)sb.st_size > SIZE_MAX)
    {
        close(fd);
        return PCAP_ERR_NOMEM;   /* không map nổi vào không gian địa chỉ */
    }
    size = (size_t)sb.st_size;

    base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);   /* mapping giữ file mở, không cần fd nữa */
    if (base == MAP_FAILED)
        return PCAP_ERR_IO;
    /* Chỉ là gợi ý cho kernel đọc trước; lỗi cũng không sao. */
    (void)posix_madvise(base, size, POSIX_MADV_SEQUENTIAL);

    st = parse_global_header(base, &big_endian, &nanosec, &snaplen);
    if (st == PCAP_OK)
    {
        m = malloc(sizeof *m);
        if (m == NULL)
            st = PCAP_ERR_NOMEM;
    }
    if (st != PCAP_OK)
    {
        munmap(base, size);
        return st;
    }
    m->base = base;
    m->size = size;
    m->big_endian = big_endian;
    m->nanosec = nanosec;
    *out = m;
    return PCAP_OK;
}

void pcap_map_close(struct pcap_map *m)
{
    if (m == NULL)
        return;
    /* munmap nhận void*, vùng map vốn do mmap trả về dạng void*. */
    munmap((void *)(uintptr_t)m->base, m->size);
    free(m);
}

size_t pcap_map_first(const struct pcap_map *m)
{
    (void)m;
    return PCAP_GLOBAL_HEADER_LEN;
}

size_t pcap_map_size(const struct pcap_map *m)
{
    return m->size;
}

enum pcap_status pcap_map_next(const struct pcap_map *m, size_t *off,
                               struct pcap_packet *pkt)
{
    size_t left;

    if (*off >= m->size)
        return PCAP_EOF;
    left = m->size - *off;
    if (left < PCAP_RECORD_HEADER_LEN)
        return PCAP_ERR_TRUNCATED_RECORD;
    decode_record(m->big_endian, m->nanosec, m->base + *off, pkt);
    /* Cùng thứ tự kiểm tra với pcap_next để cùng file ra cùng lỗi. */
    if (pkt->caplen > PCAP_MAX_CAPLEN)
        return PCAP_ERR_CAPLEN_TOO_LARGE;
    if (pkt->caplen > left - PCAP_RECORD_HEADER_LEN)
        return PCAP_ERR_TRUNCATED_RECORD;
    pkt->data = m->base + *off + PCAP_RECORD_HEADER_LEN;
    *off += PCAP_RECORD_HEADER_LEN + pkt->caplen;
    return PCAP_OK;
}
