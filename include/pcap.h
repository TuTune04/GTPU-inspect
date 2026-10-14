/*
 * pcap.h — đọc file .pcap (không dùng libpcap).            [TUẦN 1]
 *
 * Định dạng file:
 *
 *   Global header (24 byte, một lần ở đầu file)
 *     off  size  trường
 *       0     4  magic          a1b2c3d4 = micro giây, a1b23c4d = nano giây
 *       4     2  version_major  (2)
 *       6     2  version_minor  (4)
 *       8     4  thiszone       bỏ qua
 *      12     4  sigfigs        bỏ qua
 *      16     4  snaplen        độ dài tối đa một gói khi capture
 *      20     4  linktype       1 = Ethernet (chỉ hỗ trợ loại này)
 *
 *   Record header (16 byte, trước MỖI gói)
 *       0     4  ts_sec
 *       4     4  ts_frac        micro hoặc nano giây tùy magic
 *       8     4  caplen         số byte gói THỰC CÓ trong file
 *      12     4  orig_len       độ dài gói gốc trên dây (>= caplen)
 *
 * Endianness: các trường pcap theo thứ tự byte của MÁY GHI FILE, không phải
 * network order. Đọc 4 byte magic dạng little-endian:
 *   0xa1b2c3d4 / 0xa1b23c4d  -> file little-endian
 *   0xd4c3b2a1 / 0x4d3cb2a1  -> file big-endian, mọi trường phải đọc kiểu BE
 */
#ifndef GTPU_PCAP_H
#define GTPU_PCAP_H

#include <stdint.h>   /* uint8_t, uint32_t... (C11). <cstdint> là của C++ */

#ifdef __cplusplus
extern "C" {
#endif

#define PCAP_GLOBAL_HEADER_LEN 24u
#define PCAP_RECORD_HEADER_LEN 16u
#define PCAP_LINKTYPE_ETHERNET 1u
/* Giới hạn cứng cho caplen, độc lập với snaplen trong file (cũng không tin
 * được). 262144 là giá trị tcpdump dùng mặc định. */
#define PCAP_MAX_CAPLEN 262144u

enum pcap_status {
    PCAP_OK, PCAP_EOF,
    PCAP_ERR_IO, PCAP_ERR_BAD_MAGIC, PCAP_ERR_TRUNCATED_GLOBAL_HEADER,
    PCAP_ERR_UNSUPPORTED_LINKTYPE, PCAP_ERR_TRUNCATED_RECORD,
    PCAP_ERR_CAPLEN_TOO_LARGE,
};

struct pcap_packet {            /* một gói vừa đọc được */
    const uint8_t *data;        /* trỏ vào buffer của reader */
    uint32_t caplen, orig_len;
    uint64_t ts_ns;             /* gộp ts_sec + ts_frac về nano giây */
};

/* Kiểu "opaque": người dùng chỉ cầm con trỏ, nội dung struct định nghĩa
 * trong pcap.c. Đổi field bên trong không làm thay đổi API. */
struct pcap_reader;

/* Mở file, đọc và kiểm tra global header. Thành công: *out trỏ tới reader
 * mới, trả PCAP_OK. Thất bại: *out = NULL, không leak gì. */
enum pcap_status pcap_open(const char *path, struct pcap_reader **out);

/* Đọc gói kế tiếp vào *pkt. pkt->data chỉ hợp lệ tới lần gọi pcap_next
 * tiếp theo hoặc pcap_close. Hết file bình thường: PCAP_EOF. */
enum pcap_status pcap_next(struct pcap_reader *r, struct pcap_packet *pkt);

/* Giải phóng mọi thứ. Gọi với NULL phải an toàn (giống free(NULL)). */
void pcap_close(struct pcap_reader *r);

/* Tên ngắn khớp các file .expected trong tests/data/: "ok", "bad_magic",
 * "truncated_global_header", "unsupported_linktype", "truncated_record",
 * "caplen_too_large"... */
const char *pcap_status_str(enum pcap_status s);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_PCAP_H */
