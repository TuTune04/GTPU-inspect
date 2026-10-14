/*
 * bytes.h — đọc số nguyên nhiều byte từ buffer một cách an toàn.  [TUẦN 1]
 *
 * Mọi module (pcap, parser, gtpu) đều dùng các hàm này thay vì ép kiểu.
 *
 * VÌ SAO KHÔNG VIẾT  uint32_t x = *(const uint32_t *)p;  ?
 *   1. Alignment: p có thể không chia hết cho 4 (ví dụ TEID nằm ở offset
 *      14 + 20 + 8 + 4 = 46 trong frame). Trên x86 vẫn chạy, trên ARM cũ
 *      thì crash, và với C thì đây là undefined behavior ở mọi nơi.
 *   2. Strict aliasing: truy cập một vùng uint8_t qua con trỏ uint32_t vi
 *      phạm quy tắc aliasing; compiler được phép tối ưu sai.
 *   3. Endianness: dữ liệu trên dây là big-endian (network order), còn
 *      máy x86/ARM là little-endian. Ép kiểu cho ra số bị đảo byte.
 *
 * HAI CÁCH ĐÚNG (nên thử cả hai rồi so sánh asm trên godbolt.org):
 *   a) memcpy 2/4 byte vào biến cục bộ, rồi ntohs()/ntohl()
 *      -> cần <string.h> (memcpy) và <arpa/inet.h> (ntohs/ntohl).
 *      Compiler biến memcpy cố định 4 byte thành MỘT lệnh load, không chậm.
 *   b) Ghép từng byte bằng phép dịch: (uint32_t)p[0] << 24 | ...
 *      -> không cần header nào, chạy đúng trên mọi máy bất kể endianness.
 *      Cẩn thận: p[0] << 24 với p[0] kiểu uint8_t bị promote thành int,
 *      p[0] >= 0x80 thì dịch vào bit dấu = UB. Phải ép (uint32_t) TRƯỚC khi
 *      dịch.
 *
 * Các hàm rd_le* dùng cho pcap reader (header pcap thường là little-endian,
 * xem pcap.h). Với cách (b) bạn viết được cả BE lẫn LE không phụ thuộc máy.
 *
 * CHỈ GỌI các hàm này SAU KHI đã kiểm tra còn đủ byte. Bản thân hàm không
 * biết độ dài buffer.
 *
 * Hàm `static inline` trong header: mỗi file .c include vào có bản riêng,
 * compiler inline được, không bị lỗi "multiple definition" khi link.
 */
#ifndef GTPU_BYTES_H
#define GTPU_BYTES_H

#include <stdint.h>
#include <string.h>    /* memcpy (nếu bạn chọn cách a) */
#include <arpa/inet.h> /* ntohs, ntohl (nếu bạn chọn cách a) */

#ifdef __cplusplus
extern "C"
{
#endif

    /* Đọc 2 byte big-endian (network order) tại p. */
    static inline uint16_t rd_be16(const uint8_t *p)
    {
        uint16_t v;
        memcpy(&v, p, sizeof v);
        return ntohs(v);
    }

    /* Đọc 4 byte big-endian (network order) tại p. */
    static inline uint32_t rd_be32(const uint8_t *p)
    {
        uint32_t v;
        memcpy(&v, p, sizeof v);
        return ntohl(v);
    }

    /* Hai hàm le dưới đây ghép từng byte bằng phép dịch bit.
     * Little-endian: p[0] là byte THẤP nhất, nên p[0] dịch 0, p[1] dịch 8... */

    /* Đọc 2 byte little-endian tại p (dùng cho header pcap). */
    static inline uint16_t rd_le16(const uint8_t *p)
    {
        return (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
    }

    /* Đọc 4 byte little-endian tại p (dùng cho header pcap). */
    static inline uint32_t rd_le32(const uint8_t *p)
    {
        return (uint32_t)p[0] |
               ((uint32_t)p[1] << 8) |
               ((uint32_t)p[2] << 16) |
               ((uint32_t)p[3] << 24);
    }

#ifdef __cplusplus
}
#endif

#endif /* GTPU_BYTES_H */
