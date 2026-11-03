/*
 * libFuzzer target cho parser.
 *
 * libFuzzer gọi hàm dưới đây hàng triệu lần với buffer ngẫu nhiên đã được
 * "đột biến" dựa trên coverage. Mỗi lần gọi phải:
 *   - không đọc/ghi ngoài [data, data + size)  (ASan bắt)
 *   - không có undefined behavior               (UBSan bắt)
 *   - không leak, không giữ state giữa các lần gọi
 *
 * Gọi parse_packet trên cả frame Ethernet (data, size): đi qua mọi lớp tới
 * GTP-U, chuỗi extension header và inner IPv4. Không cần kiểm tra kết quả:
 * mục tiêu là parser không bao giờ crash.
 *
 * Corpus khởi đầu: tools/make_corpus.py tách từng gói trong các file pcap ở tests/data/
 * thành một file trong fuzz/corpus/.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>   /* abort */

#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct pkt_info info;
    enum parse_result res = parse_packet(data, size, &info);

    /* Bất biến rẻ: lý do luôn trong enum, và inner (nếu có) nằm trong buffer. */
    if ((unsigned)res >= PARSE_RESULT_COUNT)
        abort();
    if (res == PARSE_OK && info.has_inner &&
        (info.inner < data || info.inner_len > size ||
         (size_t)(info.inner - data) > size - info.inner_len))
        abort();
    return 0;
}
