/*
 * libFuzzer target cho parser.
 *
 * libFuzzer gọi hàm dưới đây hàng triệu lần với buffer ngẫu nhiên đã được
 * "đột biến" dựa trên coverage. Mỗi lần gọi phải:
 *   - không đọc/ghi ngoài [data, data + size)  (ASan bắt)
 *   - không có undefined behavior               (UBSan bắt)
 *   - không leak, không giữ state giữa các lần gọi
 *
 * TODO: khi đã có parser.h, include và gọi hàm parse một frame Ethernet
 * (hoặc chỉ riêng lớp GTP-U) trên (data, size). Không cần kiểm tra kết quả:
 * mục tiêu là parser không bao giờ crash.
 *
 * Corpus khởi đầu: tools/make_corpus.py tách từng gói trong các file pcap ở tests/data/
 * thành một file trong fuzz/corpus/.
 */
#include <stddef.h>
#include <stdint.h>

/* #include "parser.h" */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    return 0;
}
