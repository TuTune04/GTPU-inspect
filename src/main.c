/*
 * main.c — chương trình gtpu-inspect.                        [TUẦN 1 -> 3]
 *
 * Cách dùng mục tiêu:
 *   gtpu-inspect [-v] [-n TOP] [-w WORKERS] file.pcap
 *     -v          in mỗi gói một dòng (tuần 1)
 *     -n TOP      số phiên trong bảng top N (tuần 2, mặc định 10)
 *     -w WORKERS  số luồng worker (tuần 3; 0 = chạy tuần tự, không thread)
 *
 * CTest tự chạy chương trình trên mọi file .pcap trong tests/data/ (test cli.*):
 * chỉ fail khi crash hoặc sanitizer báo lỗi.
 */
#include <stdio.h>    /* printf, fprintf */
#include <stdlib.h>   /* EXIT_SUCCESS, EXIT_FAILURE, strtoul */
#include <string.h>   /* strcmp */

#include "pcap.h"
#include "parser.h"
/* #include "session_table.h"   tuần 2 */
/* #include "stats.h"           tuần 2 */
/* #include "pipeline.h"        tuần 3 */

/*
 * [TUẦN 1] Chạy tuần tự
 *
 *   1. Đọc tham số. Bản tuần 1 chỉ cần argv[1] là đường dẫn file; sai số
 *      tham số -> in usage ra stderr, return 2.
 *      (getopt() có trong <unistd.h>, là POSIX — dùng được vì CMake đã
 *       định nghĩa _POSIX_C_SOURCE.)
 *   2. pcap_open. Lỗi -> fprintf(stderr, "...: %s\n", pcap_status_str(st)),
 *      return EXIT_FAILURE.
 *   3. Vòng lặp:
 *        while ((st = pcap_next(r, &pkt)) == PCAP_OK) {
 *            res = parse_packet(pkt.data, pkt.caplen, &info);
 *            counts[res]++;
 *            in một dòng: idx, parse_result_str(res), TEID, msg type,
 *            inner src -> dst (in IP từ uint32_t host order bằng phép dịch,
 *            hoặc htonl + inet_ntop của <arpa/inet.h>)
 *            idx++;
 *        }
 *      Sau vòng lặp: st != PCAP_EOF nghĩa là file hỏng giữa chừng -> báo lỗi
 *      nhưng VẪN in thống kê những gói đã đọc.
 *   4. In bảng đếm: với i < PARSE_RESULT_COUNT, counts[i] > 0 thì in
 *      parse_result_str(i) và counts[i].
 *   5. pcap_close; return EXIT_SUCCESS nếu EOF bình thường, ngược lại
 *      EXIT_FAILURE.
 *
 *   Kiểu cho bộ đếm: uint64_t counts[PARSE_RESULT_COUNT] = {0};
 *   In uint64_t đúng chuẩn: PRIu64 trong <inttypes.h>, ví dụ
 *     printf("%" PRIu64 "\n", counts[i]);
 *
 * [TUẦN 2] Thay mảng counts bằng struct stats + session_table:
 *   stats_record(...) mỗi gói, stats_print(...) cuối chương trình.
 *
 * [TUẦN 3] Nếu -w > 0: gọi pipeline_run(...) thay cho vòng lặp tuần tự.
 *   Giữ cả hai đường: chế độ tuần tự là "đáp án" để kiểm tra kết quả bản
 *   đa luồng (tổng gói, tổng byte, top N phải giống hệt).
 */
int main(int argc, char **argv)
{
    /* TODO: xóa stub và viết code của bạn */
    (void)argc;
    (void)argv;
    return EXIT_SUCCESS;
}
