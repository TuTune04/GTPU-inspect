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
#include <inttypes.h> /* PRIu64, PRIx32 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>    /* printf, fprintf */
#include <stdlib.h>   /* EXIT_SUCCESS, EXIT_FAILURE, strtoul */
#include <string.h>   /* strcmp */
#include <unistd.h>   /* getopt, optind */

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
static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [-v] file.pcap\n", prog);
}

/* IPv4 host order -> "a.b.c.d". buf tối thiểu 16 byte. */
static void fmt_ip(char *buf, size_t cap, uint32_t ip)
{
    snprintf(buf, cap, "%u.%u.%u.%u", (unsigned)((ip >> 24) & 0xffu),
             (unsigned)((ip >> 16) & 0xffu), (unsigned)((ip >> 8) & 0xffu),
             (unsigned)(ip & 0xffu));
}

static void print_packet(uint64_t idx, enum parse_result res,
                         const struct pkt_info *info)
{
    char src[16], dst[16];

    printf("#%-4" PRIu64 " %-24s", idx, parse_result_str(res));
    if (res == PARSE_OK)
    {
        printf(" teid=0x%08" PRIx32 " %s", info->gtp.teid,
               gtpu_msg_type_str(info->gtp.msg_type));
        if (info->has_inner)
        {
            fmt_ip(src, sizeof src, info->inner_src_ip);
            fmt_ip(dst, sizeof dst, info->inner_dst_ip);
            printf(" %s -> %s", src, dst);
        }
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    uint64_t counts[PARSE_RESULT_COUNT] = {0};
    uint64_t idx = 0;
    bool verbose = false;
    struct pcap_reader *reader;
    struct pcap_packet pkt;
    struct pkt_info info;
    enum pcap_status st;
    int opt;

    while ((opt = getopt(argc, argv, "v")) != -1)
    {
        if (opt != 'v')
        {
            usage(argv[0]);
            return 2;
        }
        verbose = true;
    }
    if (argc - optind != 1)
    {
        usage(argv[0]);
        return 2;
    }

    st = pcap_open(argv[optind], &reader);
    if (st != PCAP_OK)
    {
        fprintf(stderr, "%s: %s\n", argv[optind], pcap_status_str(st));
        return EXIT_FAILURE;
    }

    while ((st = pcap_next(reader, &pkt)) == PCAP_OK)
    {
        enum parse_result res = parse_packet(pkt.data, pkt.caplen, &info);
        counts[res]++;
        if (verbose)
            print_packet(idx, res, &info);
        idx++;
    }

    /* File hỏng giữa chừng: báo lỗi nhưng vẫn in thống kê phần đã đọc. */
    if (st != PCAP_EOF)
        fprintf(stderr, "%s: %s (sau %" PRIu64 " gói)\n", argv[optind],
                pcap_status_str(st), idx);

    printf("Packets: %" PRIu64 "\n", idx);
    for (int i = 0; i < PARSE_RESULT_COUNT; i++)
    {
        if (counts[i] > 0)
            printf("  %-24s %" PRIu64 "\n", parse_result_str((enum parse_result)i),
                   counts[i]);
    }

    pcap_close(reader);
    return st == PCAP_EOF ? EXIT_SUCCESS : EXIT_FAILURE;
}
