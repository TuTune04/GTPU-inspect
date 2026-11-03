/*
 * main.c — chương trình gtpu-inspect.                        [TUẦN 1 -> 3]
 *
 * Cách dùng mục tiêu:
 *   gtpu-inspect [-v] [-n TOP] [-w WORKERS [-b BATCH] [-S]] file.pcap
 *     -v          in mỗi gói một dòng (tuần 1)
 *     -n TOP      số phiên trong bảng top N (tuần 2, mặc định 10)
 *     -w WORKERS  số luồng worker (tuần 3; 0 = chạy tuần tự, không thread)
 *     -b BATCH    với -w: số gói mỗi lần đẩy qua ring (v2, mặc định 32)
 *     -S          với -w: shared-nothing, mỗi worker tự đọc một đoạn file (v2)
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
#include "session_table.h"
#include "stats.h"
#include "pipeline.h"

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
    fprintf(stderr, "usage: %s [-v] [-n TOP] [-w WORKERS [-b BATCH] [-S]] file.pcap\n",
            prog);
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

/* Số thập phân không dấu, cả chuỗi phải là số. */
static bool parse_ulong(const char *s, unsigned long *out)
{
    char *end;

    *out = strtoul(s, &end, 10);
    return *s != '\0' && *end == '\0';
}

struct merge_ctx {
    struct session_table *dst;
    uint64_t              failed;
    uint64_t              inexact;   /* session_merge trả false */
};

/* Gộp các bảng worker vào một bảng để stats_print in top N giống hệt chế độ
 * tuần tự. Dispatch theo TEID thì các bảng không chung key nào (luôn rơi vào
 * nhánh chép); shared-nothing thì một phiên có thể ở nhiều bảng, và duyệt
 * bảng theo thứ tự worker = thứ tự đoạn file như session_merge yêu cầu. */
static void merge_session(const struct session *s, void *arg)
{
    struct merge_ctx *ctx = arg;
    struct session *d = session_table_upsert(ctx->dst, &s->key);

    if (d == NULL)
        ctx->failed++;
    else if (!session_merge(d, s))
        ctx->inexact++;
}

/* [TUẦN 3] -w WORKERS: chạy pipeline thay cho vòng lặp tuần tự. */
static int run_pipeline(const struct pipeline_config *cfg, size_t top_n)
{
    const char *path = cfg->path;
    struct pipeline_result res;
    struct merge_ctx ctx = {NULL, 0, 0};
    unsigned i;

    if (pipeline_run(cfg, &res) != 0)
    {
        if (res.read_status != PCAP_OK)
            fprintf(stderr, "%s: %s\n", path, pcap_status_str(res.read_status));
        else
            fprintf(stderr, "%s: không chạy được pipeline\n", path);
        return EXIT_FAILURE;
    }
    if (res.read_status != PCAP_EOF)
        fprintf(stderr, "%s: %s (sau %" PRIu64 " gói)\n", path,
                pcap_status_str(res.read_status), res.total.packets);

    ctx.dst = session_table_create(1024);
    if (ctx.dst == NULL)
    {
        fprintf(stderr, "không đủ bộ nhớ cho bảng phiên\n");
        pipeline_result_free(&res);
        return EXIT_FAILURE;
    }
    for (i = 0; i < res.n_workers; i++)
        session_table_foreach(res.tables[i], merge_session, &ctx);

    stats_print(&res.total, ctx.dst, top_n, stdout);
    if (res.dropped_sessions > 0 || ctx.failed > 0)
        fprintf(stderr, "không thêm được phiên cho %" PRIu64 " gói, %" PRIu64
                " phiên khi gộp\n", res.dropped_sessions, ctx.failed);
    if (ctx.inexact > 0)
        fprintf(stderr, "%" PRIu64 " phiên có > %u luồng bị chia giữa các đoạn:"
                " cột Flows có thể khác chạy tuần tự (tổng gói/byte vẫn đúng)\n",
                ctx.inexact, SESSION_MAX_FLOWS);

    /* Số đo cho benchmark, ra stderr để stdout giống hệt chế độ tuần tự. */
    fprintf(stderr, "pipeline: %u worker, %s, %" PRIu64 " gói trong %.3f s"
            " (%.2f Mpps)\n", res.n_workers,
            cfg->shared_nothing ? "shared-nothing" : "reader + ring",
            res.total.packets, res.elapsed_sec,
            res.elapsed_sec > 0 ? (double)res.total.packets / res.elapsed_sec / 1e6
                                : 0.0);
    fprintf(stderr, "  %s: %.3f s\n",
            cfg->shared_nothing ? "chia file" : "reader", res.reader_sec);
    for (i = 0; i < res.n_workers; i++)
        fprintf(stderr, "  worker %u: %" PRIu64 " gói, cpu %.3f s\n", i,
                res.per_worker_packets[i], res.per_worker_cpu_sec[i]);

    session_table_destroy(ctx.dst);
    pipeline_result_free(&res);
    return res.read_status == PCAP_EOF ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    struct stats stats;
    struct session_table *sessions;
    uint64_t idx = 0;
    uint64_t dropped_sessions = 0;
    size_t top_n = 10;
    struct pipeline_config cfg = {
        .path = NULL,
        .n_workers = 0,       /* 0 = chạy tuần tự */
        .ring_capacity = 1024,
        .batch = 32,      /* đo: 32 và 128 như nhau, 1 chậm nhất */
    };
    bool verbose = false;
    struct pcap_reader *reader;
    struct pcap_packet pkt;
    struct pkt_info info;
    enum pcap_status st;
    unsigned long v;
    int opt;

    while ((opt = getopt(argc, argv, "vn:w:b:S")) != -1)
    {
        if (opt == 'v')
        {
            verbose = true;
        }
        else if (opt == 'n' && parse_ulong(optarg, &v))
        {
            top_n = (size_t)v;
        }
        else if (opt == 'w' && parse_ulong(optarg, &v) &&
                 v <= PIPELINE_MAX_WORKERS)
        {
            cfg.n_workers = (unsigned)v;
        }
        else if (opt == 'b' && parse_ulong(optarg, &v) && v >= 1 &&
                 v <= PIPELINE_MAX_BATCH)
        {
            cfg.batch = (size_t)v;
        }
        else if (opt == 'S')
        {
            cfg.shared_nothing = true;
        }
        else
        {
            usage(argv[0]);
            return 2;
        }
    }
    /* -v in theo thứ tự gói, mà worker xử lý song song: không đi cùng -w. */
    if (argc - optind != 1 || (verbose && cfg.n_workers > 0))
    {
        usage(argv[0]);
        return 2;
    }
    if (cfg.n_workers > 0)
    {
        cfg.path = argv[optind];
        return run_pipeline(&cfg, top_n);
    }

    st = pcap_open(argv[optind], &reader);
    if (st != PCAP_OK)
    {
        fprintf(stderr, "%s: %s\n", argv[optind], pcap_status_str(st));
        return EXIT_FAILURE;
    }

    stats_init(&stats);
    sessions = session_table_create(1024);
    if (sessions == NULL)
    {
        fprintf(stderr, "không đủ bộ nhớ cho bảng phiên\n");
        pcap_close(reader);
        return EXIT_FAILURE;
    }

    while ((st = pcap_next(reader, &pkt)) == PCAP_OK)
    {
        enum parse_result res = parse_packet(pkt.data, pkt.caplen, &info);
        if (stats_record(&stats, sessions, res, &info, pkt.orig_len,
                         pkt.ts_ns) != 0)
            dropped_sessions++;
        if (verbose)
            print_packet(idx, res, &info);
        idx++;
    }

    /* File hỏng giữa chừng: báo lỗi nhưng vẫn in thống kê phần đã đọc. */
    if (st != PCAP_EOF)
        fprintf(stderr, "%s: %s (sau %" PRIu64 " gói)\n", argv[optind],
                pcap_status_str(st), idx);

    if (verbose)
        printf("\n");
    stats_print(&stats, sessions, top_n, stdout);
    if (dropped_sessions > 0)
        fprintf(stderr, "không thêm được phiên cho %" PRIu64 " gói\n",
                dropped_sessions);

    session_table_destroy(sessions);
    pcap_close(reader);
    return st == PCAP_EOF ? EXIT_SUCCESS : EXIT_FAILURE;
}
