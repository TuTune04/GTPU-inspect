/*
 * pipeline.c — reader thread + N worker, dispatch theo TEID. [TUẦN 3, v2]
 *
 * VÌ SAO CHIA THEO TEID MÀ KHÔNG ROUND-ROBIN
 *   - Mọi gói của một phiên luôn đến cùng một worker -> giữ thứ tự gói
 *     trong phiên, và bảng phiên của worker không cần chia sẻ / không lock.
 *   - Cái giá: phân bố tải phụ thuộc lưu lượng từng phiên. File bench có vài
 *     phiên "nặng" — hãy đo per_worker_packets để thấy độ lệch.
 *
 * READER CHỈ ĐỌC NHANH TEID
 *   Reader đọc tới TEID ở offset cố định 14 + IHL*4 + 8 + 4 (có kiểm tra
 *   biên), worker parse đầy đủ, để phần parse chạy song song. Gói không đọc
 *   được TEID: gửi cho worker 0.
 *
 * v2: KHÔNG CHÉP GÓI
 *   v1 chép mỗi gói vào một buffer lấy từ mempool rồi trả buffer về qua
 *   free_ring. perf cho thấy riêng phần chép (fread + memcpy) chiếm ~1/3 mẫu
 *   của reader, và worker đọc dữ liệu vừa được core khác GHI nên mỗi gói là
 *   một lần chuyển cache line. v2 mmap cả file (pcap_map_*): ring chỉ chở
 *   offset của record, worker đọc thẳng từ vùng map. Không còn mempool,
 *   free_ring, hay deadlock "reader chờ join, worker chờ free_ring".
 *   Mempool vẫn đúng chỗ khi gói đến từ socket/NIC, nơi buffer phải được tái
 *   sử dụng — chỉ là đọc file thì không cần.
 *
 * KẾT THÚC
 *   Reader set done (release) SAU khi push gói cuối; worker thấy done
 *   (acquire) thì pop lại một lần nữa rồi mới thoát.
 *
 * v2: ĐẨY THEO LÔ
 *   Một push/pop mỗi gói nghĩa là mỗi gói một lần cache line head/tail đổi
 *   chủ giữa hai core. Reader gom cfg->batch offset cho từng worker rồi
 *   ring_push_bulk một lần; worker ring_pop_bulk tối đa WORKER_POP_MAX.
 *   Lô của reader nằm trong mảng batches riêng, KHÔNG nằm trong struct
 *   worker: reader ghi lô liên tục, worker ghi stats liên tục, chung cache
 *   line là false sharing.
 *
 * v2: SHARED-NOTHING (cfg->shared_nothing)
 *   Pipeline vẫn buộc mọi gói đi qua MỘT reader, nên reader là trần thông
 *   lượng. Chế độ này bỏ reader: luồng chính chỉ duyệt record header để chia
 *   file thành n đoạn gần bằng nhau về byte (pcap không có chỉ mục, không
 *   nhảy được vào giữa file mà chắc chắn tìm ra đầu record), rồi mỗi worker
 *   tự parse đoạn của mình. Không ring, không đồng bộ trong lúc chạy.
 *   Cái giá: một phiên có thể nằm ở nhiều worker, nên main phải gộp bằng
 *   session_merge theo thứ tự đoạn, và mất thứ tự xử lý trong một phiên.
 *
 * RING ĐẦY / RỖNG
 *   Ring đầy: reader sched_yield() rồi thử lại. Ring rỗng: worker tương tự.
 */
#include "pipeline.h"

#include <pthread.h>   /* pthread_create, pthread_join */
#include <sched.h>     /* sched_yield */
#include <stdatomic.h> /* _Atomic bool done */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>      /* clock_gettime, CLOCK_MONOTONIC */

#include "bytes.h"     /* rd_be32 */
#include "parser.h"
#include "pcap.h"
#include "ring.h"

#define TABLE_INITIAL_CAPACITY 1024u
#define WORKER_POP_MAX 64u
/* TEID nằm ở byte 4-7 của header GTP-U. */
#define GTPU_OFF_TEID 4u

struct worker {
    pthread_t              tid;
    struct ring           *rx;        /* reader -> worker: offset record */
    const struct pcap_map *map;       /* chỉ đọc, chung mọi luồng */
    struct session_table  *table;
    struct stats           stats;
    uint64_t               dropped_sessions;
    double                 cpu_sec;   /* CPU của riêng luồng này */
    const _Atomic bool    *done;
    size_t                 begin, end; /* shared-nothing: đoạn [begin, end) */
};

/* Lô offset reader đang gom cho một worker. Chỉ reader chạm vào. */
struct batch {
    void  *items[PIPELINE_MAX_BATCH];
    size_t n;
};

static double ts_sec(const struct timespec *t)
{
    return (double)t->tv_sec + (double)t->tv_nsec / 1e9;
}

/* CPU đã dùng của luồng gọi (POSIX). So với wall: worker rảnh mà CPU cao
 * nghĩa là nó đang spin chờ chứ không làm việc. */
static double thread_cpu_sec(void)
{
    struct timespec t;

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return ts_sec(&t);
}

/* Ring chở void*; v2 chở offset của record trong vùng map (luôn >= 24 nên
 * không bao giờ trùng NULL). Đổi qua uintptr_t: số nguyên <-> con trỏ, không
 * phải ép con trỏ buffer sang struct. */
static void *off_to_item(size_t off)
{
    return (void *)(uintptr_t)off;
}

static size_t item_to_off(void *item)
{
    return (size_t)(uintptr_t)item;
}

/* Cùng offset với parser (14 + IHL*4 + 8 + 4) và parser không xử lý VLAN,
 * nên gói nào parse OK cũng ra đúng TEID của nó -> mọi gói của một phiên về
 * cùng một worker. Gói lỗi có thể ra TEID rác, chỉ ảnh hưởng chia tải chứ
 * không ảnh hưởng kết quả. */
static bool peek_teid(const uint8_t *p, size_t len, uint32_t *teid)
{
    size_t off;

    if (len <= ETH_HEADER_LEN)
        return false;
    off = ETH_HEADER_LEN + (size_t)(p[ETH_HEADER_LEN] & 0x0fu) * 4u +
          UDP_HEADER_LEN + GTPU_OFF_TEID;
    if (len < off + 4u)
        return false;
    *teid = rd_be32(p + off);
    return true;
}

/* TEID cấp tuần tự nên trộn bằng hằng Fibonacci trước, rồi lấy 32 bit cao
 * của h * n (multiply-shift) thay cho %: dùng các bit cao đã trộn tốt. */
static unsigned pick_worker(uint32_t teid, unsigned n)
{
    uint32_t h = teid * 0x9E3779B1u;

    return (unsigned)(((uint64_t)h * n) >> 32);
}

/* Xử lý record tại *off và đưa *off tới record kế. */
static bool process(struct worker *w, size_t *off)
{
    struct pcap_packet pkt;
    struct pkt_info info;
    enum parse_result r;

    /* Reader (hoặc split_file) đã đọc thành công record này và vùng map chỉ
     * đọc, nên đọc lại luôn OK; vẫn kiểm tra thay vì tin mù. */
    if (pcap_map_next(w->map, off, &pkt) != PCAP_OK)
        return false;
    r = parse_packet(pkt.data, pkt.caplen, &info);
    if (stats_record(&w->stats, w->table, r, &info, pkt.orig_len, pkt.ts_ns) != 0)
        w->dropped_sessions++;
    return true;
}

static void *worker_main(void *arg)
{
    struct worker *w = arg;
    void *items[WORKER_POP_MAX];
    size_t k, i;

    for (;;)
    {
        k = ring_pop_bulk(w->rx, items, WORKER_POP_MAX);
        if (k == 0)
        {
            /* Reader set done SAU khi push gói cuối (release). Thấy done thì
             * pop lại một lần nữa mới chắc ring đã thật sự rỗng. */
            if (!atomic_load_explicit(w->done, memory_order_acquire))
            {
                sched_yield();
                continue;
            }
            k = ring_pop_bulk(w->rx, items, WORKER_POP_MAX);
            if (k == 0)
                break;
        }
        for (i = 0; i < k; i++)
        {
            size_t off = item_to_off(items[i]);

            process(w, &off);
        }
    }
    w->cpu_sec = thread_cpu_sec();
    return NULL;
}

/* Shared-nothing: tự đọc đoạn [begin, end) của mình, không chờ ai. */
static void *chunk_main(void *arg)
{
    struct worker *w = arg;
    size_t off = w->begin;

    while (off < w->end && process(w, &off))
        ;
    w->cpu_sec = thread_cpu_sec();
    return NULL;
}

/* Chia vùng record thành n đoạn gần bằng nhau về byte, cắt đúng đầu record:
 * bounds[i] .. bounds[i + 1] là đoạn i. Duyệt hết mọi record header nên ra
 * luôn trạng thái cuối và điểm dừng (EOF hay lỗi) giống hệt reader. */
static enum pcap_status split_file(const struct pcap_map *m, unsigned n,
                                   size_t *bounds)
{
    size_t first = pcap_map_first(m);
    size_t step = (pcap_map_size(m) - first) / n;
    size_t off = first;
    struct pcap_packet pkt;
    enum pcap_status st;
    unsigned k = 1;

    bounds[0] = first;
    for (;;)
    {
        size_t rec = off;

        while (k < n && rec - first >= step * k)
            bounds[k++] = rec;
        st = pcap_map_next(m, &off, &pkt);
        if (st != PCAP_OK)
        {
            while (k <= n)
                bounds[k++] = rec;
            return st;
        }
    }
}

/* Đẩy hết lô; ring đầy thì nhường CPU cho worker rồi đẩy phần còn lại. */
static void flush_batch(struct ring *rx, struct batch *b)
{
    size_t done = 0;

    while (done < b->n)
    {
        size_t k = ring_push_bulk(rx, b->items + done, b->n - done);

        if (k == 0)
            sched_yield();
        done += k;
    }
    b->n = 0;
}

/*
 * pipeline_run
 *   1. Kiểm tra cfg, pcap_map_open.
 *   2. Tạo cho từng worker: ring, session_table, stats_init.
 *   3. pthread_create các worker.
 *   4. Luồng hiện tại làm reader: pcap_map_next -> peek TEID -> pick_worker
 *      -> thêm offset vào lô của worker đó, đủ lô thì flush_batch.
 *      (shared-nothing: split_file TRƯỚC khi tạo worker, không có reader.)
 *   5. Flush mọi lô còn dở, set done; pthread_join mọi worker.
 *   6. Gộp stats vào res->total; chuyển quyền sở hữu các table sang res.
 *   7. Dọn mọi thứ còn lại (goto cleanup).
 */
int pipeline_run(const struct pipeline_config *cfg, struct pipeline_result *res)
{
    struct worker *ws = NULL;
    struct batch *batches = NULL;
    struct pcap_map *map = NULL;
    struct pcap_packet pkt;
    struct timespec t0, tr, t1;
    _Atomic bool done;
    unsigned n, i, started = 0;
    enum pcap_status st;
    size_t off, batch;
    size_t bounds[PIPELINE_MAX_WORKERS + 1];
    bool sn = cfg->shared_nothing;
    int rc = -1;

    memset(res, 0, sizeof *res);
    stats_init(&res->total);
    n = cfg->n_workers;
    batch = cfg->batch == 0 ? 1 : cfg->batch;
    if (n == 0 || n > PIPELINE_MAX_WORKERS || batch > PIPELINE_MAX_BATCH ||
        batch > cfg->ring_capacity)
        return -1;

    st = pcap_map_open(cfg->path, &map);
    if (st != PCAP_OK)
    {
        res->read_status = st;
        return -1;
    }

    atomic_init(&done, false);
    ws = calloc(n, sizeof *ws);
    batches = calloc(n, sizeof *batches);
    if (ws == NULL || batches == NULL)
        goto cleanup;
    for (i = 0; i < n; i++)
    {
        /* ring_create tự từ chối capacity không phải lũy thừa 2.
         * Shared-nothing không cần ring. */
        ws[i].rx = sn ? NULL : ring_create(cfg->ring_capacity);
        ws[i].table = session_table_create(TABLE_INITIAL_CAPACITY);
        if ((!sn && ws[i].rx == NULL) || ws[i].table == NULL)
            goto cleanup;
        ws[i].map = map;
        stats_init(&ws[i].stats);
        ws[i].done = &done;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (sn)
    {
        res->read_status = split_file(map, n, bounds);
        for (i = 0; i < n; i++)
        {
            ws[i].begin = bounds[i];
            ws[i].end = bounds[i + 1];
        }
        clock_gettime(CLOCK_MONOTONIC, &tr);
    }
    for (started = 0; started < n; started++)
    {
        if (pthread_create(&ws[started].tid, NULL, sn ? chunk_main : worker_main,
                           &ws[started]) != 0)
            goto stop;
    }
    rc = 0;
    if (sn)
        goto stop;

    off = pcap_map_first(map);
    for (;;)
    {
        size_t rec = off;
        uint32_t teid;
        unsigned w = 0;   /* gói không đọc được TEID: worker 0 */

        st = pcap_map_next(map, &off, &pkt);
        if (st != PCAP_OK)
            break;
        if (peek_teid(pkt.data, pkt.caplen, &teid))
            w = pick_worker(teid, n);
        batches[w].items[batches[w].n++] = off_to_item(rec);
        if (batches[w].n == batch)
            flush_batch(ws[w].rx, &batches[w]);
    }
    res->read_status = st;
    for (i = 0; i < n; i++)
        flush_batch(ws[i].rx, &batches[i]);

stop:
    if (!sn)
        clock_gettime(CLOCK_MONOTONIC, &tr);
    atomic_store_explicit(&done, true, memory_order_release);
    for (i = 0; i < started; i++)
        pthread_join(ws[i].tid, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (rc == 0)
    {
        for (i = 0; i < n; i++)
        {
            stats_merge(&res->total, &ws[i].stats);
            res->dropped_sessions += ws[i].dropped_sessions;
            res->per_worker_packets[i] = ws[i].stats.packets;
            res->per_worker_cpu_sec[i] = ws[i].cpu_sec;
            res->tables[i] = ws[i].table;   /* chuyển quyền sở hữu sang res */
            ws[i].table = NULL;
        }
        res->n_workers = n;
        res->elapsed_sec = ts_sec(&t1) - ts_sec(&t0);
        res->reader_sec = ts_sec(&tr) - ts_sec(&t0);
    }

cleanup:
    if (ws != NULL)
    {
        for (i = 0; i < n; i++)
        {
            ring_destroy(ws[i].rx);
            session_table_destroy(ws[i].table);
        }
    }
    free(ws);
    free(batches);
    pcap_map_close(map);
    return rc;
}

/* pipeline_result_free: session_table_destroy cho từng tables[i]. */
void pipeline_result_free(struct pipeline_result *res)
{
    unsigned i;

    for (i = 0; i < res->n_workers; i++)
    {
        session_table_destroy(res->tables[i]);
        res->tables[i] = NULL;
    }
    res->n_workers = 0;
}
