/*
 * pipeline.c — reader thread + N worker, dispatch theo TEID. [TUẦN 3]
 *
 * VÌ SAO CHIA THEO TEID MÀ KHÔNG ROUND-ROBIN
 *   - Mọi gói của một phiên luôn đến cùng một worker -> giữ thứ tự gói
 *     trong phiên, và bảng phiên của worker không cần chia sẻ / không lock.
 *   - Cái giá: phân bố tải phụ thuộc lưu lượng từng phiên. File bench có vài
 *     phiên "nặng" — hãy đo per_worker_packets để thấy độ lệch.
 *
 * VẤN ĐỀ: READER PHẢI HASH TEID TRƯỚC KHI GỬI
 *   Reader cần TEID mà chưa parse cả gói. Hai lựa chọn:
 *     a) Reader gọi parse_packet đầy đủ, gửi kèm kết quả -> worker chỉ cập
 *        nhật bảng. Đơn giản, nhưng phần parse nằm trên một luồng.
 *     b) Reader chỉ đọc nhanh tới TEID (offset cố định 14+IHL*4+8+4, vẫn
 *        phải kiểm tra biên!), worker parse đầy đủ. Song song tốt hơn.
 *   Làm (a) trước cho đúng, đo, rồi thử (b) và so sánh — đây là một câu
 *   chuyện benchmark rất hay để kể khi phỏng vấn.
 *   Gói lỗi / không phải GTP-U: gửi cho worker 0, hoặc reader tự đếm.
 *
 * VẤN ĐỀ: TRẢ BUFFER VỀ POOL
 *   mempool không thread-safe; reader alloc nhưng worker dùng xong. Giải
 *   pháp đối xứng: mỗi worker i có thêm free_ring[i] (SPSC, worker -> reader).
 *   Worker push buffer đã xong vào free_ring[i]; reader pop ra và
 *   mempool_free. Mỗi ring vẫn đúng một producer, một consumer.
 *   (Cách khác: mỗi worker một pool riêng — tự so sánh ưu nhược.)
 *
 * VẤN ĐỀ: KẾT THÚC
 *   Reader đọc hết file -> báo cho worker dừng. Cách đơn giản: một biến
 *   _Atomic bool done; worker chỉ thoát khi done == true VÀ ring rỗng.
 *   Thứ tự: reader set done SAU khi push gói cuối (release), worker load
 *   done (acquire) rồi kiểm tra ring lần nữa trước khi thoát.
 *
 * VẤN ĐỀ: RING ĐẦY / RỖNG
 *   Ring đầy: reader spin (thử lại), có thể chèn sched_yield() (<sched.h>)
 *   sau vài lần thất bại. Ring rỗng: worker tương tự. Busy-polling là cách
 *   các hệ thống data plane thật (DPDK) làm; đổi lại 100% CPU.
 *
 * Gợi ý cấu trúc:
 *
 *   struct pkt_buf {                  phần tử đi qua ring
 *       uint32_t caplen, orig_len;
 *       uint64_t ts_ns;
 *       uint8_t  data[PCAP_MAX_CAPLEN];   hoặc nhỏ hơn + kiểm tra caplen
 *   };
 *
 *   struct worker {
 *       pthread_t             tid;
 *       unsigned              id;
 *       struct ring          *rx;         reader -> worker
 *       struct ring          *free_ring;  worker -> reader
 *       struct session_table *table;
 *       struct stats          stats;
 *       const _Atomic bool   *done;
 *   };
 *
 *   static void *worker_main(void *arg);
 *       Chữ ký bắt buộc của pthread_create. arg là struct worker*.
 *       Vòng lặp: pop -> parse -> stats_record -> push vào free_ring.
 *
 *   static unsigned pick_worker(uint32_t teid, unsigned n);
 *       Đừng dùng teid % n trực tiếp — TEID cấp tuần tự sẽ phân bố theo kiểu
 *       round-robin "giả". Trộn bit trước (dùng lại hàm hash của
 *       session_table, hoặc nhân với hằng số Fibonacci 0x9E3779B1u).
 *
 * Đo thời gian: clock_gettime(CLOCK_MONOTONIC, &ts) trong <time.h>.
 * Đo riêng thời gian đọc file và thời gian xử lý.
 */
#include "pipeline.h"

#include <pthread.h>   /* pthread_create, pthread_join */
#include <stdatomic.h> /* _Atomic bool done */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>      /* clock_gettime, CLOCK_MONOTONIC */

#include <sched.h>     /* sched_yield */

#include "bytes.h"     /* rd_be32 */
#include "mempool.h"
#include "parser.h"
#include "pcap.h"
#include "ring.h"

/* Ô pool chứa vừa gói <= 2048 byte (MTU 1500 + outer header còn dư). Gói
 * lớn hơn, hoặc khi tắt mempool, cấp riêng bằng malloc đúng caplen. */
#define POOL_DATA_LEN 2048u
#define TABLE_INITIAL_CAPACITY 1024u/* TEID nằm ở byte 4-7 của header GTP-U. */
#define GTPU_OFF_TEID 4u

struct pkt_buf {
    uint32_t caplen, orig_len;
    uint64_t ts_ns;
    bool     pooled;       /* true: trả về mempool, false: free() */
    uint8_t  data[];
};

struct worker {
    pthread_t             tid;
    struct ring          *rx;         /* reader -> worker */
    struct ring          *free_ring;  /* worker -> reader */
    struct session_table *table;
    struct stats          stats;
    uint64_t              dropped_sessions;
    const _Atomic bool   *done;
    _Atomic bool          finished;   /* worker set ngay trước khi thoát */
};

/* Chọn reader (b): reader chỉ đọc nhanh TEID, worker parse đầy đủ, để phần
 * parse chạy song song. Cùng offset với parser (14 + IHL*4 + 8 + 4) và
 * parser không xử lý VLAN, nên gói nào parse OK cũng ra đúng TEID của nó ->
 * mọi gói của một phiên về cùng một worker. Gói lỗi có thể ra TEID rác, chỉ
 * ảnh hưởng chia tải chứ không ảnh hưởng kết quả. */
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

static void process(struct worker *w, struct pkt_buf *b)
{
    struct pkt_info info;
    enum parse_result r = parse_packet(b->data, b->caplen, &info);

    if (stats_record(&w->stats, w->table, r, &info, b->orig_len, b->ts_ns) != 0)
        w->dropped_sessions++;
    while (!ring_push(w->free_ring, b))
        sched_yield();
}

static void *worker_main(void *arg)
{
    struct worker *w = arg;
    void *item;

    for (;;)
    {
        if (ring_pop(w->rx, &item))
        {
            process(w, item);
            continue;
        }
        /* Reader set done SAU khi push gói cuối (release). Thấy done thì
         * pop lại một lần nữa mới chắc ring đã thật sự rỗng. */
        if (atomic_load_explicit(w->done, memory_order_acquire))
        {
            if (!ring_pop(w->rx, &item))
                break;
            process(w, item);
            continue;
        }
        sched_yield();
    }
    atomic_store_explicit(&w->finished, true, memory_order_release);
    return NULL;
}

static void release_buf(struct mempool *pool, struct pkt_buf *b)
{
    if (b->pooled)
        mempool_free(pool, b);
    else
        free(b);
}

/* Chỉ reader gọi: reader là consumer duy nhất của mọi free_ring và là luồng
 * duy nhất chạm vào pool. */
static void drain_free(struct worker *ws, unsigned n, struct mempool *pool)
{
    unsigned i;
    void *item;

    for (i = 0; i < n; i++)
    {
        while (ring_pop(ws[i].free_ring, &item))
            release_buf(pool, item);
    }
}

static struct pkt_buf *get_buf(struct worker *ws, unsigned n,
                               struct mempool *pool, uint32_t caplen)
{
    struct pkt_buf *b;

    if (pool != NULL && caplen <= POOL_DATA_LEN)
    {
        /* Hết pool = backpressure: chờ worker trả buffer, không malloc thêm. */
        while ((b = mempool_alloc(pool)) == NULL)
        {
            drain_free(ws, n, pool);
            if (mempool_available(pool) == 0)
                sched_yield();
        }
        b->pooled = true;
        return b;
    }
    b = malloc(sizeof *b + caplen);
    if (b != NULL)
        b->pooled = false;
    return b;
}

/*
 * pipeline_run
 *   1. Kiểm tra cfg (n_workers trong khoảng, ring_capacity lũy thừa 2).
 *   2. Tạo cho từng worker: ring, free_ring, session_table, stats_init.
 *   3. Tạo mempool (nếu use_mempool).
 *   4. pthread_create các worker.
 *   5. Luồng hiện tại làm reader: pcap_next -> lấy buffer (pool/malloc) ->
 *      memcpy gói vào -> pick_worker -> ring_push (spin khi đầy). Mỗi vòng
 *      cũng rút free_ring để trả buffer về pool.
 *   6. Set done; pthread_join mọi worker; rút nốt free_ring.
 *   7. Gộp stats vào res->total; chuyển quyền sở hữu các table sang res.
 *   8. Dọn mọi thứ còn lại. Lỗi giữa chừng: dừng các worker đã tạo trước
 *      khi return (dùng goto cleanup).
 */
int pipeline_run(const struct pipeline_config *cfg, struct pipeline_result *res)
{
    struct worker *ws = NULL;
    struct mempool *pool = NULL;
    struct pcap_reader *reader = NULL;
    struct pcap_packet pkt;
    struct timespec t0, t1;
    _Atomic bool done;
    unsigned n, i, started = 0;
    enum pcap_status st;
    int rc = -1;

    memset(res, 0, sizeof *res);
    stats_init(&res->total);
    n = cfg->n_workers;
    if (n == 0 || n > PIPELINE_MAX_WORKERS)
        return -1;
    if (cfg->use_mempool && (cfg->pool_size == 0 || cfg->pool_size > SIZE_MAX / n))
        return -1;

    st = pcap_open(cfg->path, &reader);
    if (st != PCAP_OK)
    {
        res->read_status = st;
        return -1;
    }

    atomic_init(&done, false);
    ws = calloc(n, sizeof *ws);
    if (ws == NULL)
        goto cleanup;
    for (i = 0; i < n; i++)
    {
        /* ring_create tự từ chối capacity không phải lũy thừa 2. */
        ws[i].rx = ring_create(cfg->ring_capacity);
        ws[i].free_ring = ring_create(cfg->ring_capacity);
        ws[i].table = session_table_create(TABLE_INITIAL_CAPACITY);
        if (ws[i].rx == NULL || ws[i].free_ring == NULL || ws[i].table == NULL)
            goto cleanup;
        stats_init(&ws[i].stats);
        ws[i].done = &done;
        atomic_init(&ws[i].finished, false);
    }
    if (cfg->use_mempool)
    {
        pool = mempool_create(sizeof(struct pkt_buf) + POOL_DATA_LEN,
                              cfg->pool_size * n);
        if (pool == NULL)
            goto cleanup;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (started = 0; started < n; started++)
    {
        if (pthread_create(&ws[started].tid, NULL, worker_main, &ws[started]) != 0)
            goto stop;
    }
    rc = 0;

    while ((st = pcap_next(reader, &pkt)) == PCAP_OK)
    {
        uint32_t teid;
        unsigned w = 0;   /* gói không đọc được TEID: worker 0 */
        struct pkt_buf *b = get_buf(ws, n, pool, pkt.caplen);

        if (b == NULL)
        {
            rc = -1;
            break;
        }
        b->caplen = pkt.caplen;
        b->orig_len = pkt.orig_len;
        b->ts_ns = pkt.ts_ns;
        memcpy(b->data, pkt.data, pkt.caplen);
        if (peek_teid(b->data, b->caplen, &teid))
            w = pick_worker(teid, n);
        while (!ring_push(ws[w].rx, b))
        {
            drain_free(ws, n, pool);
            sched_yield();
        }
        res->per_worker_packets[w]++;
    }
    res->read_status = st;

stop:
    atomic_store_explicit(&done, true, memory_order_release);
    /* Không join ngay: worker có thể đang chờ free_ring còn chỗ, mà chỉ
     * reader rút free_ring -> reader chờ join, worker chờ reader = deadlock.
     * Rút free_ring tới khi mọi worker báo đã thoát rồi mới join. */
    for (;;)
    {
        bool all_finished = true;

        drain_free(ws, n, pool);
        for (i = 0; i < started; i++)
        {
            if (!atomic_load_explicit(&ws[i].finished, memory_order_acquire))
                all_finished = false;
        }
        if (all_finished)
            break;
        sched_yield();
    }
    for (i = 0; i < started; i++)
        pthread_join(ws[i].tid, NULL);
    drain_free(ws, n, pool);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (rc == 0)
    {
        for (i = 0; i < n; i++)
        {
            stats_merge(&res->total, &ws[i].stats);
            res->dropped_sessions += ws[i].dropped_sessions;
            res->tables[i] = ws[i].table;   /* chuyển quyền sở hữu sang res */
            ws[i].table = NULL;
        }
        res->n_workers = n;
        res->elapsed_sec = (double)(t1.tv_sec - t0.tv_sec) +
                           (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    }

cleanup:
    if (ws != NULL)
    {
        for (i = 0; i < n; i++)
        {
            ring_destroy(ws[i].rx);
            ring_destroy(ws[i].free_ring);
            session_table_destroy(ws[i].table);
        }
    }
    free(ws);
    mempool_destroy(pool);
    pcap_close(reader);
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
