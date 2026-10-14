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

#include "mempool.h"
#include "parser.h"
#include "pcap.h"
#include "ring.h"

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
    /* TODO: xóa stub và viết code của bạn */
    (void)cfg;
    (void)res;
    return -1;
}

/* pipeline_result_free: session_table_destroy cho từng tables[i]. */
void pipeline_result_free(struct pipeline_result *res)
{
    /* TODO */
    (void)res;
}
