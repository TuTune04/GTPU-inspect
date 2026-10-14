/*
 * session_table.h — bảng phiên GTP-U, hash table open addressing.
 *                                                            [TUẦN 2]
 *
 * Key = (TEID, IP của tunnel endpoint NHẬN gói = outer dst IP).
 * Vì sao không chỉ TEID: TEID do chính endpoint nhận cấp phát, nên chỉ duy
 * nhất trong phạm vi một endpoint. Hai UPF khác nhau hoàn toàn có thể cùng
 * cấp TEID 0x1001.
 *
 * Bảng KHÔNG thread-safe, và không cần: ở tuần 3 mỗi worker sở hữu một bảng
 * riêng, chỉ một luồng chạm vào nó.
 */
#ifndef GTPU_SESSION_TABLE_H
#define GTPU_SESSION_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Số luồng inner tối đa lưu cho mỗi phiên. Luồng thứ 9 trở đi chỉ đếm vào
 * flows_overflow — giữ kích thước struct session cố định, không malloc. */
#define SESSION_MAX_FLOWS 8u

struct session_key {
    uint32_t teid;
    uint32_t endpoint_ip;   /* outer dst IP, host order */
};

/* Một luồng bên trong tunnel: 5-tuple của inner IP. */
struct inner_flow {
    uint32_t src_ip, dst_ip;
    uint16_t sport, dport;
    uint8_t  proto;
    uint64_t packets, bytes;
};

struct session {
    struct session_key key;
    uint64_t packets, bytes;
    uint64_t first_ts_ns, last_ts_ns;
    uint8_t  last_qfi;
    uint8_t  n_flows;
    uint64_t flows_overflow;
    struct inner_flow flows[SESSION_MAX_FLOWS];
};

struct session_table;   /* opaque, định nghĩa trong session_table.c */

/* capacity: số slot ban đầu (nên làm tròn lên lũy thừa của 2).
 * Trả NULL nếu hết bộ nhớ. */
struct session_table *session_table_create(size_t capacity);
void                  session_table_destroy(struct session_table *t);

/* Tìm phiên theo key; chưa có thì tạo mới (counter = 0).
 * Trả NULL chỉ khi bảng đầy và không resize được.
 * CHÚ Ý: nếu bảng resize, mọi con trỏ struct session* lấy được TRƯỚC lần
 * gọi này đều mất hiệu lực. Đừng giữ con trỏ phiên qua nhiều gói. */
struct session *session_table_upsert(struct session_table *t,
                                     const struct session_key *key);

/* Chỉ tìm, không tạo. Không có -> NULL. */
struct session *session_table_find(const struct session_table *t,
                                   const struct session_key *key);

size_t session_table_size(const struct session_table *t);

/* Gọi fn cho mọi phiên đang có, thứ tự bất kỳ. */
typedef void (*session_visit_fn)(const struct session *s, void *ctx);
void session_table_foreach(const struct session_table *t,
                           session_visit_fn fn, void *ctx);

/* Ghi tối đa n con trỏ phiên có bytes lớn nhất vào out[], giảm dần.
 * Trả số phần tử thực ghi (<= n). */
size_t session_table_top_n(const struct session_table *t,
                           const struct session **out, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* GTPU_SESSION_TABLE_H */
