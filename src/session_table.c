/*
 * session_table.c — hash table open addressing.             [TUẦN 2]
 *
 * Test: tests/test_session_table.cpp
 *
 * KHÁI NIỆM
 *   Open addressing: mọi phần tử nằm ngay trong một mảng slot. Khi slot
 *   hash(key) % cap đã bị chiếm, dò slot kế tiếp (linear probing: i+1, i+2...)
 *   cho tới khi gặp key cần tìm hoặc slot trống.
 *   So với chaining (mỗi slot là một linked list): ít malloc hơn, dữ liệu
 *   liền nhau nên thân thiện cache CPU, nhưng hiệu năng tụt nhanh khi bảng
 *   đầy -> phải giữ load factor (size / cap) thấp, thường <= 0.7.
 *
 * QUYẾT ĐỊNH BẠN PHẢI TỰ ĐƯA RA (ghi lý do vào comment):
 *   1. Hàm hash cho (teid, endpoint_ip). TEID thường cấp tuần tự (0x1001,
 *      0x1002...), nên `teid % cap` phân bố kém nếu cap không tốt. Gợi ý tìm
 *      hiểu: trộn 64 bit `((uint64_t)teid << 32 | ip)` bằng finalizer của
 *      murmur3/splitmix64, hoặc FNV-1a trên 8 byte.
 *   2. cap là lũy thừa của 2 -> dùng `h & (cap - 1)` thay cho `h % cap`.
 *   3. Đánh dấu slot trống: thêm `bool used` trong slot, hay dùng một key
 *      đặc biệt? (TEID = 0 là hợp lệ — Echo dùng TEID 0 — nên không dùng
 *      teid==0 làm "trống" được.)
 *   4. Resize: khi size+1 > cap * 0.7, cấp mảng gấp đôi và chèn lại mọi
 *      phần tử (KHÔNG memcpy mảng cũ: vị trí phụ thuộc cap). Lưu ý: con trỏ
 *      struct session* trả ra trước đó sẽ không còn hợp lệ sau resize — ghi
 *      rõ điều này trong session_table.h.
 *   5. Xóa phần tử: bản tối thiểu không cần. Nếu làm, tìm hiểu "tombstone"
 *      và vì sao không được đơn giản đánh dấu slot là trống.
 *
 * Gợi ý struct:
 *
 *   struct slot {
 *       bool           used;
 *       struct session s;
 *   };
 *
 *   struct session_table {
 *       struct slot *slots;
 *       size_t       cap;     lũy thừa của 2
 *       size_t       size;
 *   };
 *
 * Hàm static gợi ý (bỏ comment khi bắt đầu dùng):
 *
 *   static uint64_t key_hash(const struct session_key *k);
 *   static bool     key_eq(const struct session_key *a,
 *                          const struct session_key *b);
 *       So sánh từng field. Không dùng memcmp trên struct: padding giữa các
 *       field có giá trị không xác định.
 *   static struct slot *probe(struct slot *slots, size_t cap,
 *                             const struct session_key *k);
 *       Trả slot chứa k, hoặc slot trống đầu tiên gặp trên đường dò.
 *   static int grow(struct session_table *t);
 */
#include "session_table.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>   /* calloc, free, qsort */
#include <string.h>   /* memset */

#define MIN_CAPACITY 16u
/* Resize khi (size + 1) / cap > 7/10. Linear probing tụt nhanh khi bảng đầy;
 * 0.7 giữ số lần dò trung bình thấp mà không tốn quá nhiều bộ nhớ. Luôn còn
 * ít nhất 30% slot trống nên vòng probe chắc chắn kết thúc. */
#define LOAD_NUM 7u
#define LOAD_DEN 10u

struct slot {
    bool           used;
    struct session s;
};

struct session_table {
    struct slot *slots;
    size_t       cap;     /* luôn là lũy thừa của 2 */
    size_t       size;
};

/*
 * Hash: ghép (teid, ip) thành 64 bit rồi trộn bằng finalizer của splitmix64.
 * TEID cấp tuần tự (0x1001, 0x1002...) nên `teid % cap` sẽ dồn vào các slot
 * liền kề; finalizer làm mỗi bit đầu vào ảnh hưởng tới mọi bit đầu ra, nên
 * lấy các bit thấp (h & (cap - 1)) vẫn phân bố đều.
 */
static uint64_t key_hash(const struct session_key *k)
{
    uint64_t x = ((uint64_t)k->teid << 32) | k->endpoint_ip;

    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

/* So từng field, không memcmp: padding trong struct không xác định. */
static bool key_eq(const struct session_key *a, const struct session_key *b)
{
    return a->teid == b->teid && a->endpoint_ip == b->endpoint_ip;
}

/* Trả slot chứa k, hoặc slot trống đầu tiên trên đường dò. */
static struct slot *probe(struct slot *slots, size_t cap,
                          const struct session_key *k)
{
    size_t mask = cap - 1u;
    size_t i = (size_t)key_hash(k) & mask;

    while (slots[i].used && !key_eq(&slots[i].s.key, k))
        i = (i + 1u) & mask;
    return &slots[i];
}

/* Cấp mảng gấp đôi và chèn lại từng phần tử: vị trí phụ thuộc cap nên
 * không thể memcpy mảng cũ. Lỗi -> -1 và bảng giữ nguyên. */
static int grow(struct session_table *t)
{
    size_t new_cap, i;
    struct slot *new_slots;

    if (t->cap > SIZE_MAX / 2u)
        return -1;
    new_cap = t->cap * 2u;
    new_slots = calloc(new_cap, sizeof *new_slots);
    if (new_slots == NULL)
        return -1;

    for (i = 0; i < t->cap; i++)
    {
        if (t->slots[i].used)
            *probe(new_slots, new_cap, &t->slots[i].s.key) = t->slots[i];
    }
    free(t->slots);
    t->slots = new_slots;
    t->cap = new_cap;
    return 0;
}

/*
 * session_table_create
 *   - Làm tròn capacity lên lũy thừa của 2 (tối thiểu ví dụ 16).
 *   - calloc struct + calloc mảng slot (calloc -> mọi used = false).
 *   - Lỗi giữa chừng: free phần đã cấp, trả NULL.
 *   - Kiểm tra tràn: cap * sizeof(struct slot) có thể tràn size_t nếu cap
 *     khổng lồ; calloc(cap, size) tự kiểm tra giúp bạn, malloc(cap*size) thì
 *     không.
 */
struct session_table *session_table_create(size_t capacity)
{
    struct session_table *t;
    size_t cap = MIN_CAPACITY;

    while (cap < capacity)
    {
        if (cap > SIZE_MAX / 2u)
            return NULL;
        cap *= 2u;
    }

    t = calloc(1, sizeof *t);
    if (t == NULL)
        return NULL;
    t->slots = calloc(cap, sizeof *t->slots);   /* calloc tự kiểm tra tràn */
    if (t->slots == NULL)
    {
        free(t);
        return NULL;
    }
    t->cap = cap;
    return t;
}

/* session_table_destroy: NULL-safe; free mảng slot rồi free struct. */
void session_table_destroy(struct session_table *t)
{
    if (t == NULL)
        return;
    free(t->slots);
    free(t);
}

/*
 * session_table_upsert
 *   1. Nếu thêm một phần tử sẽ vượt load factor -> grow(). Lỗi -> NULL.
 *   2. slot = probe(...).
 *   3. slot đã used (cùng key) -> trả &slot->s.
 *   4. Chưa used: memset slot, used = true, s.key = *key, size++,
 *      trả &slot->s.
 */
struct session *session_table_upsert(struct session_table *t,
                                     const struct session_key *key)
{
    struct slot *slot = probe(t->slots, t->cap, key);

    if (slot->used)
        return &slot->s;

    /* Chỉ resize khi thật sự phải chèn mới, để lookup key đã có không làm
     * mất hiệu lực con trỏ phiên. */
    if ((t->size + 1u) * LOAD_DEN > t->cap * LOAD_NUM)
    {
        if (grow(t) != 0)
            return NULL;
        slot = probe(t->slots, t->cap, key);
    }

    memset(slot, 0, sizeof *slot);
    slot->used = true;
    slot->s.key = *key;
    t->size++;
    return &slot->s;
}

/* session_table_find: như upsert nhưng gặp slot trống thì trả NULL. */
struct session *session_table_find(const struct session_table *t,
                                   const struct session_key *key)
{
    struct slot *slot = probe(t->slots, t->cap, key);

    return slot->used ? &slot->s : NULL;
}

size_t session_table_size(const struct session_table *t)
{
    return t->size;
}

/* session_table_foreach: duyệt mảng slot, gọi fn(&slot->s, ctx) nếu used. */
void session_table_foreach(const struct session_table *t,
                           session_visit_fn fn, void *ctx)
{
    size_t i;

    for (i = 0; i < t->cap; i++)
    {
        if (t->slots[i].used)
            fn(&t->slots[i].s, ctx);
    }
}

/*
 * session_table_top_n
 *   Cách đơn giản: chép con trỏ mọi phiên vào mảng tạm, qsort giảm dần theo
 *   bytes, lấy n phần tử đầu. O(size log size).
 *   Cách tốt hơn (để nói khi phỏng vấn): min-heap kích thước n, O(size log n),
 *   không cần mảng tạm cỡ size.
 *
 *   Hàm so sánh cho qsort phải có chữ ký
 *     static int cmp_bytes_desc(const void *a, const void *b);
 *   và KHÔNG được viết `return (int)(y - x);` với uint64_t (tràn / sai dấu).
 *   Dùng: return (x < y) - (x > y);
 */
/* Giảm dần theo bytes; bằng nhau thì xếp theo key để thứ tự ổn định giữa
 * các lần chạy (tuần 3 cần so kết quả tuần tự với đa luồng). */
static int cmp_bytes_desc(const void *a, const void *b)
{
    const struct session *x = *(const struct session *const *)a;
    const struct session *y = *(const struct session *const *)b;

    if (x->bytes != y->bytes)
        return (x->bytes < y->bytes) - (x->bytes > y->bytes);
    if (x->key.teid != y->key.teid)
        return (x->key.teid > y->key.teid) - (x->key.teid < y->key.teid);
    return (x->key.endpoint_ip > y->key.endpoint_ip) -
           (x->key.endpoint_ip < y->key.endpoint_ip);
}

size_t session_table_top_n(const struct session_table *t,
                           const struct session **out, size_t n)
{
    const struct session **all;
    size_t i, k = 0;

    if (n == 0 || t->size == 0)
        return 0;
    all = malloc(t->size * sizeof *all);
    if (all == NULL)
        return 0;

    for (i = 0; i < t->cap; i++)
    {
        if (t->slots[i].used)
            all[k++] = &t->slots[i].s;
    }
    qsort(all, k, sizeof *all, cmp_bytes_desc);

    if (n > k)
        n = k;
    memcpy(out, all, n * sizeof *out);
    free(all);
    return n;
}
