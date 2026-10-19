// Test cho bảng phiên (src/session_table.c): hash table open addressing,
// key = (TEID, IP tunnel endpoint).
#include <gtest/gtest.h>

#include <cstdint>

#include "session_table.h"

namespace {

constexpr uint32_t kUpf1 = 0xc0a81401;  // 192.168.20.1
constexpr uint32_t kUpf2 = 0xc0a82801;  // 192.168.40.1

session_key key(uint32_t teid, uint32_t ip) { return session_key{teid, ip}; }

// RAII để test nào fail giữa chừng cũng không rò bộ nhớ (LeakSanitizer).
struct Table {
  explicit Table(size_t cap) : t(session_table_create(cap)) {}
  ~Table() { session_table_destroy(t); }
  session_table *t;
};

}  // namespace

TEST(SessionTable, InsertThenLookup) {
  // Thêm vài key, tra lại được đúng bản ghi; key chưa thêm trả NULL.
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  EXPECT_EQ(session_table_size(tb.t), 0u);

  session_key a = key(0x1001, kUpf1), b = key(0x1002, kUpf1);
  session *sa = session_table_upsert(tb.t, &a);
  session *sb = session_table_upsert(tb.t, &b);
  ASSERT_NE(sa, nullptr);
  ASSERT_NE(sb, nullptr);
  EXPECT_NE(sa, sb);
  EXPECT_EQ(sa->packets, 0u);
  EXPECT_EQ(session_table_size(tb.t), 2u);

  EXPECT_EQ(session_table_find(tb.t, &a), sa);
  EXPECT_EQ(session_table_find(tb.t, &b), sb);
  EXPECT_EQ(session_table_upsert(tb.t, &a), sa);  // key có rồi: không tạo mới
  EXPECT_EQ(session_table_size(tb.t), 2u);

  session_key missing = key(0x9999, kUpf1);
  EXPECT_EQ(session_table_find(tb.t, &missing), nullptr);
  EXPECT_EQ(session_table_size(tb.t), 2u);  // find không được tạo phiên
}

TEST(SessionTable, SameTeidDifferentEndpointIsDifferentSession) {
  // TEID chỉ duy nhất trong phạm vi một endpoint: (0x1001, 192.168.20.1)
  // và (0x1001, 192.168.40.1) phải là hai phiên khác nhau.
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  session_key a = key(0x1001, kUpf1), b = key(0x1001, kUpf2);
  session *sa = session_table_upsert(tb.t, &a);
  session *sb = session_table_upsert(tb.t, &b);
  ASSERT_NE(sa, nullptr);
  ASSERT_NE(sb, nullptr);
  EXPECT_NE(sa, sb);
  EXPECT_EQ(session_table_size(tb.t), 2u);
  EXPECT_EQ(sa->key.endpoint_ip, kUpf1);
  EXPECT_EQ(sb->key.endpoint_ip, kUpf2);
}

TEST(SessionTable, CountersAccumulate) {
  // Cập nhật cùng một phiên 3 lần với 100/200/300 byte -> 3 gói, 600 byte.
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  session_key k = key(0x1001, kUpf1);
  for (uint64_t bytes : {100u, 200u, 300u}) {
    session *s = session_table_upsert(tb.t, &k);
    ASSERT_NE(s, nullptr);
    s->packets++;
    s->bytes += bytes;
  }
  session *s = session_table_find(tb.t, &k);
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(s->packets, 3u);
  EXPECT_EQ(s->bytes, 600u);
  EXPECT_EQ(session_table_size(tb.t), 1u);
}

TEST(SessionTable, HandlesCollisions) {
  // Hash là chi tiết bên trong nên không chọn được key trùng bucket; thay vào
  // đó nhét 11 key vào bảng 16 slot (chưa tới ngưỡng resize 0.7): chắc chắn
  // có va chạm và lookup vẫn phải đúng với từng key.
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  for (uint32_t i = 0; i < 11; i++) {
    session_key k = key(0x1000 + i, kUpf1);
    session *s = session_table_upsert(tb.t, &k);
    ASSERT_NE(s, nullptr);
    s->bytes = i + 1;
  }
  for (uint32_t i = 0; i < 11; i++) {
    session_key k = key(0x1000 + i, kUpf1);
    session *s = session_table_find(tb.t, &k);
    ASSERT_NE(s, nullptr) << "teid index " << i;
    EXPECT_EQ(s->key.teid, 0x1000 + i);
    EXPECT_EQ(s->bytes, i + 1);
  }
}

TEST(SessionTable, GrowsOrReportsFull) {
  // Thêm vượt load factor bạn chọn: hoặc resize đúng (mọi key vẫn tra được),
  // hoặc trả lỗi "đầy" rõ ràng. Không được lặp vô hạn khi bảng đầy.
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  const uint32_t n = 5000;
  for (uint32_t i = 0; i < n; i++) {
    session_key k = key(i, kUpf1 + (i & 3));
    session *s = session_table_upsert(tb.t, &k);
    ASSERT_NE(s, nullptr) << i;
    s->bytes = i;
  }
  EXPECT_EQ(session_table_size(tb.t), n);
  for (uint32_t i = 0; i < n; i++) {
    session_key k = key(i, kUpf1 + (i & 3));
    session *s = session_table_find(tb.t, &k);
    ASSERT_NE(s, nullptr) << i;
    EXPECT_EQ(s->bytes, i);  // dữ liệu còn nguyên sau mỗi lần resize
  }
}

TEST(SessionTable, ForeachVisitsEverySessionOnce) {
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  for (uint32_t i = 0; i < 40; i++) {
    session_key k = key(i, kUpf1);
    ASSERT_NE(session_table_upsert(tb.t, &k), nullptr);
  }
  size_t visited = 0;
  uint64_t teid_sum = 0;
  struct Acc { size_t *n; uint64_t *sum; } acc{&visited, &teid_sum};
  session_table_foreach(
      tb.t,
      [](const session *s, void *ctx) {
        auto *a = static_cast<Acc *>(ctx);
        ++*a->n;
        *a->sum += s->key.teid;
      },
      &acc);
  EXPECT_EQ(visited, 40u);
  EXPECT_EQ(teid_sum, 40u * 39u / 2u);
}

TEST(SessionTable, TopNByBytes) {
  // Với 10 phiên có số byte khác nhau, top 3 trả đúng thứ tự giảm dần.
  Table tb(16);
  ASSERT_NE(tb.t, nullptr);
  const uint64_t bytes[10] = {50, 900, 10, 400, 700, 20, 5, 300, 800, 100};
  for (uint32_t i = 0; i < 10; i++) {
    session_key k = key(0x2000 + i, kUpf1);
    session *s = session_table_upsert(tb.t, &k);
    ASSERT_NE(s, nullptr);
    s->bytes = bytes[i];
  }
  const session *top[3] = {};
  ASSERT_EQ(session_table_top_n(tb.t, top, 3), 3u);
  EXPECT_EQ(top[0]->bytes, 900u);
  EXPECT_EQ(top[1]->bytes, 800u);
  EXPECT_EQ(top[2]->bytes, 700u);

  // n lớn hơn số phiên: chỉ trả số phiên thực có.
  const session *all[20] = {};
  ASSERT_EQ(session_table_top_n(tb.t, all, 20), 10u);
  for (size_t i = 1; i < 10; i++) EXPECT_GE(all[i - 1]->bytes, all[i]->bytes);
  EXPECT_EQ(session_table_top_n(tb.t, all, 0), 0u);
}
