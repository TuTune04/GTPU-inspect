// Test cho bảng phiên (src/session_table.c): hash table open addressing,
// key = (TEID, IP tunnel endpoint).
#include <gtest/gtest.h>

#include "session_table.h"

TEST(SessionTable, InsertThenLookup) {
  // Thêm vài key, tra lại được đúng bản ghi; key chưa thêm trả NULL.
  GTEST_SKIP() << "TODO";
}

TEST(SessionTable, SameTeidDifferentEndpointIsDifferentSession) {
  // TEID chỉ duy nhất trong phạm vi một endpoint: (0x1001, 192.168.20.1)
  // và (0x1001, 192.168.40.1) phải là hai phiên khác nhau.
  GTEST_SKIP() << "TODO";
}

TEST(SessionTable, CountersAccumulate) {
  // Cập nhật cùng một phiên 3 lần với 100/200/300 byte -> 3 gói, 600 byte.
  GTEST_SKIP() << "TODO";
}

TEST(SessionTable, HandlesCollisions) {
  // Tạo nhiều key cùng rơi vào một bucket (ví dụ chọn TEID sao cho
  // hash % capacity trùng nhau) và kiểm tra lookup vẫn đúng.
  GTEST_SKIP() << "TODO";
}

TEST(SessionTable, GrowsOrReportsFull) {
  // Thêm vượt load factor bạn chọn: hoặc resize đúng (mọi key vẫn tra được),
  // hoặc trả lỗi "đầy" rõ ràng. Không được lặp vô hạn khi bảng đầy.
  GTEST_SKIP() << "TODO";
}

TEST(SessionTable, TopNByBytes) {
  // Với 10 phiên có số byte khác nhau, top 3 trả đúng thứ tự giảm dần.
  GTEST_SKIP() << "TODO";
}
