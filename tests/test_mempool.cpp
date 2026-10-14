// Test cho memory pool (src/mempool.c) — phần tuần 3.
#include <gtest/gtest.h>

#include "mempool.h"

TEST(Mempool, AllocUntilExhausted) {
  // Pool N phần tử: cấp được đúng N lần, lần N+1 trả NULL.
  GTEST_SKIP() << "TODO";
}

TEST(Mempool, FreeThenReuse) {
  // Trả lại một buffer rồi cấp lại: phải dùng lại được.
  GTEST_SKIP() << "TODO";
}

TEST(Mempool, BuffersDoNotOverlapAndAreAligned) {
  // Mọi buffer cấp ra khác nhau, cách nhau >= kích thước phần tử, và căn lề
  // đúng (ví dụ alignof(max_align_t) hoặc 64 byte theo cache line).
  GTEST_SKIP() << "TODO";
}
