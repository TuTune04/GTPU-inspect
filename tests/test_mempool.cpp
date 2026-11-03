// Test cho memory pool (src/mempool.c) — phần tuần 3.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "mempool.h"

TEST(Mempool, CreateRejectsBadSizes) {
  EXPECT_EQ(mempool_create(64, 0), nullptr);
  EXPECT_EQ(mempool_create(SIZE_MAX, 1), nullptr);      // làm tròn tràn số
  EXPECT_EQ(mempool_create(1024, SIZE_MAX / 2), nullptr);  // nhân tràn số
  mempool_destroy(nullptr);
}

TEST(Mempool, AllocUntilExhausted) {
  const std::size_t n = 16;
  struct mempool *p = mempool_create(100, n);
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(mempool_available(p), n);

  for (std::size_t i = 0; i < n; i++)
    ASSERT_NE(mempool_alloc(p), nullptr) << "lần " << i;
  EXPECT_EQ(mempool_available(p), 0u);
  EXPECT_EQ(mempool_alloc(p), nullptr);
  mempool_destroy(p);
}

TEST(Mempool, FreeThenReuse) {
  struct mempool *p = mempool_create(32, 2);
  ASSERT_NE(p, nullptr);
  void *a = mempool_alloc(p);
  void *b = mempool_alloc(p);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  EXPECT_EQ(mempool_alloc(p), nullptr);

  mempool_free(p, a);
  EXPECT_EQ(mempool_available(p), 1u);
  EXPECT_EQ(mempool_alloc(p), a);  // LIFO: ô vừa trả được dùng lại ngay
  mempool_free(p, nullptr);        // không làm gì
  EXPECT_EQ(mempool_available(p), 0u);

  mempool_free(p, b);
  mempool_free(p, a);
  EXPECT_EQ(mempool_available(p), 2u);
  mempool_destroy(p);
}

TEST(Mempool, BuffersDoNotOverlapAndAreAligned) {
  // Mọi buffer cấp ra khác nhau, cách nhau >= kích thước phần tử, và căn lề
  // 64 byte theo cache line. Ghi kín từng buffer để ASan bắt chồng lấn.
  const std::size_t n = 64, obj = 100;
  struct mempool *p = mempool_create(obj, n);
  ASSERT_NE(p, nullptr);
  std::vector<std::uintptr_t> addrs;

  for (std::size_t i = 0; i < n; i++) {
    void *b = mempool_alloc(p);
    ASSERT_NE(b, nullptr);
    std::memset(b, static_cast<int>(i), obj);
    addrs.push_back(reinterpret_cast<std::uintptr_t>(b));
    EXPECT_EQ(addrs.back() % 64, 0u);
    EXPECT_EQ(addrs.back() % alignof(std::max_align_t), 0u);
  }
  std::sort(addrs.begin(), addrs.end());
  for (std::size_t i = 1; i < n; i++)
    EXPECT_GE(addrs[i] - addrs[i - 1], obj);
  mempool_destroy(p);
}
