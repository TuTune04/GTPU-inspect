// Test cho ring buffer SPSC lock-free (src/ring.c) — phần tuần 3.
#include <gtest/gtest.h>

#include <cstdint>
#include <thread>

#include "ring.h"

namespace {

// Phần tử ring là void*; mã hóa số nguyên thành con trỏ để khỏi cấp phát.
void *as_item(std::uintptr_t v) { return reinterpret_cast<void *>(v); }
std::uintptr_t as_value(void *p) { return reinterpret_cast<std::uintptr_t>(p); }

}  // namespace

TEST(Ring, CreateRejectsBadCapacity) {
  EXPECT_EQ(ring_create(0), nullptr);
  EXPECT_EQ(ring_create(1), nullptr);
  EXPECT_EQ(ring_create(3), nullptr);
  EXPECT_EQ(ring_create(1000), nullptr);
  struct ring *r = ring_create(2);
  ASSERT_NE(r, nullptr);
  ring_destroy(r);
  ring_destroy(nullptr);
}

TEST(Ring, PushPopSingleThread) {
  struct ring *r = ring_create(8);
  ASSERT_NE(r, nullptr);
  void *item = nullptr;

  EXPECT_FALSE(ring_pop(r, &item));
  for (std::uintptr_t i = 1; i <= 3; i++)
    ASSERT_TRUE(ring_push(r, as_item(i)));
  EXPECT_EQ(ring_count(r), 3u);
  for (std::uintptr_t i = 1; i <= 3; i++) {
    ASSERT_TRUE(ring_pop(r, &item));
    EXPECT_EQ(as_value(item), i);
  }
  EXPECT_FALSE(ring_pop(r, &item));
  EXPECT_EQ(ring_count(r), 0u);
  ring_destroy(r);
}

TEST(Ring, FullAndWrapAround) {
  const std::uintptr_t cap = 4;
  struct ring *r = ring_create(cap);
  ASSERT_NE(r, nullptr);
  void *item = nullptr;
  std::uintptr_t next_push = 0, next_pop = 0;

  for (std::uintptr_t i = 0; i < cap; i++)
    ASSERT_TRUE(ring_push(r, as_item(next_push++)));
  EXPECT_FALSE(ring_push(r, as_item(999)));  // đầy: không ghi đè
  EXPECT_EQ(ring_count(r), cap);

  // Pop một nửa, push tiếp, lặp nhiều vòng: head/tail vượt capacity
  // hàng trăm lần mà thứ tự vẫn đúng.
  for (int round = 0; round < 500; round++) {
    for (std::uintptr_t i = 0; i < cap / 2; i++) {
      ASSERT_TRUE(ring_pop(r, &item));
      ASSERT_EQ(as_value(item), next_pop++);
    }
    for (std::uintptr_t i = 0; i < cap / 2; i++)
      ASSERT_TRUE(ring_push(r, as_item(next_push++)));
    ASSERT_FALSE(ring_push(r, as_item(999)));
  }
  while (ring_pop(r, &item))
    ASSERT_EQ(as_value(item), next_pop++);
  EXPECT_EQ(next_pop, next_push);
  ring_destroy(r);
}

TEST(Ring, ProducerConsumerThreads) {
  // Một std::thread producer đẩy 0..N-1, một thread consumer pop và kiểm tra
  // nhận đủ, đúng thứ tự. Chạy thêm với ThreadSanitizer:
  //   cmake -DCMAKE_C_FLAGS=-fsanitize=thread -DCMAKE_CXX_FLAGS=-fsanitize=thread
  const std::uintptr_t n = 1000000;
  struct ring *r = ring_create(1024);
  ASSERT_NE(r, nullptr);
  std::uintptr_t received = 0;
  bool in_order = true;

  // Bắt đầu từ 1: không đẩy con trỏ NULL để tránh nhầm với "chưa ghi".
  std::thread producer([&] {
    for (std::uintptr_t i = 1; i <= n; i++)
      while (!ring_push(r, as_item(i)))
        std::this_thread::yield();
  });
  std::thread consumer([&] {
    void *item = nullptr;
    while (received < n) {
      if (!ring_pop(r, &item)) {
        std::this_thread::yield();
        continue;
      }
      if (as_value(item) != received + 1)
        in_order = false;
      received++;
    }
  });
  producer.join();
  consumer.join();

  EXPECT_EQ(received, n);
  EXPECT_TRUE(in_order);
  EXPECT_EQ(ring_count(r), 0u);
  ring_destroy(r);
}
