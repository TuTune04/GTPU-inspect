// Test cho ring buffer SPSC lock-free (src/ring.c) — phần tuần 3.
#include <gtest/gtest.h>

#include "ring.h"

TEST(Ring, PushPopSingleThread) {
  // push 1, 2, 3 rồi pop ra đúng 1, 2, 3; pop khi rỗng trả thất bại.
  GTEST_SKIP() << "TODO";
}

TEST(Ring, FullAndWrapAround) {
  // Đẩy tới khi đầy (push thất bại), pop một nửa, đẩy tiếp: chỉ số quay vòng
  // đúng. Nếu capacity là lũy thừa của 2, kiểm tra cả trường hợp chỉ số
  // head/tail vượt quá capacity nhiều lần.
  GTEST_SKIP() << "TODO";
}

TEST(Ring, ProducerConsumerThreads) {
  // Một std::thread producer đẩy 0..N-1 (N ~ 1e6), một thread consumer pop
  // và kiểm tra nhận đủ, đúng thứ tự. Chạy thêm với ThreadSanitizer:
  //   cmake -DCMAKE_C_FLAGS=-fsanitize=thread -DCMAKE_CXX_FLAGS=-fsanitize=thread
  GTEST_SKIP() << "TODO";
}
