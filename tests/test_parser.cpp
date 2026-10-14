// Test data-driven cho parser nhiều lớp (src/parser.c):
// Ethernet -> IPv4 -> UDP -> GTP-U -> inner IPv4 -> TCP/UDP.
//
// Ý tưởng: đọc từng gói trong <fixture>.pcap bằng pcap reader của bạn,
// đưa vào parser, rồi so kết quả với dòng tương ứng trong <fixture>.expected:
//   - verdict "ok"            -> parser thành công; teid/msg_type/qfi khớp
//   - verdict "ignored:<x>"   -> parser bỏ qua gói, lý do x
//   - verdict "err:<x>"       -> parser báo lỗi, lý do x
// Bạn cần một hàm đổi enum lý do của mình sang chuỗi (ví dụ
// parse_result_str()) để so với .expected. Hàm đó cũng dùng luôn cho output
// thống kê của chương trình.
#include <gtest/gtest.h>

#include "expected.hpp"

#include "pcap.h"
#include "parser.h"

using namespace gtpu_test;

namespace {

void check_fixture(const std::string &name) {
  auto expected = load_expected(name);
  ASSERT_FALSE(expected.empty());
  // TODO:
  //   mở data_path(name + ".pcap")
  //   for mỗi gói i:
  //     kết quả = parse(gói)
  //     SCOPED_TRACE(name + " #" + std::to_string(i) + ": " + expected[i].note);
  //     EXPECT_EQ(chuỗi_verdict(kết quả), expected[i].verdict);
  //     if (expected[i].teid)     EXPECT_EQ(teid, *expected[i].teid);
  //     if (expected[i].msg_type) EXPECT_EQ(msg_type, *expected[i].msg_type);
  //     if (expected[i].qfi)      EXPECT_EQ(qfi, *expected[i].qfi);
  //   EXPECT_EQ(số gói đã đọc, expected.size());
  GTEST_SKIP() << "TODO: chưa có parser";
}

}  // namespace

TEST(Parser, Basic) { check_fixture("gtpu_basic"); }
TEST(Parser, OptionalFields) { check_fixture("gtpu_optional_fields"); }
TEST(Parser, FiveGExtensions) { check_fixture("gtpu_5g_ext"); }
TEST(Parser, Signalling) { check_fixture("gtpu_signalling"); }
TEST(Parser, NonGtpuIsIgnored) { check_fixture("non_gtpu"); }
TEST(Parser, MalformedIsRejected) { check_fixture("malformed"); }

TEST(Parser, EveryTruncationOfValidPacketIsSafe) {
  // Lấy một gói hợp lệ (ví dụ gói 0 của gtpu_5g_ext.pcap), rồi gọi parser
  // với mọi độ dài 0..len-1. Không được đọc quá buffer (ASan sẽ bắt) và
  // không bao giờ được trả "ok" với gói bị cắt.
  // Mẹo: copy vào std::vector đúng kích thước để ASan phát hiện đọc tràn.
  GTEST_SKIP() << "TODO";
}
