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

#include <cstdint>
#include <string>
#include <vector>

#include "expected.hpp"

#include "pcap.h"
#include "parser.h"

using namespace gtpu_test;

namespace {

// Đọc từng gói trong <name>.pcap, parse, rồi so với dòng tương ứng trong
// <name>.expected. Các gói thuộc tuần 2 (lý do lỗi bắt đầu bằng "gtp_ext")
// chưa kiểm tra vì parser chưa duyệt chuỗi extension header.
void check_fixture(const std::string &name) {
  auto expected = load_expected(name);
  ASSERT_FALSE(expected.empty());

  pcap_reader *r = nullptr;
  ASSERT_EQ(pcap_open(data_path(name + ".pcap").c_str(), &r), PCAP_OK);

  pcap_packet pkt;
  size_t i = 0;
  while (pcap_next(r, &pkt) == PCAP_OK) {
    ASSERT_LT(i, expected.size());
    const ExpectedPacket &e = expected[i];
    SCOPED_TRACE(name + " #" + std::to_string(i) + ": " + e.note);
    ++i;
    if (e.reason().rfind("gtp_ext", 0) == 0) continue;

    pkt_info info;
    parse_result res = parse_packet(pkt.data, pkt.caplen, &info);
    EXPECT_EQ(std::string(parse_result_str(res)), e.verdict);
    if (res != PARSE_OK) continue;
    if (e.teid) {
      EXPECT_EQ(info.gtp.teid, *e.teid);
    }
    if (e.msg_type) {
      EXPECT_EQ(info.gtp.msg_type, *e.msg_type);
    }
    if (e.qfi) {
      EXPECT_TRUE(info.gtp.has_qfi);
      EXPECT_EQ(info.gtp.qfi, *e.qfi);
    }
  }
  EXPECT_EQ(i, expected.size());
  pcap_close(r);
}

}  // namespace

TEST(Parser, Basic) { check_fixture("gtpu_basic"); }
TEST(Parser, OptionalFields) { check_fixture("gtpu_optional_fields"); }
TEST(Parser, FiveGExtensions) {
  GTEST_SKIP() << "TODO tuần 2: duyệt chuỗi extension header, lấy QFI";
  check_fixture("gtpu_5g_ext");
}
TEST(Parser, Signalling) { check_fixture("gtpu_signalling"); }
TEST(Parser, NonGtpuIsIgnored) { check_fixture("non_gtpu"); }
TEST(Parser, MalformedIsRejected) { check_fixture("malformed"); }

TEST(Parser, EveryTruncationOfValidPacketIsSafe) {
  // Gói 0 của gtpu_basic.pcap: parse với mọi độ dài 0..len-1. Không được đọc
  // quá buffer (ASan bắt) và không bao giờ được trả "ok" với gói bị cắt.
  pcap_reader *r = nullptr;
  ASSERT_EQ(pcap_open(data_path("gtpu_basic.pcap").c_str(), &r), PCAP_OK);
  pcap_packet pkt;
  ASSERT_EQ(pcap_next(r, &pkt), PCAP_OK);
  const std::vector<uint8_t> full(pkt.data, pkt.data + pkt.caplen);
  pcap_close(r);

  pkt_info info;
  ASSERT_EQ(parse_packet(full.data(), full.size(), &info), PARSE_OK);
  for (size_t n = 0; n < full.size(); ++n) {
    // Copy vào vector đúng kích thước n để ASan phát hiện đọc tràn.
    const std::vector<uint8_t> cut(full.begin(), full.begin() + n);
    EXPECT_NE(parse_packet(cut.data(), cut.size(), &info), PARSE_OK)
        << "len=" << n;
  }
}
