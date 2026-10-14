// Kiểm tra bản thân bộ dữ liệu test (không đụng tới code core).
// Nếu các test này fail thì lỗi nằm ở tools/gen_pcaps.py hoặc tests/data/,
// không phải ở parser của bạn.
#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <set>

#include "expected.hpp"

using namespace gtpu_test;

namespace {

const char *kPacketFixtures[] = {
    "gtpu_basic", "gtpu_optional_fields", "gtpu_5g_ext",
    "gtpu_signalling", "non_gtpu", "malformed",
};

// Đếm số record trong pcap little-endian hợp lệ, chỉ để đối chiếu fixture.
unsigned count_records(const std::string &path) {
  std::ifstream in(path, std::ios::binary);
  in.seekg(24);
  unsigned n = 0;
  unsigned char rec[16];
  while (in.read(reinterpret_cast<char *>(rec), sizeof rec)) {
    uint32_t caplen = static_cast<uint32_t>(rec[8]) |
                      static_cast<uint32_t>(rec[9]) << 8 |
                      static_cast<uint32_t>(rec[10]) << 16 |
                      static_cast<uint32_t>(rec[11]) << 24;
    in.seekg(caplen, std::ios::cur);
    if (!in) break;
    ++n;
  }
  return n;
}

}  // namespace

class PacketFixture : public ::testing::TestWithParam<const char *> {};

TEST_P(PacketFixture, ExpectedMatchesPcap) {
  const std::string name = GetParam();
  auto rows = load_expected(name);
  ASSERT_FALSE(rows.empty());
  EXPECT_EQ(rows.size(), count_records(data_path(name + ".pcap")));
  for (size_t i = 0; i < rows.size(); ++i) {
    EXPECT_EQ(rows[i].idx, i);
    EXPECT_TRUE(rows[i].is_ok() || rows[i].is_error() || rows[i].is_ignored())
        << "verdict lạ: " << rows[i].verdict;
  }
}

INSTANTIATE_TEST_SUITE_P(All, PacketFixture, ::testing::ValuesIn(kPacketFixtures));

TEST(Fixtures, MalformedHasDistinctReasons) {
  std::set<std::string> reasons;
  for (const auto &r : load_expected("malformed")) {
    EXPECT_TRUE(r.is_error()) << r.idx;
    reasons.insert(r.reason());
  }
  EXPECT_GE(reasons.size(), 15u);
}

TEST(Fixtures, PcapReaderCasesLoad) {
  for (const char *name :
       {"pcap_big_endian", "pcap_nanosec", "pcap_empty", "bad_pcap_magic",
        "bad_pcap_short_header", "bad_pcap_linktype",
        "bad_pcap_truncated_record", "bad_pcap_caplen_huge"}) {
    auto f = load_expected_file(name);
    EXPECT_FALSE(f.verdict.empty()) << name;
  }
}
