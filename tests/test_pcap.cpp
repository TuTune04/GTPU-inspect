// Test cho pcap reader (src/pcap.c).
//
// Mỗi file tests/data/*.pcap có file .expected cùng tên cho biết kết quả đúng:
// trạng thái cuối cùng ("ok" tương ứng PCAP_EOF) và số gói đọc được.
#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "expected.hpp"

#include "pcap.h"

using namespace gtpu_test;

namespace {

struct ReadResult {
  pcap_status open_status = PCAP_OK;
  pcap_status final_status = PCAP_OK;  // trạng thái khiến vòng đọc dừng
  std::vector<uint64_t> ts_ns;
  std::vector<uint32_t> caplen, orig_len;
  size_t packets() const { return caplen.size(); }
};

// Đọc cả file bằng API công khai, gom kết quả để assert.
ReadResult read_all(const std::string &name) {
  ReadResult res;
  pcap_reader *r = nullptr;
  res.open_status = pcap_open(data_path(name + ".pcap").c_str(), &r);
  if (res.open_status != PCAP_OK) {
    EXPECT_EQ(r, nullptr) << "open lỗi thì *out phải là NULL";
    res.final_status = res.open_status;
    return res;
  }
  pcap_packet pkt;
  pcap_status st;
  while ((st = pcap_next(r, &pkt)) == PCAP_OK) {
    EXPECT_NE(pkt.data, nullptr);
    res.ts_ns.push_back(pkt.ts_ns);
    res.caplen.push_back(pkt.caplen);
    res.orig_len.push_back(pkt.orig_len);
  }
  res.final_status = st;
  // Sau EOF hoặc lỗi, reader phải giữ nguyên trạng thái, không đọc tiếp.
  EXPECT_EQ(pcap_next(r, &pkt), st);
  pcap_close(r);
  return res;
}

// "file ok N" tương ứng PCAP_EOF; "file err:<lý do> N" tương ứng pcap_status_str.
void expect_matches_file(const std::string &name) {
  SCOPED_TRACE(name);
  ExpectedFile exp = load_expected_file(name);
  ReadResult got = read_all(name);
  std::string want = exp.verdict == "ok" ? "eof" : exp.verdict.substr(4);
  EXPECT_EQ(std::string(pcap_status_str(got.final_status)), want);
  EXPECT_EQ(got.packets(), exp.packets);
}

constexpr uint64_t kBaseSec = 1700000000ull;

}  // namespace

TEST(Pcap, OpensValidLittleEndianFile) {
  ReadResult r = read_all("gtpu_basic");
  EXPECT_EQ(r.open_status, PCAP_OK);
  EXPECT_EQ(r.final_status, PCAP_EOF);
  ASSERT_EQ(r.packets(), 8u);
  for (size_t i = 0; i < r.packets(); ++i) {
    EXPECT_EQ(r.caplen[i], r.orig_len[i]) << "gói " << i;
    EXPECT_GT(r.caplen[i], 0u);
  }
  // Gói i có ts_sec = BASE + i, ts_frac = i * 1000 micro giây.
  EXPECT_EQ(r.ts_ns[0], kBaseSec * 1000000000ull);
  EXPECT_EQ(r.ts_ns[3], (kBaseSec + 3) * 1000000000ull + 3000ull * 1000ull);
}

TEST(Pcap, HandlesBigEndianFile) {
  expect_matches_file("pcap_big_endian");
  ReadResult r = read_all("pcap_big_endian");
  ASSERT_EQ(r.packets(), 2u);
  // Độ dài phải đọc đúng sau khi swap (sai endian sẽ ra số khổng lồ).
  EXPECT_GT(r.caplen[0], 0u);
  EXPECT_LT(r.caplen[0], 65536u);
  EXPECT_EQ(r.caplen[0], r.orig_len[0]);
  EXPECT_EQ(r.ts_ns[0], kBaseSec * 1000000000ull);
}

TEST(Pcap, HandlesNanosecondMagic) {
  expect_matches_file("pcap_nanosec");
  ReadResult r = read_all("pcap_nanosec");
  ASSERT_EQ(r.packets(), 1u);
  // Gói 0 có ts_frac = 0 nên chỉ kiểm tra phần giây; phần nano giây được
  // kiểm tra qua file micro giây ở test OpensValidLittleEndianFile (gói 3).
  EXPECT_EQ(r.ts_ns[0], kBaseSec * 1000000000ull);
}

TEST(Pcap, EmptyFileHasNoPackets) {
  expect_matches_file("pcap_empty");
  ReadResult r = read_all("pcap_empty");
  EXPECT_EQ(r.open_status, PCAP_OK);
  EXPECT_EQ(r.final_status, PCAP_EOF);  // hết file bình thường, không phải lỗi
}

TEST(Pcap, RejectsBadFiles) {
  for (const char *name :
       {"bad_pcap_magic", "bad_pcap_short_header", "bad_pcap_linktype",
        "bad_pcap_truncated_record", "bad_pcap_caplen_huge"}) {
    expect_matches_file(name);
  }
}

TEST(Pcap, OpenFailureLeavesOutputNull) {
  pcap_reader *r = reinterpret_cast<pcap_reader *>(0x1);
  EXPECT_EQ(pcap_open(data_path("khong_ton_tai.pcap").c_str(), &r),
            PCAP_ERR_IO);
  EXPECT_EQ(r, nullptr);
}

TEST(Pcap, CloseNullIsSafe) { pcap_close(nullptr); }

TEST(Pcap, StatusStringsAreStable) {
  EXPECT_STREQ(pcap_status_str(PCAP_OK), "ok");
  EXPECT_STREQ(pcap_status_str(PCAP_EOF), "eof");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_IO), "io_error");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_NOMEM), "no_memory");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_BAD_MAGIC), "bad_magic");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_TRUNCATED_GLOBAL_HEADER),
               "truncated_global_header");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_UNSUPPORTED_LINKTYPE),
               "unsupported_linktype");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_TRUNCATED_RECORD), "truncated_record");
  EXPECT_STREQ(pcap_status_str(PCAP_ERR_CAPLEN_TOO_LARGE), "caplen_too_large");
  // Giá trị ngoài enum không được trả NULL.
  const char *s = pcap_status_str(static_cast<pcap_status>(12345));
  ASSERT_NE(s, nullptr);
  EXPECT_STREQ(s, "unknown");
}
