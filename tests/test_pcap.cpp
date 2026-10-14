// Test cho pcap reader (src/pcap.c).
//
// Cách bật: viết src/pcap.c, rồi thay GTEST_SKIP() bằng assertion thật.
// Các file .expected tương ứng cho biết kết quả đúng.
#include <gtest/gtest.h>

#include "expected.hpp"

#include "pcap.h"

using namespace gtpu_test;

TEST(Pcap, OpensValidLittleEndianFile) {
  // gtpu_basic.pcap: magic 0xa1b2c3d4, linktype 1, 8 gói.
  // Kiểm tra: mở được, đọc đúng 8 gói, gói đầu có caplen == origlen.
  GTEST_SKIP() << "TODO: chưa có pcap reader";
}

TEST(Pcap, HandlesBigEndianFile) {
  // pcap_big_endian.pcap: mọi trường header đều phải được swap byte.
  // Kết quả phải giống hệt khi đọc bản little-endian.
  GTEST_SKIP() << "TODO";
}

TEST(Pcap, HandlesNanosecondMagic) {
  // pcap_nanosec.pcap: magic 0xa1b23c4d, ts_frac là nano giây.
  GTEST_SKIP() << "TODO";
}

TEST(Pcap, EmptyFileHasNoPackets) {
  // pcap_empty.pcap: chỉ có global header; lần đọc đầu tiên trả "hết file",
  // không phải lỗi.
  GTEST_SKIP() << "TODO";
}

TEST(Pcap, RejectsBadFiles) {
  // Với mỗi file bad_pcap_*.pcap: reader phải trả đúng mã lỗi trong
  // .expected, đọc được đúng số gói trước khi dừng, và không crash/leak.
  //   bad_pcap_magic            -> bad_magic
  //   bad_pcap_short_header     -> truncated_global_header
  //   bad_pcap_linktype         -> unsupported_linktype
  //   bad_pcap_truncated_record -> truncated_record (sau 1 gói)
  //   bad_pcap_caplen_huge      -> caplen_too_large (sau 1 gói)
  // Câu hỏi để tự nghĩ: caplen > snaplen thì sao? caplen > 65535 thì sao?
  GTEST_SKIP() << "TODO";
}
