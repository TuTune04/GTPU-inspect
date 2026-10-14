// Unit test cho riêng lớp GTP-U (src/gtpu.c), làm việc trực tiếp trên
// buffer byte dựng tay, không qua pcap. Byte được viết theo đúng thứ tự
// trên dây (network byte order) để bạn đối chiếu với TS 29.281 mục 5.1.
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

// extern "C" {
// #include "gtpu.h"
// }

namespace {

// G-PDU tối thiểu: flags=0x30 (v1, PT=1), type=255, length=4, TEID=0x12345678,
// theo sau là 4 byte payload.
const std::vector<uint8_t> kMinimalGpdu = {
    0x30, 0xff, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78,
    0xde, 0xad, 0xbe, 0xef};

// E=1, next ext = 0x85, PDU Session Container UL, QFI=9.
const std::vector<uint8_t> kWithPduSession = {
    0x34, 0xff, 0x00, 0x08, 0x00, 0x00, 0x50, 0x01,  // header bắt buộc
    0x00, 0x00, 0x00, 0x85,                          // seq, N-PDU, next=0x85
    0x01, 0x10, 0x09, 0x00};                         // len=1, UL, QFI=9, next=0

}  // namespace

TEST(Gtpu, ParsesMinimalHeader) {
  // TEID == 0x12345678, msg_type == 255, payload offset == 8, payload len 4.
  (void)kMinimalGpdu;
  GTEST_SKIP() << "TODO";
}

TEST(Gtpu, ParsesPduSessionContainer) {
  // QFI == 9, PDU type == UL (1), payload offset == 16, payload len 0.
  (void)kWithPduSession;
  GTEST_SKIP() << "TODO";
}

TEST(Gtpu, LengthFieldIsNotTrusted) {
  // Sửa byte 2..3 của kMinimalGpdu thành 0xffff: phải báo len mismatch.
  GTEST_SKIP() << "TODO";
}

TEST(Gtpu, ExtensionLengthZeroIsRejected) {
  // Sửa byte 12 của kWithPduSession thành 0: phải báo lỗi, không lặp vô hạn.
  GTEST_SKIP() << "TODO";
}

TEST(Gtpu, UnknownExtensionIsSkipped) {
  // Extension type lạ (ví dụ 0x40 UDP Port) nhưng length hợp lệ: bỏ qua
  // đúng len*4 byte và đi tiếp. Đọc TS 29.281 mục 5.2.1 về hai bit cao của
  // type ("comprehension required") để quyết định khi nào phải báo lỗi.
  GTEST_SKIP() << "TODO";
}
