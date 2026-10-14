// Unit test cho riêng lớp GTP-U (src/gtpu.c), làm việc trực tiếp trên
// buffer byte dựng tay, không qua pcap. Byte được viết theo đúng thứ tự
// trên dây (network byte order) để bạn đối chiếu với TS 29.281 mục 5.1.
#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "gtpu.h"

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
  gtpu_hdr h;
  size_t off = 0;
  ASSERT_EQ(gtpu_parse(kMinimalGpdu.data(), kMinimalGpdu.size(), &h, &off),
            PARSE_OK);
  EXPECT_EQ(h.teid, 0x12345678u);
  EXPECT_EQ(h.msg_type, GTPU_MSG_GPDU);
  EXPECT_EQ(h.length, 4u);
  EXPECT_FALSE(h.has_opt);
  EXPECT_EQ(off, 8u);
  EXPECT_EQ(kMinimalGpdu.size() - off, 4u);  // payload 4 byte
}

TEST(Gtpu, ParsesOptionalFields) {
  // S=1: có 4 byte tùy chọn, seq = 0x0102.
  const std::vector<uint8_t> b = {0x32, 0xff, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
                                  0x01, 0x02, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef};
  gtpu_hdr h;
  size_t off = 0;
  ASSERT_EQ(gtpu_parse(b.data(), b.size(), &h, &off), PARSE_OK);
  EXPECT_TRUE(h.has_opt);
  EXPECT_EQ(h.seq, 0x0102u);
  EXPECT_EQ(off, 12u);
}

TEST(Gtpu, RejectsBadVersionAndPt) {
  gtpu_hdr h;
  size_t off = 0;
  std::vector<uint8_t> b = kMinimalGpdu;
  b[0] = 0x50;  // version 2
  EXPECT_EQ(gtpu_parse(b.data(), b.size(), &h, &off), PARSE_ERR_GTP_BAD_VERSION);
  b[0] = 0x20;  // version 1, PT=0
  EXPECT_EQ(gtpu_parse(b.data(), b.size(), &h, &off), PARSE_ERR_GTP_BAD_PT);
}

TEST(Gtpu, RejectsTruncatedHeaders) {
  gtpu_hdr h;
  size_t off = 0;
  EXPECT_EQ(gtpu_parse(kMinimalGpdu.data(), 7, &h, &off),
            PARSE_ERR_GTP_TRUNCATED);
  // Cờ S bật nhưng chỉ có 10 byte (thiếu 2 byte tùy chọn).
  std::vector<uint8_t> b = {0x32, 0xff, 0x00, 0x04, 0, 0, 0, 1, 0, 1};
  EXPECT_EQ(gtpu_parse(b.data(), b.size(), &h, &off),
            PARSE_ERR_GTP_OPT_TRUNCATED);
}

TEST(Gtpu, MessageTypeNames) {
  EXPECT_STREQ(gtpu_msg_type_str(GTPU_MSG_GPDU), "G-PDU");
  EXPECT_STREQ(gtpu_msg_type_str(GTPU_MSG_ECHO_REQ), "Echo Request");
  EXPECT_STREQ(gtpu_msg_type_str(GTPU_MSG_ECHO_RESP), "Echo Response");
  EXPECT_STREQ(gtpu_msg_type_str(GTPU_MSG_ERROR_IND), "Error Indication");
  EXPECT_STREQ(gtpu_msg_type_str(GTPU_MSG_END_MARKER), "End Marker");
  EXPECT_STREQ(gtpu_msg_type_str(0), "Unknown");
}

TEST(Gtpu, ParsesPduSessionContainer) {
  // QFI == 9, PDU type == UL (1), payload offset == 16, payload len 0.
  (void)kWithPduSession;
  GTEST_SKIP() << "TODO tuần 2";
}

TEST(Gtpu, LengthFieldIsNotTrusted) {
  // Sửa byte 2..3 của kMinimalGpdu thành 0xffff: phải báo len mismatch.
  std::vector<uint8_t> b = kMinimalGpdu;
  b[2] = 0xff;
  b[3] = 0xff;
  gtpu_hdr h;
  size_t off = 0;
  EXPECT_EQ(gtpu_parse(b.data(), b.size(), &h, &off), PARSE_ERR_GTP_LEN_MISMATCH);
  b[2] = 0x00;
  b[3] = 0x01;  // nhỏ hơn thực tế
  EXPECT_EQ(gtpu_parse(b.data(), b.size(), &h, &off), PARSE_ERR_GTP_LEN_MISMATCH);
}

TEST(Gtpu, ExtensionLengthZeroIsRejected) {
  // Sửa byte 12 của kWithPduSession thành 0: phải báo lỗi, không lặp vô hạn.
  GTEST_SKIP() << "TODO tuần 2";
}

TEST(Gtpu, UnknownExtensionIsSkipped) {
  // Extension type lạ (ví dụ 0x40 UDP Port) nhưng length hợp lệ: bỏ qua
  // đúng len*4 byte và đi tiếp. Đọc TS 29.281 mục 5.2.1 về hai bit cao của
  // type ("comprehension required") để quyết định khi nào phải báo lỗi.
  GTEST_SKIP() << "TODO tuần 2";
}
