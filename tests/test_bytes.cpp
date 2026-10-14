// Test cho các hàm đọc byte trong include/bytes.h.
#include <gtest/gtest.h>

#include <cstdint>

#include "bytes.h"

namespace {
// Bốn byte đầu của một file pcap little-endian: magic 0xa1b2c3d4.
const uint8_t kMagicLe[4] = {0xd4, 0xc3, 0xb2, 0xa1};
}  // namespace

TEST(Bytes, LittleEndian32) {
  EXPECT_EQ(rd_le32(kMagicLe), 0xa1b2c3d4u);
}

TEST(Bytes, BigEndian32) {
  EXPECT_EQ(rd_be32(kMagicLe), 0xd4c3b2a1u);
}

TEST(Bytes, LittleEndian16) { EXPECT_EQ(rd_le16(kMagicLe), 0xc3d4u); }

TEST(Bytes, BigEndian16) { EXPECT_EQ(rd_be16(kMagicLe), 0xd4c3u); }

TEST(Bytes, HighBitBytesDoNotSignExtend) {
  const uint8_t b[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(rd_le32(b), 0xffffffffu);
  EXPECT_EQ(rd_be32(b), 0xffffffffu);
  EXPECT_EQ(rd_le16(b), 0xffffu);
  EXPECT_EQ(rd_be16(b), 0xffffu);
}

TEST(Bytes, UnalignedPointerIsSafe) {
  // TEID trong frame thật nằm ở offset lẻ; đọc từ địa chỉ không căn lề.
  const uint8_t buf[8] = {0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00};
  EXPECT_EQ(rd_be32(buf + 1), 0x12345678u);
  EXPECT_EQ(rd_le32(buf + 1), 0x78563412u);
}
