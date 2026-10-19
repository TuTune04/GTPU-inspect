// Test cho thống kê (src/stats.c): chạy pcap fixture qua parser + stats và
// kiểm tra tổng, đếm theo loại, phiên và QFI.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "expected.hpp"
#include "parser.h"
#include "pcap.h"
#include "session_table.h"
#include "stats.h"

using namespace gtpu_test;

namespace {

struct Replay {
  stats st;
  session_table *sessions = session_table_create(16);
  uint64_t wire_bytes = 0;

  explicit Replay(const std::string &name) {
    stats_init(&st);
    pcap_reader *r = nullptr;
    EXPECT_EQ(pcap_open(data_path(name + ".pcap").c_str(), &r), PCAP_OK);
    pcap_packet pkt;
    while (pcap_next(r, &pkt) == PCAP_OK) {
      pkt_info info;
      parse_result res = parse_packet(pkt.data, pkt.caplen, &info);
      EXPECT_EQ(stats_record(&st, sessions, res, &info, pkt.orig_len, pkt.ts_ns), 0);
      wire_bytes += pkt.orig_len;
    }
    pcap_close(r);
  }
  ~Replay() { session_table_destroy(sessions); }
};

}  // namespace

TEST(Stats, BasicTotalsAndSessions) {
  Replay run("gtpu_basic");
  EXPECT_EQ(run.st.packets, 8u);
  EXPECT_EQ(run.st.bytes, run.wire_bytes);
  EXPECT_EQ(run.st.by_result[PARSE_OK], 8u);
  EXPECT_EQ(run.st.by_msg_type[GTPU_MSG_GPDU], 8u);
  // UL 0x1001 (4 gói: 0,1,2,7), DL 0x2001, 0x1002, 0x1003, 0xffffffff.
  EXPECT_EQ(session_table_size(run.sessions), 5u);

  const session *top[1];
  ASSERT_EQ(session_table_top_n(run.sessions, top, 1), 1u);
  EXPECT_EQ(top[0]->key.teid, 0x1001u);
  EXPECT_EQ(top[0]->packets, 4u);
  EXPECT_EQ(top[0]->n_flows, 1u);
  EXPECT_LE(top[0]->first_ts_ns, top[0]->last_ts_ns);
}

TEST(Stats, QfiIsCounted) {
  Replay run("gtpu_5g_ext");
  EXPECT_EQ(run.st.by_qfi[9], 1u);
  EXPECT_EQ(run.st.by_qfi[5], 1u);
  EXPECT_EQ(run.st.by_qfi[1], 1u);
  EXPECT_EQ(run.st.by_qfi[63], 1u);
  session_key k{0x5001, 0xc0a82801};  // 192.168.40.1
  const session *s = session_table_find(run.sessions, &k);
  ASSERT_NE(s, nullptr);
  EXPECT_EQ(s->last_qfi, 9u);
}

TEST(Stats, SignallingDoesNotCreateSessions) {
  // Echo/Error Indication đếm theo message type; chỉ End Marker (TEID 0x2001)
  // gắn với một phiên.
  Replay run("gtpu_signalling");
  EXPECT_EQ(run.st.by_msg_type[GTPU_MSG_ECHO_REQ], 1u);
  EXPECT_EQ(run.st.by_msg_type[GTPU_MSG_ECHO_RESP], 1u);
  EXPECT_EQ(run.st.by_msg_type[GTPU_MSG_ERROR_IND], 1u);
  EXPECT_EQ(run.st.by_msg_type[GTPU_MSG_END_MARKER], 1u);
  EXPECT_EQ(session_table_size(run.sessions), 1u);
}

TEST(Stats, ErrorsAreCountedByReason) {
  Replay run("malformed");
  EXPECT_EQ(run.st.packets, 21u);
  EXPECT_EQ(run.st.by_result[PARSE_OK], 0u);
  EXPECT_EQ(run.st.by_result[PARSE_ERR_GTP_EXT_BAD_LEN], 1u);
  EXPECT_EQ(run.st.by_result[PARSE_ERR_GTP_EXT_TRUNCATED], 2u);
  EXPECT_EQ(run.st.by_result[PARSE_ERR_GTP_EXT_TOO_MANY], 1u);
  EXPECT_EQ(session_table_size(run.sessions), 0u);
}

TEST(Stats, FlowOverflowIsCountedNotDropped) {
  session s{};
  pkt_info info{};
  info.has_inner = true;
  for (uint32_t i = 0; i < SESSION_MAX_FLOWS + 2; i++) {
    info.inner_sport = static_cast<uint16_t>(1000 + i);
    session_account(&s, &info, 100, i);
  }
  EXPECT_EQ(s.packets, SESSION_MAX_FLOWS + 2u);
  EXPECT_EQ(s.n_flows, SESSION_MAX_FLOWS);
  EXPECT_EQ(s.flows_overflow, 2u);
}

TEST(Stats, MergeAddsEveryCounter) {
  stats a, b;
  stats_init(&a);
  stats_init(&b);
  a.packets = 3;  a.bytes = 30;  a.by_msg_type[255] = 3;  a.by_qfi[9] = 1;
  b.packets = 2;  b.bytes = 20;  b.by_msg_type[255] = 1;  b.by_result[PARSE_OK] = 2;
  stats_merge(&a, &b);
  EXPECT_EQ(a.packets, 5u);
  EXPECT_EQ(a.bytes, 50u);
  EXPECT_EQ(a.by_msg_type[255], 4u);
  EXPECT_EQ(a.by_qfi[9], 1u);
  EXPECT_EQ(a.by_result[PARSE_OK], 2u);
}

TEST(Stats, PrintMentionsTopSession) {
  Replay run("gtpu_basic");
  char *buf = nullptr;
  size_t n = 0;
  FILE *f = open_memstream(&buf, &n);
  ASSERT_NE(f, nullptr);
  stats_print(&run.st, run.sessions, 3, f);
  fclose(f);
  std::string out(buf, n);
  free(buf);
  EXPECT_NE(out.find("Packets: 8"), std::string::npos);
  EXPECT_NE(out.find("G-PDU (255)"), std::string::npos);
  EXPECT_NE(out.find("0x00001001"), std::string::npos);
}
