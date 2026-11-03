// Test cho pipeline đa luồng (src/pipeline.c) — phần tuần 3: kết quả phải
// giống hệt chạy tuần tự parser + stats trên cùng file.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "expected.hpp"
#include "parser.h"
#include "pcap.h"
#include "pipeline.h"
#include "session_table.h"
#include "stats.h"

using namespace gtpu_test;

namespace {

struct Sequential {
  stats st;
  session_table *sessions = session_table_create(16);

  explicit Sequential(const std::string &path) {
    stats_init(&st);
    pcap_reader *r = nullptr;
    EXPECT_EQ(pcap_open(path.c_str(), &r), PCAP_OK);
    pcap_packet pkt;
    while (pcap_next(r, &pkt) == PCAP_OK) {
      pkt_info info;
      parse_result res = parse_packet(pkt.data, pkt.caplen, &info);
      stats_record(&st, sessions, res, &info, pkt.orig_len, pkt.ts_ns);
    }
    pcap_close(r);
  }
  ~Sequential() { session_table_destroy(sessions); }
};

struct Lookup {
  const session_table *seq;
  int mismatches = 0;
};

// Mỗi phiên của worker phải có ở bản tuần tự với cùng counter.
void check_session(const session *s, void *arg) {
  Lookup *l = static_cast<Lookup *>(arg);
  const session *e = session_table_find(l->seq, &s->key);
  if (e == nullptr || e->packets != s->packets || e->bytes != s->bytes ||
      e->n_flows != s->n_flows)
    l->mismatches++;
}

void expect_same_as_sequential(const std::string &name, unsigned workers,
                               size_t ring_capacity) {
  SCOPED_TRACE(name + " workers=" + std::to_string(workers) +
               " ring=" + std::to_string(ring_capacity));
  const std::string path = data_path(name + ".pcap");
  Sequential seq(path);
  pipeline_config cfg = {path.c_str(), workers, ring_capacity};
  pipeline_result res;

  ASSERT_EQ(pipeline_run(&cfg, &res), 0);
  EXPECT_EQ(res.read_status, PCAP_EOF);
  ASSERT_EQ(res.n_workers, workers);
  EXPECT_EQ(std::memcmp(&res.total, &seq.st, sizeof seq.st), 0);

  uint64_t dispatched = 0;
  size_t sessions = 0;
  Lookup lookup{seq.sessions};
  for (unsigned i = 0; i < workers; i++) {
    dispatched += res.per_worker_packets[i];
    sessions += session_table_size(res.tables[i]);
    session_table_foreach(res.tables[i], check_session, &lookup);
  }
  EXPECT_EQ(dispatched, seq.st.packets);
  // Bằng nhau về số lượng + mọi phiên đều khớp => không phiên nào bị chia
  // sang hai worker.
  EXPECT_EQ(sessions, session_table_size(seq.sessions));
  EXPECT_EQ(lookup.mismatches, 0);
  pipeline_result_free(&res);
}

}  // namespace

TEST(Pipeline, MatchesSequentialOnFixtures) {
  for (const char *name : {"gtpu_basic", "gtpu_optional_fields", "gtpu_5g_ext",
                           "gtpu_signalling", "malformed", "non_gtpu"})
    for (unsigned workers : {1u, 2u, 4u})
      expect_same_as_sequential(name, workers, 1024);
}

TEST(Pipeline, TinyRingsApplyBackpressure) {
  // Ring 2 slot: reader liên tục phải chờ worker, nhưng không được mất hay
  // lặp gói nào.
  for (unsigned workers : {1u, 3u})
    expect_same_as_sequential("gtpu_basic", workers, 2);
}

TEST(Pipeline, RejectsBadConfig) {
  const std::string path = data_path("gtpu_basic.pcap");
  pipeline_result res;
  pipeline_config cfg = {path.c_str(), 0, 1024};
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  cfg.n_workers = PIPELINE_MAX_WORKERS + 1;
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  cfg.n_workers = 2;
  cfg.ring_capacity = 1000;  // không phải lũy thừa 2
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
}

TEST(Pipeline, ReportsOpenError) {
  const std::string path = data_path("does_not_exist.pcap");
  pipeline_config cfg = {path.c_str(), 2, 1024};
  pipeline_result res;
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  EXPECT_EQ(res.read_status, PCAP_ERR_IO);
}
