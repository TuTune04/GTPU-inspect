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
  pcap_status final_status = PCAP_OK;

  explicit Sequential(const std::string &path) {
    stats_init(&st);
    pcap_reader *r = nullptr;
    EXPECT_EQ(pcap_open(path.c_str(), &r), PCAP_OK);
    pcap_packet pkt;
    while ((final_status = pcap_next(r, &pkt)) == PCAP_OK) {
      pkt_info info;
      parse_result res = parse_packet(pkt.data, pkt.caplen, &info);
      stats_record(&st, sessions, res, &info, pkt.orig_len, pkt.ts_ns);
    }
    pcap_close(r);
  }
  ~Sequential() { session_table_destroy(sessions); }
};

struct Merge {
  session_table *dst;
  int inexact = 0;
};

// Gộp như main: phiên mới thì chép, đã có thì session_merge (theo thứ tự
// bảng = thứ tự đoạn file ở chế độ shared-nothing).
void merge_into(const session *s, void *arg) {
  Merge *m = static_cast<Merge *>(arg);
  session *d = session_table_upsert(m->dst, &s->key);
  ASSERT_NE(d, nullptr);
  if (!session_merge(d, s)) m->inexact++;
}

struct Lookup {
  const session_table *seq;
  int mismatches = 0;
};

// Mỗi phiên đã gộp phải có ở bản tuần tự với cùng mọi counter.
void check_session(const session *s, void *arg) {
  Lookup *l = static_cast<Lookup *>(arg);
  const session *e = session_table_find(l->seq, &s->key);
  if (e == nullptr || e->packets != s->packets || e->bytes != s->bytes ||
      e->first_ts_ns != s->first_ts_ns || e->last_ts_ns != s->last_ts_ns ||
      e->last_qfi != s->last_qfi || e->n_flows != s->n_flows ||
      e->flows_overflow != s->flows_overflow)
    l->mismatches++;
}

void expect_same_as_sequential(const std::string &name, unsigned workers,
                               size_t ring_capacity, size_t batch = 1,
                               bool shared_nothing = false) {
  SCOPED_TRACE(name + " workers=" + std::to_string(workers) +
               " ring=" + std::to_string(ring_capacity) +
               " batch=" + std::to_string(batch) +
               " shared_nothing=" + std::to_string(shared_nothing));
  const std::string path = data_path(name + ".pcap");
  Sequential seq(path);
  pipeline_config cfg = {path.c_str(), workers, ring_capacity, batch,
                         shared_nothing};
  pipeline_result res;

  ASSERT_EQ(pipeline_run(&cfg, &res), 0);
  EXPECT_EQ(res.read_status, seq.final_status);
  ASSERT_EQ(res.n_workers, workers);
  EXPECT_EQ(std::memcmp(&res.total, &seq.st, sizeof seq.st), 0);

  uint64_t dispatched = 0;
  size_t sessions = 0;
  Merge merge{session_table_create(16)};
  for (unsigned i = 0; i < workers; i++) {
    dispatched += res.per_worker_packets[i];
    sessions += session_table_size(res.tables[i]);
    session_table_foreach(res.tables[i], merge_into, &merge);
  }
  EXPECT_EQ(dispatched, seq.st.packets);
  // Dispatch theo TEID: không phiên nào bị chia sang hai worker.
  if (!shared_nothing) {
    EXPECT_EQ(sessions, session_table_size(seq.sessions));
  }
  EXPECT_EQ(merge.inexact, 0);  // fixture không có phiên nào > 8 luồng
  Lookup lookup{seq.sessions};
  EXPECT_EQ(session_table_size(merge.dst), session_table_size(seq.sessions));
  session_table_foreach(merge.dst, check_session, &lookup);
  EXPECT_EQ(lookup.mismatches, 0);
  session_table_destroy(merge.dst);
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

TEST(Pipeline, BatchesMatchSequential) {
  // Lô lớn hơn số gói của file (chỉ flush ở cuối), lô vừa, và lô bằng đúng
  // capacity của ring (ring 4 slot, lô 4: mỗi flush lấp đầy ring).
  for (const char *name : {"gtpu_basic", "malformed", "gtpu_5g_ext"})
    for (unsigned workers : {1u, 3u}) {
      expect_same_as_sequential(name, workers, 1024, 256);
      expect_same_as_sequential(name, workers, 1024, 7);
      expect_same_as_sequential(name, workers, 4, 4);
    }
}

TEST(Pipeline, SharedNothingMatchesSequential) {
  // Kể cả nhiều worker hơn số gói (vài đoạn rỗng) và file cắt cụt giữa
  // chừng (phải dừng đúng chỗ và báo đúng lỗi như reader tuần tự).
  for (const char *name : {"gtpu_basic", "gtpu_optional_fields", "gtpu_5g_ext",
                           "gtpu_signalling", "malformed", "non_gtpu",
                           "pcap_empty", "bad_pcap_truncated_record"})
    for (unsigned workers : {1u, 2u, 3u, 8u, 64u})
      expect_same_as_sequential(name, workers, 1024, 1, true);
}

TEST(Pipeline, TruncatedFileMatchesSequential) {
  for (unsigned workers : {1u, 3u})
    expect_same_as_sequential("bad_pcap_truncated_record", workers, 1024);
}

TEST(Pipeline, RejectsBadConfig) {
  const std::string path = data_path("gtpu_basic.pcap");
  pipeline_result res;
  pipeline_config cfg = {path.c_str(), 0, 1024, 1, false};
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  cfg.n_workers = PIPELINE_MAX_WORKERS + 1;
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  cfg.n_workers = 2;
  cfg.ring_capacity = 1000;  // không phải lũy thừa 2
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  cfg.ring_capacity = 16;
  cfg.batch = 32;  // lô lớn hơn ring: không bao giờ đẩy trọn một lô
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  cfg.batch = PIPELINE_MAX_BATCH + 1;
  cfg.ring_capacity = 1024;
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
}

TEST(Pipeline, ReportsOpenError) {
  const std::string path = data_path("does_not_exist.pcap");
  pipeline_config cfg = {path.c_str(), 2, 1024, 1, false};
  pipeline_result res;
  EXPECT_NE(pipeline_run(&cfg, &res), 0);
  EXPECT_EQ(res.read_status, PCAP_ERR_IO);
}
