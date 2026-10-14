// Đọc file tests/data/*.expected do tools/gen_pcaps.py sinh ra.
//
// Dùng trong test data-driven: với mỗi gói trong pcap, so kết quả parser
// của bạn với dòng tương ứng trong file .expected.
#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace gtpu_test {

inline std::string data_path(const std::string &name) {
  return std::string(GTPU_TEST_DATA_DIR) + "/" + name;
}

struct ExpectedPacket {
  unsigned idx = 0;
  std::string verdict;               // "ok", "ignored:<lý do>", "err:<lý do>"
  std::optional<uint32_t> teid;
  std::optional<unsigned> msg_type;
  std::optional<unsigned> qfi;
  std::string note;

  bool is_ok() const { return verdict == "ok"; }
  bool is_error() const { return verdict.rfind("err:", 0) == 0; }
  bool is_ignored() const { return verdict.rfind("ignored:", 0) == 0; }
  // Phần sau dấu ':' ("gtp_truncated", "not_udp"...), rỗng nếu verdict=ok.
  std::string reason() const {
    auto pos = verdict.find(':');
    return pos == std::string::npos ? "" : verdict.substr(pos + 1);
  }
};

// Kết quả mong đợi cho pcap reader (file pcap_*.pcap / bad_pcap_*.pcap).
struct ExpectedFile {
  std::string verdict;               // "ok" hoặc "err:<lý do>"
  unsigned packets = 0;              // số gói đọc được trước khi dừng
};

namespace detail {
inline std::string strip_comment(const std::string &line, std::string *note) {
  auto pos = line.find('#');
  if (pos == std::string::npos) return line;
  if (note) {
    auto start = line.find_first_not_of(' ', pos + 1);
    *note = start == std::string::npos ? "" : line.substr(start);
  }
  return line.substr(0, pos);
}

template <typename T>
std::optional<T> parse_opt(const std::string &tok, int base) {
  if (tok == "-") return std::nullopt;
  return static_cast<T>(std::stoul(tok, nullptr, base));
}
}  // namespace detail

// Đọc <name>.expected (name không có đuôi), ví dụ "gtpu_basic".
inline std::vector<ExpectedPacket> load_expected(const std::string &name) {
  std::ifstream in(data_path(name + ".expected"));
  if (!in) throw std::runtime_error("không mở được " + name + ".expected");
  std::vector<ExpectedPacket> out;
  std::string line;
  while (std::getline(in, line)) {
    ExpectedPacket e;
    std::istringstream ss(detail::strip_comment(line, &e.note));
    std::string teid, mtype, qfi;
    if (!(ss >> e.idx >> e.verdict >> teid >> mtype >> qfi)) continue;
    e.teid = detail::parse_opt<uint32_t>(teid, 16);
    e.msg_type = detail::parse_opt<unsigned>(mtype, 10);
    e.qfi = detail::parse_opt<unsigned>(qfi, 10);
    out.push_back(e);
  }
  return out;
}

inline ExpectedFile load_expected_file(const std::string &name) {
  std::ifstream in(data_path(name + ".expected"));
  if (!in) throw std::runtime_error("không mở được " + name + ".expected");
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream ss(detail::strip_comment(line, nullptr));
    std::string tag;
    ExpectedFile f;
    if (ss >> tag >> f.verdict >> f.packets && tag == "file") return f;
  }
  throw std::runtime_error(name + ".expected không có dòng 'file ...'");
}

}  // namespace gtpu_test
