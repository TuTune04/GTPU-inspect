# GTPU-inspect

**gtpu-inspect** is a user-plane traffic analyzer for 4G/5G mobile networks, written in C11.

In LTE and 5G, user data between the radio access network (eNB/gNB) and the core
(SGW/UPF) is carried inside GTP-U tunnels over UDP port 2152, with each session
identified by a Tunnel Endpoint Identifier (TEID). This project reads raw `.pcap`
captures, decodes the Ethernet → IPv4 → UDP → GTP-U → inner IP stack according to
3GPP TS 29.281, and reports traffic statistics per tunnel session.

### Features
- Pcap file reader written from scratch (no libpcap)
- GTP-U decoding: mandatory and optional header fields, extension header chains
  (including the 5G PDU Session Container / QFI), G-PDU, Echo, Error Indication, End Marker
- Per-TEID session table (open-addressing hash table) with packet/byte counters
- Strict bounds checking: malformed packets are counted by error type, never trusted
- *(planned)* Multi-worker pipeline with TEID-based dispatch and lock-free SPSC ring buffers
- *(planned)* Fixed-size memory pool and throughput benchmarks

### Quality
- Builds with `-Wall -Wextra -Werror -std=c11` on GCC and Clang
- Unit tests (GoogleTest), AddressSanitizer/UBSan and Valgrind in CI
- Parser fuzzing with libFuzzer *(planned)*

### Motivation
During my internship in network protocol research, I analyzed traffic with Wireshark.
This project is my way of understanding what the software that processes that traffic
inside a mobile network actually does.

### Build & test
```sh
pip install -r tools/requirements.txt     # only needed to regenerate test data
cmake -B build -DGTPU_SANITIZE=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

| CMake option | Effect |
|---|---|
| `GTPU_SANITIZE=ON` | build with AddressSanitizer + UBSan |
| `GTPU_BUILD_FUZZ=ON` | build the libFuzzer target (requires `CC=clang CXX=clang++`) |
| `GTPU_BUILD_BENCH=ON` | build programs in `bench/` |
| `GTPU_BUILD_TESTS=OFF` | skip unit tests |

### Repository layout
```
include/, src/   core C11 (parser, GTP-U, session table, ring, mempool)
tests/           GoogleTest unit tests + data-driven tests on tests/data/*.pcap
tests/data/      generated pcaps, each with a .expected file (per-packet verdict)
tools/           gen_pcaps.py (Scapy), make_corpus.py, tshark_dump.sh
fuzz/            libFuzzer target
bench/           benchmark notes and programs
docs/ROADMAP.md  week-by-week plan and checklist
docs/5g-6g/      5G/6G study notes linked to the code
```
