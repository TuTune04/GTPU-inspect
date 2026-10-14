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
