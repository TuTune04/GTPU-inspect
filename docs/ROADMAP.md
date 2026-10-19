# Lộ trình tự làm

Khung repo đã có sẵn build, test, CI, dữ liệu test. Phần core trong `src/` và
`include/` là của bạn. Mỗi khi bạn tạo một file trong danh sách
`GTPU_CORE_CANDIDATES` (xem `CMakeLists.txt`), CMake tự đưa nó vào build.

## Bản đồ file

Header trong `include/` đã khai báo đủ kiểu và prototype. Mỗi hàm trong
`src/*.c` có comment hướng dẫn ngay phía trên và một stub `/* TODO */`:
xóa stub, viết code của bạn vào đó.

| Tuần | Header | Cần viết |
|---|---|---|
| 1 | `bytes.h` | `rd_be16`, `rd_be32`, `rd_le16`, `rd_le32` (viết ngay trong header) |
| 1 | `pcap.h` | `src/pcap.c` |
| 1 | `parse_result.h`, `parser.h` | `src/parser.c` |
| 1 (+2) | `gtpu.h` | `src/gtpu.c` (tuần 2: extension header) |
| 1 → 3 | | `src/main.c` |
| 2 | `session_table.h` | `src/session_table.c` |
| 2 | `stats.h` | `src/stats.c` |
| 3 | `ring.h` | `src/ring.c` |
| 3 | `mempool.h` | `src/mempool.c` |
| 3 | `pipeline.h` | `src/pipeline.c` |

Bạn được đổi API trong header nếu thấy hợp lý hơn; nhớ sửa test theo.

## Vòng lặp làm việc

```sh
cmake -B build -DGTPU_SANITIZE=ON      # lần đầu, hoặc khi thêm file .c mới
cmake --build build -j && ctest --test-dir build --output-on-failure
```

Bật một test: trong `tests/test_*.cpp`, thay `GTEST_SKIP()` bằng assertion
thật. Các header đã có sẵn `extern "C"` nên include thẳng từ C++ được.

## Tuần 1: đọc pcap và parse tới GTP-U

- [x] `include/pcap.h`, `src/pcap.c`: mở file, đọc global header, đọc từng record.
      Test: `tests/test_pcap.cpp`, dữ liệu `pcap_*.pcap`, `bad_pcap_*.pcap`.
  - Tự trả lời: phân biệt little/big-endian bằng magic thế nào? Có nên malloc
    theo `caplen` không? Nên giới hạn `caplen` tối đa bao nhiêu?
- [x] `include/parser.h`, `src/parser.c`: Ethernet → IPv4 → UDP.
  - Gợi ý thiết kế: hàm nhận `(const uint8_t *buf, size_t len)` và một struct
    kết quả do người gọi cấp; trả về enum lý do (ok / ignored / từng loại lỗi).
    Đọc trường nhiều byte bằng `memcpy` vào biến rồi `ntohs`/`ntohl`.
  - Mọi lần đọc đều phải có kiểm tra "còn đủ byte không" ngay trước đó.
- [x] `include/gtpu.h`, `src/gtpu.c`: 8 byte bắt buộc + 4 byte tùy chọn.
      Test: `tests/test_gtpu.cpp`.
- [x] `src/main.c`: in mỗi gói một dòng. Khi có file này, CTest tự thêm các
      test `cli.*` chạy chương trình trên mọi fixture.
- [x] Bật `tests/test_parser.cpp` cho `gtpu_basic`, `gtpu_optional_fields`,
      `non_gtpu`. So với Wireshark: `tools/tshark_dump.sh tests/data/gtpu_basic.pcap`.

## Tuần 2: extension header, bảng phiên, gói lỗi

- [ ] Duyệt chuỗi extension header, lấy QFI từ PDU Session Container (0x85).
      Fixture: `gtpu_5g_ext`.
  - Đọc TS 29.281 mục 5.2: đơn vị độ dài, ý nghĩa 2 bit cao của type,
    vì sao length = 0 là nguy hiểm.
- [ ] Toàn bộ `malformed.pcap` cho đúng lý do lỗi; test
      `EveryTruncationOfValidPacketIsSafe` pass dưới ASan.
- [ ] `src/session_table.c`: open addressing, key (TEID, IP endpoint).
      Test: `tests/test_session_table.cpp`.
  - Tự trả lời: hàm hash nào? linear hay quadratic probing? xóa phần tử thế
    nào (tombstone)? load factor bao nhiêu thì resize?
- [ ] `src/stats.c`: đếm theo message type, theo lý do lỗi, top N phiên.
- [ ] Valgrind sạch: CI job `valgrind` xanh.

## Tuần 3: đa luồng, mempool, benchmark, fuzz

- [ ] `src/ring.c`: SPSC ring với `<stdatomic.h>`. Test: `tests/test_ring.cpp`,
      chạy thêm với ThreadSanitizer.
  - Tự trả lời: vì sao producer chỉ ghi `head`, consumer chỉ ghi `tail`?
    Chỗ nào cần `memory_order_release`, chỗ nào `acquire`? False sharing là gì
    và vì sao đặt `head`/`tail` trên hai cache line khác nhau?
- [ ] `src/mempool.c`: free list kích thước cố định. Test: `tests/test_mempool.cpp`.
- [ ] Reader thread + N worker, dispatch `hash(TEID) % N`.
- [ ] Benchmark theo `bench/README.md`, ghi số liệu thật vào README.
- [ ] Nối `fuzz/fuzz_parser.c` với parser, fuzz nhiều giờ:
  ```sh
  CC=clang CXX=clang++ cmake -B build-fuzz -DGTPU_BUILD_FUZZ=ON
  cmake --build build-fuzz -j && python3 tools/make_corpus.py
  ./build-fuzz/fuzz/fuzz_parser fuzz/corpus -max_total_time=3600 -jobs=4
  ```
  Mỗi crash tìm được: thêm thành fixture trong `tools/gen_pcaps.py` trước khi sửa.

## Dữ liệu test

`tools/gen_pcaps.py` sinh `tests/data/*.pcap` kèm `*.expected` (kết quả mong
đợi từng gói). Muốn thêm case: sửa script, chạy `cmake --build build -t fixtures`
(hoặc `python3 tools/gen_pcaps.py`), commit cả `.pcap` lẫn `.expected`.
CI job `fixtures` sinh lại và báo lỗi nếu khác file đã commit.

Tên lý do lỗi trong `.expected` chỉ là gợi ý; nếu bạn phân loại khác, sửa
script cho khớp. Điều quan trọng là mỗi gói lỗi có một lý do rõ ràng và
được đếm.
