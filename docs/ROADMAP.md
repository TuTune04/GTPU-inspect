# Lộ trình tự làm

Khung repo đã có sẵn build, test, CI, dữ liệu test. Phần core trong `src/` và
`include/` là của bạn. Mỗi khi bạn tạo một file trong danh sách
`GTPU_CORE_CANDIDATES` (xem `CMakeLists.txt`), CMake tự đưa nó vào build.

## Vòng lặp làm việc

```sh
cmake -B build -DGTPU_SANITIZE=ON      # lần đầu, hoặc khi thêm file .c mới
cmake --build build -j && ctest --test-dir build --output-on-failure
```

Bật một test: bỏ comment phần `#include` trong file `tests/test_*.cpp`,
thay `GTEST_SKIP()` bằng assertion. Header C dùng trong C++ cần
`extern "C"`, tốt nhất đặt luôn trong header:

```c
#ifdef __cplusplus
extern "C" {
#endif
/* ... khai báo ... */
#ifdef __cplusplus
}
#endif
```

## Tuần 1: đọc pcap và parse tới GTP-U

- [ ] `include/pcap.h`, `src/pcap.c`: mở file, đọc global header, đọc từng record.
      Test: `tests/test_pcap.cpp`, dữ liệu `pcap_*.pcap`, `bad_pcap_*.pcap`.
  - Tự trả lời: phân biệt little/big-endian bằng magic thế nào? Có nên malloc
    theo `caplen` không? Nên giới hạn `caplen` tối đa bao nhiêu?
- [ ] `include/parser.h`, `src/parser.c`: Ethernet → IPv4 → UDP.
  - Gợi ý thiết kế: hàm nhận `(const uint8_t *buf, size_t len)` và một struct
    kết quả do người gọi cấp; trả về enum lý do (ok / ignored / từng loại lỗi).
    Đọc trường nhiều byte bằng `memcpy` vào biến rồi `ntohs`/`ntohl`.
  - Mọi lần đọc đều phải có kiểm tra "còn đủ byte không" ngay trước đó.
- [ ] `include/gtpu.h`, `src/gtpu.c`: 8 byte bắt buộc + 4 byte tùy chọn.
      Test: `tests/test_gtpu.cpp`.
- [ ] `src/main.c`: in mỗi gói một dòng. Khi có file này, CTest tự thêm các
      test `cli.*` chạy chương trình trên mọi fixture.
- [ ] Bật `tests/test_parser.cpp` cho `gtpu_basic`, `gtpu_optional_fields`,
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
