# Benchmark

Sinh file pcap lớn (không commit, đã có trong `.gitignore`):

```sh
python3 tools/gen_pcaps.py --bench-out bench/data/big.pcap \
    --bench-packets 2000000 --bench-sessions 10000
```

Phân phối gói giữa các phiên bị lệch (một vài phiên rất "nặng") để giống
thực tế và để thấy ảnh hưởng của việc chia worker theo TEID.

Build Release rồi đo:

```sh
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release && cmake --build build-rel -j
./build-rel/gtpu-inspect bench/data/big.pcap   # thêm cờ số worker của bạn
```

Gợi ý cách đo cho số liệu đáng tin:
- Chạy mỗi cấu hình ít nhất 5 lần, báo median, ghi rõ CPU và số core.
- Đọc toàn bộ file vào RAM (hoặc chạy lại để file nằm trong page cache)
  để không đo tốc độ đĩa.
- Tách thời gian đọc file khỏi thời gian xử lý.
- `perf stat` / `perf record` để xem cache miss và hàm nóng.

| Cấu hình | Worker | Mempool | Mpps | Ghi chú |
|---|---|---|---|---|
| | 1 | không | | |
| | 2 | có | | |
| | 4 | có | | |
