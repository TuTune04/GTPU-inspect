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
./build-rel/gtpu-inspect bench/data/big.pcap            # tuần tự
./build-rel/gtpu-inspect -w 4 bench/data/big.pcap       # reader + 4 worker
./build-rel/gtpu-inspect -w 4 -b 1 bench/data/big.pcap  # đẩy từng gói, không gom lô
./build-rel/gtpu-inspect -w 4 -S bench/data/big.pcap    # shared-nothing
```

Với `-w`, stdout giống hệt chế độ tuần tự; Mpps, thời gian reader (hoặc
chia file), số gói, CPU và số lần ngủ của từng worker in ra stderr.

So nhiều cấu hình (chạy xen kẽ theo vòng, in bảng median):

```sh
RUNS=9 tools/bench.sh bench/data/big.pcap \
    "build-rel/gtpu-inspect" "build-rel/gtpu-inspect -w 4" \
    "build-rel/gtpu-inspect -w 4 -S"
```

Gợi ý cách đo cho số liệu đáng tin:
- Chạy mỗi cấu hình ít nhất 5 lần, báo median, ghi rõ CPU và số core.
- Đọc toàn bộ file vào RAM (hoặc chạy lại để file nằm trong page cache)
  để không đo tốc độ đĩa.
- Tách thời gian đọc file khỏi thời gian xử lý.
- `perf stat` / `perf record` để xem cache miss và hàm nóng.
- Laptop dao động ~±10%: chỉ tin chênh lệch lớn hơn mức đó.

## Kết quả

Intel i5-1135G7 (4 core / 8 thread, L3 8 MB), Linux, GCC, Release.
`big.pcap`: 2 000 000 gói, 10 000 phiên, 1.26 GB, đã nằm trong page cache.
`tools/bench.sh` 9 vòng, median. Mpps của `-w` là số in ra stderr (từ lúc
tạo worker tới khi join xong); wall và cpu là cả process.

| Cấu hình | v1 (`week3_v1`) | v2 (`week3_v2`) | cpu v2 |
|---|---|---|---|
| tuần tự | 6.06 Mpps | 6.08 Mpps | 327 ms |
| reader + 1 worker | 4.87 | **13.44** | 324 ms |
| reader + 2 worker | 4.07 | 11.15 | 472 ms |
| reader + 4 worker | 2.79 | 10.20 | 566 ms |
| shared-nothing 4 worker | – | 9.82 | 448 ms |

v1 chép mỗi gói vào buffer mempool rồi đẩy qua ring: chưa cấu hình đa
luồng nào thắng chạy tuần tự. v2 mmap file, ring chỉ chở offset, đẩy theo
lô 32, worker spin ngắn rồi ngủ: 1 worker nhanh gấp 2.2 lần chạy tuần tự.
Thêm worker vẫn không nhanh hơn, vì reader (hoặc bước chia file) phải đi
hết chuỗi record header trên một luồng: vị trí record sau phụ thuộc
`caplen` của record trước, mỗi bước là một lần trượt cache xuống DRAM.

Phân tích đầy đủ, perf, và mọi thử nghiệm đã bỏ (nhánh `exp/*`):
[docs/review-v1.md](../docs/review-v1.md),
[docs/review-v2.md](../docs/review-v2.md).
