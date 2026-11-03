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
./build-rel/gtpu-inspect bench/data/big.pcap          # tuần tự
./build-rel/gtpu-inspect -w 4 bench/data/big.pcap     # 4 worker, mempool
./build-rel/gtpu-inspect -w 4 -m bench/data/big.pcap  # 4 worker, malloc mỗi gói
```

Với `-w`, stdout giống hệt chế độ tuần tự; thời gian, Mpps và số gói từng
worker in ra stderr.

Gợi ý cách đo cho số liệu đáng tin:
- Chạy mỗi cấu hình ít nhất 5 lần, báo median, ghi rõ CPU và số core.
- Đọc toàn bộ file vào RAM (hoặc chạy lại để file nằm trong page cache)
  để không đo tốc độ đĩa.
- Tách thời gian đọc file khỏi thời gian xử lý.
- `perf stat` / `perf record` để xem cache miss và hàm nóng.

## Kết quả

Intel i5-1135G7 (4 core / 8 thread, L3 8 MB), Linux, GCC, Release.
`big.pcap`: 2 000 000 gói, 10 000 phiên, 1.26 GB, đã nằm trong page cache.
Median 5 lần. Mpps của `-w` là số in ra stderr (từ lúc tạo worker tới khi
join xong, không gồm mở file và in báo cáo); cột wall là cả process.

| Cấu hình | Worker | Mempool | Mpps | Wall | Ghi chú |
|---|---|---|---|---|---|
| tuần tự | 0 | – | 6.6 | 301 ms | đáp án, nhanh nhất |
| pipeline | 1 | không | 3.54 | 572 ms | malloc/free mỗi gói |
| pipeline | 1 | có | 5.05 | 403 ms | mempool nhanh hơn malloc ~43% |
| pipeline | 2 | có | 4.35 | 466 ms | chia 1 041 073 / 958 927 gói |
| pipeline | 4 | có | 2.87 | 704 ms | |

Thêm worker làm **chậm** đi. Việc của mỗi gói (parse + đếm, vài chục ns)
rẻ hơn chi phí đưa gói sang core khác: memcpy ~600 byte vào buffer, rồi
cache line của buffer và của head/tail ring phải chuyển giữa hai core.
Luồng reader là nút thắt (pcap_next + memcpy + push), nên chạy tuần tự,
không chép và không đồng bộ, thắng. Pipeline chỉ có lợi khi mỗi gói tốn
nhiều việc hơn (DPI, giải mã, tra bảng lớn) hoặc khi đọc từ nhiều nguồn
song song (nhiều hàng đợi NIC, mỗi hàng một reader).

Đã thử:
- Cache chỉ số bên kia trong ring (commit `a9212ba`): 1/2/4 worker
  4.49/4.04/2.89 -> 5.09/4.38/2.96 Mpps. Giữ.
- Rút free_ring mỗi 32 gói thay vì đợi pool cạn: chậm hơn (5.09 -> 4.23 với
  1 worker). Bỏ, lưu ở nhánh `exp/drain-free-every-32`.
- Ghim `taskset -c 0-3` để không worker nào chung core vật lý với reader:
  không đổi (5.21/4.35/4.09 so với 5.18/4.37/4.03), hyperthread không phải
  nguyên nhân.

Chưa đo: `perf stat` (máy chưa cài perf). Ứng viên tiếp theo: reader đẩy
theo lô (ghi head một lần cho nhiều gói), hoặc truyền con trỏ vào buffer
đọc thay vì memcpy.
