# Đánh giá v2 và bài học (nhánh `week3_v2`)

v2 là bản nâng cấp của tuần 3, làm theo 5 ưu tiên trong
[review-v1.md](review-v1.md). Cùng máy, cùng dữ liệu, cùng cách đo:
i5-1135G7, `big.pcap` 2M gói / 1.26 GB trong page cache, Release,
`tools/bench.sh` 9 vòng xen kẽ, median. Laptop dao động ~±10% giữa các lần
chạy, nên chênh lệch dưới mức đó coi như bằng nhau.

## Kết quả tổng

| Cấu hình | v1 Mpps | v2 Mpps | v1 cpu (ms) | v2 cpu (ms) |
|---|---|---|---|---|
| tuần tự (không đổi) | 6.06 | 6.08 | 328 | 327 |
| `-w 1` | 4.87 | **13.44** | 824 | 324 |
| `-w 2` | 4.07 | 11.15 | 1480 | 472 |
| `-w 4` | 2.79 | 10.20 | 3585 | 566 |
| `-w 8` | – | 9.95 | – | 590 |
| `-w 1 -S` | – | 7.46 | – | 301 |
| `-w 2 -S` | – | 8.91 | – | 353 |
| `-w 4 -S` | – | 9.82 | – | 448 |
| `-w 8 -S` | – | 9.33 | – | 765 |

- Tốt nhất v2: `-w 1` 13.44 Mpps, **gấp 2.8 lần v1 `-w 1`** và **2.2 lần chạy
  tuần tự**. v1 chưa cấu hình đa luồng nào thắng được chạy tuần tự.
- 4 worker: gấp 3.7 lần v1, CPU giảm từ 3.6 s xuống 0.57 s (−84%).
- Vẫn còn: thêm worker không làm nhanh hơn. Chỗ nghẽn đã dời đi chứ chưa
  biến mất (xem bài học 1).
- Output của mọi cấu hình giống hệt chạy tuần tự trên mọi fixture và trên
  `big.pcap`. Sạch dưới ASan/UBSan, ThreadSanitizer, Valgrind.

## Từng ưu tiên: giả định -> kết quả

### 1. Đo trước — đúng, và rẻ nhất

`perf` + `tools/bench.sh` (chạy xen kẽ, median), pipeline báo thêm thời
gian reader, CPU và số lần ngủ của từng worker. Chính các số này bác bỏ ba
giả định sau (2 cái ở v1, 1 cái ở bước 4) trước khi tốn công tối ưu sai chỗ,
và cho thấy v1 4 worker: reader bận 100% thời gian, mỗi worker cpu 0.72 s
cho 1/4 số gói — tức là gần hết thời gian worker chỉ chờ.

### 2. mmap, ring chỉ chở offset — đúng, lợi lớn nhất

Giả định: reader chép mỗi gói 2 lần (fread, rồi memcpy vào pool) và worker
đọc dữ liệu core khác vừa ghi. Bỏ chép thì reader nhẹ hẳn.

`-w 1` 4.73 -> 13.49 Mpps (commit `da7ed0e`). Kèm theo là bớt code: không
còn mempool, free_ring, buffer > 2048 byte phải malloc riêng, hay vòng rút
free_ring để tránh deadlock khi join; `pipeline.c` ngắn đi ~100 dòng. Reader
mmap cho ra đúng gói và đúng mã lỗi như reader stream trên cả 14 fixture.

### 3. Push/pop theo lô — đúng một phần, lợi nhỏ

Giả định: một lần cập nhật `head`/`tail` mỗi gói là quá mịn.

| lô | 1 | 8 | 32 | 128 |
|---|---|---|---|---|
| 1 worker | 14.26 | 14.56 | 14.41 | 14.42 |
| 4 worker | 9.84 | – | 11.20 | 11.26 |

Chỉ đáng kể khi nhiều worker (+14% với 4), gần như không đổi với 1 worker:
sau khi bỏ chép, chi phí đồng bộ không còn là phần lớn. Mặc định `-b 32`.

### 4. Shared-nothing — sai về hiệu năng, đúng về độ đúng

Giả định: bỏ reader trung tâm thì scale theo số core.

Thực tế 4 worker 9.82 Mpps, **thua** reader + ring 1 worker (13.44). Riêng
bước chia file mất ~0.13 s, trong khi mỗi worker chỉ cần ~0.075 s cho đoạn
của mình. perf: sys chỉ 0.09 s nên không phải page fault (giả định ban đầu,
sai); đó là user time của **chuỗi load phụ thuộc**: phải đọc `caplen` của
record này mới biết record sau ở đâu, nên 2M lần đọc header là 2M lần trượt
cache xuống DRAM nối tiếp nhau, không chạy song song được.

Prefetch 4 KB phía trước: chia file 0.124 -> 0.109 s (−12%), pipeline +1.6%.
Lợi nhỏ, lại là builtin ngoài chuẩn C11: không merge, lưu ở nhánh
`exp/prefetch-map-next`.

Về độ đúng thì đáng giá: `session_merge` gộp một phiên bị chia giữa các
đoạn ra đúng như chạy tuần tự, và tự báo trường hợp duy nhất không tái tạo
được (phiên > 8 luồng, gói đã rơi vào `flows_overflow`) thay vì im lặng cho
lệch.

### 5. Worker chờ theo bậc — đúng về CPU, không ảnh hưởng thông lượng

Giả định A: spin -> yield -> ngủ thì vừa nhanh vừa tiết kiệm CPU.
Giả định B: worker spin 100% làm hạ turbo của cả chip, kéo reader chậm theo.

| chờ khi ring rỗng (4 worker) | Mpps | CPU 4 worker | lần ngủ |
|---|---|---|---|
| chỉ `sched_yield` (v1, bước 2-4) | 10.23 | 0.78 s | 0 |
| spin 256 -> yield 64 -> ngủ | 9.79 | 0.81 s | 2 |
| spin 16 -> ngủ (giữ lại) | 10.29 | 0.51 s | 53 527 |
| ngủ ngay | 10.00 | 0.32 s | 61 689 |

A sai với ngưỡng ban đầu: lô mới đến mỗi ~9 µs, ngắn hơn 256 vòng spin nên
worker không bao giờ tới bậc ngủ (lưu ở nhánh `exp/idle-spin256-yield64`).
Ngưỡng phải ngắn hơn khoảng cách giữa hai lô. Bậc `sched_yield` không giúp ở
cấu hình nào nên bị bỏ. B sai: ngủ nhiều hay ít, thông lượng như nhau.

Sys time 4 worker: v1 2.67 s -> v2 0.30 s (giờ là futex khi đánh thức).

## perf của v2

| | v1 `-w 1` | v2 `-w 1` | v2 `-w 4` | v2 `-w 4 -S` |
|---|---|---|---|---|
| instructions | 2.07 G | 1.08 G | 1.14 G | 1.02 G |
| cycles | 1.62 G | 0.99 G | 1.40 G | 1.38 G |
| L1d miss | 45.9 M | 22.4 M | 24.9 M | 20.9 M |
| user / sys (s) | 0.39 / 0.44 | 0.25 / 0.09 | 0.37 / 0.30 | 0.35 / 0.10 |

Hàm nóng v2 `-w 1`: `pcap_map_next` 43% (reader duyệt record + worker giải
mã lại record), `session_table_upsert` 21%, `pipeline_run` 10% (vòng
reader), `session_account` 7%, `parse_packet` 6%.

## Bài học

1. **Nút thắt thật là định dạng file, không phải code.** pcap là một
   linked list trên đĩa: vị trí record sau phụ thuộc vào nội dung record
   trước. Mọi thiết kế (reader + ring, shared-nothing) đều phải đi hết chuỗi
   này trên MỘT luồng, và chuỗi đó bị giới hạn bởi độ trễ DRAM. Muốn scale
   thật phải đổi đầu vào: một file chỉ mục offset tạo một lần, pcapng có
   block index, hoặc nhiều file/nhiều hàng đợi NIC mỗi cái một reader.
2. **Bỏ việc thừa thắng mọi tối ưu đồng bộ.** mmap (bỏ 2 lần chép) cho 2.8x;
   lô + cách chờ cộng lại chưa tới 15%. Trước khi tối ưu cách chuyển dữ
   liệu, hỏi xem có cần chuyển dữ liệu không.
3. **Đoán sai nhiều hơn đoán đúng.** 5 giả định bị số đo bác bỏ (pool lớn
   hơn L3, hyperthread, page fault, chờ 3 bậc, turbo). Mỗi lần đều đúng một
   khuôn: nghe hợp lý, đo thì không. Đo trước khi sửa, và lưu thử nghiệm sai
   kèm số đo (`exp/*`) để lần sau khỏi thử lại.
4. **Ngưỡng tối ưu phụ thuộc nhịp của dữ liệu.** Ngưỡng spin chỉ có nghĩa
   khi so với khoảng cách giữa hai lô; lô chỉ có nghĩa khi đồng bộ là phần
   lớn chi phí. Hằng số copy từ chỗ khác (256 vòng spin) sai ở đây.
5. **Đúng trước, nhanh sau — và đúng có thể kiểm bằng máy.** Mọi chế độ đều
   được test so với chạy tuần tự (fixture, file cắt cụt, 64 worker cho file
   vài gói, 300 lần chạy để bắt lost wakeup) dưới ASan, TSan, Valgrind.
   Nhờ vậy mới dám thử nhanh nhiều biến thể.
6. **Laptop là máy đo tồi.** Dao động ±10% (một lần đo lẻ 5.78 Mpps suýt
   thành kết luận "ngủ làm chậm 2 lần"). Chạy xen kẽ nhiều vòng, lấy median,
   và chỉ tin chênh lệch lớn hơn nhiễu.
7. **mempool không sai, chỉ là không cần ở đây.** Nó thắng malloc 30% khi
   phải chép gói (v1). Đọc file thì mmap thắng cả hai; đọc từ socket/NIC thì
   pool lại là lựa chọn đúng.

## Hướng tiếp theo nếu làm v3

- Chỉ mục offset (tạo một lần, ghi cạnh file `.pcap`) để chia file cho
  shared-nothing mà không phải duyệt chuỗi. Ước lượng thô, chưa đo: mỗi
  worker hiện cần ~0.075 s cho 1/4 file, tức cỡ 25 Mpps với 4 worker nếu
  bỏ được bước chia file.
- `session_table_upsert` 21%: thử bảng lớn sẵn (ít resize), hoặc gom key
  liền nhau để giảm cache miss khi dò.
- Fuzz `pcap_map_next` và `session_merge`; fuzz parser nhiều giờ (vẫn mở).
