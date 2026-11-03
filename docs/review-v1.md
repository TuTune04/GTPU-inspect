# Nhận xét sau khi chạy v1 (tuần 3, nhánh `week3_v1`)

Máy: Intel i5-1135G7 (4 core / 8 thread, L3 8 MB), Linux 7.2, GCC, Release.
Dữ liệu: `bench/data/big.pcap`, 2 000 000 gói, 10 000 phiên, 1.26 GB, đã
nằm trong page cache. Số đo bằng `tools/bench.sh` (7 vòng, xen kẽ cấu hình,
median) và `perf` 7.2 (`perf_event_paranoid = 2`: chỉ thấy user-space).

## Kết quả đúng

- Ring SPSC, mempool, pipeline 1 reader + N worker: sạch dưới ASan/UBSan,
  ThreadSanitizer (cả 2M gói, 4 worker) và Valgrind. CI xanh 9/9 job.
- Output của `-w N` giống hệt chế độ tuần tự trên mọi fixture và trên
  `big.pcap`, với 1/2/4/8 worker, có và không mempool.
- Fuzz `parse_packet` 15 phút, 4 job, ~1.4 tỷ lần: không crash.

## Thông lượng

| Cấu hình | wall (ms) | cpu (ms) | Mpps |
|---|---|---|---|
| tuần tự | 321 | 319 | 6.23 |
| `-w 1 -m` (malloc) | 534 | 1060 | 3.78 |
| `-w 1` | 408 | 806 | 4.99 |
| `-w 2` | 488 | 1443 | 4.16 |
| `-w 4` | 724 | 3555 | 2.81 |

Pipeline thua chạy tuần tự ở mọi cấu hình, và thêm worker thì chậm thêm.
CPU tiêu thụ tăng theo số worker (4 worker: 3.5 s CPU cho 0.7 s wall) mà
không đổi được thông lượng.

## perf nói gì

`perf stat` (user-space):

| | tuần tự | `-w 1` | `-w 4` |
|---|---|---|---|
| instructions | 1.54 G | 2.07 G | 2.28 G |
| cycles | 0.68 G | 1.62 G | 4.29 G |
| IPC | 2.28 | 1.28 | 0.53 |
| L1d miss | 9.6 M | 45.9 M | 66.4 M |
| LLC miss | 0.36 M | 0.78 M | 1.56 M |
| user / sys (s) | 0.16 / 0.15 | 0.39 / 0.44 | 1.05 / 2.67 |

Hàm nóng (`perf record`, % mẫu user-space):

- **Tuần tự**: `session_table_upsert` 22%, `fread` 12%, `session_account`
  9%, `gtpu_parse` 7%, `pcap_next` 7%, `parse_packet` 6%. Việc thật (bảng
  phiên + parse) chiếm phần lớn; đọc file ~20%.
- **`-w 1`**: `fread` 19%, `pipeline_run` 14% (chính là `memcpy` gói vào
  buffer pool, inline), `session_table_upsert` 13%, `ring_push` +
  `ring_pop` 8%, `sched_yield` 3%.
- **`-w 4`**: `worker_main` 17% + `ring_pop` 9% + `sched_yield` 10% —
  khoảng 36% mẫu là worker **đang chờ**. `fread` 14%, `pipeline_run` 9%.

## Nhận xét

1. **Reader là nút thắt, và nó làm việc thừa.** Mỗi gói bị chép hai lần:
   kernel -> buffer stdio (`read`, phần sys 0.15 s ngay cả khi tuần tự) ->
   buffer của reader (`fread`) -> buffer pool (`memcpy`). Worker đọc buffer
   pool trên core khác nên dữ liệu vừa ghi phải chuyển cache: L1d miss
   tăng 4.8 lần chỉ với 1 worker.
2. **Một push/pop mỗi gói là quá mịn.** Mỗi gói một lần store `head`
   (release) và một lần cache line của `head`/`tail` đổi chủ giữa hai core.
   Việc mỗi gói chỉ ~150 ns, nên chi phí đồng bộ cùng cỡ với việc thật.
3. **Worker chờ bằng `sched_yield` đốt CPU và kernel.** Với 4 worker, sys
   2.67 s: worker rảnh (vì reader chậm) gọi syscall liên tục. IPC tụt còn
   0.53. Chế độ chờ này không ảnh hưởng nhiều tới thông lượng nhưng lãng
   phí gần 3 core.
4. **Dispatch theo TEID là đúng về kết quả** (mọi gói của một phiên về một
   worker, không cần lock) nhưng buộc mọi gói đi qua một reader duy nhất.
   Với tải nhẹ như thống kê, đó là trần thông lượng.
5. **Mempool có ích** (5.0 so với 3.8 Mpps khi malloc mỗi gói), nhưng chỉ
   vì v1 chép gói. Nếu không chép thì không cần buffer để tái sử dụng.
6. **Đo còn thiếu**: v1 chỉ in tổng thời gian, không tách thời gian reader
   và thời gian worker, không có CPU từng worker. Giả định "pool lớn hơn L3"
   (nhánh `exp/drain-free-every-32`) và "hyperthread" đều sai vì đoán trước
   khi đo.

## Hướng v2 (5 ưu tiên)

1. Đo trước: `perf` + `tools/bench.sh`, pipeline báo thời gian reader và CPU
   từng worker.
2. mmap cả file, ring chỉ chuyển con trỏ tới record: bỏ cả hai lần chép,
   bỏ mempool và free_ring.
3. Push/pop theo lô: một lần cập nhật `head`/`tail` cho nhiều gói.
4. Shared-nothing: mỗi worker tự parse một đoạn file, gộp phiên ở cuối —
   không còn reader trung tâm.
5. Worker chờ theo bậc: spin (pause) -> `sched_yield` -> ngủ trên condvar.

Kết quả và bài học sau khi làm: [review-v2.md](review-v2.md).
