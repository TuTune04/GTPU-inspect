# Thiết kế giao diện web (tools/ui)

Giao diện chạy trên máy, để xem kết quả của `gtpu-inspect`, tạo gói test,
so với Wireshark / `.expected`, và chạy build + test. Giao diện chỉ *gọi*
binary; không viết lại parser trong `src/`.

```sh
.venv/bin/pip install -r tools/ui/requirements.txt
.venv/bin/python tools/ui/server.py          # http://127.0.0.1:8152
```

## Kiến trúc

```
trình duyệt ── fetch ──> tools/ui/server.py (FastAPI, chỉ nghe 127.0.0.1)
                            ├─ build/gtpu-inspect -v | -j   (kết quả cần kiểm tra)
                            ├─ tshark                        (đối chiếu)
                            ├─ cmake / ctest                 (build & test)
                            ├─ tools/gen_pcaps.py            (dựng gói, import lại helper)
                            └─ tools/ui/dissect.py           (cắt byte theo lớp để vẽ)
```

- `dissect.py` là bộ cắt lớp *chỉ để vẽ*: dung thứ gói hỏng, không phán
  verdict. Verdict luôn lấy từ binary của bạn.
- File sinh ra (pcap tự tạo, file tải lên) nằm trong `build/ui/`.
- Server từ chối request có `Host` lạ (chống DNS rebinding) và request ghi
  (POST) thiếu header `X-GTPU-UI` (chống trang web khác gọi vào).

## Định dạng `-j` (NDJSON) — bạn tự viết trong `src/main.c`

Mỗi dòng một object JSON. Khi `-j` bật thì thay cho output text; lỗi file
vẫn ra stderr, exit code giữ nguyên.

```json
{"type":"packet","idx":0,"result":"ok","teid":20481,"msg_type":255,"msg_name":"G-PDU","qfi":9,"inner_src":"10.45.0.2","inner_dst":"8.8.8.8","len":98,"ts_ns":1700000000000000000}
{"type":"summary","packets":12,"bytes":1234,"dropped_sessions":0,"results":{"ok":10,"err:gtp_truncated":2},"msg_types":{"255":10},"qfi":{"9":1},"top_sessions":[{"teid":20481,"endpoint":"192.168.40.1","packets":3,"bytes":300,"flows":1,"qfi":9}]}
```

- Trường không có giá trị: `null`. TEID là số thập phân.
- `len` là `orig_len` của record (giống bộ đếm Bytes hiện tại).
- Chưa có `-j`: giao diện tự đọc output `-v` (khi đó cột QFI từng gói trống).

## Ngôn ngữ thiết kế

Gói tin được vẽ như hình header trong spec 3GPP: lưới octet, mỗi hàng 8 bit
(bit 8 → 1), mỗi trường một ô có tên và giá trị. Trên lưới là dải byte cả
gói, chia đoạn theo lớp, rộng tỉ lệ với số byte. Trường làm parser dừng được
viền đỏ. Đây là điểm nhấn duy nhất; phần còn lại yên tĩnh.

| Token | Sáng | Tối | Dùng cho |
|---|---|---|---|
| paper | `#EEF1F5` | `#141A26` | nền |
| ink | `#1A2233` | `#DCE3EE` | chữ, viền lưới |
| eth | `#8A94A6` | `#9AA4B6` | lớp Ethernet |
| ip / udp | `#3A6EA5` / `#2F9C95` | sáng hơn | IPv4, UDP |
| gtp / ext | `#6B4FBB` / `#B04A9A` | sáng hơn | GTP-U, extension |
| inner | `#C98A1B` | sáng hơn | IP bên trong |
| bad / good | `#C2412D` / `#2E7D5B` | sáng hơn | lỗi, khớp |

Chữ: Atkinson Hyperlegible cho giao diện; JetBrains Mono chỉ cho dữ liệu
(byte, TEID, IP). Thang 13 / 15 / 18 / 24 px, chữ thường kiểu câu.
Chuyển động duy nhất: dải byte co giãn khi đổi gói; tắt theo
`prefers-reduced-motion`.

## Bốn tab

1. **Phân tích**: câu tóm tắt + thanh đếm verdict (bấm để lọc), bảng gói
   (↑/↓ để duyệt), panel phải gồm dải byte + lưới octet của lớp đang chọn,
   bảng top phiên.
2. **Tạo gói**: form (outer, GTP-U, chuỗi extension, inner, phá hỏng) →
   xem trước dải byte, lưới octet và verdict của binary ngay khi gõ; ghi pcap,
   phân tích, mở Wireshark, xuất code fixture để dán vào `gen_pcaps.py`.
3. **So sánh**: theo idx gói, gtpu-inspect | `.expected` | tshark; ô khác
   nhau tô đỏ. Verdict so với `.expected`; TEID / message / QFI so với cả hai.
4. **Build & test**: công tắc sanitizer, Configure / Build / CTest, log chạy
   trực tiếp, lưới ô kết quả test.
