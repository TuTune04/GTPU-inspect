# GTPU-inspect

[English](README.md) | **Tiếng Việt**

**gtpu-inspect** là công cụ phân tích lưu lượng user plane của mạng di động 4G/5G, viết bằng C11.

Trong LTE và 5G, dữ liệu người dùng đi giữa mạng truy nhập vô tuyến (eNB/gNB) và mạng
lõi (SGW/UPF) được bọc trong tunnel GTP-U chạy trên UDP cổng 2152; mỗi phiên được
nhận diện bằng Tunnel Endpoint Identifier (TEID). Dự án đọc file capture `.pcap`,
giải mã chồng giao thức Ethernet → IPv4 → UDP → GTP-U → IP bên trong theo
3GPP TS 29.281, và thống kê lưu lượng theo từng phiên tunnel.

### Tính năng
- Tự viết bộ đọc file pcap (không dùng libpcap)
- Giải mã GTP-U: trường bắt buộc và tùy chọn, chuỗi extension header
  (gồm PDU Session Container / QFI của 5G), G-PDU, Echo, Error Indication, End Marker
- Bảng phiên theo TEID (hash table open addressing) đếm gói và byte
- Kiểm tra biên chặt chẽ: gói lỗi được đếm theo từng loại lỗi, không bao giờ tin dữ liệu đầu vào
- *(dự kiến)* Pipeline nhiều worker, chia gói theo TEID, ring buffer SPSC không khóa
- *(dự kiến)* Memory pool kích thước cố định và benchmark thông lượng

### Chất lượng
- Build với `-Wall -Wextra -Werror -std=c11` trên GCC và Clang
- Unit test (GoogleTest), AddressSanitizer/UBSan và Valgrind trong CI
- Fuzz parser bằng libFuzzer *(dự kiến)*

### Động lực
Trong thời gian thực tập nghiên cứu giao thức mạng, tôi phân tích lưu lượng bằng Wireshark.
Dự án này là cách tôi tìm hiểu phần mềm xử lý chính lưu lượng đó bên trong mạng di động
thực sự làm những gì.

### Build và test
```sh
pip install -r tools/requirements.txt     # chỉ cần khi sinh lại dữ liệu test
cmake -B build -DGTPU_SANITIZE=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

| Tùy chọn CMake | Tác dụng |
|---|---|
| `GTPU_SANITIZE=ON` | build kèm AddressSanitizer + UBSan |
| `GTPU_BUILD_FUZZ=ON` | build target libFuzzer (cần `CC=clang CXX=clang++`) |
| `GTPU_BUILD_BENCH=ON` | build các chương trình trong `bench/` |
| `GTPU_BUILD_TESTS=OFF` | bỏ qua unit test |

### Giao diện web
Giao diện web chạy trên máy, dựa trên binary `gtpu-inspect`: mở một file capture, xem
vì sao từng gói được chấp nhận hay bị từ chối, tạo gói test, so với Wireshark và chạy
build. Mỗi gói được vẽ thành lưới octet giống hình header trong spec 3GPP, và rê chuột
lên trường nào cũng có giải thích.

![Tab Phân tích: malformed.pcap, gói #14 bị từ chối vì extension length = 0](docs/images/ui-analyze.png)

#### Cài đặt
Yêu cầu: Python 3 (đã thử với 3.14), CMake, GCC hoặc Clang. Tùy chọn: `tshark` cho tab
So sánh, Wireshark cho các nút "Mở bằng Wireshark".

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt -r tools/ui/requirements.txt
cmake -B build -DGTPU_SANITIZE=ON && cmake --build build -j   # giao diện chạy build/gtpu-inspect
```

Trên Arch Linux: `pacman -S cmake wireshark-qt` (cài kèm cả `tshark`).

#### Khởi động
```sh
.venv/bin/python tools/ui/server.py              # http://127.0.0.1:8152
.venv/bin/python tools/ui/server.py --port 9000  # dùng cổng khác
```
Server chỉ nghe trên 127.0.0.1. Sửa code C thì cần build lại (tab Build & test hoặc
`cmake --build build`); sửa `tools/ui/*.py` thì cần khởi động lại server; sửa
`tools/ui/static/` thì chỉ cần tải lại trang.

#### Cách dùng
- **Cột trái**: chọn fixture trong `tests/data/`, tải lên file `.pcap`, hoặc gõ đường
  dẫn như `~/lab/n3.pcap`. File đang chọn được dùng chung cho mọi tab. Link dạng
  `/?file=tests/data/malformed.pcap&idx=14#analyze` mở thẳng một file, một gói và một tab.
- **Phân tích**: thanh đếm verdict đồng thời là bộ lọc. Chọn gói bằng chuột hoặc ↑/↓;
  dải byte vẽ mỗi lớp đúng kích thước thật, vùng gạch đỏ là số byte trường Length của
  GTP đòi mà gói không có, bấm vào một lớp để xem lưới octet của lớp đó. Trường làm
  parser dừng được viền đỏ. Rê chuột lên một trường sẽ tô sáng các byte của nó trong
  khung hex. File trên 3000 gói: bảng và tab So sánh chỉ có chi tiết 3000 gói đầu; số
  đếm verdict và bảng phiên vẫn tính trên cả file.
- **Tạo gói**: chỉnh IP/UDP lớp ngoài, cờ GTP-U, chuỗi extension, IP bên trong, hoặc
  cố tình làm hỏng gói (cắt ngắn, sai length, extension length = 0…). Lưới octet và
  verdict của parser cập nhật ngay khi gõ. Ghi ra `build/ui/<tên>.pcap`, phân tích,
  mở bằng Wireshark, hoặc xuất code Python để dán vào `tools/gen_pcaps.py` thành
  fixture mới.
- **So sánh**: kết quả của bạn đặt cạnh file `.expected` và `tshark`, chỗ lệch tô đỏ.
  Bấm vào một dòng để mở gói đó ở tab Phân tích.
- **Build & test**: configure (có hoặc không có sanitizer), build và chạy CTest, xem
  log trực tiếp; test lỗi có thể chạy lại riêng.
- **Chú giải**: thuật ngữ gạch chân chấm và mọi ô trong lưới octet đều hiện giải thích
  ngắn khi rê chuột. Bấm (hoặc Enter) để mở ngăn chi tiết: giá trị của trường trong
  gói đang xem, phân tích 5W1H (Là gì / Tại sao / Ai / Khi nào / Ở đâu / Thế nào),
  liên hệ với code của dự án và tài liệu spec. Esc để đóng. Nội dung nằm trong
  `tools/ui/static/glossary.js`.

| Tạo gói | Chú giải |
|---|---|
| ![Tab Tạo gói](docs/images/ui-build.png) | ![Ngăn chú giải của trường TEID](docs/images/ui-glossary.png) |
| **So sánh** | **Build & test** |
| ![Tab So sánh](docs/images/ui-compare.png) | ![Tab Build & test](docs/images/ui-test.png) |

Khi `gtpu-inspect` chưa hỗ trợ `-j`, giao diện đọc output text của `-v` và cột QFI
từng gói để trống. Định dạng NDJSON mà giao diện cần được đặc tả trong
`docs/ui-design.md`; khi binary nhận `-j`, giao diện tự chuyển sang dùng nó.

Test của giao diện (đọc output, dựng gói, và đối chiếu từng trường của lưới octet với
`tshark`):
```sh
.venv/bin/python -m pytest tools/ui
```

### Cấu trúc thư mục
```
include/, src/   lõi C11 (parser, GTP-U, bảng phiên, ring, mempool)
tests/           unit test GoogleTest + test theo dữ liệu trên tests/data/*.pcap
tests/data/      pcap được sinh ra, mỗi file kèm .expected (verdict từng gói)
tools/           gen_pcaps.py (Scapy), make_corpus.py, tshark_dump.sh
tools/ui/        giao diện web: xem gói, tạo gói test, so sánh, build & test
fuzz/            target libFuzzer
bench/           ghi chú và chương trình benchmark
docs/ROADMAP.md  kế hoạch và checklist từng tuần
docs/5g-6g/      ghi chú học 5G/6G gắn với code
```
