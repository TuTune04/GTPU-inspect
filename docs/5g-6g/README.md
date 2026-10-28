# Học thêm 5G / 6G

Thư mục này là sổ tay học song song với code. Mỗi chủ đề gắn với một chỗ cụ thể
trong dự án, để kiến thức đọc được luôn có chỗ thử. Ghi chú riêng của bạn:
thêm file `NN-ten-chu-de.md` cạnh file này (ví dụ `01-kien-truc-5gc.md`).

## Dự án nằm ở đâu trong mạng 5G

```
            control plane (N1/N2: NAS, NGAP)          N4: PFCP
   UE ───── gNB ─────────────────────────── AMF ── SMF ───────┐
             │                                                 │
             └──── N3: GTP-U/UDP 2152 ──── UPF ── N9 ── UPF ── N6 ── Internet
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                   gtpu-inspect đọc lưu lượng ở đây (N3, N9; 4G: S1-U, S5-U)
```

gtpu-inspect làm phần việc "nhìn" của một UPF: tách tunnel theo TEID, đọc QFI,
đếm theo phiên. Một UPF thật còn phải *quyết định* làm gì với gói: việc đó do
SMF cài qua PFCP (mục 3).

## Lộ trình

Đánh dấu `[x]` khi xong, giống `docs/ROADMAP.md`.

### 1. Kiến trúc 5G Core
- [ ] Đọc TS 23.501 mục 4 (kiến trúc, các NF, các điểm tham chiếu N1–N9) và
      mục 5.7 (QoS model).
- Tự trả lời: vì sao 5G tách control plane / user plane (CUPS) rõ hơn 4G?
  PDU session, QoS flow, QFI, 5QI liên hệ với nhau thế nào? Một PDU session
  có thể có mấy QoS flow, và tất cả đi chung một TEID hay không?
- Liên hệ code: `include/gtpu.h` (QFI), fixture `tests/data/gtpu_5g_ext.pcap`.

### 2. GTP-U và PDU Session Container (đã làm ở tuần 1–2)
- [x] TS 29.281: header, extension header, Echo / Error Indication / End Marker.
- [ ] TS 38.415: định dạng đầy đủ của PDU Session Container (DL vs UL, RQI, PPI).
- Tự trả lời: End Marker dùng trong handover thế nào? Vì sao gNB cần biết QFI
  mà không cần đọc IP bên trong?

### 3. PFCP (N4): UPF biết TEID từ đâu
- [ ] TS 29.244 mục 5.2: PDR, FAR, QER, URR.
- Tự trả lời: khi gói G-PDU tới, UPF so khớp PDR theo những trường nào?
  Session table của dự án giống và khác bảng PDR ở đâu?
- Bài tập: bắt PFCP (UDP 8805) bằng lab ở mục "Lab", xem TEID mà SMF cấp,
  rồi đối chiếu với TEID gtpu-inspect đếm được trên N3.

### 4. Control plane: NGAP và NAS
- [ ] TS 38.413 (NGAP): thủ tục PDU Session Resource Setup, nơi TEID uplink
      và downlink được trao đổi giữa gNB và core.
- [ ] TS 24.501 (NAS 5GS): registration, PDU session establishment.
- Tự trả lời: vẽ lại sequence diagram từ lúc UE bật máy tới lúc gói dữ liệu
  đầu tiên đi qua N3.

### 5. RAN và chia tách gNB
- [ ] TS 38.300: chồng giao thức NR (SDAP / PDCP / RLC / MAC / PHY).
- [ ] TS 38.401, 38.425: tách CU/DU, giao diện F1-U cũng chạy GTP-U
      (extension NR RAN Container).
- Tự trả lời: SDAP ánh xạ QoS flow → DRB ở đâu? Parser của dự án cần thêm gì
  để đọc được F1-U?

### 6. Network slicing và edge
- [ ] TS 23.501 mục 5.15 (S-NSSAI), mục 5.13 (edge computing, UL CL).
- Tự trả lời: một UE có nhiều slice thì trên N3 trông thế nào?

### 7. Hướng tới 6G
6G chưa có spec chính thức. Mốc chung: ITU-R IMT-2030 (khung M.2160, 2023),
3GPP bắt đầu nghiên cứu 6G từ Release 20, spec chuẩn dự kiến ở Release 21,
triển khai thương mại quanh 2030. Kiểm tra lại mốc mới nhất trên 3gpp.org.
- [ ] Đọc ITU-R M.2160 (các kịch bản sử dụng và chỉ tiêu).
- [ ] Theo dõi các chủ đề: AI/ML native trong RAN và core, ISAC (vừa truyền
      thông vừa cảm biến), NTN (vệ tinh, đã có từ Rel-17), băng sub-THz,
      kiến trúc core đơn giản hơn / cloud-native.
- Tự trả lời: user plane 6G có còn GTP-U không? Đọc các đề xuất thay thế
  (ví dụ SRv6 cho mobile user plane, RFC 9433) và so với những gì dự án đang parse.

## Lab: sinh lưu lượng 5G thật

Mạng 5G giả lập chạy được trên một máy, đủ để bắt pcap N3 thật cho gtpu-inspect:

| Phần | Công cụ mã nguồn mở |
|---|---|
| 5G Core | Open5GS, free5GC |
| gNB + UE giả lập | UERANSIM |
| RAN thật (cần SDR) | srsRAN Project, OpenAirInterface |

Gợi ý: chạy Open5GS + UERANSIM, `ping` từ interface `uesimtun0`, bắt
`tcpdump -i any -w n3.pcap udp port 2152`, rồi chạy gtpu-inspect trên file đó
và so với `tools/tshark_dump.sh n3.pcap`. Pcap Linux `any` dùng linktype SLL,
không phải Ethernet: bắt trên một interface cụ thể, hoặc coi đây là bài tập
mở rộng parser.

## Tài liệu

- Spec 3GPP: https://www.3gpp.org/ftp/Specs/archive/ (thư mục theo series,
  ví dụ `29_series/29.281/`). Chọn bản mới nhất của Release bạn quan tâm.
- Sách: *5G Core Networks* (Rommer và cộng sự), *5G NR: The Next Generation
  Wireless Access Technology* (Dahlman, Parkvall, Sköld).
- Wireshark: mở pcap của lab, bật dissector GTP, PFCP, NGAP để xem từng trường.
