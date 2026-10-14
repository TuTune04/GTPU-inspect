#!/usr/bin/env python3
"""Sinh các file pcap test cho gtpu-inspect.

Mỗi file .pcap đi kèm một file .expected (văn bản) mô tả kết quả mong đợi
cho từng gói, để unit test và bạn (khi mở bằng Wireshark) cùng đối chiếu.

Định dạng file .expected, mỗi dòng một gói (index tính từ 0, giống
"frame number - 1" trong Wireshark):

    <idx> <verdict> <teid> <msg_type> <qfi> # ghi chú

    verdict : ok | ignored:<lý do> | err:<lý do>
    teid    : hex (0x...) hoặc '-'
    msg_type: số thập phân (255, 1, 2, 26, 254) hoặc '-'
    qfi     : số thập phân hoặc '-'

Riêng các file bad_pcap_*.pcap kiểm tra pcap reader, file .expected
chỉ có một dòng tổng: "file <verdict> <số gói đọc được trước khi dừng>".

Mọi trường đều cố định (timestamp, IP id, cổng...) nên chạy lại script
luôn cho ra đúng từng byte như cũ. CI dựa vào điều này để phát hiện
fixture bị sửa tay hoặc quên commit.

Cách dùng:
    python3 tools/gen_pcaps.py                       # ghi vào tests/data/
    python3 tools/gen_pcaps.py --out-dir /tmp/x
    python3 tools/gen_pcaps.py --bench-out bench/big.pcap \\
            --bench-packets 2000000 --bench-sessions 10000
"""

import argparse
import os
import random
import struct
import sys
from pathlib import Path

from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, Raw  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.contrib.gtp import (  # noqa: E402
    GTP_U_Header,
    GTPPDUSessionContainer,
    GTPEchoRequest,
    GTPEchoResponse,
)

GTPU_PORT = 2152

# Địa chỉ của các tunnel endpoint (giả lập).
ENB_MAC, SGW_MAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
ENB_IP, SGW_IP = "192.168.10.1", "192.168.20.1"   # 4G: eNB <-> SGW (S1-U)
GNB_IP, UPF_IP = "192.168.30.1", "192.168.40.1"   # 5G: gNB <-> UPF (N3)

BASE_TS = 1_700_000_000  # timestamp cố định cho mọi gói


# ---------------------------------------------------------------------------
# Ghi file pcap (tự viết thay vì dùng wrpcap để kiểm soát từng byte, kể cả
# tạo file hỏng có chủ đích).
# ---------------------------------------------------------------------------

PCAP_MAGIC_US = 0xA1B2C3D4   # timestamp micro giây
PCAP_MAGIC_NS = 0xA1B23C4D   # timestamp nano giây
LINKTYPE_ETHERNET = 1


def pcap_global_header(endian="<", magic=PCAP_MAGIC_US, snaplen=65535,
                       linktype=LINKTYPE_ETHERNET):
    # magic, version major, version minor, thiszone, sigfigs, snaplen, network
    return struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(data, idx, endian="<", orig_len=None, caplen=None):
    ts_sec = BASE_TS + idx
    ts_frac = idx * 1000
    incl = len(data) if caplen is None else caplen
    orig = len(data) if orig_len is None else orig_len
    return struct.pack(endian + "IIII", ts_sec, ts_frac, incl, orig) + data


def write_pcap(path, packets, endian="<", magic=PCAP_MAGIC_US, snaplen=65535):
    """packets: list[bytes] hoặc list[(bytes, orig_len)]."""
    with open(path, "wb") as f:
        f.write(pcap_global_header(endian, magic, snaplen))
        for i, p in enumerate(packets):
            if isinstance(p, tuple):
                data, orig = p
                f.write(pcap_record(data, i, endian, orig_len=orig))
            else:
                f.write(pcap_record(p, i, endian))


def write_expected(path, rows, header):
    with open(path, "w") as f:
        f.write(f"# {header}\n")
        f.write("# idx verdict teid msg_type qfi # ghi chú\n")
        for i, (verdict, teid, mtype, qfi, note) in enumerate(rows):
            teid_s = "-" if teid is None else f"0x{teid:08x}"
            mtype_s = "-" if mtype is None else str(mtype)
            qfi_s = "-" if qfi is None else str(qfi)
            f.write(f"{i} {verdict} {teid_s} {mtype_s} {qfi_s} # {note}\n")


# ---------------------------------------------------------------------------
# Helper dựng gói
# ---------------------------------------------------------------------------

def outer(src_ip=ENB_IP, dst_ip=SGW_IP, sport=GTPU_PORT, dport=GTPU_PORT,
          ip_id=1):
    return (Ether(src=ENB_MAC, dst=SGW_MAC)
            / IP(src=src_ip, dst=dst_ip, id=ip_id)
            / UDP(sport=sport, dport=dport))


def inner_tcp(src="10.45.0.2", dst="93.184.216.34", sport=40000, dport=443,
              payload=b"hello"):
    return IP(src=src, dst=dst, id=1) / TCP(sport=sport, dport=dport,
                                            flags="PA", seq=1, ack=1) / payload


def inner_udp(src="10.45.0.2", dst="8.8.8.8", sport=50000, dport=53,
              payload=b"\x12\x34" + b"\x00" * 10):
    return IP(src=src, dst=dst, id=1) / UDP(sport=sport, dport=dport) / payload


def gtpu_raw(teid, msg_type=255, payload=b"", flags=None, opt=None,
             ext=b"", length=None, version=1, pt=1):
    """Dựng header GTP-U bằng tay, kiểm soát được mọi trường kể cả sai.

    flags: (E, S, PN). Nếu bất kỳ cờ nào bật thì header có thêm 4 byte
    tùy chọn `opt` = (seq, npdu, next_ext_type); `ext` là chuỗi extension
    header đã encode sẵn. `length` mặc định = phần sau 8 byte bắt buộc.
    """
    e, s, pn = flags or (0, 0, 0)
    b0 = (version << 5) | (pt << 4) | (e << 2) | (s << 1) | pn
    body = b""
    if e or s or pn:
        seq, npdu, nxt = opt or (0, 0, 0)
        body += struct.pack("!HBB", seq, npdu, nxt)
    body += ext + payload
    if length is None:
        length = len(body)
    return struct.pack("!BBHI", b0, msg_type, length, teid) + body


def ext_pdu_session_ul(qfi, next_type=0):
    # PDU Session Container (0x85), PDU type 1 = UL PDU SESSION INFORMATION.
    # len=1 (đơn vị 4 byte): [len][type<<4][qfi][next]
    return bytes([1, 1 << 4, qfi & 0x3F, next_type])


def ext_pdu_session_dl(qfi, rqi=0, next_type=0):
    # PDU type 0 = DL PDU SESSION INFORMATION: [len][type<<4][PPP|RQI|QFI][next]
    return bytes([1, 0 << 4, (rqi << 6) | (qfi & 0x3F), next_type])


def ext_udp_port(port, next_type):
    # UDP Port extension (0x40): [len=1][port hi][port lo][next]
    return bytes([1]) + struct.pack("!H", port) + bytes([next_type])


# ---------------------------------------------------------------------------
# Các bộ fixture
# ---------------------------------------------------------------------------

def gen_basic():
    """4G G-PDU đơn giản: không cờ tùy chọn, 3 phiên, cả uplink lẫn downlink."""
    pkts, rows = [], []

    def add(pkt, teid, note):
        pkts.append(bytes(pkt))
        rows.append(("ok", teid, 255, None, note))

    for i in range(3):
        add(outer(ip_id=i + 1) / GTP_U_Header(teid=0x1001)
            / inner_tcp(payload=b"A" * (10 + i)), 0x1001, "UL TCP, phiên 1")
    add(outer(SGW_IP, ENB_IP) / GTP_U_Header(teid=0x2001)
        / inner_tcp("93.184.216.34", "10.45.0.2", 443, 40000, b"B" * 100),
        0x2001, "DL TCP, phiên 1 (TEID chiều xuống khác chiều lên)")
    add(outer() / GTP_U_Header(teid=0x1002) / inner_udp(), 0x1002,
        "UL UDP (DNS), phiên 2")
    add(outer() / GTP_U_Header(teid=0x1003)
        / IP(src="10.45.0.9", dst="1.1.1.1", id=1) / ICMP(), 0x1003,
        "UL ICMP, phiên 3: inner không phải TCP/UDP")
    add(outer() / GTP_U_Header(teid=0xFFFFFFFF) / inner_udp(), 0xFFFFFFFF,
        "TEID lớn nhất, kiểm tra ntohl/kiểu unsigned")
    add(outer() / GTP_U_Header(teid=0x1001)
        / inner_tcp(payload=b"C" * 1400), 0x1001,
        "UL TCP payload lớn, phiên 1")
    return pkts, rows


def gen_optional_fields():
    """Header có 4 byte tùy chọn (cờ S và PN)."""
    pkts, rows = [], []
    for i in range(3):
        p = outer() / GTP_U_Header(teid=0x3001, S=1, seq=100 + i) / inner_udp()
        pkts.append(bytes(p))
        rows.append(("ok", 0x3001, 255, None, f"cờ S, seq={100 + i}"))
    p = outer() / GTP_U_Header(teid=0x3002, PN=1, npdu=7) / inner_udp()
    pkts.append(bytes(p))
    rows.append(("ok", 0x3002, 255, None, "cờ PN, N-PDU=7"))
    p = outer() / GTP_U_Header(teid=0x3003, S=1, PN=1, seq=0xFFFF, npdu=0xFF) \
        / inner_tcp()
    pkts.append(bytes(p))
    rows.append(("ok", 0x3003, 255, None, "cờ S+PN, seq=65535"))
    return pkts, rows


def gen_5g_extensions():
    """5G N3: PDU Session Container (0x85) và chuỗi nhiều extension header."""
    pkts, rows = [], []

    p = (outer(GNB_IP, UPF_IP) / GTP_U_Header(teid=0x5001, E=1, next_ex=0x85)
         / GTPPDUSessionContainer(type=1, QFI=9) / inner_tcp())
    pkts.append(bytes(p))
    rows.append(("ok", 0x5001, 255, 9, "UL PDU session container, QFI=9"))

    p = (outer(UPF_IP, GNB_IP) / GTP_U_Header(teid=0x6001, E=1, next_ex=0x85)
         / GTPPDUSessionContainer(type=0, QFI=5, RQI=1)
         / inner_tcp("93.184.216.34", "10.45.0.2", 443, 40000))
    pkts.append(bytes(p))
    rows.append(("ok", 0x6001, 255, 5, "DL PDU session container, QFI=5, RQI=1"))

    payload = bytes(inner_udp())
    ext = ext_udp_port(40000, 0x85) + ext_pdu_session_ul(qfi=1)
    p = outer(GNB_IP, UPF_IP) / Raw(gtpu_raw(
        0x5002, payload=payload, flags=(1, 0, 0), opt=(0, 0, 0x40), ext=ext))
    pkts.append(bytes(p))
    rows.append(("ok", 0x5002, 255, 1,
                 "chuỗi 2 extension: UDP Port (0x40) -> PDU session (0x85)"))

    ext = ext_pdu_session_ul(qfi=63)
    p = outer(GNB_IP, UPF_IP) / Raw(gtpu_raw(
        0x5003, payload=payload, flags=(1, 1, 0), opt=(42, 0, 0x85), ext=ext))
    pkts.append(bytes(p))
    rows.append(("ok", 0x5003, 255, 63, "cờ E+S cùng lúc, QFI=63 (max 6 bit)"))
    return pkts, rows


def gen_signalling():
    """Các message type không phải G-PDU."""
    pkts, rows = [], []

    p = outer() / GTP_U_Header(teid=0, gtp_type=1, S=1, seq=1) / GTPEchoRequest()
    pkts.append(bytes(p))
    rows.append(("ok", 0, 1, None, "Echo Request (TEID phải = 0)"))

    p = (outer(SGW_IP, ENB_IP) / GTP_U_Header(teid=0, gtp_type=2, S=1, seq=1)
         / GTPEchoResponse() / Raw(b"\x0e\x00"))
    pkts.append(bytes(p))
    rows.append(("ok", 0, 2, None, "Echo Response, có IE Recovery (type 14)"))

    # Error Indication: IE TEID Data I (16) + GTP-U Peer Address (133)
    ies = (b"\x10" + struct.pack("!I", 0x1001)
           + b"\x85" + struct.pack("!H", 4) + bytes([192, 168, 10, 1]))
    p = outer(SGW_IP, ENB_IP) / Raw(gtpu_raw(0, msg_type=26, payload=ies))
    pkts.append(bytes(p))
    rows.append(("ok", 0, 26, None, "Error Indication cho TEID 0x1001"))

    p = outer(SGW_IP, ENB_IP) / Raw(gtpu_raw(0x2001, msg_type=254))
    pkts.append(bytes(p))
    rows.append(("ok", 0x2001, 254, None, "End Marker (handover), không payload"))
    return pkts, rows


def gen_non_gtpu():
    """Gói không phải GTP-U: phải được bỏ qua và đếm, không coi là lỗi."""
    pkts, rows = [], []

    def add(pkt, reason, note):
        pkts.append(bytes(pkt))
        rows.append((f"ignored:{reason}", None, None, None, note))

    add(Ether(src=ENB_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(psrc=ENB_IP, pdst=SGW_IP), "not_ipv4", "ARP")
    add(Ether(src=ENB_MAC, dst=SGW_MAC) / IPv6(src="fd00::1", dst="fd00::2")
        / UDP(sport=GTPU_PORT, dport=GTPU_PORT), "not_ipv4",
        "IPv6 (bản tối thiểu chỉ hỗ trợ outer IPv4)")
    add(Ether(src=ENB_MAC, dst=SGW_MAC) / IP(src=ENB_IP, dst=SGW_IP, id=1)
        / TCP(sport=1234, dport=80), "not_udp", "TCP thường")
    add(outer(sport=5353, dport=5353) / Raw(b"x" * 20), "not_gtpu_port",
        "UDP cổng khác 2152")
    add(outer(dport=2123) / Raw(b"\x48\x01\x00\x04" + b"\x00" * 8),
        "not_gtpu_port", "GTP-C (cổng 2123) — không phải GTP-U")
    add(Ether(src=ENB_MAC, dst=SGW_MAC)
        / IP(src=ENB_IP, dst=SGW_IP, id=7, flags="MF", frag=0)
        / UDP(sport=GTPU_PORT, dport=GTPU_PORT) / Raw(b"\x30\xff\x00\x00" + b"\x00" * 20),
        "ip_fragment",
        "outer IP bị phân mảnh (MF=1): bản tối thiểu không ghép mảnh")
    return pkts, rows


def gen_malformed():
    """Mỗi gói là một kiểu lỗi. Parser phải đếm đúng lý do và KHÔNG crash."""
    pkts, rows = [], []
    good_inner = bytes(inner_udp())
    base = Ether(src=ENB_MAC, dst=SGW_MAC)

    def add(data, reason, note, orig_len=None):
        pkts.append((data, orig_len if orig_len is not None else len(data)))
        rows.append((f"err:{reason}", None, None, None, note))

    def udp_with(gtp_bytes, **ip_kw):
        return bytes(base / IP(src=ENB_IP, dst=SGW_IP, id=1, **ip_kw)
                     / UDP(sport=GTPU_PORT, dport=GTPU_PORT) / Raw(gtp_bytes))

    good = udp_with(gtpu_raw(0x1001, payload=good_inner))

    # --- lớp 2/3/4 ---
    add(good[:10], "eth_truncated", "chỉ còn 10 byte, chưa đủ 14 byte Ethernet")
    add(good[:14 + 12], "ip_truncated", "IPv4 header bị cắt ở byte 12")
    bad = bytearray(good); bad[14] = 0x43  # version 4, IHL=3 (<5)
    add(bytes(bad), "ip_bad_ihl", "IHL=3, nhỏ hơn mức tối thiểu 5")
    bad = bytearray(good); bad[14] = 0x65  # version 6 nhưng EtherType 0x0800
    add(bytes(bad), "ip_bad_version", "EtherType IPv4 nhưng version=6")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner), len=2000),
        "ip_len_mismatch", "IP total length=2000 lớn hơn dữ liệu thực có")
    add(good[:14 + 20 + 4], "udp_truncated", "UDP header chỉ còn 4 byte")
    bad = bytearray(good); struct.pack_into("!H", bad, 14 + 20 + 4, 4000)
    add(bytes(bad), "udp_len_mismatch", "UDP length=4000 vượt quá IP payload")
    bad = bytearray(good); struct.pack_into("!H", bad, 14 + 20 + 4, 4)
    add(bytes(bad), "udp_len_mismatch", "UDP length=4 (<8)")

    # --- GTP-U ---
    add(udp_with(gtpu_raw(0x1001)[:5]), "gtp_truncated",
        "GTP-U chỉ có 5 byte (<8 byte bắt buộc)")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner, version=2)),
        "gtp_bad_version", "version=2 (GTPv2-C) trên cổng GTP-U")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner, pt=0)),
        "gtp_bad_pt", "PT=0 (GTP'), không phải GTP")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner, length=5000)),
        "gtp_len_mismatch", "GTP length=5000 lớn hơn phần còn lại của UDP")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner,
                          length=len(good_inner) - 7)),
        "gtp_len_mismatch", "GTP length nhỏ hơn thực tế (không khớp UDP length)")
    add(udp_with(gtpu_raw(0x1001, flags=(0, 1, 0), opt=(1, 0, 0))[:10]),
        "gtp_opt_truncated", "cờ S bật nhưng chỉ còn 2/4 byte tùy chọn")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner, flags=(1, 0, 0),
                          opt=(0, 0, 0x85), ext=bytes([0, 0x10, 9, 0]))),
        "gtp_ext_bad_len", "extension length=0 (cấm theo spec; dễ gây lặp vô hạn)")
    add(udp_with(gtpu_raw(0x1001, flags=(1, 0, 0), opt=(0, 0, 0x85),
                          ext=bytes([10, 0x10, 9, 0]))),
        "gtp_ext_truncated", "extension length=10 (40 byte) vượt quá gói")
    add(udp_with(gtpu_raw(0x1001, flags=(1, 0, 0), opt=(0, 0, 0x85),
                          ext=bytes([1, 0x10]))),
        "gtp_ext_truncated", "extension bị cắt giữa chừng (2/4 byte)")
    many = b"".join(ext_udp_port(1000 + i, 0x40) for i in range(64))
    add(udp_with(gtpu_raw(0x1001, payload=good_inner, flags=(1, 0, 0),
                          opt=(0, 0, 0x40), ext=many)),
        "gtp_ext_too_many",
        "chuỗi 64 extension header liên tiếp: nên đặt giới hạn số lượng")
    add(udp_with(gtpu_raw(0x1001, payload=good_inner[:12])),
        "inner_truncated", "G-PDU nhưng inner IPv4 chỉ có 12 byte")
    bad = bytearray(gtpu_raw(0x1001, payload=good_inner)); bad[8] = 0x43
    add(udp_with(bytes(bad)), "inner_bad_ihl", "inner IPv4 IHL=3 (<5)")

    # --- Gói bị cắt do snaplen (caplen < orig_len) ---
    add(good[:60], "ip_len_mismatch",
        "caplen=60 < orig_len: capture bị cắt, IP total length > caplen",
        orig_len=len(good))
    return pkts, rows


# ---------------------------------------------------------------------------
# File pcap hỏng để test pcap reader
# ---------------------------------------------------------------------------

def gen_bad_pcaps(out):
    one = bytes(outer() / GTP_U_Header(teid=0x1001) / inner_udp())
    files = {}

    # Big-endian (máy ghi là big-endian): hợp lệ, reader phải tự đổi byte.
    p = out / "pcap_big_endian.pcap"
    write_pcap(p, [one, one], endian=">")
    files[p] = "file ok 2 # magic big-endian, phải swap mọi trường header"

    p = out / "pcap_nanosec.pcap"
    write_pcap(p, [one], magic=PCAP_MAGIC_NS)
    files[p] = "file ok 1 # magic nano giây 0xa1b23c4d"

    p = out / "bad_pcap_magic.pcap"
    p.write_bytes(b"\xde\xad\xbe\xef" + pcap_global_header()[4:])
    files[p] = "file err:bad_magic 0"

    p = out / "bad_pcap_short_header.pcap"
    p.write_bytes(pcap_global_header()[:20])
    files[p] = "file err:truncated_global_header 0 # chỉ 20/24 byte"

    p = out / "bad_pcap_linktype.pcap"
    p.write_bytes(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, 113)
                  + pcap_record(one, 0))
    files[p] = "file err:unsupported_linktype 0 # 113 = Linux cooked (SLL)"

    p = out / "bad_pcap_truncated_record.pcap"
    p.write_bytes(pcap_global_header() + pcap_record(one, 0)
                  + pcap_record(one, 1)[:30])
    files[p] = "file err:truncated_record 1 # gói 2 bị cắt giữa chừng"

    p = out / "bad_pcap_caplen_huge.pcap"
    p.write_bytes(pcap_global_header(snaplen=65535) + pcap_record(one, 0)
                  + struct.pack("<IIII", BASE_TS, 0, 0x7FFFFFFF, 0x7FFFFFFF))
    files[p] = ("file err:caplen_too_large 1 "
                "# caplen=2^31-1: không được malloc theo trường này")

    p = out / "pcap_empty.pcap"
    p.write_bytes(pcap_global_header())
    files[p] = "file ok 0 # chỉ có global header, không có gói"

    for path, line in files.items():
        path.with_suffix(".expected").write_text(
            "# kết quả mong đợi của pcap reader: file <verdict> <số gói>\n"
            + line + "\n")
    return len(files)


# ---------------------------------------------------------------------------
# File lớn cho benchmark
# ---------------------------------------------------------------------------

def gen_bench(path, n_packets, n_sessions, seed=1):
    rng = random.Random(seed)
    templates = []
    for s in range(n_sessions):
        teid = 0x10000 + s
        ue_ip = f"10.{45 + (s >> 16) % 200}.{(s >> 8) & 0xFF}.{s & 0xFF}"
        size = rng.choice([40, 200, 600, 1300])
        if s % 2:
            gtp = GTP_U_Header(teid=teid, E=1, next_ex=0x85) \
                / GTPPDUSessionContainer(type=1, QFI=1 + s % 9)
            o = outer(GNB_IP, UPF_IP)
        else:
            gtp = GTP_U_Header(teid=teid)
            o = outer()
        templates.append(bytes(o / gtp / inner_udp(src=ue_ip,
                                                   payload=b"x" * size)))
    # Phân phối lệch (vài phiên "nặng") cho giống thực tế hơn uniform.
    weights = [1.0 / (i + 1) ** 0.8 for i in range(n_sessions)]
    picks = rng.choices(range(n_sessions), weights=weights, k=n_packets)
    with open(path, "wb") as f:
        f.write(pcap_global_header())
        for i, s in enumerate(picks):
            data = templates[s]
            f.write(struct.pack("<IIII", BASE_TS + i // 1_000_000,
                                i % 1_000_000, len(data), len(data)))
            f.write(data)
    print(f"bench: {n_packets} gói, {n_sessions} phiên -> {path} "
          f"({os.path.getsize(path) / 1e6:.1f} MB)")


# ---------------------------------------------------------------------------

FIXTURES = {
    "gtpu_basic": (gen_basic, "4G G-PDU cơ bản, không cờ tùy chọn"),
    "gtpu_optional_fields": (gen_optional_fields, "cờ S / PN, 4 byte tùy chọn"),
    "gtpu_5g_ext": (gen_5g_extensions, "5G extension header, QFI"),
    "gtpu_signalling": (gen_signalling, "Echo, Error Indication, End Marker"),
    "non_gtpu": (gen_non_gtpu, "gói không phải GTP-U, phải bị bỏ qua"),
    "malformed": (gen_malformed, "gói lỗi có chủ đích, mỗi gói một lý do"),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    root = Path(__file__).resolve().parent.parent
    ap.add_argument("--out-dir", type=Path, default=root / "tests" / "data")
    ap.add_argument("--bench-out", type=Path,
                    help="chỉ sinh file benchmark lớn vào đường dẫn này")
    ap.add_argument("--bench-packets", type=int, default=1_000_000)
    ap.add_argument("--bench-sessions", type=int, default=10_000)
    args = ap.parse_args()

    if args.bench_out:
        args.bench_out.parent.mkdir(parents=True, exist_ok=True)
        gen_bench(args.bench_out, args.bench_packets, args.bench_sessions)
        return 0

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    for name, (fn, desc) in FIXTURES.items():
        pkts, rows = fn()
        write_pcap(out / f"{name}.pcap", pkts)
        write_expected(out / f"{name}.expected", rows, desc)
        print(f"{name:24s} {len(pkts):3d} gói  — {desc}")
    n = gen_bad_pcaps(out)
    print(f"{'pcap reader cases':24s} {n:3d} file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
