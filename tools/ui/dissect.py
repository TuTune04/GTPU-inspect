"""Đọc pcap và cắt từng gói thành các lớp để vẽ lưới octet.

Chỉ phục vụ hiển thị: dung thứ gói hỏng (trường thiếu byte đánh dấu
missing) và không phán verdict. Verdict luôn lấy từ binary gtpu-inspect.
"""

import struct

GTPU_PORT = 2152
MAX_EXT = 80  # đủ cho fixture 64 extension, chặn vòng lặp vô hạn

# PDU Session Container: tên 4 bit sau PDU type và 2 bit trước QFI.
PDU_SESSION_BITS = {
    0: (("QMP", "SNP", "MSNP", "Spare"), ("PPP", "RQI")),
    1: (("QMP", "DL Delay Ind", "UL Delay Ind", "SNP"),
        ("N3/N9 Delay Ind", "New IE Flag")),
    None: (("Flag 4", "Flag 3", "Flag 2", "Flag 1"), ("Bit 8", "Bit 7")),
}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000), b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1),
}
MAX_RECORD = 262_144


def read_pcap(path, limit=None):
    """Trả về (danh sách bytes của từng gói, lỗi hoặc None)."""
    packets = []
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            return packets, "global header thiếu byte"
        fmt = PCAP_MAGICS.get(head[:4])
        if fmt is None:
            return packets, "magic không phải pcap"
        endian = fmt[0]
        while limit is None or len(packets) < limit:
            rec = f.read(16)
            if not rec:
                return packets, None
            if len(rec) < 16:
                return packets, "record header thiếu byte"
            _, _, caplen, _ = struct.unpack(endian + "IIII", rec)
            if caplen > MAX_RECORD:
                return packets, f"caplen {caplen} quá lớn"
            data = f.read(caplen)
            if len(data) < caplen:
                return packets, "record bị cắt"
            packets.append(data)
    return packets, None


class _Layer:
    def __init__(self, key, name, data, start):
        self.key, self.name, self.data, self.start = key, name, data, start
        self.end = start
        self.fields = []

    def field(self, name, off, bits, bit=0, fmt="dec", note=None):
        """Thêm trường tại byte `off` (tuyệt đối), bit `bit` tính từ MSB."""
        first_bit = off * 8 + bit
        last_byte = (first_bit + bits - 1) // 8
        missing = last_byte >= len(self.data)
        value = None
        if not missing:
            nbytes = last_byte - off + 1
            raw = int.from_bytes(self.data[off:off + nbytes], "big")
            shift = nbytes * 8 - bit - bits
            value = (raw >> shift) & ((1 << bits) - 1)
        self.fields.append({
            "name": name, "off": off, "bit": bit, "bits": bits,
            "value": value, "text": _fmt(value, fmt, bits), "missing": missing,
            "note": note,
        })
        self.end = max(self.end, min(last_byte + 1, len(self.data)))
        return value

    def bytes_field(self, name, off, length, fmt="hex"):
        avail = self.data[off:off + length]
        missing = len(avail) < length
        if fmt == "mac" and not missing:
            text = ":".join(f"{b:02x}" for b in avail)
        elif fmt == "ip" and not missing:
            text = ".".join(str(b) for b in avail)
        elif not missing:
            text = avail.hex() if length <= 8 else f"{length} byte"
        else:
            text = None
        self.fields.append({
            "name": name, "off": off, "bit": 0, "bits": length * 8,
            "value": None, "text": text, "missing": missing, "note": None,
        })
        self.end = max(self.end, min(off + length, len(self.data)))

    def out(self, declared_end=None):
        return {
            "key": self.key, "name": self.name, "start": self.start,
            "end": self.end,
            "declared_end": declared_end if declared_end is not None
            else self.end,
            "fields": self.fields,
        }


def _fmt(value, fmt, bits):
    if value is None:
        return None
    if fmt == "hex":
        return f"0x{value:0{max(2, (bits + 3) // 4)}x}"
    if fmt == "ip":
        return ".".join(str((value >> s) & 0xFF) for s in (24, 16, 8, 0))
    return str(value)


def _ipv4(layers, data, off, key, name):
    ly = _Layer(key, name, data, off)
    ver = ly.field("Version", off, 4)
    ihl = ly.field("IHL", off, 4, bit=4, note="đơn vị 4 byte")
    ly.field("DSCP / ECN", off + 1, 8, fmt="hex")
    total = ly.field("Total length", off + 2, 16)
    ly.field("Identification", off + 4, 16, fmt="hex")
    flags = ly.field("Flags", off + 6, 3, fmt="hex")
    frag = ly.field("Fragment offset", off + 6, 13, bit=3)
    ly.field("TTL", off + 8, 8)
    proto = ly.field("Protocol", off + 9, 8)
    ly.field("Header checksum", off + 10, 16, fmt="hex")
    ly.bytes_field("Source", off + 12, 4, fmt="ip")
    ly.bytes_field("Destination", off + 16, 4, fmt="ip")
    hlen = (ihl or 5) * 4
    if ihl is not None and ihl > 5:
        ly.bytes_field("Options", off + 20, hlen - 20)
    layers.append(ly.out())
    fragment = bool((flags or 0) & 1 or frag)  # MF = 1 hoặc offset ≠ 0
    return ver, max(hlen, 20), proto, total, fragment


def dissect(data):
    """Cắt gói thành các lớp. Trả về dict {len, layers}."""
    layers = []
    n = len(data)

    eth = _Layer("eth", "Ethernet", data, 0)
    eth.bytes_field("Destination MAC", 0, 6, fmt="mac")
    eth.bytes_field("Source MAC", 6, 6, fmt="mac")
    etype = eth.field("EtherType", 12, 16, fmt="hex")
    layers.append(eth.out())
    off = 14
    if etype != 0x0800 or off >= n:
        return _rest(data, off, layers)

    _, hlen, proto, _, fragment = _ipv4(layers, data, off, "ip", "IPv4")
    off += hlen
    # Mảnh IP: phần sau chỉ có nghĩa khi ghép đủ mảnh (parser trả
    # ignored:ip_fragment, Wireshark cũng dừng ở đây).
    if proto != 17 or fragment or off >= n:
        return _rest(data, off, layers)

    udp = _Layer("udp", "UDP", data, off)
    udp.field("Source port", off, 16)
    dport = udp.field("Destination port", off + 2, 16)
    udp.field("Length", off + 4, 16)
    udp.field("Checksum", off + 6, 16, fmt="hex")
    layers.append(udp.out())
    off += 8
    if dport != GTPU_PORT or off >= n:
        return _rest(data, off, layers)

    gtp = _Layer("gtp", "GTP-U", data, off)
    gtp.field("Version", off, 3)
    gtp.field("PT", off, 1, bit=3)
    gtp.field("(*)", off, 1, bit=4)
    e = gtp.field("E", off, 1, bit=5)
    s = gtp.field("S", off, 1, bit=6)
    pn = gtp.field("PN", off, 1, bit=7)
    mtype = gtp.field("Message type", off + 1, 8)
    length = gtp.field("Length", off + 2, 16, note="byte sau 8 byte đầu")
    gtp.field("TEID", off + 4, 32, fmt="hex")
    gtp_start = off
    off += 8
    nxt = 0
    if e or s or pn:
        gtp.field("Sequence number", off, 16)
        gtp.field("N-PDU number", off + 2, 8)
        nxt = gtp.field("Next ext type", off + 3, 8, fmt="hex") or 0
        off += 4
    declared = gtp_start + 8 + length if length is not None else None
    layers.append(gtp.out(declared))

    if e and nxt and off < n:
        ext = _Layer("ext", "Extension", data, off)
        count = 0
        while nxt and off < n and count < MAX_EXT:
            count += 1
            elen = ext.field(f"#{count} length", off, 8,
                             note=f"type 0x{nxt:02x}, đơn vị 4 byte")
            if not elen:
                # length = 0: không biết extension dài bao nhiêu, dừng hẳn.
                layers.append(ext.out())
                return _rest(data, off + 1, layers)
            size = elen * 4
            if nxt == 0x85:
                # Bố cục theo TS 38.415 §5.5.2, khác nhau giữa DL và UL.
                ptype = ext.field(f"#{count} PDU type", off + 1, 4,
                                  note="0 = DL, 1 = UL")
                bits = PDU_SESSION_BITS.get(ptype, PDU_SESSION_BITS[None])
                for i, name in enumerate(bits[0]):
                    ext.field(f"#{count} {name}", off + 1, 1, bit=4 + i)
                for i, name in enumerate(bits[1]):
                    ext.field(f"#{count} {name}", off + 2, 1, bit=i)
                ext.field(f"#{count} QFI", off + 2, 6, bit=2)
                if size > 4:
                    ext.bytes_field(f"#{count} content", off + 3, size - 4)
            elif size > 2:
                ext.bytes_field(f"#{count} content", off + 1, size - 2)
            nxt = ext.field(f"#{count} next type", off + size - 1, 8,
                            fmt="hex") or 0
            off += size
        layers.append(ext.out())

    if mtype == 255 and off < n:
        if off + 20 <= n and data[off] >> 4 == 4:
            _, hlen, _, _, _ = _ipv4(layers, data, off, "inner", "IP bên trong")
            off += hlen
        else:
            inner = _Layer("inner", "IP bên trong", data, off)
            inner.bytes_field("Header", off, 20)
            layers.append(inner.out())
            off = n
    return _rest(data, off, layers)


def _rest(data, off, layers):
    if off < len(data):
        layers.append({"key": "payload", "name": "Payload", "start": off,
                       "end": len(data), "declared_end": len(data),
                       "fields": []})
    return {"len": len(data), "hex": data.hex(), "layers": layers}


# Verdict -> (lớp, trường) để viền đỏ chỗ parser dừng.
VERDICT_FIELD = {
    "err:eth_truncated": ("eth", None),
    "err:ip_truncated": ("ip", None),
    "err:ip_bad_ihl": ("ip", "IHL"),
    "err:ip_bad_version": ("ip", "Version"),
    "err:ip_len_mismatch": ("ip", "Total length"),
    "err:udp_truncated": ("udp", None),
    "err:udp_len_mismatch": ("udp", "Length"),
    "err:gtp_truncated": ("gtp", None),
    "err:gtp_bad_version": ("gtp", "Version"),
    "err:gtp_bad_pt": ("gtp", "PT"),
    "err:gtp_len_mismatch": ("gtp", "Length"),
    "err:gtp_opt_truncated": ("gtp", None),
    "err:gtp_ext_bad_len": ("ext", "length"),
    "err:gtp_ext_truncated": ("ext", None),
    "err:gtp_ext_too_many": ("ext", None),
    "err:inner_truncated": ("inner", None),
    "err:inner_bad_ihl": ("inner", "IHL"),
    "ignored:not_ipv4": ("eth", "EtherType"),
    "ignored:not_udp": ("ip", "Protocol"),
    "ignored:not_gtpu_port": ("udp", "Destination port"),
    "ignored:ip_fragment": ("ip", "Flags"),
}


def blame(verdict):
    """Lớp và trường (khớp theo hậu tố tên) mà verdict trỏ tới."""
    layer, field = VERDICT_FIELD.get(verdict, (None, None))
    return {"layer": layer, "field": field}
