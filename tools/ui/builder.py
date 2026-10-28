"""Dựng gói từ form của tab "Tạo gói", dùng lại helper của gen_pcaps.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gen_pcaps as g  # noqa: E402
from scapy.all import ICMP, IP, Raw  # noqa: E402

EXT_TYPE = {"pdu_ul": 0x85, "pdu_dl": 0x85, "udp_port": 0x40}


def _int(v, default, lo=0, hi=0xFFFFFFFF):
    try:
        x = int(str(v), 0) if v not in (None, "") else default
    except ValueError:
        raise ValueError(f"không đọc được số: {v!r}")
    if not lo <= x <= hi:
        raise ValueError(f"{x} nằm ngoài khoảng {lo}..{hi}")
    return x


def _ext_bytes(exts):
    out = b""
    for i, x in enumerate(exts):
        nxt = EXT_TYPE[exts[i + 1]["type"]] if i + 1 < len(exts) else 0
        kind = x["type"]
        if kind == "pdu_ul":
            out += g.ext_pdu_session_ul(_int(x.get("qfi"), 9, 0, 63), nxt)
        elif kind == "pdu_dl":
            out += g.ext_pdu_session_dl(_int(x.get("qfi"), 9, 0, 63),
                                        _int(x.get("rqi"), 0, 0, 1), nxt)
        elif kind == "udp_port":
            out += g.ext_udp_port(_int(x.get("port"), 2152, 0, 0xFFFF), nxt)
        else:
            raise ValueError(f"extension không hỗ trợ: {kind}")
    return out


def _inner(spec):
    proto = spec.get("proto", "udp")
    size = _int(spec.get("size"), 12, 0, 9000)
    src, dst = spec.get("src") or "10.45.0.2", spec.get("dst") or "8.8.8.8"
    if proto == "none":
        return b"x" * size
    if proto == "tcp":
        return bytes(g.inner_tcp(src, dst, payload=b"x" * size))
    if proto == "icmp":
        return bytes(IP(src=src, dst=dst, id=1) / ICMP() / (b"x" * size))
    return bytes(g.inner_udp(src, dst, payload=b"x" * size))


def build(spec):
    """spec (dict từ form) -> bytes của một frame Ethernet."""
    o, gt = spec.get("outer", {}), spec.get("gtp", {})
    bad = spec.get("corrupt", {})
    exts = gt.get("ext", [])
    s, pn = int(bool(gt.get("S"))), int(bool(gt.get("PN")))
    e = int(bool(exts))
    msg_type = _int(gt.get("msg_type"), 255, 0, 255)
    payload = _inner(spec.get("inner", {})) if msg_type == 255 else b""
    ext = _ext_bytes(exts)
    if ext and bad.get("ext_len_zero"):
        ext = b"\x00" + ext[1:]
    gtp = g.gtpu_raw(
        _int(gt.get("teid"), 0x1001), msg_type=msg_type, payload=payload,
        flags=(e, s, pn),
        opt=(_int(gt.get("seq"), 0, 0, 0xFFFF), _int(gt.get("npdu"), 0, 0, 255),
             EXT_TYPE[exts[0]["type"]] if exts else 0),
        ext=ext,
        length=None if bad.get("gtp_length") in (None, "")
        else _int(bad["gtp_length"], 0, 0, 0xFFFF),
        version=_int(bad.get("version"), 1, 0, 7),
        pt=_int(bad.get("pt"), 1, 0, 1))
    frame = bytes(g.outer(o.get("src") or g.GNB_IP, o.get("dst") or g.UPF_IP,
                          _int(o.get("sport"), 2152, 0, 0xFFFF),
                          _int(o.get("dport"), 2152, 0, 0xFFFF)) / Raw(gtp))
    cut = bad.get("truncate")
    if cut not in (None, ""):
        frame = frame[:_int(cut, len(frame), 0, len(frame))]
    return frame


def write(path, specs):
    frames = [build(s) for s in specs]
    path.parent.mkdir(parents=True, exist_ok=True)
    # Gói cắt bằng form là gói "thật sự ngắn": caplen = orig_len, giống
    # các fixture trong malformed.pcap.
    g.write_pcap(path, frames)
    return frames


def fixture_code(specs, name="my_case"):
    """Đoạn Python để dán vào gen_pcaps.py (dựng lại đúng các gói này)."""
    lines = [f"def gen_{name}():",
             '    """Sinh từ giao diện tools/ui; sửa note và verdict cho đúng."""',
             "    pkts, rows = [], []"]
    for sp in specs:
        o, gt = sp.get("outer", {}), sp.get("gtp", {})
        bad, inner = sp.get("corrupt", {}), sp.get("inner", {})
        exts = gt.get("ext", [])
        ext_parts = []
        for i, x in enumerate(exts):
            nxt = f"0x{EXT_TYPE[exts[i + 1]['type']]:02x}" if i + 1 < len(exts) \
                else "0"
            if x["type"] == "pdu_ul":
                ext_parts.append(f"ext_pdu_session_ul({x.get('qfi', 9)}, {nxt})")
            elif x["type"] == "pdu_dl":
                ext_parts.append(f"ext_pdu_session_dl({x.get('qfi', 9)}, "
                                 f"{x.get('rqi', 0)}, {nxt})")
            else:
                ext_parts.append(f"ext_udp_port({x.get('port', 2152)}, {nxt})")
        ext = " + ".join(ext_parts) or 'b""'
        if exts and bad.get("ext_len_zero"):
            ext = f"b'\\x00' + ({ext})[1:]"
        proto = inner.get("proto", "udp")
        size = inner.get("size", 12)
        src = inner.get("src") or "10.45.0.2"
        dst = inner.get("dst") or "8.8.8.8"
        payload = {
            "udp": f'bytes(inner_udp("{src}", "{dst}", payload=b"x" * {size}))',
            "tcp": f'bytes(inner_tcp("{src}", "{dst}", payload=b"x" * {size}))',
            "icmp": f'bytes(IP(src="{src}", dst="{dst}", id=1) / ICMP() '
                    f'/ (b"x" * {size}))',
            "none": f'b"x" * {size}',
        }[proto]
        msg = gt.get("msg_type", 255)
        if str(msg) != "255":
            payload = 'b""'
        first = f"0x{EXT_TYPE[exts[0]['type']]:02x}" if exts else "0"
        args = [f"{gt.get('teid', '0x1001')}", f"msg_type={msg}",
                f"payload={payload}",
                f"flags=({int(bool(exts))}, {int(bool(gt.get('S')))}, "
                f"{int(bool(gt.get('PN')))})",
                f"opt=({gt.get('seq') or 0}, {gt.get('npdu') or 0}, {first})",
                f"ext={ext}"]
        if bad.get("gtp_length") not in (None, ""):
            args.append(f"length={bad['gtp_length']}")
        if bad.get("version") not in (None, "", 1, "1"):
            args.append(f"version={bad['version']}")
        if bad.get("pt") not in (None, "", 1, "1"):
            args.append(f"pt={bad['pt']}")
        outer = (f'outer("{o.get("src") or g.GNB_IP}", '
                 f'"{o.get("dst") or g.UPF_IP}", {o.get("sport") or 2152}, '
                 f'{o.get("dport") or 2152})')
        expr = f"bytes({outer} / Raw(gtpu_raw(\n        " + \
            ",\n        ".join(args) + ")))"
        if bad.get("truncate") not in (None, ""):
            expr += f"[:{bad['truncate']}]"
        lines.append(f"    pkts.append({expr})")
        lines.append('    rows.append(("ok", None, None, None, "TODO: ghi chú"))')
    lines.append("    return pkts, rows")
    return "\n".join(lines) + "\n"
