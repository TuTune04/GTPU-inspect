"""Chạy gtpu-inspect / tshark và đọc kết quả thành dict cho giao diện."""

import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
BINARY = BUILD / "gtpu-inspect"

MSG_TYPES = {"Echo Request": 1, "Echo Response": 2, "Error Indication": 26,
             "End Marker": 254, "G-PDU": 255}

_PKT_RE = re.compile(
    r"^#(\d+)\s+(\S+)"
    r"(?:\s+teid=0x([0-9a-fA-F]+)\s+(.*?)"
    r"(?:\s+(\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+))?)?\s*$")
_SESSION_RE = re.compile(
    r"^0x([0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$")
_COUNT_RE = re.compile(r"^(.*?)\s+(\d+)$")

# shortcut: chỉ giữ chi tiết MAX_PACKETS gói đầu (bảng cũng chỉ hiện chừng
# đó); tổng số gói vẫn đúng. Cần phân trang khi muốn duyệt hết file lớn.
MAX_PACKETS = 3000

_json_support = {}  # mtime của binary -> binary có hỗ trợ -j không


def _int_or_none(s):
    return None if s in (None, "-", "") else int(s)


def parse_text(stdout, limit=MAX_PACKETS):
    """Đọc output `gtpu-inspect -v` (định dạng text hiện tại)."""
    packets = []
    summary = {"packets": 0, "bytes": 0, "results": {}, "msg_types": {},
               "qfi": {}, "top_sessions": []}
    section = None
    for line in stdout.splitlines():
        m = _PKT_RE.match(line)
        if m and len(packets) >= limit:
            continue
        if m:
            idx, verdict, teid, name, src, dst = m.groups()
            name = name.strip() if name else None
            packets.append({
                "idx": int(idx), "result": verdict,
                "teid": int(teid, 16) if teid else None,
                "msg_type": MSG_TYPES.get(name) if name else None,
                "msg_name": name or None, "qfi": None,
                "inner_src": src, "inner_dst": dst, "len": None,
            })
            continue
        if line.startswith("Packets:"):
            nums = re.findall(r"\d+", line)
            summary["packets"], summary["bytes"] = int(nums[0]), int(nums[1])
            continue
        head = line.split()
        if not head:
            continue
        if head[0] == "Result" and line.rstrip().endswith("Count"):
            section = "results"
        elif line.startswith("Message type") and line.rstrip().endswith("Count"):
            section = "msg_types"
        elif head[0] == "QFI" and line.rstrip().endswith("Count"):
            section = "qfi"
        elif line.startswith("Top ") and "sessions" in line:
            section = "skip_header"
        elif section == "skip_header":
            section = "sessions"
        elif section == "sessions":
            m = _SESSION_RE.match(line)
            if m:
                teid, ep, pk, by, fl, qfi = m.groups()
                summary["top_sessions"].append({
                    "teid": int(teid, 16), "endpoint": ep, "packets": int(pk),
                    "bytes": int(by), "flows": int(fl),
                    "qfi": _int_or_none(qfi)})
        elif section in ("results", "msg_types", "qfi"):
            m = _COUNT_RE.match(line.strip())
            if m:
                key = m.group(1).strip()
                if section == "msg_types":
                    num = re.search(r"\((\d+)\)$", key)
                    key = num.group(1) if num else key
                summary[section][key] = int(m.group(2))
    return packets, summary


def parse_ndjson(stdout, limit=MAX_PACKETS):
    """Đọc output `gtpu-inspect -j` (xem docs/ui-design.md)."""
    packets, summary = [], {}
    for line in stdout.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        kind = obj.pop("type", None)
        if kind == "packet" and len(packets) < limit:
            packets.append(obj)
        elif kind == "summary":
            summary = obj
    return packets, summary


def _supports_json():
    key = BINARY.stat().st_mtime_ns
    if key not in _json_support:
        r = subprocess.run([str(BINARY), "-j", "/dev/null"],
                           capture_output=True, text=True, timeout=10)
        _json_support[key] = "usage" not in r.stderr
    return _json_support[key]


def analyze(pcap, top=10):
    if not BINARY.exists():
        return {"error": "no_binary"}
    use_json = _supports_json()
    args = [str(BINARY), "-j" if use_json else "-v", "-n", str(top), str(pcap)]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    try:
        packets, summary = (parse_ndjson if use_json else parse_text)(r.stdout)
    except (ValueError, KeyError) as e:
        return {"error": "bad_output", "detail": str(e), "stdout": r.stdout,
                "stderr": r.stderr, "rc": r.returncode}
    return {"format": "json" if use_json else "text", "packets": packets,
            "truncated": summary.get("packets", 0) > len(packets),
            "summary": summary, "stderr": r.stderr, "rc": r.returncode,
            "command": " ".join(args[:-1] + [Path(pcap).name])}


def read_expected(pcap):
    """Đọc file .expected cạnh pcap. Trả về dict hoặc None."""
    path = Path(pcap).with_suffix(".expected")
    if not path.exists():
        return None
    rows, file_line = [], None
    for line in path.read_text().splitlines():
        body, _, note = line.partition("#")
        parts = body.split()
        if not parts:
            continue
        if parts[0] == "file":
            file_line = {"verdict": parts[1], "packets": int(parts[2]),
                         "note": note.strip()}
            continue
        idx, verdict, teid, mtype, qfi = parts[:5]
        rows.append({"idx": int(idx), "result": verdict,
                     "teid": None if teid == "-" else int(teid, 16),
                     "msg_type": _int_or_none(mtype), "qfi": _int_or_none(qfi),
                     "note": note.strip()})
    return {"rows": rows, "file": file_line}


TSHARK_FIELDS = ["frame.number", "gtp.teid", "gtp.message",
                 "gtp.ext_hdr.pdu_ses_con.qos_flow_id", "_ws.expert.message"]


def tshark(pcap):
    exe = shutil.which("tshark")
    if exe is None:
        return {"error": "no_tshark"}
    args = [exe, "-r", str(pcap), "-c", str(MAX_PACKETS), "-T", "fields",
            "-E", "occurrence=f",
            "-E", "separator=\t"]
    for f in TSHARK_FIELDS:
        args += ["-e", f]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    rows = []
    for line in r.stdout.splitlines():
        cols = (line.split("\t") + [""] * 5)[:5]
        frame, teid, msg, qfi, expert = cols
        rows.append({
            "idx": int(frame) - 1,
            "teid": int(teid, 16) if teid else None,
            "msg_type": int(msg, 16) if msg.startswith("0x") else
            _int_or_none(msg),
            "qfi": _int_or_none(qfi), "expert": expert or None})
    return {"rows": rows, "stderr": r.stderr.strip() or None}


def compare(pcap):
    ours = analyze(pcap)
    exp = read_expected(pcap)
    if exp:
        exp["rows"] = exp["rows"][:MAX_PACKETS]
    ts = tshark(pcap)
    n = max(len(ours.get("packets", [])),
            len(exp["rows"]) if exp else 0, len(ts.get("rows", [])))
    by = lambda rows: {r["idx"]: r for r in rows}  # noqa: E731
    o, e, t = by(ours.get("packets", [])), by(exp["rows"] if exp else []), \
        by(ts.get("rows", []))
    rows, mism = [], 0
    for i in range(n):
        a, b, c = o.get(i), e.get(i), t.get(i)
        diff = []
        if b is not None:
            if a is None or a["result"] != b["result"]:
                diff.append("result")
            for k in ("teid", "msg_type", "qfi"):
                if a is None or a.get(k) != b.get(k):
                    # Output text chưa có QFI từng gói: không tính là lệch.
                    if k == "qfi" and ours.get("format") == "text":
                        continue
                    diff.append(k)
        if c is not None and a is not None and a["result"] == "ok":
            for k in ("teid", "msg_type", "qfi"):
                if k == "qfi" and ours.get("format") == "text":
                    continue
                if a.get(k) != c.get(k):
                    diff.append("ts_" + k)
        if diff:
            mism += 1
        rows.append({"idx": i, "ours": a, "expected": b, "tshark": c,
                     "diff": diff})
    return {"rows": rows, "mismatches": mism,
            "file": exp["file"] if exp else None,
            "has_expected": exp is not None, "ours_rc": ours.get("rc"),
            "ours_stderr": ours.get("stderr"), "ours_error": ours.get("error"),
            "format": ours.get("format"), "tshark_error": ts.get("error"),
            "truncated": ours.get("truncated", False)}
