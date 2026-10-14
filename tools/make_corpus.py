#!/usr/bin/env python3
"""Tách từng gói trong tests/data/*.pcap thành file riêng làm seed corpus
cho libFuzzer (fuzz/corpus/). Mỗi file là một frame Ethernet thô.

    python3 tools/make_corpus.py [--out fuzz/corpus]
"""
import argparse
import struct
from pathlib import Path

root = Path(__file__).resolve().parent.parent


def frames(path):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] != b"\xd4\xc3\xb2\xa1":
        return  # chỉ lấy pcap little-endian hợp lệ
    off = 24
    while off + 16 <= len(data):
        caplen = struct.unpack_from("<I", data, off + 8)[0]
        off += 16
        if off + caplen > len(data):
            return
        yield data[off:off + caplen]
        off += caplen


ap = argparse.ArgumentParser()
ap.add_argument("--out", type=Path, default=root / "fuzz" / "corpus")
args = ap.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
n = 0
for pcap in sorted((root / "tests" / "data").glob("*.pcap")):
    for i, frame in enumerate(frames(pcap)):
        (args.out / f"{pcap.stem}_{i:03d}").write_bytes(frame)
        n += 1
print(f"{n} seed -> {args.out}")
