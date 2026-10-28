"""Test phần đọc output và cắt lớp của giao diện.

    .venv/bin/python -m pytest tools/ui
"""

import json
import os

import builder
import dissect
import runner

TEXT_OUT = """\
#0    ok                       teid=0x00005001 G-PDU 10.45.0.2 -> 93.184.216.34
#1    ok                       teid=0x00000000 Echo Request
#2    err:gtp_truncated

Packets: 3   Bytes: 300

Result                            Count
ok                                    2
err:gtp_truncated                     1

Message type                      Count
G-PDU (255)                           1
Echo Request (1)                      1

QFI                               Count
9                                     1

Top 10 sessions by bytes
TEID        Endpoint         Packets      Bytes  Flows  QFI
0x00005001  192.168.40.1           1        103      1  9
0x00000000  192.168.20.1           1         50      1  -
"""


def test_parse_text():
    pk, sm = runner.parse_text(TEXT_OUT)
    assert [p["result"] for p in pk] == ["ok", "ok", "err:gtp_truncated"]
    assert pk[0]["teid"] == 0x5001 and pk[0]["inner_dst"] == "93.184.216.34"
    assert pk[1]["msg_type"] == 1 and pk[1]["inner_src"] is None
    assert pk[2]["teid"] is None
    assert sm["packets"] == 3 and sm["bytes"] == 300
    assert sm["results"] == {"ok": 2, "err:gtp_truncated": 1}
    assert sm["msg_types"] == {"255": 1, "1": 1}
    assert sm["qfi"] == {"9": 1}
    assert sm["top_sessions"][1] == {"teid": 0, "endpoint": "192.168.20.1",
                                     "packets": 1, "bytes": 50, "flows": 1,
                                     "qfi": None}


def test_parse_ndjson():
    lines = [
        {"type": "packet", "idx": 0, "result": "ok", "teid": 1, "qfi": 9},
        {"type": "summary", "packets": 1, "bytes": 90, "results": {"ok": 1}},
    ]
    pk, sm = runner.parse_ndjson("\n".join(json.dumps(x) for x in lines))
    assert pk == [{"idx": 0, "result": "ok", "teid": 1, "qfi": 9}]
    assert sm["bytes"] == 90


def _layers(frame):
    return {ly["key"]: ly for ly in dissect.dissect(frame)["layers"]}


def test_dissect_ext_chain():
    spec = {"gtp": {"teid": "0x5001", "ext": [
        {"type": "udp_port", "port": 40000},
        {"type": "pdu_dl", "qfi": 5, "rqi": 1}]}, "inner": {"proto": "tcp"}}
    ly = _layers(builder.build(spec))
    gtp = {f["name"]: f["text"] for f in ly["gtp"]["fields"]}
    assert gtp["TEID"] == "0x00005001" and gtp["E"] == "1"
    assert gtp["Next ext type"] == "0x40"
    ext = {f["name"]: f["text"] for f in ly["ext"]["fields"]}
    assert ext["#1 content"] == "9c40" and ext["#2 QFI"] == "5"
    assert ly["inner"]["start"] == ly["ext"]["end"]


def test_dissect_truncated_and_zero_len():
    frame = builder.build({"corrupt": {"truncate": 46}})
    gtp = _layers(frame)["gtp"]
    assert any(f["missing"] for f in gtp["fields"])
    assert gtp["end"] == 46

    ly = _layers(builder.build({"gtp": {"ext": [{"type": "pdu_ul"}]},
                                "corrupt": {"ext_len_zero": True}}))
    assert ly["ext"]["fields"][0]["value"] == 0
    assert "inner" not in ly  # dừng ở extension length = 0


def test_fixture_code_rebuilds_same_bytes():
    spec = {"gtp": {"teid": "0x7", "S": True, "seq": "3",
                    "ext": [{"type": "pdu_ul", "qfi": 2}]},
            "inner": {"proto": "udp", "size": "4"},
            "corrupt": {"truncate": "70"}}
    code = builder.fixture_code([spec], "t")
    ns = dict(vars(builder.g))
    exec(code, ns)
    pkts, _ = ns["gen_t"]()
    assert pkts[0] == builder.build(spec)


# ---------------------------------------------------------------------------
# Đối chiếu dissect.py với Wireshark: vị trí bit/byte của từng trường phải
# khớp với cách tshark (viết theo RFC 791/768, IEEE 802.3, 3GPP TS 29.281,
# TS 38.415) giải mã. Không có tshark thì bỏ qua.
# ---------------------------------------------------------------------------

import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402

import pytest  # noqa: E402

DATA = runner.ROOT / "tests" / "data"


def _ours(d):
    """Giá trị của dissect.py, gom theo tên field của tshark, theo thứ tự."""
    out = {}

    def put(k, v):
        out.setdefault(k, []).append(v)

    for ly in d["layers"]:
        f = {re.sub(r"^#\d+ ", "", x["name"]) + (f"@{i}" if x["name"].startswith("#") else ""): x
             for i, x in enumerate(ly["fields"])}
        val = {k: v["value"] for k, v in f.items()}
        txt = {k: v["text"] for k, v in f.items()}
        if any(x["missing"] for x in ly["fields"]):
            continue  # lớp bị cắt: tshark cũng không đưa ra đủ trường
        if ly["key"] == "eth":
            put("eth.dst", txt["Destination MAC"])
            put("eth.src", txt["Source MAC"])
            put("eth.type", val["EtherType"])
        elif ly["key"] in ("ip", "inner"):
            put("ip.version", val["Version"])
            put("ip.hdr_len", val["IHL"] * 4)
            put("ip.dsfield", val["DSCP / ECN"])
            put("ip.len", val["Total length"])
            put("ip.id", val["Identification"])
            put("ip.flags.df", (val["Flags"] >> 1) & 1)
            put("ip.flags.mf", val["Flags"] & 1)
            put("ip.ttl", val["TTL"])
            put("ip.proto", val["Protocol"])
            put("ip.checksum", val["Header checksum"])
            put("ip.src", txt["Source"])
            put("ip.dst", txt["Destination"])
        elif ly["key"] == "udp":
            put("udp.srcport", val["Source port"])
            put("udp.dstport", val["Destination port"])
            put("udp.length", val["Length"])
            put("udp.checksum", val["Checksum"])
        elif ly["key"] == "gtp":
            put("gtp.flags.version", val["Version"])
            put("gtp.flags.payload", val["PT"])
            put("gtp.flags.e", val["E"])
            put("gtp.flags.s", val["S"])
            put("gtp.flags.pn", val["PN"])
            put("gtp.message", val["Message type"])
            put("gtp.length", val["Length"])
            put("gtp.teid", val["TEID"])
            if "Next ext type" in val and val["E"]:
                put("gtp.ext_hdr.next", val["Next ext type"])
        elif ly["key"] == "ext":
            for name, x in f.items():
                base = name.split("@")[0]
                v = x["value"]
                if base == "length":
                    put("gtp.ext_hdr.length", v)
                elif base == "next type":
                    put("gtp.ext_hdr.next", v)
                elif base == "PDU type":
                    put("gtp.ext_hdr.pdu_ses_con.pdu_type", v)
                elif base == "QFI":
                    put("gtp.ext_hdr.pdu_ses_con.qos_flow_id", v)
                elif base in CONTAINER_BITS:
                    put(CONTAINER_BITS[base], v)
    return out


CONTAINER_BITS = {
    "QMP": "gtp.ext_hdr.pdu_ses_con.qmp",
    "SNP": "gtp.ext_hdr.pdu_ses_con.snp",
    "MSNP": "gtp.ext_hdr.pdu_ses_con.msnp",
    "PPP": "gtp.ext_hdr.pdu_ses_cont.ppp",
    "RQI": "gtp.ext_hdr.pdu_ses_cont.rqi",
    "DL Delay Ind": "gtp.ext_hdr.pdu_ses_con.dl_delay_ind",
    "UL Delay Ind": "gtp.ext_hdr.pdu_ses_con.ul_delay_ind",
    "N3/N9 Delay Ind": "gtp.ext_hdr.pdu_ses_con.n3_n9_delay_ind",
    "New IE Flag": "gtp.ext_hdr.pdu_ses_con.new_ie_flag",
}


def _num(s):
    if s in ("True", "False"):
        return int(s == "True")
    try:
        return int(s, 0)
    except ValueError:
        return s


@pytest.mark.skipif(shutil.which("tshark") is None, reason="cần tshark")
@pytest.mark.parametrize("name", ["gtpu_basic", "gtpu_optional_fields",
                                  "gtpu_5g_ext", "gtpu_signalling",
                                  "non_gtpu"])
def test_dissect_matches_tshark(name):
    _check_against_tshark(DATA / f"{name}.pcap")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="cần tshark")
def test_pdu_session_container_bits_match_tshark(tmp_path):
    """Bật lần lượt từng bit cờ của container (cả DL và UL), so tên bit."""
    g = builder.g
    payload = bytes(g.inner_udp())
    frames = []
    for ptype in (0, 1):
        for b1 in (8, 4, 2, 1):
            ext = bytes([1, (ptype << 4) | b1, 9, 0])
            frames.append(bytes(g.outer() / g.Raw(g.gtpu_raw(
                1, payload=payload, flags=(1, 0, 0), opt=(0, 0, 0x85),
                ext=ext))))
        for b2 in (0x80, 0x40):
            ext = bytes([1, ptype << 4, b2 | 9, 0])
            frames.append(bytes(g.outer() / g.Raw(g.gtpu_raw(
                1, payload=payload, flags=(1, 0, 0), opt=(0, 0, 0x85),
                ext=ext))))
    pcap = tmp_path / "bits.pcap"
    g.write_pcap(pcap, frames)
    _check_against_tshark(pcap)


def _check_against_tshark(pcap):
    fields = sorted({k for p in dissect.read_pcap(pcap)[0]
                     for k in _ours(dissect.dissect(p))})
    args = ["tshark", "-r", str(pcap), "-T", "json"]
    for k in fields:
        args += ["-e", k]
    ws = json.loads(subprocess.run(args, capture_output=True, text=True,
                                   check=True).stdout)
    pkts, _ = dissect.read_pcap(pcap)
    checked = 0
    for i, (frame, w) in enumerate(zip(pkts, ws)):
        ours = _ours(dissect.dissect(frame))
        theirs = w["_source"]["layers"]
        for k, mine in ours.items():
            got = [_num(x) for x in theirs.get(k, [])]
            if k.startswith("udp."):
                mine, got = mine[:1], got[:1]  # UDP bên trong không tách
            if k == "eth.type" and len(got) > 1:
                got = got[:1]
            assert mine == got[:len(mine)], f"gói {i} {k}: ours={mine} tshark={got}"
            checked += len(mine)
    assert checked > 0


def test_parse_keeps_totals_when_packets_capped():
    pk, sm = runner.parse_text(TEXT_OUT, limit=2)
    assert [p["idx"] for p in pk] == [0, 1]
    assert sm["packets"] == 3 and sm["results"]["ok"] == 2
    lines = [json.dumps({"type": "packet", "idx": i, "result": "ok"})
             for i in range(5)]
    lines.append(json.dumps({"type": "summary", "packets": 5}))
    pk, sm = runner.parse_ndjson("\n".join(lines), limit=3)
    assert len(pk) == 3 and sm["packets"] == 5


def test_test_filter_only_reaches_ctest():
    server = pytest.importorskip("server")
    assert "-R" not in server._step_cmd("build", False, "Ring")
    cmd = server._step_cmd("test", False, "Ring")
    assert cmd[-2:] == ["-R", "Ring"] and str(server.JUNIT_RERUN) in cmd
    assert "-R" not in server._step_cmd("test", False)


def test_rerun_results_overlay_full_run(tmp_path, monkeypatch):
    server = pytest.importorskip("server")
    full, rerun = tmp_path / "ctest.xml", tmp_path / "ctest-rerun.xml"
    case = '<testcase name="{}" status="run">{}</testcase>'
    full.write_text("<testsuite>" + case.format("A", "<failure/>")
                    + case.format("B", "") + "</testsuite>")
    rerun.write_text("<testsuite>" + case.format("A", "") + "</testsuite>")
    os.utime(full, (1, 1))
    monkeypatch.setattr(server, "JUNIT", full)
    monkeypatch.setattr(server, "JUNIT_RERUN", rerun)
    got = {t["name"]: t["status"] for t in server.tests()["tests"]}
    assert got == {"A": "pass", "B": "pass"}
    os.utime(rerun, (0, 0))  # bản chạy lại cũ hơn lần chạy đủ: bỏ qua
    assert {t["name"]: t["status"] for t in server.tests()["tests"]}["A"] == "fail"
