"""Server giao diện web cho gtpu-inspect. Chạy:

    .venv/bin/python tools/ui/server.py [--port 8152]

Chỉ nghe 127.0.0.1. Xem docs/ui-design.md.
"""

import argparse
import re
import shutil
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent))
import builder  # noqa: E402
import dissect  # noqa: E402
import runner  # noqa: E402

ROOT = runner.ROOT
DATA = ROOT / "tests" / "data"
WORK = runner.BUILD / "ui"
STATIC = Path(__file__).resolve().parent / "static"
JUNIT = WORK / "ctest.xml"
MAX_UPLOAD = 256 * 1024 * 1024

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
_run_lock = threading.Lock()
_allowed_hosts = set()


@app.middleware("http")
async def guard(request: Request, call_next):
    # Host lạ: chặn DNS rebinding. POST thiếu header riêng: chặn trang web
    # khác gửi form/fetch "simple request" vào server này.
    if request.headers.get("host") not in _allowed_hosts:
        return JSONResponse({"detail": "host không hợp lệ"}, status_code=403)
    if request.method == "POST" and request.headers.get("x-gtpu-ui") != "1":
        return JSONResponse({"detail": "thiếu header X-GTPU-UI"},
                            status_code=403)
    return await call_next(request)


def _pcap(path):
    p = Path(path).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    p = p.resolve()
    if not p.is_file():
        raise HTTPException(404, f"không có file {path}")
    return p


def _rel(p):
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def _safe_name(name, default="custom"):
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name or default).stem)
    return (stem.strip("._") or default) + ".pcap"


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/status")
def status():
    b = runner.BINARY
    return {
        "binary": b.exists(),
        "binary_mtime": b.stat().st_mtime if b.exists() else None,
        "json": runner._supports_json() if b.exists() else None,
        "tshark": shutil.which("tshark") is not None,
        "wireshark": shutil.which("wireshark") is not None,
        "cmake": shutil.which("cmake") is not None,
        "configured": (runner.BUILD / "CMakeCache.txt").exists(),
    }


@app.get("/api/files")
def files():
    groups = []
    for title, folder in (("tests/data", DATA), ("build/ui", WORK),
                          ("build/ui/uploads", WORK / "uploads")):
        items = []
        for p in sorted(folder.glob("*.pcap")):
            if p.name.startswith("."):
                continue
            items.append({"path": _rel(p), "name": p.stem,
                          "size": p.stat().st_size,
                          "expected": p.with_suffix(".expected").exists()})
        if items:
            groups.append({"title": title, "files": items})
    return groups


@app.post("/api/upload")
async def upload(request: Request, name: str):
    body = await request.body()
    if len(body) > MAX_UPLOAD:
        raise HTTPException(413, "file quá lớn (tối đa 256 MB)")
    dest = WORK / "uploads" / _safe_name(name, "upload")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(body)
    return {"path": _rel(dest)}


@app.get("/api/analyze")
def analyze(path: str, top: int = 10):
    p = _pcap(path)
    res = runner.analyze(p, max(0, min(top, 1000)))
    res["path"] = _rel(p)
    return res


@app.get("/api/packet")
def packet(path: str, idx: int, verdict: str = ""):
    p = _pcap(path)
    pkts, err = dissect.read_pcap(p, limit=idx + 1)
    if idx < 0 or idx >= len(pkts):
        raise HTTPException(404, err or f"không có gói #{idx}")
    out = dissect.dissect(pkts[idx])
    out["blame"] = dissect.blame(verdict)
    return out


@app.post("/api/build")
async def build(request: Request):
    """Xem trước một gói trong danh sách: byte, các lớp, verdict của binary."""
    body = await request.json()
    specs, index = body.get("packets", []), int(body.get("index", 0))
    if not 0 <= index < len(specs):
        raise HTTPException(400, "index không hợp lệ")
    try:
        frames = builder.write(WORK / ".preview.pcap", specs)
    except ValueError as e:
        return {"error": str(e)}
    out = dissect.dissect(frames[index])
    res = runner.analyze(WORK / ".preview.pcap", 10)
    pkts = res.get("packets", [])
    verdict = pkts[index]["result"] if index < len(pkts) else None
    out.update({"verdict": verdict, "binary_error": res.get("error"),
                "blame": dissect.blame(verdict or ""),
                "packet": pkts[index] if index < len(pkts) else None})
    return out


@app.post("/api/save")
async def save(request: Request):
    body = await request.json()
    dest = WORK / _safe_name(body.get("name"))
    try:
        builder.write(dest, body.get("packets", []))
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"path": _rel(dest)}


@app.post("/api/fixture")
async def fixture(request: Request):
    body = await request.json()
    name = re.sub(r"\W", "_", body.get("name") or "my_case")
    return {"code": builder.fixture_code(body.get("packets", []), name)}


@app.get("/api/compare")
def compare(path: str):
    p = _pcap(path)
    res = runner.compare(p)
    res["path"] = _rel(p)
    return res


@app.post("/api/wireshark")
async def wireshark(request: Request):
    body = await request.json()
    p = _pcap(body.get("path", ""))
    exe = shutil.which("wireshark")
    if exe is None:
        raise HTTPException(404, "chưa cài wireshark")
    subprocess.Popen([exe, str(p)], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    return {"ok": True}


def _step_cmd(step, sanitize):
    if step == "configure":
        return ["cmake", "-B", str(runner.BUILD),
                f"-DGTPU_SANITIZE={'ON' if sanitize else 'OFF'}"]
    if step == "build":
        return ["cmake", "--build", str(runner.BUILD), "-j"]
    if step == "test":
        return ["ctest", "--test-dir", str(runner.BUILD),
                "--output-on-failure", "--output-junit", str(JUNIT)]
    raise HTTPException(400, f"bước không hợp lệ: {step}")


@app.post("/api/run")
async def run(request: Request):
    body = await request.json()
    cmd = _step_cmd(body.get("step"), bool(body.get("sanitize")))
    if body.get("filter"):
        cmd += ["-R", body["filter"]]
    if not _run_lock.acquire(blocking=False):
        raise HTTPException(409, "đang có một lệnh khác chạy")
    WORK.mkdir(parents=True, exist_ok=True)

    def stream():
        try:
            yield "$ " + " ".join(cmd) + "\n"
            proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    bufsize=1)
            for line in proc.stdout:
                yield line
            proc.wait()
            yield f"\n[exit {proc.returncode}]\n"
        finally:
            _run_lock.release()

    return StreamingResponse(stream(), media_type="text/plain; charset=utf-8")


@app.get("/api/tests")
def tests():
    if not JUNIT.exists():
        return {"tests": [], "time": None}
    root = ET.parse(JUNIT).getroot()
    out = []
    for tc in root.iter("testcase"):
        state = tc.get("status") or "run"
        if tc.find("failure") is not None or tc.find("error") is not None:
            state = "fail"
        elif tc.find("skipped") is not None or state in ("notrun", "disabled"):
            state = "skip"
        else:
            state = "pass"
        out.append({"name": tc.get("name"), "status": state,
                    "time": float(tc.get("time") or 0)})
    return {"tests": out, "time": JUNIT.stat().st_mtime}


app.mount("/static", StaticFiles(directory=STATIC), name="static")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8152)
    args = ap.parse_args()
    _allowed_hosts.update({f"127.0.0.1:{args.port}", f"localhost:{args.port}"})
    print(f"gtpu-inspect UI: http://127.0.0.1:{args.port}")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
