"""Storage backend scheme grammar and data-plane checks."""

from __future__ import annotations

from pathlib import Path
import hashlib
import os
import signal
import subprocess
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

_PORTS = cmdscript_ports("storage_backend_schemes")

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"


PARSE_OK = (
    ("posix:<path>", "brix_storage_backend posix:{data};"),
    ("posix://<path>", "brix_storage_backend posix://{data};"),
    ("pblock://<path>", "brix_storage_backend pblock://{pb};"),
    ("root://host:port", "brix_storage_backend root://{host}:{origin_port};"),
    ("roots://host:port", "brix_storage_backend roots://{host}:{origin_port};"),
    ("http://host/base", "brix_storage_backend http://origin.example:8080/d;"),
    ("https://host/base", "brix_storage_backend https://origin.example/d;"),
    ("s3://host:port/bucket", "brix_storage_backend s3://{host}:9000/mybucket;"),
    ("s3://host/bucket", "brix_storage_backend s3://s3.example.com/data;"),
    ("rados://pool/ns", "brix_storage_backend rados://mypool/myns;"),
    ("rados://pool", "brix_storage_backend rados://mypool;"),
    (
        "frm://+cache (tape alias)",
        "brix_storage_backend frm://stub/{tape}; brix_cache_store posix:{cache}; brix_cache_export /;",
    ),
)

PARSE_NO = (
    ("bare s3://", "brix_storage_backend s3://;", ("needs", "host", "bucket")),
    ("s3:// no bucket", "brix_storage_backend s3://{host}:9000;", ("needs", "bucket")),
    ("bare rados://", "brix_storage_backend rados://;", ("needs", "pool")),
    ("rados:/// empty pool", "brix_storage_backend rados:///ns;", ("needs", "pool")),
    (
        "frm:// without cache",
        "brix_storage_backend frm://stub/{tape};",
        ("nearline", "cache_store", "recall"),
    ),
)


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def stop_pidfile(pidfile: Path) -> None:
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def render_directives(template: str, base: Path, origin_port: int) -> str:
    return template.format(
        data=base / "data",
        pb=base / "pb",
        tape=base / "tape",
        cache=base / "cache",
        origin_port=origin_port,
        host=HOST,
    )


def write_parse_config(base: Path, port: int, directives: str) -> Path:
    conf = base / "t.conf"
    (base / "logs").mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"""daemon on; error_log {base / 'logs' / 'e.log'} info; pid {base / 't.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_auth none; {directives} }} }}
""",
        encoding="utf-8",
    )
    return conf


def parse_check(
    nginx_bin: str,
    base: Path,
    desc: str,
    directives: str,
    expect_ok: bool,
    patterns: tuple[str, ...] = (),
) -> tuple[bool, str]:
    port = _PORTS[0]  # was free_port()
    origin_port = _PORTS[1]  # was free_port()
    conf = write_parse_config(base, port, render_directives(directives, base, origin_port))
    result = run([nginx_bin, "-p", str(base), "-c", str(conf), "-t"])
    output = (result.stdout or "") + (result.stderr or "")
    if expect_ok:
        return result.returncode == 0, f"parse: {desc}"
    if result.returncode == 0:
        return False, f"reject: {desc} (expected reject)"
    lowered = output.lower()
    return any(pattern in lowered for pattern in patterns), f"reject: {desc}"


def posix_data_plane(base: Path, nginx_bin: str, xrdcp: Path = XRDCP) -> tuple[bool, str]:
    if not os.access(xrdcp, os.X_OK):
        return True, "SKIP posix:// data plane (native xrdcp not built)"
    port = _PORTS[2]  # was free_port()
    data = base / "data"
    logs = base / "logs"
    data.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    payload = data / "blob.bin"
    payload.write_bytes(deterministic_bytes(200_000, 31))
    conf = base / "p.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'p.log'} info; pid {base / 'p.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_auth none; brix_storage_backend posix://{data}; }} }}
""",
        encoding="utf-8",
    )
    start = run([nginx_bin, "-p", str(base), "-c", str(conf)])
    if start.returncode != 0:
        return False, "posix:// node start"
    try:
        time.sleep(1)
        got = base / "got.bin"
        cp = run([str(xrdcp), f"root://{HOST}:{port}//blob.bin", str(got), "-f"])
        return cp.returncode == 0 and got.read_bytes() == payload.read_bytes(), "posix:// GET byte-exact (no brix_export)"
    finally:
        stop_pidfile(base / "p.pid")
        time.sleep(0.2)


def frm_data_plane(base: Path, nginx_bin: str, xrdfs: Path = XRDFS) -> tuple[bool, str]:
    if not os.access(xrdfs, os.X_OK):
        return True, "SKIP frm:// data plane (native xrdfs not built)"
    port = _PORTS[3]  # was free_port()
    tape = base / "tape"
    fcache = base / "fcache"
    fexport = base / "fexport"
    flogs = base / "flogs"
    for path in (tape, fcache, fexport, flogs):
        path.mkdir(parents=True, exist_ok=True)
    payload = tape / "f.bin"
    payload.write_bytes(deterministic_bytes(400_000, 47))
    expected_sha = hashlib.sha256(payload.read_bytes()).hexdigest()
    conf = base / "f.conf"
    conf.write_text(
        f"""daemon on; error_log {flogs / 'e.log'} info; pid {base / 'f.pid'};
env BRIX_FRM_STUB_RECALL_DELAY_MS=800;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {fexport}; brix_auth none;
    brix_storage_backend frm://stub{base}/tape;
    brix_cache_store posix:{fcache}; }} }}
""",
        encoding="utf-8",
    )
    start = run([nginx_bin, "-p", str(base), "-c", str(conf)])
    if start.returncode != 0:
        return False, "frm:// node start"
    try:
        time.sleep(1)
        stat = run([str(xrdfs), f"root://{HOST}:{port}", "stat", "/f.bin"])
        if "Offline" not in (stat.stdout or ""):
            return False, "frm:// nearline object reports Offline"
        got = base / "f.got"
        try:
            with got.open("wb") as out:
                cat = subprocess.run(
                    [str(xrdfs), f"root://{HOST}:{port}", "cat", "/f.bin"],
                    stdout=out,
                    stderr=subprocess.PIPE,
                    timeout=60,
                )
        except subprocess.TimeoutExpired:
            return False, "frm:// cat timed out after 60s (recall stalled)"
        got_sha = hashlib.sha256(got.read_bytes()).hexdigest() if got.exists() else ""
        return cat.returncode == 0 and got_sha == expected_sha, "frm:// cat byte-exact (recall via sd_frm+sd_cache)"
    finally:
        stop_pidfile(base / "f.pid")


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    for path in (base / "logs", base / "cache", base / "data"):
        path.mkdir(parents=True, exist_ok=True)
    results = [
        parse_check(nginx_bin, base, desc, directives, True)
        for desc, directives in PARSE_OK
    ]
    results.extend(
        parse_check(nginx_bin, base, desc, directives, False, patterns)
        for desc, directives, patterns in PARSE_NO
    )
    results.append(posix_data_plane(base, nginx_bin))
    results.append(frm_data_plane(base, nginx_bin))
    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sbschemes.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_storage_backend_schemes: ALL PASS")
        return 0
    print("run_storage_backend_schemes: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
