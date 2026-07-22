"""pblock cache + pblock stage command flow."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"


def is_pblock(path: Path) -> bool:
    data = path / "data"
    if not data.is_dir():
        return False
    has_catalog = any(path.glob("*.db")) or any(path.glob("catalog*"))
    has_blocks = any(item.is_file() for item in data.rglob("*"))
    return has_catalog or has_blocks


def write_origin_config(prefix: Path, port: int) -> Path:
    conf = prefix / "nginx.conf"
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {root};
    brix_auth none; brix_allow_write on; brix_upload_resume off; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_node_config(prefix: Path, port: int, origin_port: int) -> Path:
    conf = prefix / "nginx.conf"
    root = prefix / "root"
    cache = prefix / "cacheB"
    stage = prefix / "stageC"
    logs = prefix / "logs"
    for path in (root, cache, stage, prefix / "state", logs):
        path.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
thread_pool default threads=2;
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {root};
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend root://{HOST}:{origin_port};
        brix_cache_store pblock:{cache} block_size=1m;
        brix_cache_export  /;
        brix_stage on;
        brix_stage_store pblock:{stage} block_size=1m;
        brix_stage_flush sync;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start_nginx(nginx_bin: str, prefix: Path, conf: Path) -> subprocess.CompletedProcess:
    return run([nginx_bin, "-p", str(prefix), "-c", str(conf)])


def stop_nginx(prefix: Path) -> None:
    pidfile = prefix / "nginx.pid"
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def run_checks(
    base: Path,
    nginx_bin: str = NGINX_BIN,
    xrdcp: Path = XRDCP,
    xrdfs: Path = XRDFS,
) -> list[tuple[bool, str]]:
    origin_port, node_port = cmdscript_ports("cache_pblock_pblock")
    origin = base / "o"
    node = base / "n"
    origin_conf = write_origin_config(origin, origin_port)
    node_conf = write_node_config(node, node_port, origin_port)
    results: list[tuple[bool, str]] = []

    origin_start = start_nginx(nginx_bin, origin, origin_conf)
    if origin_start.returncode != 0:
        return [(False, f"origin failed: {(origin_start.stderr or origin_start.stdout)[-4000:]}")]
    node_start = start_nginx(nginx_bin, node, node_conf)
    if node_start.returncode != 0:
        stop_nginx(origin)
        return [(False, f"node failed: {(node_start.stderr or node_start.stdout)[-4000:]}")]

    try:
        time.sleep(1)

        write_payload = base / "cpb_w.bin"
        write_payload.write_bytes(deterministic_bytes(2_621_440, 17))
        put = run([str(xrdcp), "-f", str(write_payload), f"root://{HOST}:{node_port}//w.bin"])
        results.append((put.returncode == 0, "PUT through the stage tier"))
        time.sleep(1)

        backend_write = origin / "root" / "w.bin"
        if backend_write.exists():
            results.append(
                (
                    backend_write.read_bytes() == write_payload.read_bytes(),
                    "backend copy byte-exact (via pblock stage)",
                )
            )
        else:
            results.append((False, "backend file missing - stage flush did not run"))
        results.append((is_pblock(node / "stageC"), "stage tier is pblock"))

        backend_read = origin / "root" / "r.bin"
        backend_read.write_bytes(deterministic_bytes(1_500_000, 43))
        read_got = base / "cpb_r.got"
        with read_got.open("wb") as out:
            cat = subprocess.run(
                [str(xrdfs), f"root://{HOST}:{node_port}", "cat", "/r.bin"],
                stdout=out,
                stderr=subprocess.PIPE,
                text=False,
            )
        results.append(
            (cat.returncode == 0 and read_got.read_bytes() == backend_read.read_bytes(),
             "read-through fill byte-exact")
        )
        results.append((is_pblock(node / "cacheB"), "read cache is pblock"))

        sidecars = list((node / "cacheB").rglob("*.meta"))
        sidecars.extend((node / "cacheB").rglob("*.cinfo"))
        sidecars.extend((node / "stageC").rglob("*.meta"))
        sidecars.extend((node / "stageC").rglob("*.cinfo"))
        results.append((not sidecars, "no POSIX sidecars leaked into the pblock stores"))

        hidden = origin / "root" / "r.bin.hidden"
        backend_read.rename(hidden)
        warm_got = base / "cpb_r2.got"
        with warm_got.open("wb") as out:
            warm = subprocess.run(
                [str(xrdfs), f"root://{HOST}:{node_port}", "cat", "/r.bin"],
                stdout=out,
                stderr=subprocess.PIPE,
                text=False,
            )
        results.append(
            (
                warm.returncode == 0 and warm_got.read_bytes() == hidden.read_bytes(),
                "warm hit byte-exact with the backend file hidden",
            )
        )
    finally:
        stop_nginx(node)
        stop_nginx(origin)

    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_pb.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_pblock_pblock: ALL PASS")
        return 0
    print("run_cache_pblock_pblock: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
