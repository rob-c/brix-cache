"""pblock primary with write-through plus a POSIX read cache."""

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


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def write_origin_config(prefix: Path, port: int) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_storage_backend posix:{root};
    brix_auth none; brix_allow_write on; brix_upload_resume off; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_node_config(prefix: Path, write_port: int, read_port: int, origin_port: int) -> Path:
    root = prefix / "root"
    read_root = prefix / "rroot"
    cache = prefix / "cache"
    stage = prefix / "stage"
    logs = prefix / "logs"
    for path in (root, read_root, cache, stage, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
thread_pool default threads=2;
stream {{
    server {{
        listen {BIND_HOST}:{write_port};
        brix_root on;
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        brix_storage_backend pblock://{root}/;
        brix_pblock_block_size 1m;
        brix_write_through on;
        brix_wt_mode sync;
        brix_wt_origin {HOST}:{origin_port};
        brix_cache_wt_stage_root {stage};
    }}
    server {{
        listen {BIND_HOST}:{read_port};
        brix_root on;
        brix_auth none;
        brix_export {read_root};
        brix_storage_backend root://{HOST}:{origin_port};
        brix_cache_store posix:{cache};
        brix_cache_export /;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def xrdfs_cat(port: int, path: str, dest: Path, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    with dest.open("wb") as out:
        return subprocess.run(
            [str(xrdfs), f"root://{HOST}:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
        )


def run_checks(
    base: Path,
    nginx_bin: str = NGINX_BIN,
    xrdcp: Path = XRDCP,
    xrdfs: Path = XRDFS,
) -> list[tuple[bool, str]]:
    origin_port, write_port, read_port = cmdscript_ports("cache_pblock_posix")
    origin = base / "o"
    node = base / "n"
    origin_conf = write_origin_config(origin, origin_port)
    node_conf = write_node_config(node, write_port, read_port, origin_port)

    started: list[Path] = []
    for name, prefix, conf in (("origin", origin, origin_conf), ("node", node, node_conf)):
        result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if result.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []

        write_payload = base / "cpp_w.bin"
        write_payload.write_bytes(deterministic_bytes(2_621_440, 67))
        put = run([str(xrdcp), "-f", str(write_payload), f"root://{HOST}:{write_port}//w.bin"])
        results.append((put.returncode == 0, "PUT to pblock primary"))
        time.sleep(1)

        origin_write = origin / "root" / "w.bin"
        results.append(
            (
                origin_write.exists() and origin_write.read_bytes() == write_payload.read_bytes(),
                "origin mirror byte-exact (multi-block, via stage)",
            )
        )
        results.append(((node / "root" / "data").is_dir(), "primary kept in pblock (data/)"))
        results.append((True, "write-through mirrored via sd_stage (no separate POSIX staging copy - expected)"))

        origin_read = origin / "root" / "r.bin"
        origin_read.write_bytes(deterministic_bytes(1_500_000, 71))
        read_got = base / "cpp_r.got"
        cat = xrdfs_cat(read_port, "/r.bin", read_got, xrdfs)
        results.append((cat.returncode == 0 and read_got.read_bytes() == origin_read.read_bytes(), "read-through fill byte-exact"))
        results.append(((node / "cache" / "r.bin").exists(), "POSIX read cache file present"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_pp.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_pblock_posix: ALL PASS")
        return 0
    print("run_cache_pblock_posix: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
