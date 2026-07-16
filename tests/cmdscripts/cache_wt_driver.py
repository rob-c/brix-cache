"""Write-through flushes to a root:// origin through the storage driver."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from settings import NGINX_BIN, free_ports

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
stream {{ server {{ listen 127.0.0.1:{port}; brix_root on; brix_storage_backend posix:{root};
    brix_auth none; brix_allow_write on; brix_upload_resume off; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_node_config(prefix: Path, port: int, origin_port: int, mode: str) -> Path:
    export = prefix / "export"
    logs = prefix / "logs"
    export.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_auth none;
    brix_storage_backend posix:{export};
    brix_allow_write on; brix_upload_resume off;
    brix_write_through on; brix_wt_mode {mode};
    brix_wt_origin root://127.0.0.1:{origin_port};
}} }}
""",
        encoding="utf-8",
    )
    return conf


def xrdcp_put(port: int, source: Path, dest: str, xrdcp: Path = XRDCP) -> subprocess.CompletedProcess:
    return run([str(xrdcp), "-f", str(source), f"root://127.0.0.1:{port}//{dest}"])


def xrdfs_cat(port: int, path: str, dest: Path, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    with dest.open("wb") as out:
        return subprocess.run(
            [str(xrdfs), f"root://127.0.0.1:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
        )


def wait_for_bytes(path: Path, expected: bytes, attempts: int = 40) -> bool:
    for _ in range(attempts):
        if path.exists() and path.read_bytes() == expected:
            return True
        time.sleep(0.1)
    return path.exists() and path.read_bytes() == expected


def run_checks(
    base: Path,
    nginx_bin: str = NGINX_BIN,
    xrdcp: Path = XRDCP,
    xrdfs: Path = XRDFS,
) -> list[tuple[bool, str]]:
    origin_port, sync_port, async_port = free_ports(3)
    origin = base / "o"
    sync = base / "s"
    async_node = base / "a"
    configs = (
        ("origin", origin, write_origin_config(origin, origin_port)),
        ("sync", sync, write_node_config(sync, sync_port, origin_port, "sync")),
        ("async", async_node, write_node_config(async_node, async_port, origin_port, "async")),
    )

    started: list[Path] = []
    for name, prefix, conf in configs:
        result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if result.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        small = deterministic_bytes(300_000, 83)
        big = deterministic_bytes(2_600_000, 89)
        small_path = base / "wt_drv_small.bin"
        big_path = base / "wt_drv_big.bin"
        small_path.write_bytes(small)
        big_path.write_bytes(big)

        sync_small = xrdcp_put(sync_port, small_path, "s_small.bin", xrdcp)
        results.append((sync_small.returncode == 0 and (sync / "export" / "s_small.bin").exists(), "write landed locally on S (write-through cache)"))
        results.append(((origin / "root" / "s_small.bin").exists() and (origin / "root" / "s_small.bin").read_bytes() == small, "flushed byte-exact to ORIGIN via driver"))

        sync_big = xrdcp_put(sync_port, big_path, "s_big.bin", xrdcp)
        results.append((sync_big.returncode == 0 and (origin / "root" / "s_big.bin").exists() and (origin / "root" / "s_big.bin").read_bytes() == big, "multi-chunk flushed byte-exact via driver"))

        async_small = xrdcp_put(async_port, small_path, "a_small.bin", xrdcp)
        async_ok = async_small.returncode == 0 and wait_for_bytes(origin / "root" / "a_small.bin", small)
        results.append((async_ok, "async flushed byte-exact to ORIGIN via driver"))

        read_got = base / "wt_drv_rb.got"
        read_back = xrdfs_cat(sync_port, "/s_small.bin", read_got, xrdfs)
        results.append((read_back.returncode == 0 and read_got.read_bytes() == small, "read-back byte-exact"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wt_drv.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_wt_driver: ALL PASS")
        return 0
    print("run_cache_wt_driver: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
