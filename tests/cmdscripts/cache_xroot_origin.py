"""Read cache with a root:// source backend."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from settings import NGINX_BIN, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
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
stream {{ server {{ listen 127.0.0.1:{port}; brix_root on; brix_export {root};
    brix_auth none; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_cache_config(prefix: Path, port: int, origin_port: int) -> Path:
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:{origin_port};
    brix_cache_store posix:{cache};
    brix_cache_export /;
}} }}
""",
        encoding="utf-8",
    )
    return conf


def xrdfs_cat(port: int, path: str, dest: Path, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    with dest.open("wb") as out:
        return subprocess.run(
            [str(xrdfs), f"root://127.0.0.1:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
        )


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdfs: Path = XRDFS) -> list[tuple[bool, str]]:
    if not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP cache root origin data plane (native xrdfs not built)")]

    origin_port, cache_port = free_ports(2)
    origin = base / "o"
    node = base / "n"
    origin_conf = write_origin_config(origin, origin_port)
    node_conf = write_cache_config(node, cache_port, origin_port)
    (origin / "root" / "small.bin").write_bytes(deterministic_bytes(600_000, 23))
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_800_000, 29))

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
        expected_small = (origin / "root" / "small.bin").read_bytes()

        small_got = base / "cache_xroot_s.got"
        small = xrdfs_cat(cache_port, "/small.bin", small_got, xrdfs)
        results.append(
            (
                small.returncode == 0 and small_got.read_bytes() == expected_small,
                "root origin fill byte-exact",
            )
        )
        results.append(((node / "cache" / "small.bin").exists(), "object landed in the local cache"))

        warm_got = base / "cache_xroot_s2.got"
        warm = xrdfs_cat(cache_port, "/small.bin", warm_got, xrdfs)
        results.append((warm.returncode == 0 and warm_got.read_bytes() == expected_small, "warm cache hit byte-exact"))

        big_got = base / "cache_xroot_b.got"
        big = xrdfs_cat(cache_port, "/big.bin", big_got, xrdfs)
        expected_big = (origin / "root" / "big.bin").read_bytes()
        results.append((big.returncode == 0 and big_got.read_bytes() == expected_big, "multi-chunk root fill byte-exact"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_xroot.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_xroot_origin: ALL PASS")
        return 0
    print("run_cache_xroot_origin: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
