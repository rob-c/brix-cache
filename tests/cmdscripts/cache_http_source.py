"""Read cache with a plain HTTP source backend."""

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
http {{
    access_log off;
    server {{ listen 127.0.0.1:{port}; location / {{ root {root}; }} }}
}}
""",
        encoding="utf-8",
    )
    return conf


def write_cache_config(prefix: Path, port: int, origin_port: int) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_auth none;
    brix_storage_backend http://127.0.0.1:{origin_port};
    brix_cache_store posix:{cache}; brix_cache_export /;
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
        return [(True, "SKIP cache HTTP source data plane (native xrdfs not built)")]
    origin_port, cache_port = free_ports(2)
    origin = base / "o"
    node = base / "b"
    origin_conf = write_origin_config(origin, origin_port)
    node_conf = write_cache_config(node, cache_port, origin_port)
    (origin / "root" / "small.bin").write_bytes(deterministic_bytes(500_000, 101))
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_600_000, 109))

    started: list[Path] = []
    for name, prefix, conf in (("O", origin, origin_conf), ("B", node, node_conf)):
        result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if result.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        small_got = base / "cache_http_s.got"
        small = xrdfs_cat(cache_port, "/small.bin", small_got, xrdfs)
        expected_small = (origin / "root" / "small.bin").read_bytes()
        results.append(
            (
                small.returncode == 0 and small_got.read_bytes() == expected_small,
                "byte-exact serve (filled from HTTP)",
            )
        )
        results.append(((node / "cache" / "small.bin").exists(), "object landed in the local cache (fill stored)"))

        warm_got = base / "cache_http_s2.got"
        warm = xrdfs_cat(cache_port, "/small.bin", warm_got, xrdfs)
        results.append((warm.returncode == 0 and warm_got.read_bytes() == expected_small, "warm hit byte-exact"))

        big_got = base / "cache_http_b.got"
        big = xrdfs_cat(cache_port, "/big.bin", big_got, xrdfs)
        expected_big = (origin / "root" / "big.bin").read_bytes()
        results.append((big.returncode == 0 and big_got.read_bytes() == expected_big, "multi-chunk byte-exact"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_http.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_http_source: ALL PASS")
        return 0
    print("run_cache_http_source: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
