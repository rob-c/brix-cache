"""Read cache with a plain HTTP source backend."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess

from cmdscripts import run
from cmdscripts.cache_source_helpers import (exact_transfer, start_servers,
                                             stop_servers, wait_workers_ready)
from cmdscripts.command_results import print_results, selected_binary
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

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
    server {{ listen {BIND_HOST}:{port}; location / {{ root {root}; }} }}
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
    listen {BIND_HOST}:{port}; brix_root on; brix_auth none;
    brix_storage_backend http://{HOST}:{origin_port};
    brix_cache_store posix:{cache}; brix_cache_export /;
}} }}
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


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdfs: Path = XRDFS) -> list[tuple[bool, str]]:
    if not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP cache HTTP source data plane (native xrdfs not built)")]
    origin_port, cache_port = cmdscript_ports("cache_http_source")
    origin = base / "o"
    node = base / "b"
    origin_conf = write_origin_config(origin, origin_port)
    node_conf = write_cache_config(node, cache_port, origin_port)
    (origin / "root" / "small.bin").write_bytes(deterministic_bytes(500_000, 101))
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_600_000, 109))

    specifications = (("O", origin, origin_conf), ("B", node, node_conf))
    started, failure = start_servers(nginx_bin, specifications, run, stop_nginx)
    if failure:
        return [failure]

    try:
        wait_workers_ready(HOST, [(origin_port, "http"), (cache_port, "root")])
        results: list[tuple[bool, str]] = []
        small_got = base / "cache_http_s.got"
        expected_small = (origin / "root" / "small.bin").read_bytes()
        results.append(
            (
                exact_transfer(xrdfs_cat, cache_port, "/small.bin", small_got,
                               expected_small, xrdfs),
                "byte-exact serve (filled from HTTP)",
            )
        )
        results.append(((node / "cache" / "small.bin").exists(), "object landed in the local cache (fill stored)"))

        warm_got = base / "cache_http_s2.got"
        warm_ok = exact_transfer(xrdfs_cat, cache_port, "/small.bin", warm_got,
                                 expected_small, xrdfs)
        results.append((warm_ok, "warm hit byte-exact"))

        big_got = base / "cache_http_b.got"
        expected_big = (origin / "root" / "big.bin").read_bytes()
        big_ok = exact_transfer(xrdfs_cat, cache_port, "/big.bin", big_got,
                                expected_big, xrdfs)
        results.append((big_ok, "multi-chunk byte-exact"))
        return results
    finally:
        stop_servers(started, stop_nginx)


def entry(argv: list[str]) -> int:
    nginx_bin = selected_binary(argv, NGINX_BIN)
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_http.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    return print_results(results, "run_cache_http_source")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
