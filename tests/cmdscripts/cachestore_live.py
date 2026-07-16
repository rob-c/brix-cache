"""Direct Python ports for the cache-store live shell scenarios.

Ports ``run_cache_xroot_webdav_offload.sh``, ``run_xroot_cachestore_serve.sh``,
and ``run_cachestore_sidecar.sh``.  Each public scenario keeps its shell
test's own acceptance sequence and assertions; ports are allocated
dynamically instead of the scripts' fixed literals.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import struct
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, random_file, sha256
from settings import free_ports

CLIENT_REQUIREMENTS = {
    "cache-xroot-webdav-offload": (),
    "xroot-cachestore-serve": (),
    "cachestore-sidecar": (),
}


def _checks(values: list[tuple[bool, str]]) -> int:
    for passed, text in values:
        print(f"  {'ok  ' if passed else 'FAIL'} {text}")
    return 0 if all(passed for passed, _ in values) else 1


def _tail_log(log: Path, pattern: str, count: int = 8) -> None:
    if not log.exists():
        return
    lines = [
        line
        for line in log.read_text(errors="replace").splitlines()
        if re.search(pattern, line, re.I) and "access_json" not in line
    ]
    for line in lines[-count:]:
        print(f"    {line}")


def cache_xroot_webdav_offload(nginx: Path | None = None) -> int:
    """The HTTP read plane fills a cache MISS from a remote root:// source on
    a worker thread: cold GET byte-exact + 'offloaded cache fill' logged,
    warm GET a local cache hit, multi-chunk cold GET byte-exact."""
    oport, bport = free_ports(2)
    with LiveRun("cache_xrdav", nginx) as run:
        origin, node = run.mkdir("o"), run.mkdir("b")
        for directory, names in ((origin, ("root", "logs")), (node, ("export", "cache", "tmp", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        origin_conf = run.write(origin / "nginx.conf", f"""daemon on; error_log {origin}/logs/e.log info; pid {origin}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{oport}; brix_root on; brix_export {origin}/root; brix_auth none; }} }}
""")
        node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {node}/tmp;
    server {{
        listen 127.0.0.1:{bport};
        location / {{
            brix_webdav on;
            brix_export {node}/export;
            brix_webdav_auth none;
            brix_storage_backend root://127.0.0.1:{oport};
            brix_cache_store posix:{node}/cache;
        }}
    }}
}}
""")
        # seed two files DIRECTLY on the origin O's namespace
        small, big = origin / "root/small.bin", origin / "root/big.bin"
        random_file(small, 500000)
        random_file(big, 2600000)
        run.start_nginx(origin, origin_conf, oport)
        run.start_nginx(node, node_conf, bport)
        time.sleep(1)
        url = f"http://127.0.0.1:{bport}"

        cold = run.root / "cold.got"
        cold_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", cold, "-w", "%{http_code}", f"{url}/small.bin"], check=False).stdout.strip() or 0)
        cold_exact = cold.exists() and sha256(cold) == sha256(small)
        if not cold_exact:
            _tail_log(node / "logs/e.log", r"cache|xroot|offload|fill|error|stall")
        log = (node / "logs/e.log").read_text(errors="replace")

        warm = run.root / "warm.got"
        warm_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", warm, "-w", "%{http_code}", f"{url}/small.bin"], check=False).stdout.strip() or 0)
        big_got = run.root / "big.got"
        big_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", big_got, "-w", "%{http_code}", f"{url}/big.bin"], check=False).stdout.strip() or 0)
        return _checks([
            (cold_status == 200, f"cold GET 200 (got {cold_status})"),
            (cold_exact, "byte-exact (filled from remote xroot, served from local cache)"),
            ("offloaded cache fill" in log, "fill ran OFF the event loop (thread pool)"),
            ((node / "cache/small.bin").exists(), "object landed in the LOCAL posix cache store"),
            (warm_status == 200 and sha256(warm) == sha256(small), f"warm hit byte-exact (got {warm_status})"),
            (big_status == 200 and big_got.exists() and sha256(big_got) == sha256(big),
             f"multi-chunk byte-exact (status={big_status})"),
        ])


def xroot_cachestore_serve(nginx: Path | None = None) -> int:
    """A REMOTE root:// cache_store served over WebDAV: the whole cache open
    runs off-loop; cold GET fills the store + serves byte-exact, warm GET
    serves from the store with the posix source hidden."""
    sport, bport = free_ports(2)
    with LiveRun("xrcs", nginx) as run:
        store, node = run.mkdir("s"), run.mkdir("b")
        for directory, names in ((store, ("root", "logs")), (node, ("backend", "tmp", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        store_conf = run.write(store / "nginx.conf", f"""daemon on; error_log {store}/logs/e.log info; pid {store}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{sport}; brix_root on; brix_export {store}/root; brix_auth none; brix_allow_write on; }} }}
""")
        node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {node}/tmp; server {{ listen 127.0.0.1:{bport};
  location / {{ brix_webdav on; brix_export {node}/backend; brix_webdav_auth none;
    brix_cache_store root://127.0.0.1:{sport}; }} }} }}
""")
        source = node / "backend/f.bin"
        digest = random_file(source, 600000)
        run.start_nginx(store, store_conf, sport)
        run.start_nginx(node, node_conf, bport)
        time.sleep(1)
        url = f"http://127.0.0.1:{bport}/f.bin"

        cold = run.root / "cold.got"
        cold_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", cold, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)
        cold_ok = cold_status == 200 and cold.exists() and sha256(cold) == digest
        if not cold_ok:
            _tail_log(node / "logs/e.log", r"serve offload|cache|xroot|error")
        log = (node / "logs/e.log").read_text(errors="replace")

        source.rename(node / "backend/.f.hidden")  # hide the posix source
        warm = run.root / "warm.got"
        warm_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", warm, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)

        errors = len(re.findall(r"\[(error|crit|alert)\]", log))
        print(f"  info error-lines={errors}")
        return _checks([
            (cold_ok, f"cold GET 200 byte-exact (got {cold_status})"),
            ("serve offload: materialising remote" in log, "served OFF the event loop (thread pool)"),
            ((store / "root/f.bin").exists(), "cached object landed on the xroot store S"),
            (warm_status == 200 and warm.exists() and sha256(warm) == digest,
             f"WARM hit byte-exact from xroot cache (source hidden) (got {warm_status})"),
        ])


def _sidecar_cell(run: LiveRun, label: str, kind: str, sport: int, bport: int,
                  checks: list[tuple[bool, str]]) -> None:
    """One cache_store sidecar cell (s3 or http), mirroring the shell's
    test_cachestore function."""
    cell = run.mkdir(label)
    store_node, node = cell / "sa", cell / "b"
    for directory, names in ((store_node, ("store", "logs", "tmp")), (node, ("backend", "logs", "tmp"))):
        for name in names:
            (directory / name).mkdir(parents=True, exist_ok=True)
    print(f"== cache_store: {label} (SIDECAR cinfo) ==")

    if kind == "s3":
        run.write(store_node / "nginx.conf", f"""daemon on; error_log {store_node}/logs/e.log info; pid {store_node}/nginx.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen 127.0.0.1:{sport};
  location / {{ brix_s3 on; brix_export {store_node}/store; brix_s3_bucket xrdcache; brix_allow_write on; }} }} }}
""")
        store_url = f"s3://127.0.0.1:{sport}/xrdcache"
    else:
        run.write(store_node / "nginx.conf", f"""daemon on; error_log {store_node}/logs/e.log info; pid {store_node}/nginx.pid;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {store_node}/tmp; server {{ listen 127.0.0.1:{sport};
  location / {{ dav_methods PUT DELETE; brix_webdav on; brix_export {store_node}/store; brix_webdav_auth none; brix_allow_write on; }} }} }}
""")
        store_url = f"http://127.0.0.1:{sport}"
    node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {node}/tmp; server {{ listen 127.0.0.1:{bport};
  location / {{ brix_webdav on; brix_export {node}/backend; brix_webdav_auth none;
    brix_cache_store {store_url}; }} }} }}
""")
    source = node / "backend/f.bin"
    digest = random_file(source, 450000)
    try:
        run.start_nginx(store_node, store_node / "nginx.conf", sport)
    except LiveFailure as exc:
        checks.append((False, f"{label} store server failed: {exc}"))
        return
    try:
        run.start_nginx(node, node_conf, bport)
    except LiveFailure as exc:
        checks.append((False, f"{label} node failed: {exc}"))
        return
    time.sleep(1)
    url = f"http://127.0.0.1:{bport}/f.bin"

    cold = run.root / f"{label}_cold.got"
    cold_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", cold, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)
    cold_ok = cold_status == 200 and cold.exists() and sha256(cold) == digest
    if not cold_ok:
        _tail_log(node / "logs/e.log", r"cinfo|sidecar|cache|stage move|error", 6)
    checks.append((cold_ok, f"{label} cold GET byte-exact (filled store + sidecar) (got {cold_status})"))

    # xmeta: the record rides as "<key>.cinfo" (a stock-readable cinfo v4)
    sidecar = store_node / "store/f.bin.cinfo"
    checks.append((sidecar.is_file(), f"{label} <key>.cinfo xmeta sidecar landed on the store"))
    prefix_v4 = False
    if sidecar.is_file():
        head = sidecar.read_bytes()[:4]
        prefix_v4 = len(head) == 4 and struct.unpack("<i", head)[0] == 4
    checks.append((prefix_v4, f"{label} sidecar is a stock-prefixed record (cinfo v4)"))

    source.rename(node / "backend/.hidden")  # hide the SOURCE
    run.stop_nginx(node)
    time.sleep(0.6)
    try:
        run.start_nginx(node, node_conf, bport)
    except LiveFailure as exc:
        checks.append((False, f"{label} B restart failed: {exc}"))
        run.stop_nginx(store_node)
        return
    time.sleep(1)
    warm = run.root / f"{label}_warm.got"
    warm_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", warm, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)
    warm_ok = warm_status == 200 and warm.exists() and sha256(warm) == digest
    if not warm_ok:
        _tail_log(node / "logs/e.log", r"cinfo|sidecar|cache|error", 6)
    checks.append((warm_ok,
                   f"{label} post-restart hit byte-exact (cinfo LOADED from sidecar, served from store; source hidden) (got {warm_status})"))
    run.stop_nginx(node)
    run.stop_nginx(store_node)


def cachestore_sidecar(nginx: Path | None = None) -> int:
    """http/s3 as a cache_store via SIDECAR cinfo: a cold GET fills the store
    + writes '<key>.cinfo'; after a node restart with the source hidden, the
    sidecar is loaded and the object serves from the store (G3)."""
    s3_sport, s3_bport, http_sport, http_bport = free_ports(4)
    with LiveRun("cssc", nginx) as run:
        checks: list[tuple[bool, str]] = []
        _sidecar_cell(run, "s3", "s3", s3_sport, s3_bport, checks)
        _sidecar_cell(run, "http", "http", http_sport, http_bport, checks)
        return _checks(checks)


SCENARIOS = {
    "cache-xroot-webdav-offload": cache_xroot_webdav_offload,
    "xroot-cachestore-serve": xroot_cachestore_serve,
    "cachestore-sidecar": cachestore_sidecar,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"cachestore scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
