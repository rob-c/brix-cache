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
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST

_PORTS = cmdscript_ports("cachestore_live")

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
    oport, bport = _PORTS[0:2]  # was free_ports(2)
    with LiveRun("cache_xrdav", nginx) as run:
        context = _prepare_offload(run, oport, bport)
        run.start_nginx(context["origin"], context["origin_conf"], oport)
        run.start_nginx(context["node"], context["node_conf"], bport)
        time.sleep(1)
        return _exercise_offload(run, context, bport)


def _make_directories(directory, names):
    for name in names:
        (directory / name).mkdir(parents=True, exist_ok=True)


def _prepare_offload(run, origin_port, node_port):
    origin, node = run.mkdir("o"), run.mkdir("b")
    _make_directories(origin, ("root", "logs"))
    _make_directories(node, ("export", "cache", "tmp", "logs"))
    origin_conf = run.write(origin / "nginx.conf", f"""daemon on; error_log {origin}/logs/e.log info; pid {origin}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{origin_port}; brix_root on; brix_export {origin}/root; brix_auth none; }} }}
""")
    node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {node}/tmp;
    server {{
        listen {BIND_HOST}:{node_port};
        location / {{
            brix_webdav on;
            brix_export {node}/export;
            brix_webdav_auth none;
            brix_storage_backend root://{HOST}:{origin_port};
            brix_cache_store posix:{node}/cache;
        }}
    }}
}}
""")
    small, big = origin / "root/small.bin", origin / "root/big.bin"
    random_file(small, 500000)
    random_file(big, 2600000)
    return {"origin": origin, "node": node, "origin_conf": origin_conf,
            "node_conf": node_conf, "small": small, "big": big}


def _curl_download(run, url, destination):
    result = run.call(
        ["curl", "-sS", "--max-time", "25", "-o", destination,
         "-w", "%{http_code}", url], check=False,
    )
    return int(result.stdout.strip() or 0)


def _download_exact(status, destination, source):
    return status == 200 and destination.exists() and sha256(destination) == sha256(source)


def _exercise_offload(run, context, port):
    node, small, big = context["node"], context["small"], context["big"]
    url = f"http://{HOST}:{port}"
    cold = run.root / "cold.got"
    cold_status = _curl_download(run, f"{url}/small.bin", cold)
    cold_exact = _download_exact(cold_status, cold, small)
    if not cold_exact:
        _tail_log(node / "logs/e.log", r"cache|xroot|offload|fill|error|stall")
    log = (node / "logs/e.log").read_text(errors="replace")
    warm = run.root / "warm.got"
    warm_status = _curl_download(run, f"{url}/small.bin", warm)
    big_got = run.root / "big.got"
    big_status = _curl_download(run, f"{url}/big.bin", big_got)
    return _offload_results(
        node, small, big, cold_status, cold_exact, log,
        warm, warm_status, big_got, big_status,
    )


def _offload_results(node, small, big, cold_status, cold_exact, log,
                     warm, warm_status, big_got, big_status):
    return _checks([
        (cold_status == 200, f"cold GET 200 (got {cold_status})"),
        (cold_exact, "byte-exact remote fill"),
        ("offloaded cache fill" in log, "fill ran off the event loop"),
        ((node / "cache/small.bin").exists(), "object landed in local cache"),
        (_download_exact(warm_status, warm, small), "warm hit byte-exact"),
        (_download_exact(big_status, big_got, big), "multi-chunk hit byte-exact"),
    ])


def xroot_cachestore_serve(nginx: Path | None = None) -> int:
    """A REMOTE root:// cache_store served over WebDAV: the whole cache open
    runs off-loop; cold GET fills the store + serves byte-exact, warm GET
    serves from the store with the posix source hidden."""
    sport, bport = _PORTS[2:4]  # was free_ports(2)
    with LiveRun("xrcs", nginx) as run:
        context = _prepare_remote_store(run, sport, bport)
        run.start_nginx(context["store"], context["store_conf"], sport)
        run.start_nginx(context["node"], context["node_conf"], bport)
        time.sleep(1)
        return _exercise_remote_store(run, context, bport)


def _prepare_remote_store(run, store_port, node_port):
    store, node = run.mkdir("s"), run.mkdir("b")
    _make_directories(store, ("root", "logs"))
    _make_directories(node, ("backend", "tmp", "logs"))
    store_conf = run.write(store / "nginx.conf", f"""daemon on; error_log {store}/logs/e.log info; pid {store}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{store_port}; brix_root on; brix_export {store}/root; brix_auth none; brix_allow_write on;
  # The node persists its cinfo as a "<key>.cinfo" sidecar here; a reserved name
  # is answered kXR_NotFound on an ordinary export, so S has to declare itself
  # the trusted cache-STORE surface or the warm hit refills forever.
  brix_cache_store_endpoint on; }} }}
""")
    node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {node}/tmp; server {{ listen {BIND_HOST}:{node_port};
  location / {{ brix_webdav on; brix_export {node}/backend; brix_webdav_auth none;
    brix_cache_store root://{HOST}:{store_port}; }} }} }}
""")
    source = node / "backend/f.bin"
    digest = random_file(source, 600000)
    return {"store": store, "node": node, "store_conf": store_conf,
            "node_conf": node_conf, "source": source, "digest": digest}


def _exercise_remote_store(run, context, port):
    store, node = context["store"], context["node"]
    source, digest = context["source"], context["digest"]
    url = f"http://{HOST}:{port}/f.bin"
    cold = run.root / "cold.got"
    cold_status = _curl_download(run, url, cold)
    cold_ok = cold_status == 200 and cold.exists() and sha256(cold) == digest
    if not cold_ok:
        _tail_log(node / "logs/e.log", r"serve offload|cache|xroot|error")
    log = (node / "logs/e.log").read_text(errors="replace")
    source.rename(node / "backend/.f.hidden")
    warm = run.root / "warm.got"
    warm_status = _curl_download(run, url, warm)
    print(f"  info error-lines={len(re.findall(r'\[(error|crit|alert)\]', log))}")
    return _remote_store_results(
        store, cold_ok, cold_status, log, warm, warm_status, digest
    )


def _remote_store_results(store, cold_ok, cold_status, log,
                          warm, warm_status, digest):
    return _checks([
        (cold_ok, f"cold GET byte-exact ({cold_status})"),
        ("serve offload: materialising remote" in log, "serve ran off event loop"),
        ((store / "root/f.bin").exists(), "object landed on xroot store"),
        (warm_status == 200 and warm.exists() and sha256(warm) == digest,
         f"warm hit byte-exact with source hidden ({warm_status})"),
    ])


def _sidecar_cell(run: LiveRun, label: str, kind: str, sport: int, bport: int,
                  checks: list[tuple[bool, str]]) -> None:
    """One cache_store sidecar cell (s3 or http), mirroring the shell's
    test_cachestore function."""
    context = _prepare_sidecar_cell(run, label, kind, sport, bport)
    print(f"== cache_store: {label} (SIDECAR cinfo) ==")
    if not _start_sidecar_cell(run, context, sport, bport, checks):
        return
    time.sleep(1)
    _check_sidecar_cold(run, context, bport, checks)
    _check_sidecar_record(context, checks)
    if not _restart_sidecar_node(run, context, bport, checks):
        return
    _check_sidecar_warm(run, context, bport, checks)
    run.stop_nginx(context["node"])
    run.stop_nginx(context["store"])


def _prepare_sidecar_cell(run, label, kind, store_port, node_port):
    cell = run.mkdir(label)
    store, node = cell / "sa", cell / "b"
    _make_directories(store, ("store", "logs", "tmp"))
    _make_directories(node, ("backend", "logs", "tmp"))
    store_url = _write_sidecar_store_config(run, store, kind, store_port)
    node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {node}/tmp; server {{ listen {BIND_HOST}:{node_port};
  location / {{ brix_webdav on; brix_export {node}/backend; brix_webdav_auth none;
    brix_cache_store {store_url};
    brix_cache_meta sidecar; }} }} }}
""")
    source = node / "backend/f.bin"
    digest = random_file(source, 450000)
    return {"label": label, "store": store, "node": node,
            "node_conf": node_conf, "source": source, "digest": digest}


def _write_sidecar_store_config(run, store, kind, port):
    if kind == "s3":
        run.write(store / "nginx.conf", f"""daemon on; error_log {store}/logs/e.log info; pid {store}/nginx.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:{port};
  location / {{ brix_s3 on; brix_export {store}/store; brix_s3_bucket xrdcache; brix_allow_write on; brix_cache_store_endpoint on; }} }} }}
""")
        return f"s3://{HOST}:{port}/xrdcache"
    run.write(store / "nginx.conf", f"""daemon on; error_log {store}/logs/e.log info; pid {store}/nginx.pid;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {store}/tmp; server {{ listen {BIND_HOST}:{port};
  location / {{ dav_methods PUT DELETE; brix_webdav on; brix_export {store}/store; brix_webdav_auth none; brix_allow_write on; brix_cache_store_endpoint on; }} }} }}
""")
    return f"http://{HOST}:{port}"


def _start_sidecar_cell(run, context, store_port, node_port, checks):
    label, store, node = context["label"], context["store"], context["node"]
    try:
        run.start_nginx(store, store / "nginx.conf", store_port)
    except LiveFailure as exc:
        checks.append((False, f"{label} store server failed: {exc}"))
        return False
    try:
        run.start_nginx(node, context["node_conf"], node_port)
    except LiveFailure as exc:
        checks.append((False, f"{label} node failed: {exc}"))
        return False
    return True


def _check_sidecar_cold(run, context, port, checks):
    label, node = context["label"], context["node"]
    cold = run.root / f"{label}_cold.got"
    status = _curl_download(run, f"http://{HOST}:{port}/f.bin", cold)
    cold_ok = status == 200 and cold.exists() and sha256(cold) == context["digest"]
    if not cold_ok:
        _tail_log(node / "logs/e.log", r"cinfo|sidecar|cache|stage move|error", 6)
    checks.append((cold_ok, f"{label} cold GET byte-exact (got {status})"))


def _check_sidecar_record(context, checks):
    label = context["label"]
    sidecar = context["store"] / "store/f.bin.cinfo"
    checks.append((sidecar.is_file(), f"{label} <key>.cinfo xmeta sidecar landed on the store"))
    prefix_v4 = False
    if sidecar.is_file():
        head = sidecar.read_bytes()[:4]
        prefix_v4 = len(head) == 4 and struct.unpack("<i", head)[0] == 4
    checks.append((prefix_v4, f"{label} sidecar is a stock-prefixed record (cinfo v4)"))


def _restart_sidecar_node(run, context, port, checks):
    label, node = context["label"], context["node"]
    context["source"].rename(node / "backend/.hidden")
    run.stop_nginx(node)
    time.sleep(0.6)
    try:
        run.start_nginx(node, context["node_conf"], port)
    except LiveFailure as exc:
        checks.append((False, f"{label} B restart failed: {exc}"))
        run.stop_nginx(context["store"])
        return False
    time.sleep(1)
    return True


def _check_sidecar_warm(run, context, port, checks):
    label, node = context["label"], context["node"]
    warm = run.root / f"{label}_warm.got"
    status = _curl_download(run, f"http://{HOST}:{port}/f.bin", warm)
    warm_ok = status == 200 and warm.exists() and sha256(warm) == context["digest"]
    if not warm_ok:
        _tail_log(node / "logs/e.log", r"cinfo|sidecar|cache|error", 6)
    checks.append((warm_ok, f"{label} post-restart sidecar hit byte-exact ({status})"))


def cachestore_sidecar(nginx: Path | None = None) -> int:
    """http/s3 as a cache_store via SIDECAR cinfo: a cold GET fills the store
    + writes '<key>.cinfo'; after a node restart with the source hidden, the
    sidecar is loaded and the object serves from the store (G3)."""
    s3_sport, s3_bport, http_sport, http_bport = _PORTS[4:8]  # was free_ports(4)
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
