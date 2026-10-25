"""conformance_common.py — shared harness for the Phase-84 CVMFS conformance corpora.

Provides: per-file port-block allocation, a `srv_instance` context manager (mock
origin + LiveRun nginx with a generated brix_cvmfs config), a `fuse_mount`
context manager for brixcvmfs/brixMount mounts with robust always-unmount
teardown, and small raw-socket HTTP helpers (arbitrary method/headers and
absolute-form request lines for proxy-mode tests).
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
import urllib.request

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.live_common import LiveRun
from lib_py.util import wait_tcp
from lib_py import fuse_host
from settings import BIND_HOST, HOST, TEST_PORT_START
from lib_py.util import budget_scale
from port_ladder import CVMFS_CONFORMANCE_OFFSET
from cvmfs.conformance_ports import (
    BLOCK_WIDTH, CANONICAL_ORDER as _CANONICAL_ORDER, MATRIX_WIDTH as _MATRIX_WIDTH,
)

MOCK = str(REPO_ROOT / "tests/cvmfs/mock_stratum1.py")
BRIXMOUNT = os.environ.get("BRIXMOUNT_BIN", str(REPO_ROOT / "client/bin/brixMount"))
NGINX_BIN = os.environ.get("NGINX_BIN") or (
    str(REPO_ROOT / "objs/nginx") if (REPO_ROOT / "objs/nginx").exists()
    else "/tmp/nginx-1.28.3/objs/nginx")

# Each corpus file owns a 20-port block (design doc §"Port blocks"). Mock origins
# take base+0..9, nginx instances base+10..19 — no collisions under xdist since a
# module runs in a single worker and distinct files own distinct blocks. The
# per-file relative layout is preserved (index*20), so per-file structure a test
# relies on (e.g. srv_proxy's guaranteed-dead ports at base+17..19) still holds.
#
# The whole map is anchored to THIS suite's TEST_PORT_START, immediately past the
# fixed-fleet ladder (port_ladder.CVMFS_CONFORMANCE_OFFSET), so every mock/nginx
# port stays within TEST_PORT_START+2000 — part of the main fleet's port band, not
# an absolute 13100+ range disconnected from it.  A second suite run with a
# different TEST_PORT_START therefore draws a fully DISJOINT range automatically
# (no cross-suite / debug collision) — which replaces the old absolute per-session
# tiling.  `CVMFS_CONFORMANCE_PORT_BASE` still pins the sub-ladder base explicitly
# for CI/debugging when TEST_PORT_START anchoring is not wanted.
# +1 matches port_ladder._port(offset, 0) = PORT_START + offset + 1, so this
# category begins exactly where the fixed-fleet ladder ends (no gap, no overlap).
_CVMFS_BASE = int(os.environ.get("CVMFS_CONFORMANCE_PORT_BASE",
                                 TEST_PORT_START + CVMFS_CONFORMANCE_OFFSET + 1))
PORT_BLOCKS = {name: _CVMFS_BASE + i * BLOCK_WIDTH
               for i, name in enumerate(_CANONICAL_ORDER)}
# NOTE: the prefetch/prewarm suites (test_cvmfs_prefetch.py, test_cvmfs_prewarm.py)
# deliberately use OS-assigned ephemeral ports (bind port 0) instead of a block
# here: they control both the origin and the client's $BRIXCVMFS_SERVER.

# TEST_PORT_START now separates concurrent suites, so no per-session tile shift is
# applied on top of the anchored bases.
_SESSION_OFFSET = 0

# A dedicated sub-range, just past the catalogue's file blocks, for suites that spin up MANY
# short-lived mock origins CONCURRENTLY (the fuse-trust tamper matrix runs ~30 at
# once through a thread pool — far more than a single 10-port block).  Still within
# TEST_PORT_START+2000; hand out a distinct fixed port per caller, thread-safely,
# so these mocks never fall back to an OS-ephemeral port (which would escape the
# +2000 fleet band).
# The block map above is collision-free under xdist because a module runs in one
# worker and distinct files own distinct blocks.  This shared round-robin range
# broke that invariant: threading.Lock serialises THREADS, but every xdist worker
# is its own PROCESS, each starting _matrix_next at 0 and therefore handing out
# the identical sequence.  Two files whose matrices ran on two workers both took
# base+0, base+1, ... -- "bind() to 127.0.0.1:<port> failed (98: Address already
# in use)", the single largest source of failures in a high-concurrency run.
# Fix: give each worker a DISJOINT slice of the window, so the per-process
# counter can no longer overlap another worker's ports.
def _xdist_worker_slot() -> tuple[int, int]:
    """(index, total) for this xdist worker; (0, 1) when not running under it.

    Callers that must partition a resource per worker key on the INDEX: it is
    disjoint by construction, unlike a pid folded into a fixed number of slots.
    """
    match = re.match(r"gw(\d+)$", os.environ.get("PYTEST_XDIST_WORKER", ""))
    if match is None:
        return 0, 1
    try:
        total = max(1, int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", "1")))
    except ValueError:
        total = 1
    return int(match.group(1)), total


# The matrix sub-range is part of the DECLARED ladder (test_fleet_ports asserts
# the named lane is fully accounted for), so it stays where it is.  What changes
# is the counter: it was a round-robin int guarded by a threading.Lock, which
# serialises THREADS while every xdist worker is its own PROCESS -- each
# restarting at 0 and handing out the identical sequence, so two workers took
# base+0, base+1, ... and collided.  That was the single largest source of
# "bind() ... Address already in use" in a parallel run.  The cursor now lives in
# a file under TEST_ROOT with an flock around the increment, exactly like
# ephemeral_port's lease registry, so it is unique ACROSS processes too.
_MATRIX_BASE = _CVMFS_BASE + len(_CANONICAL_ORDER) * BLOCK_WIDTH
_matrix_lock = threading.Lock()


def _matrix_cursor_path() -> "Path":
    root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    root.mkdir(parents=True, exist_ok=True)
    return root / f"cvmfs-matrix-cursor.{_MATRIX_BASE}"


def _read_matrix_cursor(cursor) -> int:
    cursor.seek(0)
    try:
        return int(cursor.read().strip() or "0")
    except ValueError:
        return 0


def _choose_matrix_port(nxt: int) -> tuple[int, int]:
    for step in range(_MATRIX_WIDTH):
        candidate = _MATRIX_BASE + ((nxt + step) % _MATRIX_WIDTH)
        if _port_is_free(candidate):
            return candidate, step + 1
    return _MATRIX_BASE + (nxt % _MATRIX_WIDTH), 1


def matrix_port() -> int:
    """Return a distinct fixed port from the cvmfs matrix sub-range.

    The cursor lives in a TEST_ROOT file under an flock, so the sequence is
    unique across xdist WORKER PROCESSES -- the old threading.Lock only
    serialised threads inside one process, and every worker restarted the
    counter at 0 and replayed the same ports.  The search for a free slot and
    the cursor write happen under that same lock, so two workers cannot pick
    the same slot, and the cursor advances PAST whatever was skipped so
    back-to-back calls never repeat a number.
    """
    import fcntl

    path = _matrix_cursor_path()
    with _matrix_lock:
        with open(path, "a+", encoding="utf-8") as cursor:
            fcntl.flock(cursor.fileno(), fcntl.LOCK_EX)
            try:
                nxt = _read_matrix_cursor(cursor)
                chosen, advance = _choose_matrix_port(nxt)
                cursor.seek(0)
                cursor.truncate()
                cursor.write(str(nxt + advance))
                cursor.flush()
            finally:
                fcntl.flock(cursor.fileno(), fcntl.LOCK_UN)
    return chosen


def _port_is_free(port: int) -> bool:
    """True when nothing is listening on `port` right now."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((HOST, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


class PortBlock:
    """Sequential allocator within a file's 20-port block, shifted into this
    session's private tile."""

    def __init__(self, name: str):
        if name not in PORT_BLOCKS:
            raise KeyError(f"no port block for {name!r}; add it to PORT_BLOCKS")
        self.base = PORT_BLOCKS[name] + _SESSION_OFFSET
        self._mock = 0
        self._nginx = 0

    def mock(self) -> int:
        p = self.base + self._mock
        self._mock += 1
        if self._mock > 10:
            raise RuntimeError(f"exhausted mock sub-block for base {self.base}")
        return p

    def nginx(self) -> int:
        p = self.base + 10 + self._nginx
        self._nginx += 1
        if self._nginx > 10:
            raise RuntimeError(f"exhausted nginx sub-block for base {self.base}")
        return p


# ---- mock control-plane helpers -------------------------------------------

def _ctl_get(port: int, endpoint: str) -> object:
    with urllib.request.urlopen(f"http://{HOST}:{port}/ctl/{endpoint}",
                                timeout=10 * budget_scale()) as r:
        return json.load(r)


def _ctl_post(port: int, endpoint: str, payload: dict | None = None) -> None:
    data = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(f"http://{HOST}:{port}/ctl/{endpoint}",
                                 method="POST", data=data)
    urllib.request.urlopen(req, timeout=10 * budget_scale()).read()


class Server:
    """A running mock+nginx instance and the handles a corpus test needs."""

    def __init__(self, run: LiveRun, nginx_port: int, mock_ports: list[int],
                 cache: Path, error_log: Path, prefix: Path, repo: str, location: str):
        self.run = run
        self.nginx_port = nginx_port
        self.mock_ports = mock_ports
        self.cache = cache
        self.error_log = error_log
        self.prefix = prefix
        self.repo = repo
        self.location = location

    @property
    def base_url(self) -> str:
        return f"http://{HOST}:{self.nginx_port}"

    @property
    def mock_url(self) -> str:
        return f"http://{HOST}:{self.mock_ports[0]}"

    @property
    def nginx_pid(self) -> int | None:
        pidfile = self.prefix / "nginx.pid"
        try:
            return int(pidfile.read_text().strip())
        except (OSError, ValueError):
            return None

    def get_log(self, mock: int = 0) -> list:
        return _ctl_get(self.mock_ports[mock], "log")

    def get_heads(self, mock: int = 0) -> list:
        return _ctl_get(self.mock_ports[mock], "heads")

    def objects(self, mock: int = 0) -> list:
        return _ctl_get(self.mock_ports[mock], "objects")

    def set_fault(self, mode: str, count: int, *, path_re: str | None = None, mock: int = 0) -> None:
        payload = {"mode": mode, "count": count}
        if path_re is not None:
            payload["path_re"] = path_re
        _ctl_post(self.mock_ports[mock], "fault", payload)

    def reset_log(self, mock: int = 0) -> None:
        _ctl_post(self.mock_ports[mock], "reset-log")

    def bump(self, mock: int = 0) -> None:
        urllib.request.urlopen(f"http://{HOST}:{self.mock_ports[mock]}/ctl/manifest/bump",
                               timeout=10).read()

    def count_log(self, needle: str, *, mock: int = 0) -> int:
        return sum(1 for e in self.get_log(mock) if needle in e["path"])


def _spawn_mock(run: LiveRun, port: int, *, webroot=None, objects=8, seed=1,
                repo="test.cern.ch", keepalive=False) -> None:
    argv = [sys.executable, MOCK, "--port", str(port), "--repo", repo,
            "--objects", str(objects), "--seed", str(seed)]
    if webroot is not None:
        argv += ["--webroot", str(webroot)]
    if keepalive:
        argv.append("--keepalive")
    run.spawn(argv)
    if not wait_tcp(BIND_HOST, port, 10):
        raise RuntimeError(f"mock Stratum-1 did not listen on {port}")


# Config-knob -> directive; None-valued kwargs are omitted from the config.
_KNOBS = {
    "manifest_ttl": "brix_cvmfs_manifest_ttl", "negative_ttl": "brix_cvmfs_negative_ttl",
    "offline_ttl": "brix_cvmfs_offline_ttl",
    "quarantine_dir": "brix_cvmfs_quarantine_dir", "client_hold": "brix_cvmfs_client_hold",
    "origin_select": "brix_cvmfs_origin_select", "reuse_conn": "brix_cvmfs_origin_reuse_conn",
    "connect_timeout": "brix_cvmfs_origin_connect_timeout",
    "attempt_timeout": "brix_cvmfs_origin_attempt_timeout",
    "stall_timeout": "brix_cvmfs_origin_stall_timeout",
    "stall_bytes": "brix_cvmfs_origin_stall_bytes", "fill_max_life": "brix_cvmfs_fill_max_life",
    "fill_retry_policy": "brix_cvmfs_fill_retry_policy", "geo_answer": "brix_cvmfs_geo_answer",
    "geo_max_servers": "brix_cvmfs_geo_max_servers", "geo_cache_ttl": "brix_cvmfs_geo_cache_ttl",
    "upstream_max": "brix_cvmfs_upstream_max", "shared_cache": "brix_cvmfs_shared_cache",
    "unified_origin": "brix_cvmfs_unified_origin", "scvmfs_authz": "brix_scvmfs_authz",
    "token_issuers": "brix_scvmfs_token_issuers",
    "verify_manifest": "brix_cvmfs_verify_manifest",
}


def _port_block(value: str | PortBlock) -> PortBlock:
    return value if isinstance(value, PortBlock) else PortBlock(value)


def _start_mocks(run, block, count, webroot, objects, seed, repo, keepalive):
    ports = [block.mock() for _ in range(count)]
    for index, port in enumerate(ports):
        _spawn_mock(run, port, webroot=webroot, objects=objects,
                    seed=seed + index, repo=repo, keepalive=keepalive)
    return ports


def _backend_directives(mock_ports, proxy_mode, origins):
    if not proxy_mode:
        backend = origins or "|".join(f"http://{HOST}:{port}" for port in mock_ports)
        return [f'brix_storage_backend "{backend}";']
    return []


def _allow_directives(proxy_mode, upstream_allow):
    if upstream_allow:
        return [f"brix_cvmfs_upstream_allow {upstream_allow};"]
    return [f"brix_cvmfs_upstream_allow {HOST};"] if proxy_mode else []


def _knob_directives(knobs):
    return [f"{directive} {knobs[key]};"
            for key, directive in _KNOBS.items() if knobs.get(key) is not None]


def _location_directives(cache, mock_ports, proxy_mode, origins,
                         upstream_allow, scvmfs, extra_directives, knobs,
                         cache_store=None):
    store = cache_store.format(cache=cache) if cache_store else f"posix:{cache}"
    lines = ["brix_cvmfs on;", f"brix_cache_store {store};"]
    lines.extend(_backend_directives(mock_ports, proxy_mode, origins))
    lines.extend(_allow_directives(proxy_mode, upstream_allow))
    lines.extend(["brix_scvmfs on;"] if scvmfs else [])
    lines.extend(_knob_directives(knobs))
    lines.extend([extra_directives] if extra_directives else [])
    return lines


def _ssl_config(port, ssl_cert, ssl_key, ssl_client_ca, ssl_verify_client):
    listen = f"listen {BIND_HOST}:{port}"
    if not ssl_cert:
        return listen, ""
    listen += " ssl"
    directives = f"ssl_certificate {ssl_cert}; ssl_certificate_key {ssl_key};"
    if ssl_client_ca:
        directives += f" ssl_client_certificate {ssl_client_ca};"
    if ssl_verify_client:
        directives += f" ssl_verify_client {ssl_verify_client};"
    return listen, directives


def _write_server_config(run, port, location, directives, worker_threads,
                         ssl_cert, ssl_key, ssl_client_ca, ssl_verify_client):
    listen, ssl_lines = _ssl_config(
        port, ssl_cert, ssl_key, ssl_client_ca, ssl_verify_client)
    error_log = run.root / "logs/e.log"
    user_line = "user root;\n" if os.geteuid() == 0 else ""
    config = run.write(
        run.root / "nginx.conf",
        f"""{user_line}daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
worker_processes 1; thread_pool default threads={worker_threads};
events {{ worker_connections 256; }}
http {{ access_log off; server {{ {listen}; {ssl_lines}
    location = /metrics {{ brix_metrics on; }}
    location {location} {{
        {' '.join(directives)}
    }}
}} }}
""")
    return config, error_log


@contextmanager
def srv_instance(port_block: str | PortBlock, *, webroot=None, objects=8, seed=1,
                 repo="test.cern.ch", n_mocks=1, keepalive=False, origins=None,
                 location=None, proxy_mode=False, upstream_allow=None,
                 scvmfs=False, ssl_cert=None, ssl_key=None, worker_threads=2,
                 ssl_verify_client=None, ssl_client_ca=None,
                 extra_directives="", nginx=None, cache_store=None, **knobs):
    """Start `n_mocks` mock origins + a LiveRun nginx with a brix_cvmfs config.

    Reverse mode (default): `location /cvmfs/` proxies to the mock(s) via
    brix_storage_backend. Proxy mode (`proxy_mode=True`): `location /` gates
    absolute-form requests with brix_cvmfs_upstream_allow (no storage backend).
    Unrecognised **knobs** map through _KNOBS to brix_cvmfs* directives.
    `cache_store` overrides the store spec ("{cache}" expands to the run's
    cache dir), e.g. "pblock:{cache}?dedup=1&pack=1 block_size=256m"
    (phase-88); default = the classic local posix store.
    """
    block = _port_block(port_block)
    loc = location or ("/" if proxy_mode else "/cvmfs/")
    with LiveRun("cvmfs_conf", nginx or NGINX_BIN) as run:
        cache = run.mkdir("cache")
        run.mkdir("logs")
        mock_ports = _start_mocks(
            run, block, n_mocks, webroot, objects, seed, repo, keepalive)
        lines = _location_directives(
            cache, mock_ports, proxy_mode, origins, upstream_allow,
            scvmfs, extra_directives, knobs, cache_store)

        nginx_port = block.nginx()
        config, error_log = _write_server_config(
            run, nginx_port, loc, lines, worker_threads, ssl_cert, ssl_key,
            ssl_client_ca, ssl_verify_client)
        run.start_nginx(run.root, config, nginx_port)
        yield Server(run, nginx_port, mock_ports, cache, error_log, run.root, repo, loc)


# ---- fuse mount context manager -------------------------------------------

def _unmount(mnt: Path) -> None:
    """Plain unmount through the host's tool, then a lazy detach. Never raises.
    Teardown MUST always run: an orphaned FUSE mount wedges the whole test fleet."""
    if fuse_host.unmount(str(mnt)).returncode != 0:
        fuse_host.unmount(str(mnt), lazy=True)


def _wait_mounted(mnt: Path, timeout: float) -> bool:
    """Wait for the FUSE mount, stretching the budget on a busy/shared host.

    Every other wall-clock budget in the suite scales through budget_scale()
    (that is what TEST_BUDGET_SCALE exists for); these cvmfs helpers were the
    exception, so a mount that simply took longer under a high-concurrency run
    -- several lanes plus their fleets on one box -- reported as a fixture ERROR
    rather than as "slow".  budget_scale() floors at 1.0, so a host that
    declares nothing keeps the original timeout exactly.
    """
    deadline = time.monotonic() + timeout * budget_scale()
    while time.monotonic() < deadline:
        if os.path.ismount(str(mnt)):
            return True
        time.sleep(0.1)
    return os.path.ismount(str(mnt))


def _workspace_path(workdir, name, supplied):
    if supplied is not None:
        return supplied
    path = workdir / name
    path.mkdir(exist_ok=True)
    return path


def _mount_environment(workdir, server_url, pubkey, cache, tmp, extra_env):
    tmp_path = _workspace_path(workdir, "tmp", tmp)
    cache_path = _workspace_path(workdir, "cache", cache)
    env = {**os.environ, "BRIXCVMFS_SERVER": server_url,
           "BRIXCVMFS_PUBKEY": str(pubkey), "BRIXCVMFS_TMP": str(tmp_path),
           "BRIXCVMFS_CACHE": str(cache_path)}
    env.update(extra_env or {})
    return env


def _terminate_mount(proc, mnt):
    _unmount(mnt)
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(3)
    except subprocess.TimeoutExpired:
        proc.kill()


@contextmanager
def fuse_mount(fqrn: str, server_url: str, pubkey: str | os.PathLike, *,
               cache=None, tmp=None, mount_type="cvmfs", opts="auto_unmount",
               brixmount=None, extra_env=None, extra_args=(), timeout=15):
    """Mount through brixMount and always unmount and remove its workspace."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_mount."))
    mnt = workdir / "mnt"
    mnt.mkdir()
    env = _mount_environment(workdir, server_url, pubkey, cache, tmp, extra_env)
    argv = [brixmount or BRIXMOUNT, mount_type, fqrn, str(mnt), *extra_args, "-o", opts, "-f"]
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, proc
    finally:
        _terminate_mount(proc, mnt)
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


def check_repo(fqrn: str, server_url: str, pubkey: str | os.PathLike, *,
               cache=None, tmp=None, brixcvmfs=None, extra_env=None,
               timeout=30) -> subprocess.CompletedProcess:
    """Run `brixcvmfs --check <fqrn>` (no mount needed). Returns the completed
    process (rc 0 = healthy trust chain + root catalog)."""
    binary = brixcvmfs or os.environ.get("BRIXCVMFS_BIN")
    if binary is None:
        raise RuntimeError("no brixcvmfs binary; pass brixcvmfs= or set BRIXCVMFS_BIN")
    env = _check_environment(server_url, pubkey, cache, tmp, extra_env)
    return subprocess.run([binary, "--check", fqrn], env=env, capture_output=True,
                          text=True, timeout=timeout)


def _check_environment(server_url, pubkey, cache, tmp, extra_env):
    env = {**os.environ, "BRIXCVMFS_SERVER": server_url,
           "BRIXCVMFS_PUBKEY": str(pubkey)}
    optional = {"BRIXCVMFS_CACHE": cache, "BRIXCVMFS_TMP": tmp}
    env.update({key: str(value) for key, value in optional.items()
                if value is not None})
    env.update(extra_env or {})
    return env


# ---- raw-socket HTTP helpers ----------------------------------------------

def _request_blob(host, port, request_line, headers, body):
    hdrs = {"Host": f"{host}:{port}", "Connection": "close", **(headers or {})}
    if body:
        hdrs.setdefault("Content-Length", str(len(body)))
    blob = request_line.encode() + b"\r\n"
    blob += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()).encode()
    return blob + b"\r\n" + body


def _receive_response(sock):
    chunks = []
    while True:
        try:
            part = sock.recv(65536)
        except socket.timeout:
            break
        if not part:
            break
        chunks.append(part)
    return b"".join(chunks)


def _parse_response(raw):
    head, _, payload = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    fields = lines[0].split(b" ")
    status = int(fields[1]) if len(fields) > 1 else 0
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        headers[key.decode().strip().lower()] = value.decode().strip()
    return status, headers, payload


def raw_http(host: str, port: int, request_line: str, headers: dict | None = None,
             body: bytes = b"", timeout: float = 15) -> tuple[int, dict, bytes]:
    """Send a hand-built request and return its status, headers, and body."""
    blob = _request_blob(host, port, request_line, headers, body)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(blob)
        raw = _receive_response(s)
    return _parse_response(raw)


def request(host: str, port: int, method: str, path: str, headers: dict | None = None,
            body: bytes = b"", version: str = "HTTP/1.1") -> tuple[int, dict, bytes]:
    """Origin-form request with an arbitrary method and headers."""
    return raw_http(host, port, f"{method} {path} {version}", headers, body)


def absolute_form_request(host: str, port: int, absolute_uri: str, method: str = "GET",
                          headers: dict | None = None, version: str = "HTTP/1.1"
                          ) -> tuple[int, dict, bytes]:
    """Proxy-style absolute-form request line: '<METHOD> <absolute_uri> <version>'."""
    return raw_http(host, port, f"{method} {absolute_uri} {version}", headers)


__all__ = ["PORT_BLOCKS", "PortBlock", "Server", "srv_instance",
           "fuse_mount",
           "check_repo", "raw_http", "request", "absolute_form_request",
           "MOCK", "BRIXMOUNT", "NGINX_BIN"]
