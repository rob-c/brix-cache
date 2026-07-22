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
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
import urllib.request

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.live_common import LiveRun
from lib_py.util import wait_tcp
from settings import BIND_HOST, HOST

MOCK = str(REPO_ROOT / "tests/cvmfs/mock_stratum1.py")
BRIXMOUNT = os.environ.get("BRIXMOUNT_BIN", str(REPO_ROOT / "client/bin/brixMount"))
NGINX_BIN = os.environ.get("NGINX_BIN") or (
    str(REPO_ROOT / "objs/nginx") if (REPO_ROOT / "objs/nginx").exists()
    else "/tmp/nginx-1.28.3/objs/nginx")

# Each corpus file owns a 20-port block (design doc §"Port blocks"). Mock origins
# take base+0..9, nginx instances base+10..19 — no collisions under xdist since a
# module runs in a single worker and distinct files own distinct blocks. The bases
# below are *canonical* (offset 0); the whole map is shifted by a per-session base
# offset (see `_SESSION_OFFSET`) so two sessions never draw the same absolute port
# for the same file. The relative layout is preserved, so per-file structure a test
# relies on (e.g. srv_proxy's guaranteed-dead ports at base+17..19) still holds.
PORT_BLOCKS = {
    "srv_gate": 13100, "srv_manifest": 13120, "srv_cas": 13140, "srv_http": 13160,
    "srv_proxy": 13180, "srv_geo": 13200, "srv_resilience": 13220, "srv_config": 13240,
    "srv_verify": 13260, "srv_authz": 13280,
    "fuse_cache": 13300, "fuse_catalog": 13320, "fuse_manifest_parse": 13340,
    "fuse_posix": 13360, "fuse_read": 13380, "fuse_refresh_failover": 13400,
    "fuse_trust": 13420, "fuse_whitelist": 13440, "fuse_pin": 13460,
}
# NOTE: the prefetch/prewarm suites (test_cvmfs_prefetch.py, test_cvmfs_prewarm.py)
# deliberately use OS-assigned ephemeral ports (bind port 0) instead of a block
# here: they control both the origin and the client's $BRIXCVMFS_SERVER, and a
# new block entry would shift _CANON_HI/_TILE under sessions already running.

# The canonical map occupies [_CANON_LO, _CANON_HI); we tile that span across a wide
# range and hand each session one free tile, so concurrent sessions (multiple devs,
# CI shards, agent runs on one host) get fully disjoint windows.  Each tile carries
# one extra port past the block span: a lock port this process binds and HOLDS, so
# claiming a tile is atomic across processes (12 xdist workers starting at once
# must never probe the same tile "free" and both settle on it).
_CANON_LO = min(PORT_BLOCKS.values())
_CANON_HI = max(PORT_BLOCKS.values()) + 20
_TILE = (_CANON_HI - _CANON_LO) + 1
_TILE_LOCK: socket.socket | None = None   # held for process lifetime on purpose
# Stay below the OS ephemeral range (typically 32768+) so a tile never fights
# outbound connections' auto-assigned ports.
_N_TILES = (32768 - _CANON_LO) // _TILE
# SystemRandom is immune to pytest-randomly's global seeding, so two sessions seeded
# identically for reproducibility still pick independent tiles.
_SYSRAND = random.SystemRandom()


def _claim_tile(tile_lo: int) -> bool:
    """Atomically claim the tile by binding and HOLDING its lock port (the extra
    port past the block span), then probe a spread of sentinel ports transiently
    to skip tiles occupied by listeners that don't use the lock protocol.  Bind
    is atomic across processes: of two workers racing for a tile, exactly one
    wins the lock port and the loser moves on."""
    global _TILE_LOCK
    lock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        lock.bind((BIND_HOST, tile_lo + _TILE - 1))
    except OSError:
        lock.close()
        return False
    for d in (0, _TILE // 3, 2 * _TILE // 3, _TILE - 2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((BIND_HOST, tile_lo + d))
        except OSError:
            lock.close()
            return False
        finally:
            s.close()
    _TILE_LOCK = lock
    return True


def _pick_session_offset() -> int:
    """Choose a per-process offset (a multiple of _TILE) into a tile claimed via
    its lock port. Tiles are disjoint and the claim is atomic, so concurrent
    processes (xdist workers, other sessions on the host) can never share one.
    `CVMFS_CONFORMANCE_PORT_BASE` pins tile 0's absolute base for CI/debugging."""
    env = os.environ.get("CVMFS_CONFORMANCE_PORT_BASE")
    if env:
        return int(env) - _CANON_LO
    order = list(range(_N_TILES))
    _SYSRAND.shuffle(order)
    for t in order:
        if _claim_tile(_CANON_LO + t * _TILE):
            return t * _TILE
    return 0                                        # all tiles busy: fall back to canonical


# Computed once per process; every PortBlock in this session shares it, so a mock and
# its nginx (allocated in the same process) stay paired.
_SESSION_OFFSET = _pick_session_offset()


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
    with urllib.request.urlopen(f"http://{HOST}:{port}/ctl/{endpoint}", timeout=10) as r:
        return json.load(r)


def _ctl_post(port: int, endpoint: str, payload: dict | None = None) -> None:
    data = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(f"http://{HOST}:{port}/ctl/{endpoint}",
                                 method="POST", data=data)
    urllib.request.urlopen(req, timeout=10).read()


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


@contextmanager
def srv_instance(port_block: str | PortBlock, *, webroot=None, objects=8, seed=1,
                 repo="test.cern.ch", n_mocks=1, keepalive=False, origins=None,
                 location=None, proxy_mode=False, upstream_allow=None,
                 scvmfs=False, ssl_cert=None, ssl_key=None, worker_threads=2,
                 extra_directives="", nginx=None, **knobs):
    """Start `n_mocks` mock origins + a LiveRun nginx with a brix_cvmfs config.

    Reverse mode (default): `location /cvmfs/` proxies to the mock(s) via
    brix_storage_backend. Proxy mode (`proxy_mode=True`): `location /` gates
    absolute-form requests with brix_cvmfs_upstream_allow (no storage backend).
    Unrecognised **knobs** map through _KNOBS to brix_cvmfs* directives.
    """
    block = port_block if isinstance(port_block, PortBlock) else PortBlock(port_block)
    loc = location or ("/" if proxy_mode else "/cvmfs/")
    with LiveRun("cvmfs_conf", nginx or NGINX_BIN) as run:
        cache = run.mkdir("cache")
        run.mkdir("logs")
        mock_ports = [block.mock() for _ in range(n_mocks)]
        for i, p in enumerate(mock_ports):
            _spawn_mock(run, p, webroot=webroot, objects=objects, seed=seed + i,
                        repo=repo, keepalive=keepalive)

        lines = ["brix_cvmfs on;", f"brix_cache_store posix:{cache};"]
        if not proxy_mode:
            backend = origins or "|".join(f"http://{HOST}:{p}" for p in mock_ports)
            lines.append(f'brix_storage_backend "{backend}";')
        if upstream_allow:
            lines.append(f"brix_cvmfs_upstream_allow {upstream_allow};")
        elif proxy_mode:
            lines.append(f"brix_cvmfs_upstream_allow {HOST};")
        if scvmfs:
            lines.append("brix_scvmfs on;")
        for key, directive in _KNOBS.items():
            if knobs.get(key) is not None:
                lines.append(f"{directive} {knobs[key]};")
        if extra_directives:
            lines.append(extra_directives)

        nginx_port = block.nginx()
        listen = f"listen {BIND_HOST}:{nginx_port}"
        if ssl_cert:
            listen += " ssl"
        ssl_lines = (f"ssl_certificate {ssl_cert}; ssl_certificate_key {ssl_key};"
                     if ssl_cert else "")
        error_log = run.root / "logs/e.log"
        # Under a root harness nginx drops workers to `nobody`, which cannot
        # traverse the 0700 mkdtemp root nor write the root-owned cache store —
        # the cache fill then fails EACCES and every .cvmfspublished/data GET
        # returns 403/502. Keep workers as root (the §4b posture) so they can
        # read/write this throwaway tree; unprivileged (euid!=0, the §5a runner)
        # the invoking user already owns it, so no directive is injected.
        user_line = "user root;\n" if os.geteuid() == 0 else ""
        config = run.write(
            run.root / "nginx.conf",
            f"""{user_line}daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
worker_processes 1; thread_pool default threads={worker_threads};
events {{ worker_connections 256; }}
http {{ access_log off; server {{ {listen}; {ssl_lines}
    location {loc} {{
        {' '.join(lines)}
    }}
}} }}
""")
        run.start_nginx(run.root, config, nginx_port)
        yield Server(run, nginx_port, mock_ports, cache, error_log, run.root, repo, loc)


# ---- fuse mount context manager -------------------------------------------

def _unmount(mnt: Path) -> None:
    """fusermount3 -u / fusermount -u / lazy umount. Never raises. Teardown MUST
    always run: an orphaned FUSE mount wedges the whole test fleet."""
    for argv in (["fusermount3", "-u"], ["fusermount", "-u"], ["umount", "-l"]):
        if shutil.which(argv[0]) is None:
            continue
        rc = subprocess.run([*argv, str(mnt)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL).returncode
        if rc == 0:
            return


def _wait_mounted(mnt: Path, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.ismount(str(mnt)):
            return True
        time.sleep(0.1)
    return os.path.ismount(str(mnt))


@contextmanager
def fuse_mount(fqrn: str, server_url: str, pubkey: str | os.PathLike, *,
               cache=None, tmp=None, mount_type="cvmfs", opts="auto_unmount",
               brixmount=None, extra_env=None, extra_args=(), timeout=15):
    """Mount `fqrn` via brixMount with env pinning; ALWAYS unmount on exit.

    Yields (mnt_path, proc). The mount may not come up (bad trust chain, etc.) —
    check os.path.ismount(mnt); teardown unmounts unconditionally either way.
    """
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_mount."))
    mnt = workdir / "mnt"
    mnt.mkdir()
    env = {
        **os.environ,
        "BRIXCVMFS_SERVER": server_url,
        "BRIXCVMFS_PUBKEY": str(pubkey),
        "BRIXCVMFS_TMP": str(tmp if tmp is not None else (workdir / "tmp")),
    }
    (workdir / "tmp").mkdir(exist_ok=True)
    if cache is not None:
        env["BRIXCVMFS_CACHE"] = str(cache)
    else:
        (workdir / "cache").mkdir(exist_ok=True)
        env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    if extra_env:
        env.update(extra_env)

    argv = [brixmount or BRIXMOUNT, mount_type, fqrn, str(mnt), *extra_args, "-o", opts, "-f"]
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_mounted(mnt, timeout)
        yield mnt, proc
    finally:
        _unmount(mnt)
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()
        _unmount(mnt)          # belt-and-braces after the process is gone
        shutil.rmtree(workdir, ignore_errors=True)


def check_repo(fqrn: str, server_url: str, pubkey: str | os.PathLike, *,
               cache=None, tmp=None, brixcvmfs=None, extra_env=None,
               timeout=30) -> subprocess.CompletedProcess:
    """Run `brixcvmfs --check <fqrn>` (no mount needed). Returns the completed
    process (rc 0 = healthy trust chain + root catalog)."""
    binary = brixcvmfs or os.environ.get("BRIXCVMFS_BIN")
    if binary is None:
        raise RuntimeError("no brixcvmfs binary; pass brixcvmfs= or set BRIXCVMFS_BIN")
    env = {**os.environ, "BRIXCVMFS_SERVER": server_url, "BRIXCVMFS_PUBKEY": str(pubkey)}
    if cache is not None:
        env["BRIXCVMFS_CACHE"] = str(cache)
    if tmp is not None:
        env["BRIXCVMFS_TMP"] = str(tmp)
    if extra_env:
        env.update(extra_env)
    return subprocess.run([binary, "--check", fqrn], env=env, capture_output=True,
                          text=True, timeout=timeout)


# ---- raw-socket HTTP helpers ----------------------------------------------

def raw_http(host: str, port: int, request_line: str, headers: dict | None = None,
             body: bytes = b"", timeout: float = 15) -> tuple[int, dict, bytes]:
    """Send a hand-built request line (e.g. 'GET /path HTTP/1.1' or an
    absolute-form 'GET http://origin/x HTTP/1.1') and return (status, headers, body)."""
    hdrs = {"Host": f"{host}:{port}", "Connection": "close", **(headers or {})}
    if body:
        hdrs.setdefault("Content-Length", str(len(body)))
    blob = request_line.encode() + b"\r\n"
    blob += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()).encode()
    blob += b"\r\n" + body

    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(blob)
        chunks = []
        while True:
            try:
                part = s.recv(65536)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1]) if len(lines[0].split(b" ")) > 1 else 0
    resp_headers = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        resp_headers[k.decode().strip().lower()] = v.decode().strip()
    return status, resp_headers, payload


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
