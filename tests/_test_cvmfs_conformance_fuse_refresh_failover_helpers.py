# tests/test_cvmfs_conformance_fuse_refresh_failover.py — Phase-84 fuse corpus:
# TTL-gated refresh, replica failover, retry budget, range-resume, proxy
# precedence, -o fresh / -o tls.  Port block 13400-13419.
#
# Reference-correctness rule: official CVMFS behaviour is asserted; where brix
# deliberately or accidentally diverges the test is xfail(strict=True) with a
# `# DIVERGENCE:` comment (see docs/refactor/phase-84-cvmfs-conformance-corpus.md).
#
# Source contracts pinned from:
#   shared/cvmfs/client/client.c      — cvmfs_client_refresh: TTL-gated (manifest
#       D field, default 240), keeps old catalog on ANY refresh failure, swaps on
#       root-hash change only (no revision monotonicity check), and commits
#       cl->manifest at parse time BEFORE verify/catalog fetch.
#   shared/cvmfs/failover/failover.c  — sticky lowest-live-index selection,
#       snap-back blacklist (2s base, doubling), proxy groups.
#   shared/cvmfs/config/cvmfs_conf.c  — CVMFS_SERVER_URL split on ";,",
#       CVMFS_HTTP_PROXY groups ';' members '|', @fqrn@ expansion.
#   client/apps/fs/brixcvmfs.c        — transport: range-resume with 200-slide,
#       only NO-PROGRESS attempts consume the -o retries budget, -o fresh =
#       FRESH_CONNECT+FORBID_REUSE, -o tls = https-first with http fallback,
#       env-proxy (brix_proxy_resolve) beats config proxy beats DIRECT;
#       BRIXCVMFS_SERVER pins ONE host verbatim (never split as a list).
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zlib
import hashlib
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from random import Random

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, PortBlock, _unmount, _wait_mounted  # noqa: E402
from repo_forge import Dir, File, RepoForge  # noqa: E402
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
TINY_PROXY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs", "tiny_proxy.py")

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
pytestmark = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")

# ---- port block: session tile of "fuse_refresh_failover" -------------------
# Slots are fixed offsets into the session-shifted tile (PortBlock.base), so
# a standing fleet on the canonical range can never collide.  Slots 20/21
# spill into the next tile (fuse_trust) exactly as the canonical layout did —
# safe because fuse suites never share a session concurrently.
_BASE = PortBlock("fuse_refresh_failover").base
P_TTL = _BASE + 0
P_DOWN = _BASE + 1
P_TAMPER = _BASE + 2
P_DOWNGRADE = _BASE + 3
P_MIDREF = _BASE + 4
P_FO_A_DEAD, P_FO_A_LIVE = _BASE + 5, _BASE + 6
P_FO_B_PRI, P_FO_B_SEC = _BASE + 7, _BASE + 8
P_FO_C_PRI, P_FO_C_SEC = _BASE + 9, _BASE + 10
P_FO_D_PRI, P_FO_D_SEC = _BASE + 11, _BASE + 12
P_SYN_LIVE, P_SYN_DEAD = _BASE + 13, _BASE + 14
P_RETRY = _BASE + 15
P_RESUME = _BASE + 16
P_BLIND = _BASE + 17
P_PROXY_ORIGIN, P_PROXY_A = _BASE + 18, _BASE + 19
P_PROXY_B = _BASE + 5      # reused after the failover classes have torn down
P_OPTS = _BASE + 6         # reused after the failover classes have torn down
P_REDIR = _BASE + 20
P_REDIR_MIRROR = _BASE + 21

_PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")


# ---- local in-process origin -----------------------------------------------
# mock_stratum1.py cannot express a Range-HONOURING mid-body sever (its fault
# modes replay the full body from 0), does not log the Range header, and its
# ctl plane is HTTP-only.  This origin serves a forged webroot in-process with:
#   * per-request log incl. the Range header (resume observation),
#   * sever_after=N: honour Range, send at most N body bytes, then close
#     (true mid-transfer sever → the client's range-resume path),
#   * ignore_range: answer every request 200-full (the 200-slide path),
#   * one-shot faults ("refuse" = close pre-status, "http500", "sever_half"),
#   * TCP connection counting (for -o fresh) and a stock geo API endpoint.
class LocalOrigin:
    def __init__(self, port, webroot, keepalive=False):
        self.port = port
        self.webroot = Path(webroot)
        self.keepalive = keepalive
        self.lock = threading.Lock()
        self.log = []               # [{"path","range"}]
        self.connections = 0
        self.ignore_range = False
        self.sever_after = 0
        self.faults = []            # [[mode, count, path_re]]
        self._httpd = None
        self._thread = None

    def start(self):
        handler = _make_handler(self)
        self._httpd = ThreadingHTTPServer((BIND_HOST, self.port), handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def set_fault(self, mode, count, path_re=None):
        with self.lock:
            self.faults.append([mode, count, path_re])

    def clear_faults(self):
        with self.lock:
            self.faults.clear()

    def take_fault(self, path):
        with self.lock:
            for f in self.faults:
                if f[1] > 0 and (f[2] is None or f[2] in path):
                    f[1] -= 1
                    return f[0]
        return None

    def reset_counters(self):
        with self.lock:
            self.log.clear()
            self.connections = 0

    def requests(self, needle):
        with self.lock:
            return [dict(e) for e in self.log if needle in e["path"]]


class _OriginHandler(BaseHTTPRequestHandler):
    origin = None

    def log_message(self, *args):
        pass

    def setup(self):
        with self.origin.lock:
            self.origin.connections += 1
        super().setup()

    def _reply(self, code, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _record_request(self):
        request_range = self.headers.get("Range")
        with self.origin.lock:
            self.origin.log.append({"path": self.path, "range": request_range})

    def _reply_geo(self):
        if "/api/v1.0/geo/" not in self.path:
            return False
        count = len(self.path.rsplit("/", 1)[-1].split(","))
        order = ",".join(str(index + 1) for index in range(count))
        self._reply(200, order.encode() + b"\n")
        return True

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _reply_fault(self, mode):
        if mode == "refuse":
            self.close_connection = True
            self.connection.close()
            return True
        if mode == "http500":
            self._reply(500, b"origin error")
            return True
        if mode and mode.startswith("redirect_host:"):
            location = f"http://{mode[len('redirect_host:'):]}{self.path}"
            self._redirect(location)
            return True
        if mode and mode.startswith("redirect:"):
            self._redirect(mode[len("redirect:"):])
            return True
        return False

    def _range_window(self, body):
        request_range = self.headers.get("Range")
        if not request_range or not request_range.startswith("bytes="):
            return 0, len(body) - 1, 200, {}
        if self.origin.ignore_range:
            return 0, len(body) - 1, 200, {}
        first, _, last = request_range[len("bytes="):].partition("-")
        try:
            start = int(first)
            end = int(last) if last else len(body) - 1
        except ValueError:
            start, end = 0, len(body) - 1
        if start >= len(body):
            self._reply(416, b"", {"Content-Range": f"bytes */{len(body)}"})
            return None
        end = min(end, len(body) - 1)
        extra = {"Content-Range": f"bytes {start}-{end}/{len(body)}"}
        return start, end, 206, extra

    def _sever_response(self, part, code, extra, mode):
        sever = self.origin.sever_after
        if mode == "sever_half":
            sever = max(1, len(part) // 2)
        if not sever or sever >= len(part):
            return False
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(part)))
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(part[:sever])
        self.wfile.flush()
        self.close_connection = True
        self.connection.close()
        return True

    def _serve_file(self, mode):
        full = self.origin.webroot / self.path.lstrip("/")
        if not full.is_file():
            self._reply(404, b"not found")
            return
        body = full.read_bytes()
        window = self._range_window(body)
        if window is None:
            return
        start, end, code, extra = window
        part = body[start:end + 1]
        if not self._sever_response(part, code, extra, mode):
            self._reply(code, part, extra)

    def do_GET(self):
        self._record_request()
        if self._reply_geo():
            return
        mode = self.origin.take_fault(self.path)
        if not self._reply_fault(mode):
            self._serve_file(mode)


def _make_handler(origin):
    class Handler(_OriginHandler):
        pass

    Handler.origin = origin
    Handler.protocol_version = "HTTP/1.1" if origin.keepalive else "HTTP/1.0"
    return Handler


# ---- local helpers ----------------------------------------------------------

def cas_key(content, compressed=True):
    """CAS hex of a forged File(content) — hash of the STORED bytes, identical
    zlib.compress call to repo_forge._write_cas."""
    stored = zlib.compress(content) if compressed else content
    return hashlib.sha1(stored).hexdigest()


def cas_needle(content):
    k = cas_key(content)
    return f"{k[:2]}/{k[2:]}"


def publish_revision(forge, tree, revision, *, ttl=None):
    """Re-forge a NEW revision in place: rebuild the root catalog from `tree`,
    then rewrite + resign the manifest (repo_forge gap: no public revision-bump
    API — uses its internal builders, keys are kept until forge.close())."""
    forge.revision = revision
    # A coherent publisher stamps the catalog's own 'revision' property too —
    # the client cross-checks it against the manifest 'S' (rollback protection)
    # and refuses a catalog/manifest revision mismatch.
    forge.properties["revision"] = str(revision)
    if ttl is not None:
        forge.ttl = ttl
    root = Dir(entries=tree)
    forge.root_catalog_hash, forge.root_catalog_size = forge._build_catalog(
        "", "", root, is_nested=False, props=forge.properties)
    forge.rewrite_manifest(forge._manifest_fields())
    return forge.root_catalog_hash


def _mount_workdir():
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_rf."))
    for name in ("mnt", "tmp", "cache"):
        (workdir / name).mkdir()
    return workdir


def _config_text(server_url, proxy_conf):
    lines = []
    if server_url is not None:
        lines.append(f'CVMFS_SERVER_URL="{server_url}"\n')
    if proxy_conf is not None:
        lines.append(f'CVMFS_HTTP_PROXY="{proxy_conf}"\n')
    return "".join(lines)


def _configure_mount_environment(workdir, env, server_url, proxy_conf):
    if server_url is None and proxy_conf is None:
        return
    config_dir = workdir / "etc"
    config_dir.mkdir()
    (config_dir / "default.conf").write_text(_config_text(server_url, proxy_conf))
    env["BRIXCVMFS_ETC"] = str(config_dir)


def _apply_environment(env, extra):
    for key, value in (extra or {}).items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value


def _mount_environment(workdir, pubkey, server_env, server_url, proxy_conf, extra):
    env = {
        key: value for key, value in os.environ.items()
        if key not in _PROXY_VARS and not key.startswith("BRIXCVMFS_")
    }
    env["BRIXCVMFS_PUBKEY"] = str(pubkey)
    env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    if server_env is not None:
        env["BRIXCVMFS_SERVER"] = server_env
    _configure_mount_environment(workdir, env, server_url, proxy_conf)
    _apply_environment(env, extra)
    return env


def _mount_options(retries, extra):
    opts = "auto_unmount,attr_timeout=0,entry_timeout=0"
    if retries is not None:
        opts += f",retries={retries}"
    if extra:
        opts += "," + extra
    return opts


def _start_mount(argv, env, log, mode):
    with open(log, mode) as handle:
        return subprocess.Popen(argv, env=env, stdout=handle, stderr=handle)


def _wait_or_retry_mount(proc, argv, env, mountpoint, log, timeout):
    _wait_mounted(mountpoint, timeout)
    if os.path.ismount(mountpoint) or proc.poll() is None:
        return proc
    time.sleep(2.0)
    proc = _start_mount(argv, env, log, "ab")
    _wait_mounted(mountpoint, timeout)
    return proc


def _preserve_mount_failure(mountpoint, log, workdir):
    if os.path.ismount(mountpoint) or not log.exists():
        return
    keep = Path(tempfile.gettempdir()) / "brixcvmfs_mount_failures"
    keep.mkdir(exist_ok=True)
    shutil.copy(log, keep / f"{workdir.name}.log")


def _stop_mount(proc, mountpoint, workdir):
    _unmount(mountpoint)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
    _unmount(mountpoint)
    shutil.rmtree(workdir, ignore_errors=True)


@contextmanager
def conf_mount(fqrn, pubkey, *, server_env=None, server_url=None, proxy_conf=None,
               env_extra=None, opts_extra="", retries=1, timeout=15):
    """Mount with deterministic proxy settings and always unmount on exit."""
    workdir = _mount_workdir()
    mountpoint = workdir / "mnt"
    env = _mount_environment(
        workdir, pubkey, server_env, server_url, proxy_conf, env_extra
    )
    options = _mount_options(retries, opts_extra)
    argv = [BRIXMOUNT, "cvmfs", fqrn, str(mountpoint), "-o", options, "-f"]
    log = workdir / "brixmount.log"
    proc = _start_mount(argv, env, log, "wb")
    try:
        proc = _wait_or_retry_mount(proc, argv, env, mountpoint, log, timeout)
        yield mountpoint, proc
    finally:
        _preserve_mount_failure(mountpoint, log, workdir)
        _stop_mount(proc, mountpoint, workdir)


def xattr(path, name):
    return os.getxattr(path, name).decode()


def _forge(tmp, ttl=240, revision=1, tree=None):
    forge = RepoForge(REPO, tmp / "web", ttl=ttl, revision=revision).build(
        tree if tree is not None else _tree_v1(), tmp / "repo.pub")
    return forge, tmp / "web", tmp / "repo.pub"


CHANGE_V1 = b"change-v1\n"
CHANGE_V2 = b"change-v2-different-content\n"
KEEP_V1 = b"keep-v1\n"
REMOVE_V1 = b"remove-me-v1\n"
NEW_V2 = b"new-in-rev2\n"
LEAF_V1 = b"leaf-v1\n"


def _tree_v1():
    return {"keep.txt": File(KEEP_V1), "change.txt": File(CHANGE_V1),
            "remove.txt": File(REMOVE_V1), "sub": Dir({"leaf.txt": File(LEAF_V1)})}


def _tree_v2():
    return {"keep.txt": File(KEEP_V1), "change.txt": File(CHANGE_V2),
            "new.txt": File(NEW_V2), "sub": Dir({"leaf.txt": File(LEAF_V1)})}


def _url(port):
    return f"http://{HOST}:{port}/cvmfs/{REPO}"


def _stat_errno(path):
    try:
        os.stat(path)
        return 0
    except OSError as e:
        return e.errno


# ============================================================================
# TTL refresh — publish rev2 at origin; nothing changes inside D, everything
# switches atomically after D + a triggering getattr.
# ============================================================================

def _spawn_proxy(procs, port, logfile):
    p = subprocess.Popen([sys.executable, TINY_PROXY, str(port), str(logfile)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(p)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if logfile.exists() and "listening" in logfile.read_text():
            return p
        time.sleep(0.1)
    raise RuntimeError(f"tiny_proxy did not start on {port}")


def _forwards(logfile):
    return [l for l in logfile.read_text().splitlines() if l.startswith("GET-forward")]
