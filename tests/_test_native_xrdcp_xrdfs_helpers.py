# _test_native_xrdcp_xrdfs_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_native_xrdcp_xrdfs.py.  `from _test_native_xrdcp_xrdfs_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""
Native xrdcp/xrdfs clients (phase-37) — M1: anonymous xrdfs stat/ls.

Validates the project's own clean-room `xrdfs` (built under client/, linking
libxrdproto, with NO libXrdCl/libXrdSec*) against:
  - on-disk ground truth (a file we create under DATA_ROOT), and
  - the system `xrdfs` (value + exit-code parity),
across BOTH the nginx anon endpoint (:11094) and the reference xrootd (:11098).

The native binary is built on demand (make -C client). If a C toolchain or the
build is unavailable the module is skipped rather than failing unrelated runs.

Later milestones (M2 download, M3 upload) extend this file.
"""

import hashlib
import os
import re
import shutil
import subprocess
import time

import pytest

from settings import (
    BIND_HOST,
    CA_DIR,
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    NGINX_TOKEN_PORT,
    PROXY_STD,
    REF_BRIX_PORT,
    SERVER_HOST,
    TOKENS_DIR,
    url_host,
)

pytestmark = pytest.mark.timeout(180)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")

# Native xrdcp uses root:// URLs (host:port//path).
NGINX_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
REF_URL = f"root://{HOST}:{REF_BRIX_PORT}"

# Endpoints under test: (label, host:port string). The native xrdfs accepts the
# bare "host:port" form (as well as a root:// URL).
ENDPOINTS = [
    ("nginx", f"{SERVER_HOST}:{NGINX_ANON_PORT}"),
    ("ref",   f"{HOST}:{REF_BRIX_PORT}"),
]

_CLEAN_ENV = {k: v for k, v in os.environ.items()}
_CLEAN_ENV.pop("X509_USER_PROXY", None)
_CLEAN_ENV.pop("X509_CERT_DIR", None)


@pytest.fixture(scope="module")
def native_xrdfs():
    """Build (if needed) and return the path to the native xrdfs binary."""
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler available to build the native client")
    proc = subprocess.run(
        ["make", "-C", os.path.join(REPO, "client")],
        capture_output=True, text=True, timeout=180,
    )
    if proc.returncode != 0 or not os.path.exists(NATIVE_XRDFS):
        pytest.skip(f"native client build failed:\n{proc.stdout}\n{proc.stderr}")
    return NATIVE_XRDFS


@pytest.fixture(scope="module")
def native_xrdcp(native_xrdfs):
    """The xrdcp binary is built by the same `make` as xrdfs."""
    if not os.path.exists(NATIVE_XRDCP):
        pytest.skip("native xrdcp not built")
    return NATIVE_XRDCP


def _md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run(bin_path, endpoint, *args, timeout=30, env=None):
    proc = subprocess.run(
        [bin_path, endpoint, *args],
        capture_output=True, text=True, env=env or _CLEAN_ENV, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


TOKEN_URL = f"root://{SERVER_HOST}:{NGINX_TOKEN_PORT}"
TOKEN_FILE = os.path.join(TOKENS_DIR, "upstream.jwt")


def _token_env():
    env = dict(_CLEAN_ENV)
    env["BEARER_TOKEN_FILE"] = TOKEN_FILE
    return env


def _stat_field(stdout, field):
    m = re.search(rf"^{field}:\s*(.+)$", stdout, re.MULTILINE)
    return m.group(1).strip() if m else None


def _ls_basenames(stdout):
    out = set()
    for line in stdout.splitlines():
        line = line.strip()
        if line:
            out.add(line.rstrip("/").rsplit("/", 1)[-1])
    return out


@pytest.fixture
def seeded_file():
    """Create a uniquely-named file under DATA_ROOT (served by both backends)."""
    name = f"_native_m1_{os.getpid()}_{int(time.time() * 1000)}.bin"
    path = os.path.join(DATA_ROOT, name)
    payload = os.urandom(1234)
    with open(path, "wb") as fh:
        fh.write(payload)
    try:
        yield name, len(payload)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# --------------------------------------------------------------------------
# M3 — xrdcp upload (+ POSC, --force)
# --------------------------------------------------------------------------

@pytest.fixture
def remote_upload_name():
    """A unique remote name; remove the resulting on-disk file afterwards."""
    name = f"_native_up_{os.getpid()}_{int(time.time() * 1000)}.bin"
    try:
        yield name
    finally:
        try:
            os.unlink(os.path.join(DATA_ROOT, name))
        except OSError:
            pass


# --------------------------------------------------------------------------
# M4 — token (ztn) authentication on :11097
# --------------------------------------------------------------------------

@pytest.fixture
def have_token():
    if not os.path.exists(TOKEN_FILE):
        pytest.skip("no minted bearer token in the harness")
    return TOKEN_FILE


# --------------------------------------------------------------------------
# M4 — GSI (X.509 proxy) authentication on :11095 (cleartext GSI)
# --------------------------------------------------------------------------

GSI_URL = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"


@pytest.fixture
def have_proxy():
    if not os.path.exists(PROXY_STD) or not os.path.isdir(CA_DIR):
        pytest.skip("no GSI proxy / CA dir in the harness")
    return PROXY_STD


def _gsi_env():
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = CA_DIR
    return env


# --------------------------------------------------------------------------
# M7 — in-protocol TLS: GSI over roots:// on :11096
# --------------------------------------------------------------------------

GSI_TLS_ENDPOINT = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
GSI_TLS_URL = GSI_TLS_ENDPOINT


# --------------------------------------------------------------------------
# M5 — redirect / kXR_wait following (self-contained in-process stub server)
#
# These exercise the client's redirect follower without the full CMS cluster:
# a tiny TCP server speaks just enough of the protocol (handshake + login + one
# reply) to drive each path. See upstream_protocol_stubs.py for the wire helpers.
# --------------------------------------------------------------------------

import socket as _socket
import struct as _struct
import threading as _threading

from upstream_protocol_stubs import (
    _bootstrap_login_ok,
    _hdr,
    _read_request,
    _recv_exact,
    _redirect_body,
    kXR_ok,
    kXR_redirect,
    kXR_wait,
)


class _StubServer:
    """A one-shot-per-connection XRootD stub on 127.0.0.1:<ephemeral port>.

    `handler(conn, port)` runs for each accepted connection; the client makes a
    fresh connection per redirect hop, so the handler is re-entered each time.
    """

    def __init__(self, handler):
        self._handler = handler
        self._srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        self._srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, 0))
        self.port = self._srv.getsockname()[1]
        self._srv.listen(8)
        self._thread = _threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        try:
            self._srv.close()
        except OSError:
            pass

    def _loop(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            try:
                conn.settimeout(10)
                self._handler(conn, self.port)
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass


def _stat_ok_reply(conn, sid):
    """Reply to a kXR_stat with a minimal valid '<id> <size> <flags> <mtime>'."""
    body = b"1 42 16 1700000000"
    conn.sendall(_hdr(sid, kXR_ok, len(body)))
    conn.sendall(body)


# --------------------------------------------------------------------------
# M6 — paged I/O (kXR_pgread/pgwrite) + --cksum
# --------------------------------------------------------------------------

kXR_status = 4007

# Standard reflected CRC32c (Castagnoli): init 0xFFFFFFFF, final XOR 0xFFFFFFFF
# (check value of "123456789" == 0xe3069283). This is exactly what libxrdproto's
# brix_crc32c produces — verified C-vs-Python — which the client uses for both
# the kXR_status header digest and per-page digests, and which the server's
# kXR_Qcksum crc32c also matches.
_CRC32C_POLY = 0x82F63B78
_CRC32C_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_CRC32C_POLY if (_c & 1) else 0)
    _CRC32C_TAB.append(_c & 0xFFFFFFFF)


def _crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32C_TAB[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def _pgread_status_frame(streamid, file_off, page_data, corrupt_page=False):
    """Build a complete kXR_status pgread reply: 8B hdr + 16B status + 8B offset
    + one [crc32c(4)][data] page unit. corrupt_page flips a data byte AFTER the
    CRC is computed so the page digest no longer matches (header CRC stays valid).
    """
    crc = _crc32c(page_data)
    data = bytearray(page_data)
    if corrupt_page and data:
        data[0] ^= 0xFF
    pgdata = _struct.pack(">I", crc) + bytes(data)

    # Status body bytes [streamID..offset] (20 bytes), CRC-covered.
    covered = (streamid +                       # streamID[2]
               bytes([30, 0]) +                 # requestid(pgread-3000), resptype(Final)
               b"\x00\x00\x00\x00" +            # reserved[4]
               _struct.pack(">I", len(pgdata)) +  # bdy.dlen
               _struct.pack(">q", file_off))    # offset[8]
    hdr_crc = _crc32c(covered)
    status_body = _struct.pack(">I", hdr_crc) + covered      # 24 bytes
    hdr = _struct.pack(">2sHI", streamid, kXR_status, len(status_body))
    return hdr + status_body + pgdata


def _serve_one_pgread(conn, payload, corrupt_page):
    """stat → open → pgread(one frame) → close, for a single small file."""
    _bootstrap_login_ok(conn)
    # stat
    sid = _read_request(conn)
    body = ("1 %d 16 1700000000" % len(payload)).encode()
    conn.sendall(_hdr(sid, kXR_ok, len(body)))
    conn.sendall(body)
    # open (read) → 4-byte fhandle
    sid = _read_request(conn)
    conn.sendall(_hdr(sid, kXR_ok, 4))
    conn.sendall(b"\x00\x00\x00\x00")
    # pgread → one Final kXR_status frame
    hdr = _recv_exact(conn, 24)
    sid = hdr[:2]
    dlen = _struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    conn.sendall(_pgread_status_frame(sid, 0, payload, corrupt_page))
    # close
    sid = _read_request(conn)
    conn.sendall(_hdr(sid, kXR_ok, 0))


# --------------------------------------------------------------------------
# M9 — full xrdfs: mkdir/rm/rmdir/mv/chmod/truncate/cat/tail/locate/query/
#      statvfs/prepare + the interactive REPL. Each test creates under an
#      autocleaned _fstest_ directory (mirrors tests/test_fs_ops.py).
# --------------------------------------------------------------------------

import shutil as _shutil
import zlib as _zlib


@pytest.fixture
def m9_dir():
    """A unique remote directory name; its on-disk tree is removed afterwards."""
    name = f"_fstest_{os.getpid()}_{int(time.time() * 1000)}"
    try:
        yield name
    finally:
        _shutil.rmtree(os.path.join(DATA_ROOT, name), ignore_errors=True)


def _fs(native_xrdfs, *args, timeout=15):
    return _run(native_xrdfs, NGINX_URL, *args, timeout=timeout)


# --------------------------------------------------------------------------
# M8 — parallel --streams (kXR_bind) + server-side --tpc
# --------------------------------------------------------------------------

import socket as _m8_socket

from settings import ROOT_TPC_NGINX_PORT, ROOT_TPC_REF_PORT

TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
ROOT_TPC_DATA = os.path.join(TEST_ROOT, "data-root-tpc")
ROOT_TPC_REF_DATA = os.path.join(TEST_ROOT, "data-root-tpc-ref")
ANON_ACCESS_LOG = os.path.join(TEST_ROOT, "logs", "brix_access_anon.log")


def _port_open(port):
    try:
        with _m8_socket.create_connection((SERVER_HOST, port), timeout=1):
            return True
    except OSError:
        return False


def _count_log(path, needle):
    try:
        with open(path, "r", errors="replace") as fh:
            return sum(1 for ln in fh if needle in ln)
    except OSError:
        return 0

__all__ = [n for n in dir() if not n.startswith('__')]
