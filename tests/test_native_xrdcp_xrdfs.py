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
    REF_XROOTD_PORT,
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
REF_URL = f"root://{HOST}:{REF_XROOTD_PORT}"

# Endpoints under test: (label, host:port string). The native xrdfs accepts the
# bare "host:port" form (as well as a root:// URL).
ENDPOINTS = [
    ("nginx", f"{SERVER_HOST}:{NGINX_ANON_PORT}"),
    ("ref",   f"{HOST}:{REF_XROOTD_PORT}"),
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
# success
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_stat_size_matches_disk(native_xrdfs, seeded_file, label, endpoint):
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, endpoint, "stat", f"/{name}")
    assert rc == 0, f"[{label}] stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), f"[{label}] size mismatch:\n{out}"
    flags = _stat_field(out, "Flags")
    assert flags is not None and "IsReadable" in flags, f"[{label}] flags:\n{out}"


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_ls_contains_seeded_file(native_xrdfs, seeded_file, label, endpoint):
    name, _ = seeded_file
    rc, out, err = _run(native_xrdfs, endpoint, "ls", "/")
    assert rc == 0, f"[{label}] ls failed rc={rc}: {err}"
    assert name in _ls_basenames(out), f"[{label}] {name} not in ls:\n{out}"


@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_ls_matches_system_xrdfs(native_xrdfs, label, endpoint):
    """The native client and the system xrdfs see the same directory entries.

    Lists a dedicated, test-owned subdirectory — NOT the shared root.  The suite
    runs under pytest-xdist and sibling tests continuously create and delete files
    in "/", so an exact set-equality comparison of two time-separated `ls /` calls
    is inherently racy (the entry set changes between the native and the system
    call).  A private subdirectory that only this test populates is stable, so any
    difference is a genuine native-vs-stock divergence rather than a timing flake."""
    if shutil.which("xrdfs") is None:
        pytest.skip("system xrdfs not installed")
    sub = f"_native_lsmatch_{os.getpid()}_{int(time.time() * 1000)}"
    subdir = os.path.join(DATA_ROOT, sub)
    os.makedirs(subdir, exist_ok=True)
    try:
        for fn in ("alpha.bin", "beta.txt", "gamma.dat"):
            with open(os.path.join(subdir, fn), "wb") as fh:
                fh.write(os.urandom(64))
        os.makedirs(os.path.join(subdir, "nested"), exist_ok=True)
        rc_n, out_n, _ = _run(native_xrdfs, endpoint, "ls", f"/{sub}")
        rc_s, out_s, _ = _run("xrdfs", endpoint, "ls", f"/{sub}")
        assert rc_n == 0 and rc_s == 0, f"[{label}] native rc={rc_n} system rc={rc_s}"
        assert _ls_basenames(out_n) == _ls_basenames(out_s), (
            f"[{label}] entry set differs:\nnative={_ls_basenames(out_n)}\n"
            f"system={_ls_basenames(out_s)}"
        )
    finally:
        shutil.rmtree(subdir, ignore_errors=True)


# --------------------------------------------------------------------------
# M2 — xrdcp download
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "label,url",
    [("nginx", NGINX_URL), ("ref", REF_URL)],
)
def test_download_md5_matches_origin(native_xrdcp, seeded_file, tmp_path, label, url):
    name, _ = seeded_file
    origin = os.path.join(DATA_ROOT, name)
    out = str(tmp_path / "dl.bin")
    rc = subprocess.run(
        [native_xrdcp, "-f", f"{url}//{name}", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60,
    ).returncode
    assert rc == 0, f"[{label}] download failed rc={rc}"
    assert _md5_file(out) == _md5_file(origin), f"[{label}] bytes differ"


def test_download_large_200mb(native_xrdcp, tmp_path):
    """The harness seeds large200.bin (200 MB); download it byte-exact."""
    origin = os.path.join(DATA_ROOT, "large200.bin")
    if not os.path.exists(origin):
        pytest.skip("large200.bin not seeded")
    out = str(tmp_path / "large.bin")
    rc = subprocess.run(
        [native_xrdcp, "-f", f"{NGINX_URL}//large200.bin", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=120,
    ).returncode
    assert rc == 0, f"200MB download failed rc={rc}"
    assert _md5_file(out) == _md5_file(origin)


def test_download_to_stdout(native_xrdcp):
    proc = subprocess.run(
        [native_xrdcp, f"{NGINX_URL}//test.txt", "-"],
        capture_output=True, env=_CLEAN_ENV, timeout=30,
    )
    assert proc.returncode == 0
    with open(os.path.join(DATA_ROOT, "test.txt"), "rb") as fh:
        assert proc.stdout == fh.read()


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


def test_upload_roundtrip_md5(native_xrdcp, remote_upload_name, tmp_path):
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(3 * 1024 * 1024 + 17))
    src_md5 = _md5_file(src)
    remote = f"{NGINX_URL}//{remote_upload_name}"

    rc = subprocess.run([native_xrdcp, src, remote],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "upload failed"
    # On-disk file the server wrote matches the source byte-for-byte.
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == src_md5
    # And it reads back identically.
    back = str(tmp_path / "back.bin")
    rc = subprocess.run([native_xrdcp, "-f", remote, back],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0 and _md5_file(back) == src_md5


def test_upload_existing_without_force_fails(native_xrdcp, remote_upload_name, tmp_path):
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(1024))
    remote = f"{NGINX_URL}//{remote_upload_name}"
    assert subprocess.run([native_xrdcp, src, remote], capture_output=True,
                          env=_CLEAN_ENV, timeout=30).returncode == 0
    # Second upload without -f must fail (destination exists).
    rc = subprocess.run([native_xrdcp, src, remote], capture_output=True,
                        env=_CLEAN_ENV, timeout=30).returncode
    assert rc != 0, "upload over existing file without -f should fail"


def test_upload_force_overwrites(native_xrdcp, remote_upload_name, tmp_path):
    remote = f"{NGINX_URL}//{remote_upload_name}"
    a = str(tmp_path / "a.bin")
    b = str(tmp_path / "b.bin")
    with open(a, "wb") as fh:
        fh.write(os.urandom(2048))
    with open(b, "wb") as fh:
        fh.write(os.urandom(4096))
    assert subprocess.run([native_xrdcp, a, remote], capture_output=True,
                          env=_CLEAN_ENV, timeout=30).returncode == 0
    assert subprocess.run([native_xrdcp, "-f", b, remote], capture_output=True,
                          env=_CLEAN_ENV, timeout=30).returncode == 0
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == _md5_file(b)


def test_upload_posc(native_xrdcp, remote_upload_name, tmp_path):
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(64 * 1024))
    remote = f"{NGINX_URL}//{remote_upload_name}"
    rc = subprocess.run([native_xrdcp, "-f", "-P", src, remote],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=30).returncode
    assert rc == 0, "POSC upload failed"
    # POSC commits on clean close → the file persists.
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == _md5_file(src)


# --------------------------------------------------------------------------
# M4 — token (ztn) authentication on :11097
# --------------------------------------------------------------------------

@pytest.fixture
def have_token():
    if not os.path.exists(TOKEN_FILE):
        pytest.skip("no minted bearer token in the harness")
    return TOKEN_FILE


def test_token_stat(native_xrdfs, have_token, seeded_file):
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_TOKEN_PORT}",
                        "stat", f"/{name}", env=_token_env())
    assert rc == 0, f"token stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), out


def test_token_ls(native_xrdfs, have_token, seeded_file):
    name, _ = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_TOKEN_PORT}",
                        "ls", "/", env=_token_env())
    assert rc == 0, f"token ls failed rc={rc}: {err}"
    assert name in _ls_basenames(out), out


def test_token_download_md5(native_xrdcp, have_token, seeded_file, tmp_path):
    name, _ = seeded_file
    out = str(tmp_path / "tok.bin")
    rc = subprocess.run(
        [native_xrdcp, "-f", f"{TOKEN_URL}//{name}", out],
        capture_output=True, text=True, env=_token_env(), timeout=60,
    ).returncode
    assert rc == 0, "token download failed"
    assert _md5_file(out) == _md5_file(os.path.join(DATA_ROOT, name))


def test_token_missing_creds_fails(native_xrdfs):
    """Token server with no token → clean auth failure (non-zero), not a crash."""
    rc, _, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_TOKEN_PORT}",
                      "stat", "/test.txt")   # _CLEAN_ENV has no BEARER_TOKEN*
    assert rc != 0, f"expected auth failure, got rc={rc}: {err}"


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


def test_gsi_stat(native_xrdfs, have_proxy, seeded_file):
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_GSI_PORT}",
                        "stat", f"/{name}", env=_gsi_env())
    assert rc == 0, f"GSI stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), out


def test_gsi_ls(native_xrdfs, have_proxy, seeded_file):
    name, _ = seeded_file
    rc, out, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_GSI_PORT}",
                        "ls", "/", env=_gsi_env())
    assert rc == 0, f"GSI ls failed rc={rc}: {err}"
    assert name in _ls_basenames(out), out


def test_gsi_download_md5(native_xrdcp, have_proxy, seeded_file, tmp_path):
    name, _ = seeded_file
    out = str(tmp_path / "gsi.bin")
    proc = subprocess.run(
        [native_xrdcp, "-f", f"{GSI_URL}//{name}", out],
        capture_output=True, text=True, env=_gsi_env(), timeout=60,
    )
    assert proc.returncode == 0, f"GSI download failed: {proc.stderr}"
    assert _md5_file(out) == _md5_file(os.path.join(DATA_ROOT, name))


def test_gsi_no_proxy_fails(native_xrdfs, have_proxy):
    """GSI server with no proxy → clean auth failure, not a crash."""
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = "/nonexistent/proxy.pem"
    env["X509_CERT_DIR"] = CA_DIR
    rc, _, err = _run(native_xrdfs, f"{SERVER_HOST}:{NGINX_GSI_PORT}",
                      "stat", "/test.txt", env=env)
    assert rc != 0, f"expected GSI failure, got rc={rc}: {err}"


# --------------------------------------------------------------------------
# M7 — in-protocol TLS: GSI over roots:// on :11096
# --------------------------------------------------------------------------

GSI_TLS_ENDPOINT = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
GSI_TLS_URL = GSI_TLS_ENDPOINT


def test_gsi_tls_stat(native_xrdfs, have_proxy, seeded_file):
    """roots:// → TLS upgrade (peer verified vs CA) then GSI auth over TLS."""
    name, size = seeded_file
    rc, out, err = _run(native_xrdfs, GSI_TLS_ENDPOINT, "stat", f"/{name}",
                        env=_gsi_env())
    assert rc == 0, f"GSI+TLS stat failed rc={rc}: {err}"
    assert _stat_field(out, "Size") == str(size), out


def test_gsi_tls_download_md5(native_xrdcp, have_proxy, seeded_file, tmp_path):
    name, _ = seeded_file
    out = str(tmp_path / "tls.bin")
    proc = subprocess.run(
        [native_xrdcp, "-f", f"{GSI_TLS_URL}//{name}", out],
        capture_output=True, text=True, env=_gsi_env(), timeout=60,
    )
    assert proc.returncode == 0, f"GSI+TLS download failed: {proc.stderr}"
    assert _md5_file(out) == _md5_file(os.path.join(DATA_ROOT, name))


def test_roots_to_nontls_port_refused(native_xrdfs, have_proxy):
    """No silent downgrade: roots:// to a non-TLS server must fail."""
    rc, _, err = _run(native_xrdfs, f"roots://{SERVER_HOST}:{NGINX_ANON_PORT}",
                      "stat", "/test.txt", env=_gsi_env())
    assert rc != 0, f"roots:// to non-TLS port should be refused, got rc={rc}"


def test_gsi_tls_bad_ca_fails(native_xrdfs, have_proxy, tmp_path):
    """TLS peer verification: an empty CA dir must make the handshake fail."""
    env = dict(_CLEAN_ENV)
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = str(tmp_path)   # no CA here
    rc, _, err = _run(native_xrdfs, GSI_TLS_ENDPOINT, "stat", "/test.txt", env=env)
    assert rc != 0, f"TLS with empty CA dir should fail verification, got rc={rc}"


# --------------------------------------------------------------------------
# error
# --------------------------------------------------------------------------

@pytest.mark.parametrize("label,endpoint", ENDPOINTS)
def test_stat_missing_matches_system_exitcode(native_xrdfs, label, endpoint):
    """A missing path fails non-zero with the same shell code as system xrdfs."""
    missing = f"/_native_m1_absent_{os.getpid()}.bin"
    rc_n, _, _ = _run(native_xrdfs, endpoint, "stat", missing)
    assert rc_n != 0, f"[{label}] stat of missing path unexpectedly succeeded"
    if shutil.which("xrdfs") is not None:
        rc_s, _, _ = _run("xrdfs", endpoint, "stat", missing)
        assert rc_n == rc_s, f"[{label}] exit code {rc_n} != system {rc_s}"


# --------------------------------------------------------------------------
# negative / invariant
# --------------------------------------------------------------------------

def test_bad_url_scheme_rejected(native_xrdfs):
    """A genuinely unsupported scheme is rejected as a usage error (exit 50), not a
    crash. root:// and http(s)/dav(s) WebDAV ARE supported now; ftp:// is not."""
    rc, _, err = _run(native_xrdfs, "ftp://example.com:21", "stat", "/x")
    assert rc == 50, f"expected usage error 50, got {rc}: {err}"


def test_no_libxrdcl_dependency(native_xrdfs):
    """The whole point of phase-37: zero libXrdCl/libXrdSec* linkage."""
    out = subprocess.run(["ldd", native_xrdfs], capture_output=True, text=True).stdout
    bad = [ln for ln in out.splitlines() if re.search(r"XrdCl|XrdSec|libXrd", ln)]
    assert not bad, f"native client links upstream xrootd libs:\n{out}"


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


def test_m5_redirect_followed_to_target(native_xrdfs):
    """A single redirect is followed to the target, which then serves the stat."""
    def serve_file(conn, port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        _stat_ok_reply(conn, sid)

    def redirect_once(conn, port, target_port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        body = _redirect_body(HOST, target_port)
        conn.sendall(_hdr(sid, kXR_redirect, len(body)))
        conn.sendall(body)

    with _StubServer(serve_file) as target:
        def redir(conn, port):
            redirect_once(conn, port, target.port)
        with _StubServer(redir) as front:
            rc, out, err = _run(
                native_xrdfs, f"root://{url_host(HOST)}:{front.port}", "stat", "/f",
                timeout=15,
            )
    assert rc == 0, f"redirect not followed (rc={rc}): {err}"
    assert "Size:" in out, f"target did not serve stat: {out}"


def test_m5_redirect_loop_refused(native_xrdfs):
    """A server that redirects to itself is detected as a loop, not chased forever."""
    def redirect_to_self(conn, port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        body = _redirect_body(HOST, port)   # point back at ourselves
        conn.sendall(_hdr(sid, kXR_redirect, len(body)))
        conn.sendall(body)

    with _StubServer(redirect_to_self) as srv:
        rc, out, err = _run(
            native_xrdfs, f"root://{url_host(HOST)}:{srv.port}", "stat", "/f",
            timeout=15,
        )
    assert rc != 0, "redirect loop was not refused"
    assert re.search(r"redirect|loop|too many", err, re.I), \
        f"expected a redirect-loop diagnostic, got: {err}"


def test_m5_wait_then_served(native_xrdfs):
    """kXR_wait is honored: the client backs off and re-sends to the same server."""
    def wait_then_ok(conn, port):
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        conn.sendall(_hdr(sid, kXR_wait, 4))
        conn.sendall(_struct.pack(">I", 1))      # wait 1 second
        sid2 = _read_request(conn)               # client re-sends the stat
        _stat_ok_reply(conn, sid2)

    with _StubServer(wait_then_ok) as srv:
        t0 = time.monotonic()
        rc, out, err = _run(
            native_xrdfs, f"root://{url_host(HOST)}:{srv.port}", "stat", "/f",
            timeout=15,
        )
        elapsed = time.monotonic() - t0
    assert rc == 0, f"wait+retry failed (rc={rc}): {err}"
    assert "Size:" in out, f"stat not served after wait: {out}"
    assert elapsed >= 1.0, f"client did not actually back off (elapsed={elapsed:.2f}s)"


# --------------------------------------------------------------------------
# M6 — paged I/O (kXR_pgread/pgwrite) + --cksum
# --------------------------------------------------------------------------

kXR_status = 4007

# Standard reflected CRC32c (Castagnoli): init 0xFFFFFFFF, final XOR 0xFFFFFFFF
# (check value of "123456789" == 0xe3069283). This is exactly what libxrdproto's
# xrootd_crc32c produces — verified C-vs-Python — which the client uses for both
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


def test_m6_pgread_download_byte_exact(native_xrdcp, seeded_file, tmp_path):
    """--pgrw download (kXR_pgread + per-page CRC32c) is byte-exact vs origin."""
    name, _ = seeded_file
    origin = os.path.join(DATA_ROOT, name)
    out = str(tmp_path / "pg.bin")
    rc = subprocess.run([native_xrdcp, "--pgrw", "-f", f"{NGINX_URL}//{name}", out],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "pgread download failed"
    assert _md5_file(out) == _md5_file(origin), "pgread bytes differ"


def test_m6_pgwrite_upload_byte_exact(native_xrdcp, remote_upload_name, tmp_path):
    """--pgrw upload (kXR_pgwrite + per-page CRC32c) lands byte-exact on disk."""
    src = str(tmp_path / "src.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(1024 * 1024 + 4097))   # spans pages, short last page
    rc = subprocess.run([native_xrdcp, "--pgrw", src, f"{NGINX_URL}//{remote_upload_name}"],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "pgwrite upload failed"
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == _md5_file(src)


def test_m6_cksum_source_agrees(native_xrdcp, seeded_file, tmp_path):
    """--cksum adler32:source computes locally and matches the server's Qcksum."""
    name, _ = seeded_file
    out = str(tmp_path / "ck.bin")
    proc = subprocess.run(
        [native_xrdcp, "--cksum", "adler32:source", "-f", f"{NGINX_URL}//{name}", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60,
    )
    assert proc.returncode == 0, f"cksum source-compare failed: {proc.stderr}"
    assert "OK (matches server)" in proc.stdout, proc.stdout


def test_m6_cksum_bad_value_fails(native_xrdcp, seeded_file, tmp_path):
    """--cksum adler32:<wrong> fails non-zero and drops the destination."""
    name, _ = seeded_file
    out = str(tmp_path / "bad.bin")
    proc = subprocess.run(
        [native_xrdcp, "--cksum", "adler32:deadbeef", "-f", f"{NGINX_URL}//{name}", out],
        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60,
    )
    assert proc.returncode != 0, "bad expected-checksum unexpectedly succeeded"
    assert not os.path.exists(out), "destination left behind after checksum failure"


def test_m6_pgread_clean_stub_ok(native_xrdcp, tmp_path):
    """Self-check: a stub with correct header+page CRC32c downloads successfully —
    this proves the Python CRC32c matches the client's, so the corruption test
    below is exercising the PAGE digest path (not a header-CRC reject)."""
    payload = os.urandom(777)
    out = str(tmp_path / "clean.bin")
    with _StubServer(lambda conn, port: _serve_one_pgread(conn, payload, False)) as srv:
        rc = subprocess.run(
            [native_xrdcp, "--pgrw", "-f", f"root://{url_host(HOST)}:{srv.port}//f", out],
            capture_output=True, text=True, env=_CLEAN_ENV, timeout=15,
        ).returncode
    assert rc == 0, "clean pgread stub failed (Python CRC32c mismatch?)"
    assert open(out, "rb").read() == payload, "clean pgread bytes differ"


def test_m6_pgread_corrupt_page_detected(native_xrdcp, tmp_path):
    """A page whose data no longer matches its CRC32c is detected and rejected."""
    payload = os.urandom(777)
    out = str(tmp_path / "corrupt.bin")
    with _StubServer(lambda conn, port: _serve_one_pgread(conn, payload, True)) as srv:
        proc = subprocess.run(
            [native_xrdcp, "--pgrw", "-f", f"root://{url_host(HOST)}:{srv.port}//f", out],
            capture_output=True, text=True, env=_CLEAN_ENV, timeout=15,
        )
    assert proc.returncode != 0, "corrupted page was NOT detected"
    assert re.search(r"crc|checksum|integrity", proc.stderr, re.I), \
        f"expected a CRC diagnostic, got: {proc.stderr}"
    assert not os.path.exists(out), "destination left behind after CRC failure"


@pytest.mark.slow
@pytest.mark.timeout(300)
def test_m6_pgrw_large_roundtrip(native_xrdcp, remote_upload_name, tmp_path):
    """200 MB up+down via paged I/O stays md5-exact (every page CRC32c checked)."""
    src = str(tmp_path / "big.bin")
    with open(src, "wb") as fh:
        for _ in range(200):
            fh.write(os.urandom(1024 * 1024))
    src_md5 = _md5_file(src)
    rc = subprocess.run([native_xrdcp, "--pgrw", src, f"{NGINX_URL}//{remote_upload_name}"],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=240).returncode
    assert rc == 0, "large pgwrite upload failed"
    back = str(tmp_path / "big_back.bin")
    rc = subprocess.run([native_xrdcp, "--pgrw", "-f",
                         f"{NGINX_URL}//{remote_upload_name}", back],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=240).returncode
    assert rc == 0, "large pgread download failed"
    assert _md5_file(back) == src_md5, "large pgrw round-trip md5 mismatch"


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


def test_m9_mkdir_stat_rmdir(native_xrdfs, m9_dir):
    rc, _, err = _fs(native_xrdfs, "mkdir", f"/{m9_dir}")
    assert rc == 0, f"mkdir failed: {err}"
    rc, out, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}")
    assert rc == 0 and "IsDir" in out, f"dir not created/flagged:\n{out}"
    rc, _, err = _fs(native_xrdfs, "rmdir", f"/{m9_dir}")
    assert rc == 0, f"rmdir failed: {err}"
    rc, _, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}")
    assert rc != 0, "stat of removed dir unexpectedly succeeded"


def test_m9_mkdir_p_nested(native_xrdfs, m9_dir):
    rc, _, err = _fs(native_xrdfs, "mkdir", "-p", f"/{m9_dir}/a/b/c")
    assert rc == 0, f"mkdir -p failed: {err}"
    rc, out, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}/a/b/c")
    assert rc == 0 and "IsDir" in out


def test_m9_mv(native_xrdcp, native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    src_disk = os.path.join(DATA_ROOT, m9_dir, "a.bin")
    with open(src_disk, "wb") as fh:
        fh.write(b"move me")
    rc, _, err = _fs(native_xrdfs, "mv", f"/{m9_dir}/a.bin", f"/{m9_dir}/b.bin")
    assert rc == 0, f"mv failed: {err}"
    assert _fs(native_xrdfs, "stat", f"/{m9_dir}/a.bin")[0] != 0, "src still present"
    assert _fs(native_xrdfs, "stat", f"/{m9_dir}/b.bin")[0] == 0, "dst missing"


def test_m9_chmod(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "c.bin")
    with open(disk, "wb") as fh:
        fh.write(b"x")
    rc, _, err = _fs(native_xrdfs, "chmod", f"/{m9_dir}/c.bin", "0640")
    assert rc == 0, f"chmod failed: {err}"
    assert (os.stat(disk).st_mode & 0o777) == 0o640, "mode not applied on disk"


def test_m9_truncate(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "t.bin")
    with open(disk, "wb") as fh:
        fh.write(b"0123456789")
    rc, _, err = _fs(native_xrdfs, "truncate", f"/{m9_dir}/t.bin", "4")
    assert rc == 0, f"truncate failed: {err}"
    rc, out, _ = _fs(native_xrdfs, "stat", f"/{m9_dir}/t.bin")
    assert _stat_field(out, "Size") == "4", f"size not truncated:\n{out}"


def test_m9_cat(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "cat.txt")
    payload = os.urandom(40000)
    with open(disk, "wb") as fh:
        fh.write(payload)
    proc = subprocess.run([native_xrdfs, NGINX_URL, "cat", f"/{m9_dir}/cat.txt"],
                          capture_output=True, env=_CLEAN_ENV, timeout=15)
    assert proc.returncode == 0, f"cat failed: {proc.stderr}"
    assert proc.stdout == payload, "cat content differs"


def test_m9_tail(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "tail.txt")
    payload = bytes(range(256)) * 40   # 10240 bytes
    with open(disk, "wb") as fh:
        fh.write(payload)
    proc = subprocess.run([native_xrdfs, NGINX_URL, "tail", "-c", "100", f"/{m9_dir}/tail.txt"],
                          capture_output=True, env=_CLEAN_ENV, timeout=15)
    assert proc.returncode == 0, f"tail failed: {proc.stderr}"
    assert proc.stdout == payload[-100:], "tail window differs"


def test_m9_locate(native_xrdfs, seeded_file):
    name, _ = seeded_file
    rc, out, err = _fs(native_xrdfs, "locate", f"/{name}")
    assert rc == 0, f"locate failed: {err}"
    assert out.strip().startswith("S"), f"unexpected locate token: {out}"


def test_m9_query_checksum_matches_adler32(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "q.bin")
    payload = os.urandom(50000)
    with open(disk, "wb") as fh:
        fh.write(payload)
    rc, out, err = _fs(native_xrdfs, "query", "checksum", f"/{m9_dir}/q.bin")
    assert rc == 0, f"query checksum failed: {err}"
    parts = out.split()
    assert len(parts) >= 2, f"unexpected checksum reply: {out}"
    if parts[0] == "adler32":
        assert int(parts[1], 16) == _zlib.adler32(payload) & 0xffffffff, "adler32 differs"


def test_m9_query_config(native_xrdfs):
    rc, out, err = _fs(native_xrdfs, "query", "config", "tpc")
    assert rc == 0, f"query config failed: {err}"
    assert out.strip() != "", "empty config reply"


def test_m9_statvfs(native_xrdfs):
    rc, out, err = _fs(native_xrdfs, "statvfs", "/")
    assert rc == 0, f"statvfs failed: {err}"
    assert len(out.split()) >= 4, f"unexpected statvfs reply: {out}"


def test_m9_repl_basic(native_xrdfs):
    """The interactive shell handles pwd/cd/stat/exit over piped stdin."""
    script = "pwd\nstat /test.txt\nexit\n"
    proc = subprocess.run([native_xrdfs, NGINX_URL], input=script,
                          capture_output=True, text=True, env=_CLEAN_ENV, timeout=15)
    assert proc.returncode == 0, f"repl failed: {proc.stderr}"
    assert "Size:" in proc.stdout, f"repl stat produced no output:\n{proc.stdout}"


# --- M9 error / security-negative ---

def test_m9_rmdir_nonempty_fails(native_xrdfs, m9_dir):
    assert _fs(native_xrdfs, "mkdir", "-p", f"/{m9_dir}/child")[0] == 0
    rc, _, _ = _fs(native_xrdfs, "rmdir", f"/{m9_dir}")
    assert rc != 0, "rmdir of a non-empty directory unexpectedly succeeded"


def test_m9_rm_missing_fails(native_xrdfs):
    rc, _, _ = _fs(native_xrdfs, "rm", f"/_fstest_absent_{os.getpid()}.bin")
    assert rc != 0, "rm of a missing file unexpectedly succeeded"


def test_m9_mv_traversal_rejected(native_xrdfs, m9_dir):
    """A destination escaping the export root must never write outside it.

    The native client normalises a leading-``../`` absolute path
    (/../../../../etc/pwn -> /etc/pwn), which the server then CONFINES under the
    export root (<root>/etc/pwn).  So the move may succeed in-root (rc=0) or be
    refused, but the one invariant is that nothing is ever written to the real
    /etc.  (The raw, un-normalised form is rejected with kXR_InvalidDest — see the
    stock-client parity in test_gsi_handshake / test_conf_errors.)"""
    assert _fs(native_xrdfs, "mkdir", f"/{m9_dir}")[0] == 0
    disk = os.path.join(DATA_ROOT, m9_dir, "s.bin")
    with open(disk, "wb") as fh:
        fh.write(b"x")
    _fs(native_xrdfs, "mv", f"/{m9_dir}/s.bin", "/../../../../etc/pwn")
    assert not os.path.exists("/etc/pwn"), "traversal wrote outside the export root"


# --------------------------------------------------------------------------
# M8 — parallel --streams (kXR_bind) + server-side --tpc
# --------------------------------------------------------------------------

import socket as _m8_socket

from settings import ROOT_TPC_NGINX_PORT, ROOT_TPC_REF_PORT

TEST_ROOT = os.environ.get("TEST_ROOT", "/tmp/xrd-test")
ROOT_TPC_DATA = os.path.join(TEST_ROOT, "data-root-tpc")
ROOT_TPC_REF_DATA = os.path.join(TEST_ROOT, "data-root-tpc-ref")
ANON_ACCESS_LOG = os.path.join(TEST_ROOT, "logs", "xrootd_access_anon.log")


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


def test_m8_streams_roundtrip_byte_exact(native_xrdcp, remote_upload_name, tmp_path):
    """xrdcp --streams 4 up+down is byte-exact and emits kXR_bind log entries."""
    src = str(tmp_path / "s.bin")
    with open(src, "wb") as fh:
        fh.write(os.urandom(2 * 1024 * 1024 + 13))
    src_md5 = _md5_file(src)
    before = _count_log(ANON_ACCESS_LOG, '"BIND - -" OK')

    rc = subprocess.run([native_xrdcp, "-f", "--streams", "4", src,
                         f"{NGINX_URL}//{remote_upload_name}"],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "streams upload failed"
    assert _md5_file(os.path.join(DATA_ROOT, remote_upload_name)) == src_md5

    back = str(tmp_path / "b.bin")
    rc = subprocess.run([native_xrdcp, "-f", "--streams", "4",
                         f"{NGINX_URL}//{remote_upload_name}", back],
                        capture_output=True, text=True, env=_CLEAN_ENV, timeout=60).returncode
    assert rc == 0, "streams download failed"
    assert _md5_file(back) == src_md5

    after = _count_log(ANON_ACCESS_LOG, '"BIND - -" OK')
    assert after > before, "no kXR_bind entries — streams fell back to one connection"


@pytest.mark.skipif(not _port_open(ROOT_TPC_NGINX_PORT),
                    reason="root-tpc nginx (:11110) not running")
def test_m8_tpc_only_nginx_to_nginx(native_xrdcp):
    """--tpc only drives a server-side third-party copy between two nginx paths
    (the dest server pulls from the source; no bytes transit the client)."""
    uid = f"{os.getpid()}_{int(time.time()*1000)}"
    src = f"_m8tpc_src_{uid}.bin"
    dst = f"_m8tpc_dst_{uid}.bin"
    payload = os.urandom(48000)
    with open(os.path.join(ROOT_TPC_DATA, src), "wb") as fh:
        fh.write(payload)
    url = f"root://{SERVER_HOST}:{ROOT_TPC_NGINX_PORT}"
    try:
        proc = subprocess.run([native_xrdcp, "-f", "--tpc", "only",
                               f"{url}//{src}", f"{url}//{dst}"],
                              capture_output=True, text=True, env=_CLEAN_ENV, timeout=60)
        assert proc.returncode == 0, f"tpc only failed: {proc.stderr}"
        landed = os.path.join(ROOT_TPC_DATA, dst)
        assert os.path.exists(landed), "TPC destination not created"
        assert open(landed, "rb").read() == payload, "TPC bytes differ"
    finally:
        for n in (src, dst):
            try:
                os.unlink(os.path.join(ROOT_TPC_DATA, n))
            except OSError:
                pass


@pytest.mark.skipif(not (_port_open(ROOT_TPC_NGINX_PORT) and _port_open(ROOT_TPC_REF_PORT)),
                    reason="root-tpc pair (:11110/:11111) not running")
def test_m8_tpc_first_falls_back_to_client_copy(native_xrdcp):
    """--tpc first against a reference xrootd (which uses the async waitresp TPC
    model the native client does not drive) cleanly falls back to a
    client-mediated copy and still completes byte-exact."""
    uid = f"{os.getpid()}_{int(time.time()*1000)}"
    src = f"_m8tpcfb_src_{uid}.bin"
    dst = f"_m8tpcfb_dst_{uid}.bin"
    payload = os.urandom(32000)
    with open(os.path.join(ROOT_TPC_DATA, src), "wb") as fh:
        fh.write(payload)
    nurl = f"root://{SERVER_HOST}:{ROOT_TPC_NGINX_PORT}"
    rurl = f"root://{SERVER_HOST}:{ROOT_TPC_REF_PORT}"
    try:
        proc = subprocess.run([native_xrdcp, "-f", "--tpc", "first",
                               f"{nurl}//{src}", f"{rurl}//{dst}"],
                              capture_output=True, text=True, env=_CLEAN_ENV, timeout=60)
        assert proc.returncode == 0, f"tpc first (fallback) failed: {proc.stderr}"
        landed = os.path.join(ROOT_TPC_REF_DATA, dst)
        if os.path.exists(landed):
            assert open(landed, "rb").read() == payload, "fallback bytes differ"
    finally:
        try:
            os.unlink(os.path.join(ROOT_TPC_DATA, src))
        except OSError:
            pass
        try:
            os.unlink(os.path.join(ROOT_TPC_REF_DATA, dst))
        except OSError:
            pass
