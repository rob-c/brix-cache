"""test_acc_residual.py — residual XrdAcc parity gaps closed after the M0–M8 port.

Each class is a self-provisioned nginx running `brix_authdb_format xrdacc` over an
anonymous root:// (or http) tier, driving raw-wire / curl requests to prove a gap
that the initial port left open:

  RA1  create-vs-update — kXR_new opens use AOP_Create (needs `i`/insert); other
       write opens use AOP_Update (needs only `w`).  `XrdOfs.cc` keys Create off
       O_CREAT (kXR_new) only — kXR_delete (truncate) is still Update.
  RA2  prepare staging routes through the engine with AOP_Stage (priv 0x180, only
       granted by `a`), not the native authdb.
  RA3  `brix_acc_resolve_hosts` reverse-DNSes the peer so `h <host>` rules match.
  RB1  `brix_authdb_refresh` hot-reloads the authdb for HTTP (WebDAV) with no
       restart.
  RB2  `brix_acc_encoding` URI-decodes authdb path tokens (`%20` -> space).
  RC1  the auth-result cache is active under xrdacc and keys on the operation, so a
       cached Update grant is never replayed for a Create on the same path.

Self-provisioning; skips cleanly when the nginx binary is absent or was built
without the engine.
"""

import os
import pathlib
import socket
import struct
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN, url_host
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-acc-residual")]

# Wire constants (XProtocol.hh).
kXR_login = 3007
kXR_open = 3010
kXR_stat = 3017
kXR_prepare = 3021
kXR_ok = 0
kXR_error = 4003
kXR_delete = 0x0002   # truncate (O_TRUNC)  -> AOP_Update
kXR_new = 0x0008      # create   (O_CREAT)  -> AOP_Create
kXR_stage = 8         # prepare options: stage


def _have_nginx():
    if not os.path.exists(NGINX_BIN):
        return False
    try:
        syms = subprocess.run(["nm", NGINX_BIN], capture_output=True, text=True)
        return "brix_acc_access" in syms.stdout
    except Exception:
        return True


# --------------------------------------------------------------------------- #
# Raw root:// wire helpers                                                     #
# --------------------------------------------------------------------------- #

def _recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-response")
        b += c
    return b


def _read_resp(s):
    _sid, status, dlen = struct.unpack("!2sHI", _recv_exact(s, 8))
    return status, (_recv_exact(s, dlen) if dlen else b"")


def _logged_in(port):
    s = socket.create_connection((HOST, port), timeout=8)
    s.settimeout(8)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _recv_exact(s, 16)                       # handshake reply
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x02", kXR_login, 0x1234,
                          b"anon\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    st, _ = _read_resp(s)
    assert st == kXR_ok, f"login failed: {st}"
    return s


def _verdict(status, body):
    if status == kXR_ok:
        return "GRANT"
    if status == kXR_error:
        return "DENY"
    return f"status={status}"


def _open(port, path, options):
    s = _logged_in(port)
    p = path.encode()
    req = struct.pack("!2sHHHH6s4sI", b"\x00\x03", kXR_open, 0o644, options, 0,
                      b"\x00" * 6, b"\x00" * 4, len(p)) + p
    s.sendall(req)
    st, body = _read_resp(s)
    s.close()
    return _verdict(st, body)


def _stat(port, path):
    s = _logged_in(port)
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", b"\x00\x03", kXR_stat, b"\x00" * 16, len(p)) + p)
    st, body = _read_resp(s)
    s.close()
    return _verdict(st, body)


def _prepare(port, path):
    s = _logged_in(port)
    p = path.encode()
    req = struct.pack("!2sHBBHH10sI", b"\x00\x05", kXR_prepare, kXR_stage, 0, 0, 0,
                      b"\x00" * 10, len(p)) + p
    s.sendall(req)
    st, body = _read_resp(s)
    s.close()
    return _verdict(st, body)


# --------------------------------------------------------------------------- #
# Server provisioning                                                          #
# --------------------------------------------------------------------------- #

class _Stream:
    """A throwaway xrdacc root:// server driven by the registry lifecycle harness.

    Seeds authdb+data under ``tmp_path`` and delegates config-render / launch /
    teardown to the ``lifecycle`` handle; the harness stops and unregisters the
    instance when the test ends.
    """

    def __init__(self, lifecycle, tmp_path, authdb, extra="", tree=("d",)):
        self._lifecycle = lifecycle
        self._extra = extra
        self.root = pathlib.Path(tmp_path) / "srv"
        self.data = self.root / "data"
        self.authdb_path = str(self.root / "authdb")
        for t in tree:
            (self.data / t).mkdir(parents=True, exist_ok=True)
        self.write_authdb(authdb)
        self.port = None
        self.access_log = None

    def write_authdb(self, contents):
        with open(self.authdb_path, "w") as f:
            f.write(contents)

    def file(self, relpath, data=b"x\n"):
        full = self.data / relpath.lstrip("/")
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data)

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name="lc-acc-residual-stream",
            template="nginx_lc_acc_residual_stream.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "AUTHDB_PATH": self.authdb_path,
                "EXTRA_DIRECTIVES": self._extra,
            },
            reason="throwaway xrdacc root:// server for residual XrdAcc parity gaps",
        ))
        self.port = ep.port
        self.access_log = pathlib.Path(ep.prefix) / "logs" / "access.log"


@pytest.fixture()
def make_server(lifecycle, tmp_path):
    """Function-scoped factory that builds a harness-backed ``_Stream``."""
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the xrdacc engine")

    def _factory(authdb, **kw):
        return _Stream(lifecycle, tmp_path, authdb, **kw)

    return _factory


# --------------------------------------------------------------------------- #
# RA1 — create vs update                                                       #
# --------------------------------------------------------------------------- #

class TestCreateVsUpdate:
    """kXR_new (create) needs `i`/insert; kXR_delete (truncate) is only Update."""

    def test_create_needs_insert(self, make_server):
        srv = make_server("u * /d rwl\n")        # lookup+write, NO insert
        srv.file("d/exist.txt")
        srv.start()
        # create (kXR_new) is AOP_Create -> needs insert -> denied
        assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"
        # truncate (kXR_delete) is AOP_Update -> needs only w -> granted
        assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"

    def test_insert_grants_create(self, make_server):
        srv = make_server("u * /d rwli\n")       # + insert
        srv.file("d/exist.txt")
        srv.start()
        assert _open(srv.port, "/d/new.txt", kXR_new) == "GRANT"
        assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"

    def test_write_required_for_both(self, make_server):
        srv = make_server("u * /d rli\n")        # insert+lookup, NO write
        srv.file("d/exist.txt")
        srv.start()
        assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"
        assert _open(srv.port, "/d/exist.txt", kXR_delete) == "DENY"


# --------------------------------------------------------------------------- #
# RA2 — prepare routes through the engine with AOP_Stage                       #
# --------------------------------------------------------------------------- #

class TestPrepareStage:
    """kXR_prepare(stage) uses AOP_Stage (priv 0x180); only `a` grants it."""

    def test_stage_denied_without_a(self, make_server):
        srv = make_server("u * /pub rwl\n")      # no stage bits
        srv.file("pub/f.txt")
        srv.start()
        assert _prepare(srv.port, "/pub/f.txt") == "DENY"

    def test_stage_granted_with_a(self, make_server):
        srv = make_server("u * /pub a\n")        # `a` = all (0x1ff) includes stage
        srv.file("pub/f.txt")
        srv.start()
        assert _prepare(srv.port, "/pub/f.txt") == "GRANT"


# --------------------------------------------------------------------------- #
# RA3 — opt-in reverse-DNS host resolution                                     #
# --------------------------------------------------------------------------- #

def _loopback_ptr():
    try:
        return socket.getnameinfo(("127.0.0.1", 0), 0)[0]  # net-literal-allow: loopback reverse-DNS resolution under test
    except Exception:
        return None


class TestResolveHosts:
    """`h <host>` rules only match when the peer is reverse-resolved (opt-in)."""

    def _authdb(self):
        name = _loopback_ptr()
        if not name or name == "127.0.0.1":  # net-literal-allow: loopback PTR identity check under test
            pytest.skip("127.0.0.1 has no usable PTR record on this host")  # net-literal-allow: loopback PTR skip condition
        return f"h {name} /pub rl\n"         # grant ONLY via the host rule

    def test_off_ip_does_not_match(self, make_server):
        srv = make_server(self._authdb())
        srv.file("pub/f.txt")
        srv.start()
        assert _stat(srv.port, "/pub/f.txt") == "DENY"

    def test_on_hostname_matches(self, make_server):
        srv = make_server(self._authdb(),
                          extra="        brix_acc_resolve_hosts on;")
        srv.file("pub/f.txt")
        srv.start()
        assert _stat(srv.port, "/pub/f.txt") == "GRANT"


# --------------------------------------------------------------------------- #
# RB2 — encoding (URI-decode authdb path tokens)                               #
# --------------------------------------------------------------------------- #

class TestEncoding:
    """`brix_acc_encoding on` URI-decodes authdb paths: `/a%20b` -> `/a b`."""

    def test_off_literal_no_match(self, make_server):
        srv = make_server("u * /a%20b rl\n", tree=("a b",))
        srv.file("a b/f.txt")
        srv.start()
        assert _stat(srv.port, "/a b/f.txt") == "DENY"

    def test_on_decoded_matches(self, make_server):
        srv = make_server("u * /a%20b rl\n", tree=("a b",),
                          extra="        brix_acc_encoding on;")
        srv.file("a b/f.txt")
        srv.start()
        assert _stat(srv.port, "/a b/f.txt") == "GRANT"


# --------------------------------------------------------------------------- #
# RC1 — auth-result cache active under xrdacc, keyed on the operation          #
# --------------------------------------------------------------------------- #

class TestAuthCache:
    """The cache serves repeat verdicts but keys on the AOP, so a cached Update
    grant is never replayed for a Create on the same path."""

    CACHE = "        brix_auth_cache zone=authz ttl=60;"

    def test_cache_hit_logs_cache_path(self, make_server):
        srv = make_server("u * /d rwl\n", extra=self.CACHE)
        srv.start()
        assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"   # engine
        assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"   # cache hit
        # The 1st open is served by the engine ("xrdacc denied"); the 2nd by
        # the cache ("auth cache: denied").  Poll: nginx buffers the access
        # log, so the second line may lag the request by a moment.
        deadline = time.monotonic() + 5.0
        log = ""
        while time.monotonic() < deadline:
            log = srv.access_log.read_text()
            if "cache" in log:
                break
            time.sleep(0.1)
        assert "xrdacc" in log, "first open should hit the engine"
        assert "cache" in log, "second open should be served from the cache"

    def test_update_grant_does_not_leak_to_create(self, make_server):
        srv = make_server("u * /d rwl\n", extra=self.CACHE)   # write but no insert
        srv.file("d/exist.txt")
        srv.start()
        # Prime the cache with an Update grant on /d/exist.txt …
        assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"
        assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"
        # … a Create (kXR_new) on the SAME path must still be denied.
        assert _open(srv.port, "/d/exist.txt", kXR_new) == "DENY"


# --------------------------------------------------------------------------- #
# RB1 — HTTP (WebDAV) hot-reload of the authdb, no restart                     #
# --------------------------------------------------------------------------- #

import urllib.request   # noqa: E402
import urllib.error     # noqa: E402


def _http_code(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


class _Webdav:
    """A throwaway xrdacc WebDAV server (1s authdb refresh) on the lifecycle harness."""

    def __init__(self, lifecycle, tmp_path):
        self._lifecycle = lifecycle
        self.root = pathlib.Path(tmp_path) / "srv"
        self.data = self.root / "data"
        self.authdb_path = str(self.root / "authdb")
        (self.data / "grant").mkdir(parents=True, exist_ok=True)
        (self.data / "grant" / "ok.txt").write_bytes(b"ok\n")
        self.write_authdb("u * /grant rl\n")
        self.port = None

    def write_authdb(self, contents, mtime=None):
        with open(self.authdb_path, "w") as f:
            f.write(contents)
        if mtime is not None:        # force a distinct mtime (1s fs granularity)
            os.utime(self.authdb_path, (mtime, mtime))

    def url(self, path):
        return f"http://{url_host(HOST)}:{self.port}{path}"

    def start(self):
        ep = self._lifecycle.start(NginxInstanceSpec(
            name="lc-acc-residual-webdav",
            template="nginx_lc_acc_residual_webdav.conf",
            protocol="http",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(self.data),
                "AUTHDB_PATH": self.authdb_path,
            },
            reason="throwaway xrdacc WebDAV server for authdb hot-reload parity",
        ))
        self.port = ep.port


@pytest.fixture()
def make_webdav(lifecycle, tmp_path):
    """Function-scoped factory that builds a harness-backed ``_Webdav``."""
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the engine")

    def _factory():
        return _Webdav(lifecycle, tmp_path)

    return _factory


class TestHttpHotReload:
    """Editing the authdb while a WebDAV worker is live takes effect within the
    refresh interval, with no restart (`brix_authdb_refresh`)."""

    def test_reload_revokes_access(self, make_webdav):
        srv = make_webdav()
        srv.write_authdb("u * /grant rl\n", mtime=1577836800)   # 2020-01-01
        srv.start()
        assert _http_code(srv.url("/grant/ok.txt")) == 200
        # Revoke /grant live with a strictly newer mtime so the timer reloads.
        srv.write_authdb("u * /other rl\n", mtime=1717200000)  # 2024-06-01
        deadline = time.monotonic() + 6.0
        code = 200
        while time.monotonic() < deadline:
            code = _http_code(srv.url("/grant/ok.txt"))
            if code == 403:
                break
            time.sleep(0.3)
        assert code == 403, "authdb edit must take effect without restart"
