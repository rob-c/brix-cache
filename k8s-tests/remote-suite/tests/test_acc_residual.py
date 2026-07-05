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
import shutil
import socket
import struct
import subprocess
import time

import pytest

from settings import free_port, HOST, BIND_HOST, url_host

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

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


def _port_up(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


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
    """A throwaway xrdacc root:// server: writes conf+authdb+data, starts nginx."""

    def __init__(self, authdb, extra="", tree=("d",)):
        self.port = free_port()
        self.root = os.path.join(os.environ["TMPDIR"], f"xrdacc-res-{self.port}")
        self.authdb_path = f"{self.root}/authdb"
        shutil.rmtree(self.root, ignore_errors=True)
        for d in ("logs", "conf") + tuple(f"data/{t}" for t in tree):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        self.write_authdb(authdb)
        self.conf = f"{self.root}/conf/nginx.conf"
        with open(self.conf, "w") as f:
            f.write(f"""worker_processes 1;
error_log {self.root}/logs/error.log info;
pid {self.root}/nginx.pid;
events {{ worker_connections 64; }}
stream {{
    brix_kv_zone authz 1m key=32 val=8;
    server {{
        listen {BIND_HOST}:{self.port};
        xrootd on;
        brix_storage_backend posix:{self.root}/data;
        brix_auth none;
        brix_allow_write on;
        brix_authdb_format xrdacc;
        brix_authdb {self.authdb_path};
        brix_authdb_audit all;
{extra}
        brix_access_log {self.root}/logs/access.log;
    }}
}}
""")

    def write_authdb(self, contents):
        with open(self.authdb_path, "w") as f:
            f.write(contents)

    def file(self, relpath, data=b"x\n"):
        full = os.path.join(self.root, "data", relpath.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)

    def start(self):
        t = subprocess.run([NGINX_BIN, "-t", "-c", self.conf],
                           capture_output=True, text=True)
        assert t.returncode == 0, f"nginx -t failed: {t.stderr}"
        subprocess.run([NGINX_BIN, "-c", self.conf], capture_output=True)
        if not _port_up(self.port):
            pytest.skip("xrdacc nginx did not start")

    def stop(self):
        subprocess.run([NGINX_BIN, "-c", self.conf, "-s", "stop"],
                       capture_output=True)
        shutil.rmtree(self.root, ignore_errors=True)


def _server(authdb, **kw):
    if not _have_nginx():
        pytest.skip("nginx binary unavailable or built without the xrdacc engine")
    srv = _Stream(authdb, **kw)
    return srv


# --------------------------------------------------------------------------- #
# RA1 — create vs update                                                       #
# --------------------------------------------------------------------------- #

class TestCreateVsUpdate:
    """kXR_new (create) needs `i`/insert; kXR_delete (truncate) is only Update."""

    def test_create_needs_insert(self):
        srv = _server("u * /d rwl\n")        # lookup+write, NO insert
        srv.file("d/exist.txt")
        srv.start()
        try:
            # create (kXR_new) is AOP_Create -> needs insert -> denied
            assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"
            # truncate (kXR_delete) is AOP_Update -> needs only w -> granted
            assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"
        finally:
            srv.stop()

    def test_insert_grants_create(self):
        srv = _server("u * /d rwli\n")       # + insert
        srv.file("d/exist.txt")
        srv.start()
        try:
            assert _open(srv.port, "/d/new.txt", kXR_new) == "GRANT"
            assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"
        finally:
            srv.stop()

    def test_write_required_for_both(self):
        srv = _server("u * /d rli\n")        # insert+lookup, NO write
        srv.file("d/exist.txt")
        srv.start()
        try:
            assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"
            assert _open(srv.port, "/d/exist.txt", kXR_delete) == "DENY"
        finally:
            srv.stop()


# --------------------------------------------------------------------------- #
# RA2 — prepare routes through the engine with AOP_Stage                       #
# --------------------------------------------------------------------------- #

class TestPrepareStage:
    """kXR_prepare(stage) uses AOP_Stage (priv 0x180); only `a` grants it."""

    def test_stage_denied_without_a(self):
        srv = _server("u * /pub rwl\n")      # no stage bits
        srv.file("pub/f.txt")
        srv.start()
        try:
            assert _prepare(srv.port, "/pub/f.txt") == "DENY"
        finally:
            srv.stop()

    def test_stage_granted_with_a(self):
        srv = _server("u * /pub a\n")        # `a` = all (0x1ff) includes stage
        srv.file("pub/f.txt")
        srv.start()
        try:
            assert _prepare(srv.port, "/pub/f.txt") == "GRANT"
        finally:
            srv.stop()


# --------------------------------------------------------------------------- #
# RA3 — opt-in reverse-DNS host resolution                                     #
# --------------------------------------------------------------------------- #

def _loopback_ptr():
    try:
        return socket.getnameinfo(("127.0.0.1", 0), 0)[0]
    except Exception:
        return None


class TestResolveHosts:
    """`h <host>` rules only match when the peer is reverse-resolved (opt-in)."""

    def _authdb(self):
        name = _loopback_ptr()
        if not name or name == "127.0.0.1":
            pytest.skip("127.0.0.1 has no usable PTR record on this host")
        return f"h {name} /pub rl\n"         # grant ONLY via the host rule

    def test_off_ip_does_not_match(self):
        srv = _server(self._authdb())
        srv.file("pub/f.txt")
        srv.start()
        try:
            assert _stat(srv.port, "/pub/f.txt") == "DENY"
        finally:
            srv.stop()

    def test_on_hostname_matches(self):
        srv = _server(self._authdb(),
                      extra="        brix_acc_resolve_hosts on;")
        srv.file("pub/f.txt")
        srv.start()
        try:
            assert _stat(srv.port, "/pub/f.txt") == "GRANT"
        finally:
            srv.stop()


# --------------------------------------------------------------------------- #
# RB2 — encoding (URI-decode authdb path tokens)                               #
# --------------------------------------------------------------------------- #

class TestEncoding:
    """`brix_acc_encoding on` URI-decodes authdb paths: `/a%20b` -> `/a b`."""

    def test_off_literal_no_match(self):
        srv = _server("u * /a%20b rl\n", tree=("a b",))
        srv.file("a b/f.txt")
        srv.start()
        try:
            assert _stat(srv.port, "/a b/f.txt") == "DENY"
        finally:
            srv.stop()

    def test_on_decoded_matches(self):
        srv = _server("u * /a%20b rl\n", tree=("a b",),
                      extra="        brix_acc_encoding on;")
        srv.file("a b/f.txt")
        srv.start()
        try:
            assert _stat(srv.port, "/a b/f.txt") == "GRANT"
        finally:
            srv.stop()


# --------------------------------------------------------------------------- #
# RC1 — auth-result cache active under xrdacc, keyed on the operation          #
# --------------------------------------------------------------------------- #

class TestAuthCache:
    """The cache serves repeat verdicts but keys on the AOP, so a cached Update
    grant is never replayed for a Create on the same path."""

    CACHE = "        brix_auth_cache zone=authz ttl=60;"

    def test_cache_hit_logs_cache_path(self):
        srv = _server("u * /d rwl\n", extra=self.CACHE)
        srv.start()
        try:
            assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"   # engine
            assert _open(srv.port, "/d/new.txt", kXR_new) == "DENY"   # cache hit
            # The 1st open is served by the engine ("xrdacc denied"); the 2nd by
            # the cache ("auth cache: denied").  Poll: nginx buffers the access
            # log, so the second line may lag the request by a moment.
            deadline = time.monotonic() + 5.0
            log = ""
            while time.monotonic() < deadline:
                with open(f"{srv.root}/logs/access.log") as f:
                    log = f.read()
                if "cache" in log:
                    break
                time.sleep(0.1)
            assert "xrdacc" in log, "first open should hit the engine"
            assert "cache" in log, "second open should be served from the cache"
        finally:
            srv.stop()

    def test_update_grant_does_not_leak_to_create(self):
        srv = _server("u * /d rwl\n", extra=self.CACHE)   # write but no insert
        srv.file("d/exist.txt")
        srv.start()
        try:
            # Prime the cache with an Update grant on /d/exist.txt …
            assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"
            assert _open(srv.port, "/d/exist.txt", kXR_delete) == "GRANT"
            # … a Create (kXR_new) on the SAME path must still be denied.
            assert _open(srv.port, "/d/exist.txt", kXR_new) == "DENY"
        finally:
            srv.stop()


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
    """A throwaway xrdacc WebDAV server with a 1s authdb refresh timer."""

    def __init__(self):
        self.port = free_port()
        self.root = os.path.join(os.environ["TMPDIR"], f"xrdacc-res-http-{self.port}")
        self.authdb_path = f"{self.root}/authdb"
        shutil.rmtree(self.root, ignore_errors=True)
        for d in ("data/grant", "logs", "conf", "tmp"):
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        with open(f"{self.root}/data/grant/ok.txt", "wb") as f:
            f.write(b"ok\n")
        self.write_authdb("u * /grant rl\n")
        self.conf = f"{self.root}/conf/nginx.conf"
        with open(self.conf, "w") as f:
            f.write(f"""worker_processes 1;
error_log {self.root}/logs/error.log info;
pid {self.root}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {self.root}/tmp/cbt;
    proxy_temp_path {self.root}/tmp/pt;
    fastcgi_temp_path {self.root}/tmp/ft;
    uwsgi_temp_path {self.root}/tmp/ut;
    scgi_temp_path {self.root}/tmp/st;
    server {{
        listen {BIND_HOST}:{self.port};
        location / {{
            brix_webdav on;
            brix_webdav_storage_backend posix:{self.root}/data;
            brix_webdav_auth none;
            brix_webdav_allow_write on;
            brix_authdb_format xrdacc;
            brix_authdb {self.authdb_path};
            brix_authdb_audit all;
            brix_authdb_refresh 1;
        }}
    }}
}}
""")

    def write_authdb(self, contents, mtime=None):
        with open(self.authdb_path, "w") as f:
            f.write(contents)
        if mtime is not None:        # force a distinct mtime (1s fs granularity)
            os.utime(self.authdb_path, (mtime, mtime))

    def url(self, path):
        return f"http://{url_host(HOST)}:{self.port}{path}"

    def start(self):
        t = subprocess.run([NGINX_BIN, "-t", "-c", self.conf],
                           capture_output=True, text=True)
        assert t.returncode == 0, f"nginx -t failed: {t.stderr}"
        subprocess.run([NGINX_BIN, "-c", self.conf], capture_output=True)
        if not _port_up(self.port):
            pytest.skip("xrdacc webdav nginx did not start")

    def stop(self):
        subprocess.run([NGINX_BIN, "-c", self.conf, "-s", "stop"],
                       capture_output=True)
        shutil.rmtree(self.root, ignore_errors=True)


class TestHttpHotReload:
    """Editing the authdb while a WebDAV worker is live takes effect within the
    refresh interval, with no restart (`brix_authdb_refresh`)."""

    def test_reload_revokes_access(self):
        if not _have_nginx():
            pytest.skip("nginx binary unavailable or built without the engine")
        srv = _Webdav()
        srv.write_authdb("u * /grant rl\n", mtime=1577836800)   # 2020-01-01
        srv.start()
        try:
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
        finally:
            srv.stop()
