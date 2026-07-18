# loc-lint: exempt — a single module-scoped autouse `params=` fixture mutates module globals (e.g. BASE_URL) that every test reads directly; splitting tests into a sibling module breaks that shared mutable state (proven: webdav 120->100). Cohesive parametrize-unit; Phase-38 §4.4.
"""
tests/test_evil_paths.py

"Truly evil" path-confinement security tests across EVERY protocol the module
serves: root:// (native XRootD), http:// + https:// (WebDAV), S3, and the
cms:// control protocol (kYR_state existence probe).

Threat model — a hostile client (or, for CMS, a hostile manager) tries to walk
out of the export root (/tmp/xrd-test/data) using:

  * classic and deep "../" traversal, mixed "/a/./../.." forms
  * URL-encoded / double-encoded / mixed-case traversal ("%2e%2e", "%252e")
  * SYMLINKS planted inside the root that point OUT of it:
      - to a directory (/link -> /etc), then /link/passwd
      - to a file (/link -> /etc/passwd)
      - to "/" (/link -> /), then /link/etc/passwd
      - symlink chains (/a -> /b -> /etc) and loops (/loop -> /loop)
      - relative escaping symlinks (/rel -> ../../../etc)
      - magic links (/proc/self/root style targets)
  * NUL-byte truncation ("/x\\0/../../etc/passwd")
  * absolute-path and double-slash injection ("//etc/passwd")
  * device / proc targets (info-leak via /proc/self/environ)

Every attempt is verified TWO ways:
  1. the wire response is an error (never 200 / kXR_ok), and
  2. the real filesystem is unchanged — no host file content is returned, and
     nothing is created/removed OUTSIDE the export root.

Run:
    TEST_SKIP_SERVER_SETUP=1 SKIP_XRDFS_CHECK=1 PYTHONPATH=tests \
        pytest tests/test_evil_paths.py -v
"""

import http.client
import os
import shutil
import socket
import ssl
import struct
import time
import uuid

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import (
    DATA_ROOT,
    TEST_ROOT,
    SERVER_HOST,
    HOST,
    BIND_HOST,
    url_host,
    NGINX_ANON_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_WEBDAV_PORT,        # https webdav (8443)
    NGINX_S3_PORT,
    NGINX_GSI_TLS_PORT,       # roots:// native XRootD over GSI + in-protocol TLS (11096)
    PROXY_STD,                # GSI proxy cert used by the XRootD client
)

# roots:// (GSI + in-protocol TLS) is driven through the real XRootD client,
# which negotiates the gotoTLS upgrade and GSI auth for us — reimplementing that
# in raw sockets would be fragile.  Optional: skip the roots:// class if pyxrootd
# is not installed.
try:
    from XRootD import client as _xrd_client
    from XRootD.client.flags import OpenFlags as _OpenFlags
    _HAVE_XRD = True
except Exception:                                   # pragma: no cover
    _HAVE_XRD = False

GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
from test_a_robustness import (
    _connect,
    _full_anon_login,
    _recv_response,
    make_request,
    make_open_req,
    server_healthy,
    kXR_ok,
    kXR_stat,
    kXR_mkdir,
    kXR_rm,
)

# The only server this module self-launches is the CMS data node in
# TestCmsStateEvil (below), now driven through the phase-81 LifecycleHarness;
# every other class probes the standing session fleet.
pytestmark = pytest.mark.uses_lifecycle_harness

kXR_open = 3010
kXR_new = 0x0001
kXR_open_updt = 0x0002

OUTSIDE = TEST_ROOT          # one level above the export root

# A secret file outside the root we will repeatedly try (and must always fail)
# to read.  /etc/passwd is world-readable and its content is unmistakable.
HOST_SECRET = b"root:x:0:0:"


# ---------------------------------------------------------------------------
# Shared payload batteries
# ---------------------------------------------------------------------------

TRAVERSAL_READ = [
    b"/../etc/passwd",
    b"/../../etc/passwd",
    b"/../../../../../../../../etc/passwd",
    b"/a/../../etc/passwd",
    b"/a/b/c/../../../../etc/passwd",
    b"/./.././../etc/passwd",
    b"//../etc/passwd",
    b"/.//..//.//../etc/passwd",
    b"/..",
    b"/../",
]

# Forms that nginx (HTTP) decodes before the handler sees them — encoded "../"
# bypasses nginx's own literal-".." URI collapsing.
TRAVERSAL_HTTP_ENCODED = [
    "/../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd",
    "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/%252e%252e/etc/passwd",            # double-encoded
    "/%2E%2E/%2E%2E/etc/passwd",         # mixed case
    "/foo/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/....//....//etc/passwd",
]

# Embedded-NUL battery (binary protocols).  A C string handler that truncates at
# the first NUL — while the wire framing carries the FULL byte length — could be
# fooled into either (a) treating a benign prefix as the whole path while the
# real escape hides after the NUL, or (b) leaking the post-NUL suffix.  The
# contract: the module uses explicit-length ngx_str_t throughout and openat2()
# gets the exact bytes, so every one of these must error and leak nothing.
TRAVERSAL_NUL = [
    b"/test.txt\x00/../../../../../../etc/passwd",  # benign prefix, escape after NUL
    b"/\x00/../../../../etc/passwd",                # NUL right after the slash
    b"/../etc/passwd\x00.txt",                      # escape before NUL, benign suffix
    b"/etc/passwd\x00",                             # trailing NUL on an absolute path
    b"/a/b\x00/../../../../../etc/passwd",          # NUL mid-path before traversal
    b"/\x00",                                       # lone NUL component
]


def _outside(name):
    return os.path.join(OUTSIDE, name)


def _assert_nothing_escaped(name):
    p = _outside(name)
    if os.path.exists(p) or os.path.islink(p):
        try:
            (os.remove if not os.path.isdir(p) else os.rmdir)(p)
        except OSError:
            pass
        pytest.fail(f"CONFINEMENT BREACH: {p} was created/left outside the root")


# ---------------------------------------------------------------------------
# Symlink battery — planted under the export root, cleaned up afterwards.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def evil_symlinks():
    """Plant a battery of escaping symlinks under DATA_ROOT.

    Returns a dict of {logical_key: description}.  logical_key is the path
    component clients will use; each is engineered to resolve OUT of the root
    if confinement is broken.
    """
    os.makedirs(DATA_ROOT, exist_ok=True)
    made = []

    def link(name, target):
        p = os.path.join(DATA_ROOT, name)
        try:
            if os.path.islink(p) or os.path.exists(p):
                os.remove(p)
            os.symlink(target, p)
            made.append(p)
            return name
        except OSError:
            return None

    keys = {}
    # dir symlink to /etc → key "<l>/passwd"
    if link("evil_etc", "/etc"):
        keys["dir_to_etc"] = "evil_etc/passwd"
    # file symlink straight to /etc/passwd
    if link("evil_passwd", "/etc/passwd"):
        keys["file_to_passwd"] = "evil_passwd"
    # symlink to filesystem root
    if link("evil_root", "/"):
        keys["to_root"] = "evil_root/etc/passwd"
    # relative escaping symlink
    if link("evil_rel", "../../../../etc"):
        keys["relative"] = "evil_rel/passwd"
    # symlink chain a -> b -> /etc
    if link("evil_chainb", "/etc") and link("evil_chaina", "evil_chainb"):
        keys["chain"] = "evil_chaina/passwd"
    # symlink loop (must not hang / must error)
    if link("evil_loop", "evil_loop"):
        keys["loop"] = "evil_loop"
    # magic-link target: /proc/self/environ (info leak if followed)
    if link("evil_proc", "/proc/self/environ"):
        keys["proc_environ"] = "evil_proc"
    # /proc/self/root magic link → whole host fs
    if link("evil_procroot", "/proc/self/root"):
        keys["proc_root"] = "evil_procroot/etc/passwd"

    # NOTE on in-root symlinks: the module's confined open path uses
    # openat2(RESOLVE_BENEATH) / O_NOFOLLOW, which refuses to follow ANY symlink
    # final component — even one whose target stays inside the root.  That is a
    # deliberate, strong posture (no symlink following at all), so we do not
    # assert that in-root symlinks resolve; the security contract this suite
    # enforces is only that NO symlink can ESCAPE the export root.

    if not keys:
        pytest.skip("could not plant any symlinks under the export root")

    yield keys

    for p in made:
        try:
            os.remove(p)
        except OSError:
            pass


# ===========================================================================
# root:// — native XRootD on the anon (write-enabled) endpoint
# ===========================================================================

@pytest.fixture(scope="module", autouse=True)
def _require_root_server():
    for _ in range(10):
        if server_healthy(SERVER_HOST, NGINX_ANON_PORT):
            return
    pytest.skip(f"root:// server not reachable at {SERVER_HOST}:{NGINX_ANON_PORT}")


def _root_stat(sock, path):
    req = make_request(b"\x00\xA0", kXR_stat, body=b"\x00" * 16,
                       payload=path + b"\x00")
    try:
        sock.sendall(req)
        return _recv_response(sock)
    except (socket.timeout, ConnectionError, OSError):
        return None, b""


class TestRootEvil:

    def test_traversal_read_blocked(self):
        s = _connect(); _full_anon_login(s)
        for p in TRAVERSAL_READ:
            st, body = _root_stat(s, p)
            if st is None:
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root stat {p!r} returned kXR_ok"
            assert HOST_SECRET not in body
        s.close()

    def test_traversal_open_read_blocked(self):
        s = _connect(); _full_anon_login(s)
        for p in TRAVERSAL_READ:
            try:
                s.sendall(make_open_req(p + b"\x00", options=0x0000))
                st, body = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root open(read) {p!r} succeeded"
            assert HOST_SECRET not in body
        s.close()

    def test_traversal_nul_read_blocked(self):
        """Embedded-NUL paths must error and never leak host content (stat+open)."""
        s = _connect(); _full_anon_login(s)
        for p in TRAVERSAL_NUL:
            st, body = _root_stat(s, p)
            if st is None:
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root stat NUL {p!r} returned kXR_ok"
            assert HOST_SECRET not in body, f"root stat NUL {p!r} leaked host content"
            try:
                s.sendall(make_open_req(p + b"\x00", options=0x0000))
                st2, body2 = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert st2 != kXR_ok, f"root open(read) NUL {p!r} succeeded"
            assert HOST_SECRET not in body2, f"root open NUL {p!r} leaked host content"
        s.close()

    def test_traversal_nul_write_creates_nothing_outside(self):
        """Embedded-NUL create/mkdir must not place anything outside the root."""
        s = _connect(); _full_anon_login(s)
        name = f"evilnul_{uuid.uuid4().hex}"
        for tmpl in (b"/x\x00/../" + name.encode(),
                     b"/../" + name.encode() + b"\x00.txt",
                     b"/" + name.encode() + b"\x00/../../" + name.encode()):
            p = tmpl + b"\x00"
            for op, opts in ((kXR_mkdir, None), (kXR_open, kXR_new | kXR_open_updt)):
                try:
                    if op == kXR_open:
                        s.sendall(make_open_req(p, options=opts))
                    else:
                        s.sendall(make_request(b"\x00\xA0", op,
                                               body=b"\x00" * 16, payload=p))
                    st, _ = _recv_response(s)
                except (socket.timeout, ConnectionError, OSError):
                    s = _connect(); _full_anon_login(s); st = 4003
                assert st != kXR_ok, f"root NUL write {tmpl!r} succeeded — escape!"
        _assert_nothing_escaped(name)
        s.close()

    def test_traversal_write_creates_nothing_outside(self):
        s = _connect(); _full_anon_login(s)
        name = f"evilroot_{uuid.uuid4().hex}"
        for op, opts in ((kXR_mkdir, None), (kXR_open, kXR_new | kXR_open_updt)):
            for tmpl in (f"/../{name}", f"/a/../../{name}", f"/./../{name}"):
                p = tmpl.encode() + b"\x00"
                try:
                    if op == kXR_open:
                        s.sendall(make_open_req(p, options=opts))
                    else:
                        s.sendall(make_request(b"\x00\xA0", op,
                                               body=b"\x00" * 16, payload=p))
                    st, _ = _recv_response(s)
                except (socket.timeout, ConnectionError, OSError):
                    s = _connect(); _full_anon_login(s); st = 4003
                assert st != kXR_ok, f"root write {tmpl!r} succeeded — escape!"
        _assert_nothing_escaped(name)
        s.close()

    def test_symlink_escapes_blocked(self, evil_symlinks):
        s = _connect(); _full_anon_login(s)
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            probe = (val if isinstance(val, str) else val[0]).encode()
            st, body = _root_stat(s, b"/" + probe)
            if st is None:
                s = _connect(); _full_anon_login(s); continue
            assert st != kXR_ok, f"root stat via symlink {key} ({probe!r}) ok!"
            assert HOST_SECRET not in body
            # also try open-read through the link
            try:
                s.sendall(make_open_req(b"/" + probe + b"\x00", options=0x0000))
                st2, body2 = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert st2 != kXR_ok, f"root open via symlink {key} succeeded!"
            assert HOST_SECRET not in body2
        s.close()


# ===========================================================================
# roots:// — native XRootD over GSI + in-protocol TLS (port 11096).
# Proves confinement holds on the TLS transport explicitly, not just
# transitively from plain root://.  Driven through the real XRootD client so the
# gotoTLS upgrade + GSI auth are negotiated for us.  Symlink escapes are the
# sharpest probe: they use literal in-root names (no "../" the client could
# normalise away client-side), so any leak is an unambiguous server-side breach.
# ===========================================================================

@pytest.mark.skipif(not _HAVE_XRD,
                    reason="pyxrootd (XRootD python client) not installed")
class TestRootsTlsEvil:

    @pytest.fixture(scope="class", autouse=True)
    def _require_roots(self):
        if not os.path.exists(PROXY_STD):
            pytest.skip(f"GSI proxy cert not found at {PROXY_STD}")
        os.environ.setdefault("X509_USER_PROXY", PROXY_STD)
        if not _port_up(NGINX_GSI_TLS_PORT):
            pytest.skip(f"roots:// (GSI+TLS) port {NGINX_GSI_TLS_PORT} not reachable")

    def _stat(self, path):
        return _xrd_client.FileSystem(GSI_TLS_URL).stat(path)[0]

    def _open_read(self, path):
        f = _xrd_client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//{path.lstrip('/')}")
        data = b""
        try:
            if status.ok:
                st2, info = f.stat()
                if st2.ok and getattr(info, "size", 0):
                    rs, data = f.read(0, info.size)
                    if not rs.ok:
                        data = b""
        finally:
            try:
                f.close()
            except Exception:
                pass
        return status, data or b""

    def test_traversal_read_blocked(self):
        for p in TRAVERSAL_READ:
            path = p.decode("latin-1")
            assert not self._stat(path).ok, f"roots:// stat {path!r} returned ok"
            ost, data = self._open_read(path)
            assert not ost.ok, f"roots:// open(read) {path!r} succeeded"
            assert HOST_SECRET not in data, f"roots:// {path!r} leaked host content"

    def test_symlink_escapes_blocked(self, evil_symlinks):
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            probe = val if isinstance(val, str) else val[0]
            assert not self._stat("/" + probe).ok, \
                f"roots:// stat via symlink {key} ({probe}) returned ok!"
            ost, data = self._open_read("/" + probe)
            assert not ost.ok, f"roots:// open via symlink {key} ({probe}) succeeded!"
            assert HOST_SECRET not in data, \
                f"roots:// symlink {key} ({probe}) leaked host content"


# ===========================================================================
# HTTP / HTTPS WebDAV  and  S3   (shared raw-request helpers)
# ===========================================================================

def _http_conn(port, tls):
    if tls:
        ctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection(SERVER_HOST, port, timeout=8,
                                            context=ctx)
    return http.client.HTTPConnection(SERVER_HOST, port, timeout=8)


def _raw(port, method, raw_path, tls=False, body=None, headers=None):
    """Send method + verbatim request-target so the SERVER does normalisation."""
    conn = _http_conn(port, tls)
    try:
        conn.putrequest(method, raw_path, skip_host=False,
                        skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _port_up(port):
    try:
        with socket.create_connection((SERVER_HOST, port), timeout=2):
            return True
    except OSError:
        return False


def _webdav_evil_suite(port, tls):
    """Run the full WebDAV evil battery against one endpoint; returns None,
    asserting on any breach."""
    # --- encoded traversal GET must never leak host files ---
    for path in TRAVERSAL_HTTP_ENCODED:
        st, data = _raw(port, "GET", path, tls=tls)
        assert HOST_SECRET not in data, f"GET {path} leaked host content ({st})"

    # --- traversal PUT / MKCOL / DELETE must not touch outside the root ---
    name = f"evildav_{uuid.uuid4().hex}"
    for path in (f"/../{name}", f"/%2e%2e/{name}", f"/foo/%2e%2e/%2e%2e/{name}"):
        try:
            _raw(port, "PUT", path, tls=tls, body=b"pwn")
            _raw(port, "MKCOL", path, tls=tls)
        except OSError:
            pass
    _assert_nothing_escaped(name)

    victim = _outside(f"victim_dav_{uuid.uuid4().hex}")
    with open(victim, "wb") as fh:
        fh.write(b"keep")
    try:
        for path in (f"/../{os.path.basename(victim)}",
                     f"/%2e%2e/{os.path.basename(victim)}"):
            try:
                _raw(port, "DELETE", path, tls=tls)
            except OSError:
                pass
        assert os.path.exists(victim), "WebDAV DELETE escaped the root"
    finally:
        if os.path.exists(victim):
            os.remove(victim)


def _webdav_symlink_suite(port, tls, evil_symlinks):
    for key, probe in evil_symlinks.items():
        st, data = _raw(port, "GET", "/" + probe, tls=tls)
        assert HOST_SECRET not in data, \
            f"WebDAV GET via symlink {key} ({probe}) leaked host content (st={st})"
        assert st in (403, 404), \
            f"WebDAV GET via symlink {key} should be 403/404, got {st}"


@pytest.mark.skipif(not _port_up(NGINX_HTTP_WEBDAV_PORT),
                    reason="http WebDAV (8080) not reachable")
class TestWebDavHttpEvil:
    def test_evil_battery(self):
        _webdav_evil_suite(NGINX_HTTP_WEBDAV_PORT, tls=False)

    def test_symlink_escapes(self, evil_symlinks):
        _webdav_symlink_suite(NGINX_HTTP_WEBDAV_PORT, tls=False, evil_symlinks=evil_symlinks)


@pytest.mark.skipif(not _port_up(NGINX_WEBDAV_PORT),
                    reason="https WebDAV (8443) not reachable")
class TestWebDavHttpsEvil:
    def test_evil_battery(self):
        _webdav_evil_suite(NGINX_WEBDAV_PORT, tls=True)

    def test_symlink_escapes(self, evil_symlinks):
        _webdav_symlink_suite(NGINX_WEBDAV_PORT, tls=True, evil_symlinks=evil_symlinks)


@pytest.mark.skipif(not _port_up(NGINX_S3_PORT),
                    reason="S3 (9001) not reachable")
class TestS3Evil:
    BUCKET = "testbucket"

    def test_traversal_get_blocked(self):
        for path in TRAVERSAL_HTTP_ENCODED:
            st, data = _raw(NGINX_S3_PORT, "GET", f"/{self.BUCKET}{path}")
            assert HOST_SECRET not in data, f"S3 GET {path} leaked host content"

    def test_symlink_escapes(self, evil_symlinks):
        for key, val in evil_symlinks.items():
            probe = val if isinstance(val, str) else val[0]
            st, data = _raw(NGINX_S3_PORT, "GET", f"/{self.BUCKET}/{probe}")
            if key == "legit_inroot":
                continue
            assert HOST_SECRET not in data, \
                f"S3 GET via symlink {key} ({probe}) leaked host content (st={st})"
            assert st in (403, 404), \
                f"S3 GET via symlink {key} should be 403/404, got {st}"

    def test_put_traversal_creates_nothing_outside(self):
        name = f"evils3_{uuid.uuid4().hex}"
        for path in (f"/{self.BUCKET}/../{name}",
                     f"/{self.BUCKET}/%2e%2e/{name}"):
            try:
                _raw(NGINX_S3_PORT, "PUT", path, body=b"pwn")
            except OSError:
                pass
        _assert_nothing_escaped(name)


# ===========================================================================
# cms:// — hostile MANAGER probes a data node with kYR_state for evil paths.
# The node must answer kYR_have ONLY for files genuinely inside the export
# root; symlink/".." escapes must be rejected (confined stat_beneath).
# ===========================================================================

CMS_RR_LOGIN = 0
CMS_RR_STATE = 20
CMS_RR_HAVE = 15
CMS_RR_STATUS = 22
CMS_RR_LOAD = 16
CMS_HDR = 8


def _cms_read_frame(sock, timeout=3.0):
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < CMS_HDR:
            c = sock.recv(CMS_HDR - len(hdr))
            if not c:
                return None
            hdr += c
        code = hdr[4]
        dlen = struct.unpack(">H", hdr[6:8])[0]
        body = b""
        while len(body) < dlen:
            c = sock.recv(dlen - len(body))
            if not c:
                break
            body += c
        return code, body
    except socket.timeout:
        return None


def _cms_state(sock, streamid, path):
    payload = path.encode() + b"\x00"
    hdr = struct.pack(">IBBH", streamid, CMS_RR_STATE, 0x20, len(payload))
    sock.sendall(hdr + payload)


class TestCmsStateEvil:
    """Stand up a mock CMS manager + a dedicated nginx data node pointing at it,
    then probe the node's kYR_state handler with escaping paths."""

    @pytest.fixture(scope="class")
    def cms_node(self, evil_symlinks):
        # mock manager listening socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((BIND_HOST, 0))
        mgr_port = srv.getsockname()[1]
        srv.listen(4)
        srv.settimeout(20)

        harness = LifecycleHarness()
        try:
            harness.start(NginxInstanceSpec(
                name="lc-evil-cms-node",
                template="nginx_evil_cms_node.conf",
                protocol="root", readiness="tcp",
                data_root=DATA_ROOT,
                template_values={"CMS_MANAGER": f"{url_host(HOST)}:{mgr_port}"}))
        except Exception:
            harness.close()
            srv.close()
            raise

        # accept the node's CMS client connection
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            harness.close()
            srv.close()
            pytest.skip("nginx CMS client never connected to mock manager")

        # Drain the node's login/status/load frames so our state frames are
        # processed cleanly.
        time.sleep(0.5)
        conn.setblocking(False)
        try:
            while True:
                if not conn.recv(4096):
                    break
        except (BlockingIOError, OSError):
            pass
        conn.setblocking(True)

        yield conn

        try:
            conn.close()
        except OSError:
            pass
        srv.close()
        harness.close()

    def test_state_symlink_escape_no_have(self, cms_node, evil_symlinks):
        conn = cms_node
        sid = 1000
        breaches = []
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            probe = val if isinstance(val, str) else val[0]
            _cms_state(conn, sid, "/" + probe)
            sid += 1
            fr = _cms_read_frame(conn, timeout=2.0)
            # A kYR_have reply for an escaping path = the node falsely claims to
            # hold a file outside its root.  Silence (None) or any non-HAVE is OK.
            if fr is not None and fr[0] == CMS_RR_HAVE:
                breaches.append((key, probe))
        assert not breaches, f"CMS kYR_state symlink escapes returned kYR_have: {breaches}"

    def test_state_dotdot_no_have(self, cms_node):
        conn = cms_node
        sid = 2000
        breaches = []
        for p in ("/../etc/passwd", "/../../etc/passwd", "/a/../../etc/passwd"):
            _cms_state(conn, sid, p)
            sid += 1
            fr = _cms_read_frame(conn, timeout=2.0)
            if fr is not None and fr[0] == CMS_RR_HAVE:
                breaches.append(p)
        assert not breaches, f"CMS kYR_state '..' escapes returned kYR_have: {breaches}"


# ===========================================================================
# EVIL WRITES — the dangerous half: can a bad actor CREATE / OVERWRITE / DELETE
# / MOVE a real file OUTSIDE the export root?  Unlike the read tests (which only
# need to deny content), these target a genuinely WRITABLE directory outside the
# root (TEST_ROOT itself, which the test user owns) reached via symlinks and
# "..", and assert the outside zone is left perfectly pristine.
# ===========================================================================

kXR_mv = 3009
kXR_rmdir = 3015
kXR_truncate = 3028
ORIGINAL = b"ORIGINAL-DO-NOT-TOUCH"


@pytest.fixture()
def write_zone():
    """A writable directory OUTSIDE the export root + a victim file, plus
    symlinks planted INSIDE the root that point at them.  Yields names; on
    teardown asserts nothing leaked and cleans up."""
    tag = uuid.uuid4().hex[:10]
    zone = os.path.join(OUTSIDE, f"evil_wzone_{tag}")
    os.makedirs(zone, exist_ok=True)
    victim = os.path.join(zone, "victim.txt")
    with open(victim, "wb") as fh:
        fh.write(ORIGINAL)

    links = []

    def link(name, target):
        p = os.path.join(DATA_ROOT, name)
        try:
            if os.path.islink(p) or os.path.exists(p):
                os.remove(p)
            os.symlink(target, p)
            links.append(p)
            return name
        except OSError:
            return None

    sl_dir = link(f"wdir_{tag}", zone)         # symlink → writable outside dir
    sl_file = link(f"wfile_{tag}", victim)     # symlink → victim file
    # an in-root regular file, used as a MOVE/COPY source trying to escape
    src = os.path.join(DATA_ROOT, f"wsrc_{tag}.txt")
    with open(src, "wb") as fh:
        fh.write(b"in-root-source")

    yield {
        "zone": zone, "victim": victim, "zone_base": os.path.basename(zone),
        "sl_dir": sl_dir, "sl_file": sl_file,
        "src_key": f"wsrc_{tag}.txt",
    }

    for p in links:
        try:
            os.remove(p)
        except OSError:
            pass
    try:
        os.remove(src)
    except OSError:
        pass
    shutil.rmtree(zone, ignore_errors=True)


def _assert_zone_pristine(z):
    """The outside zone must be untouched: victim present + original content,
    and NO extra entry created."""
    assert os.path.exists(z["victim"]), \
        f"CONFINEMENT BREACH: victim {z['victim']} was deleted from outside the root"
    with open(z["victim"], "rb") as fh:
        assert fh.read() == ORIGINAL, \
            f"CONFINEMENT BREACH: victim {z['victim']} was overwritten/truncated"
    leftover = sorted(os.listdir(z["zone"]))
    assert leftover == ["victim.txt"], \
        f"CONFINEMENT BREACH: outside zone gained entries {leftover}"


# --- WebDAV (http + https) evil writes --------------------------------------

def _webdav_write_attacks(port, tls, z):
    sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
    body = b"PWNED"
    attacks = []
    # create a new file in the outside dir via a dir-symlink
    if sd:
        attacks += [("PUT", f"/{sd}/PWNED_{uuid.uuid4().hex}", body),
                    ("MKCOL", f"/{sd}/pwndir_{uuid.uuid4().hex}", None),
                    ("DELETE", f"/{sd}/victim.txt", None)]
    # overwrite / delete the victim straight through a file-symlink
    if sf:
        attacks += [("PUT", f"/{sf}", body),
                    ("DELETE", f"/{sf}", None)]
    # pure "../" escape into the writable zone (no symlink)
    attacks += [
        ("PUT", f"/../{zb}/PWNED_{uuid.uuid4().hex}", body),
        ("PUT", f"/%2e%2e/{zb}/PWNED_{uuid.uuid4().hex}", body),
        ("DELETE", f"/../{zb}/victim.txt", None),
        ("MKCOL", f"/../{zb}/pwndir_{uuid.uuid4().hex}", None),
    ]
    for method, path, b in attacks:
        try:
            _raw(port, method, path, tls=tls, body=b)
        except OSError:
            pass
    # MOVE / COPY an in-root file out via Destination header (symlink + "..")
    for dest in ([f"/{sd}/moved_{uuid.uuid4().hex}"] if sd else []) + \
               [f"/../{zb}/moved_{uuid.uuid4().hex}"]:
        for method in ("MOVE", "COPY"):
            try:
                _raw(port, method, "/" + z["src_key"], tls=tls,
                     headers={"Destination": dest})
            except OSError:
                pass
    _assert_zone_pristine(z)


@pytest.mark.skipif(not _port_up(NGINX_HTTP_WEBDAV_PORT),
                    reason="http WebDAV (8080) not reachable")
class TestWebDavHttpEvilWrites:
    def test_write_escapes_blocked(self, write_zone):
        _webdav_write_attacks(NGINX_HTTP_WEBDAV_PORT, False, write_zone)


@pytest.mark.skipif(not _port_up(NGINX_WEBDAV_PORT),
                    reason="https WebDAV (8443) not reachable")
class TestWebDavHttpsEvilWrites:
    def test_write_escapes_blocked(self, write_zone):
        _webdav_write_attacks(NGINX_WEBDAV_PORT, True, write_zone)


# --- S3 evil writes ----------------------------------------------------------

@pytest.mark.skipif(not _port_up(NGINX_S3_PORT),
                    reason="S3 (9001) not reachable")
class TestS3EvilWrites:
    BUCKET = "testbucket"

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        attacks = []
        if sd:
            attacks += [("PUT", f"/{self.BUCKET}/{sd}/PWNED_{uuid.uuid4().hex}", b"x"),
                        ("DELETE", f"/{self.BUCKET}/{sd}/victim.txt", None)]
        if sf:
            attacks += [("PUT", f"/{self.BUCKET}/{sf}", b"x"),
                        ("DELETE", f"/{self.BUCKET}/{sf}", None)]
        attacks += [
            ("PUT", f"/{self.BUCKET}/../{zb}/PWNED_{uuid.uuid4().hex}", b"x"),
            ("PUT", f"/{self.BUCKET}/%2e%2e/{zb}/PWNED_{uuid.uuid4().hex}", b"x"),
            ("DELETE", f"/{self.BUCKET}/../{zb}/victim.txt", None),
        ]
        for method, path, b in attacks:
            try:
                _raw(NGINX_S3_PORT, method, path, body=b)
            except OSError:
                pass
        _assert_zone_pristine(z)


# --- root:// evil writes -----------------------------------------------------

class TestRootEvilWrites:

    def _op(self, s, opcode, path, body=b"\x00" * 16, open_opts=None):
        p = path.encode() + b"\x00"
        try:
            if open_opts is not None:
                s.sendall(make_open_req(p, options=open_opts))
            else:
                s.sendall(make_request(b"\x00\xA0", opcode, body=body, payload=p))
            st, _ = _recv_response(s)
            return st, s
        except (socket.timeout, ConnectionError, OSError):
            s = _connect(); _full_anon_login(s)
            return None, s

    def test_write_escapes_blocked(self, write_zone):
        z = write_zone
        sd, sf, zb = z["sl_dir"], z["sl_file"], z["zone_base"]
        s = _connect(); _full_anon_login(s)

        targets = []
        if sd:
            targets += [
                (kXR_open, f"/{sd}/PWNED_{uuid.uuid4().hex}", kXR_new | kXR_open_updt),
                (kXR_mkdir, f"/{sd}/pwndir_{uuid.uuid4().hex}", None),
                (kXR_rm, f"/{sd}/victim.txt", None),
            ]
        if sf:
            targets += [
                (kXR_open, f"/{sf}", kXR_new | kXR_open_updt),   # create/trunc victim
                (kXR_truncate, f"/{sf}", None),
                # NOTE: kXR_rm of the symlink itself is NOT an escape — unlink operates
                # on the in-root link (lstat/POSIX semantics), never the external target.
                # It legitimately succeeds; checked separately below, and
                # _assert_zone_pristine proves the victim survived.
            ]
        # pure "../" escapes into the writable zone
        targets += [
            (kXR_open, f"/../{zb}/PWNED_{uuid.uuid4().hex}", kXR_new | kXR_open_updt),
            (kXR_mkdir, f"/../{zb}/pwndir_{uuid.uuid4().hex}", None),
            (kXR_rm, f"/../{zb}/victim.txt", None),
            (kXR_rmdir, f"/../{zb}", None),
        ]
        for opcode, path, opts in targets:
            st, s = self._op(s, opcode, path, open_opts=opts)
            assert st != kXR_ok, f"root write {path!r} (op {opcode}) succeeded — escape!"

        # rm of the in-root symlink-to-victim must SUCCEED (removes the link only) and
        # must NOT delete the external victim — that is the real confinement property.
        if sf:
            st, s = self._op(s, kXR_rm, f"/{sf}")
            assert st == kXR_ok, f"rm of in-root symlink /{sf} should remove the link"

        # kXR_mv: move an in-root file OUT (src in root, dst escaping)
        for dst in ([f"/{sd}/moved"] if sd else []) + [f"/../{zb}/moved"]:
            payload = (f"/{z['src_key']}\n{dst}").encode() + b"\x00"
            try:
                s.sendall(make_request(b"\x00\xA0", kXR_mv,
                                       body=b"\x00" * 16, payload=payload))
                st, _ = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); st = 4003
            assert st != kXR_ok, f"root mv to {dst!r} succeeded — escape!"

        s.close()
        _assert_zone_pristine(z)
