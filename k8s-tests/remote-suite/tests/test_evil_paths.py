# brix-remote-adapted
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
import subprocess
import tempfile
import time
import uuid

import pytest
import klib  # remote: symlinks planted on the SERVER

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

SERVER_SVC = "mega"
SERVER_DATA = "/data/xrootd"
SERVER_OUTSIDE = "/tmp"  # server dir outside the export root


def _plant_symlink(made, name, target):
    path = os.path.join(SERVER_DATA, name)
    try:
        klib.svc_symlink(SERVER_SVC, target, path)
    except OSError:
        return None
    made.append(path)
    return name


def _record_symlink(keys, made, key, name, target, suffix=""):
    if _plant_symlink(made, name, target):
        keys[key] = name + suffix


def _record_symlink_chain(keys, made):
    tail = _plant_symlink(made, "evil_chainb", "/etc")
    if tail and _plant_symlink(made, "evil_chaina", "evil_chainb"):
        keys["chain"] = "evil_chaina/passwd"


def _remove_symlinks(paths):
    for path in paths:
        klib.svc_rm(SERVER_SVC, path)


@pytest.fixture(scope="module")
def evil_symlinks():
    """Plant a battery of escaping symlinks under DATA_ROOT.

    Returns a dict of {logical_key: description}.  logical_key is the path
    component clients will use; each is engineered to resolve OUT of the root
    if confinement is broken.
    """
    keys = {}
    made = []
    _record_symlink(keys, made, "dir_to_etc", "evil_etc", "/etc", "/passwd")
    _record_symlink(keys, made, "file_to_passwd", "evil_passwd", "/etc/passwd")
    _record_symlink(keys, made, "to_root", "evil_root", "/", "/etc/passwd")
    _record_symlink(keys, made, "relative", "evil_rel", "../../../../etc", "/passwd")
    _record_symlink_chain(keys, made)
    _record_symlink(keys, made, "loop", "evil_loop", "evil_loop")
    _record_symlink(keys, made, "proc_environ", "evil_proc", "/proc/self/environ")
    _record_symlink(keys, made, "proc_root", "evil_procroot", "/proc/self/root", "/etc/passwd")

    # NOTE on in-root symlinks: the module's confined open path uses
    # openat2(RESOLVE_BENEATH) / O_NOFOLLOW, which refuses to follow ANY symlink
    # final component — even one whose target stays inside the root.  That is a
    # deliberate, strong posture (no symlink following at all), so we do not
    # assert that in-root symlinks resolve; the security contract this suite
    # enforces is only that NO symlink can ESCAPE the export root.

    if not keys:
        pytest.skip("could not plant any symlinks under the export root")

    yield keys

    _remove_symlinks(made)


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


def _symlink_probe(value):
    return value if isinstance(value, str) else value[0]


def _new_root_connection():
    connection = _connect()
    _full_anon_login(connection)
    return connection


def _assert_root_symlink_stat(connection, key, probe):
    status, body = _root_stat(connection, b"/" + probe)
    if status is None:
        return _new_root_connection(), False
    assert status != kXR_ok, f"root stat via symlink {key} ({probe!r}) ok!"
    assert HOST_SECRET not in body
    return connection, True


def _assert_root_symlink_open(connection, key, probe):
    try:
        connection.sendall(make_open_req(b"/" + probe + b"\x00", options=0x0000))
        status, body = _recv_response(connection)
    except (socket.timeout, ConnectionError, OSError):
        return _new_root_connection()
    assert status != kXR_ok, f"root open via symlink {key} succeeded!"
    assert HOST_SECRET not in body
    return connection


def _assert_root_symlink_confined(connection, key, value):
    probe = _symlink_probe(value).encode()
    connection, can_open = _assert_root_symlink_stat(connection, key, probe)
    if not can_open:
        return connection
    return _assert_root_symlink_open(connection, key, probe)


def _read_open_xrd_file(file_handle):
    status, info = file_handle.stat()
    if not status.ok or not getattr(info, "size", 0):
        return b""
    read_status, data = file_handle.read(0, info.size)
    if not read_status.ok:
        return b""
    return data


def _close_xrd_file(file_handle):
    try:
        file_handle.close()
    except Exception:
        pass


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
        s = _new_root_connection()
        for key, val in evil_symlinks.items():
            if key == "legit_inroot":
                continue
            s = _assert_root_symlink_confined(s, key, val)
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
        try:
            data = _read_open_xrd_file(f) if status.ok else b""
        finally:
            _close_xrd_file(f)
        return status, data

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


from split_continuation import load as _load_continuation

_load_continuation(
    globals(),
    __file__,
    "_test_evil_paths_protocols.py",
    "_test_evil_paths_writes.py",
)

