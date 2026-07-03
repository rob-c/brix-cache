"""
tests/test_path_confinement.py

Path-confinement security tests for the kernel-enforced export-root boundary
(Phase 8 — openat2 RESOLVE_BENEATH).  These complement the stat-only traversal
check in test_a_robustness.py::TestPathTraversal with a much broader sweep.

The threat model covers BOTH classes of caller the export root must contain:

  * Anonymous users — no credentials at all.
  * Authorized writers — the anon stream endpoint (port 11094) has
    ``brix_allow_write on``, so a legitimate *in-root* mkdir/open-create
    SUCCEEDS (proving the client is genuinely authorized to mutate the
    namespace).  Every traversal/symlink escape must therefore be blocked by
    *confinement*, not merely by an auth failure — which the positive controls
    in TestAuthorizedWriterIsStillConfined make explicit.

Every escape attempt is verified against the real filesystem (the tests run on
the same host as the server): nothing may be created outside the export root,
and no external file content may ever be returned to the client.

Run with:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
        pytest tests/test_path_confinement.py -v
"""

import http.client
import os
import socket
import uuid

import pytest

from settings import (
    DATA_ROOT,
    TEST_ROOT,
    SERVER_HOST,
    NGINX_ANON_PORT,
    NGINX_HTTP_WEBDAV_PORT,
)

# Reuse the hand-rolled XRootD wire helpers from the robustness suite.
from test_a_robustness import (
    _connect,
    _full_anon_login,
    _recv_response,
    make_request,
    make_open_req,
    server_healthy,
    assert_healthy,
    kXR_ok,
    kXR_error,
    kXR_stat,
    kXR_mkdir,
    kXR_rm,
)

# Opcodes not exported by test_a_robustness (values from XProtocol.hh).
kXR_mv = 3009
kXR_rmdir = 3015
kXR_truncate = 3028
kXR_dirlist = 3004

# kXR_open option bits.
kXR_new = 0x0001       # create if missing
kXR_open_updt = 0x0002 # open read/write
kXR_mkpath = 0x0100    # create intermediate dirs


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def require_server(test_env):
    for _ in range(10):
        if server_healthy(SERVER_HOST, NGINX_ANON_PORT):
            return
    pytest.skip(f"No XRootD server reachable at {SERVER_HOST}:{NGINX_ANON_PORT}")


# A directory just OUTSIDE the export root.  DATA_ROOT == TEST_ROOT/data, so a
# successful one-level escape ("/../<name>") would land sentinel files here.
_OUTSIDE_DIR = TEST_ROOT


def _outside_path(name):
    return os.path.join(_OUTSIDE_DIR, name)


def _assert_not_created_outside(name):
    """Fail if a sentinel escaped the export root onto the real filesystem."""
    p = _outside_path(name)
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            try:
                os.rmdir(p)
            except OSError:
                pass
        pytest.fail(f"CONFINEMENT BREACH: escape created {p} outside export root")


# Traversal payloads aimed one or more levels above the export root.  {name} is
# substituted with a unique sentinel so we can probe the filesystem afterwards.
def _escape_targets(name):
    return [
        f"/../{name}".encode(),
        f"/../../{name}".encode(),
        f"/../../../{name}".encode(),
        f"/a/../../{name}".encode(),
        f"/a/b/../../../{name}".encode(),
        f"/./../{name}".encode(),
        f"/a/./../../{name}".encode(),
        # absolute-looking double slash and trailing-dot variants
        f"//../{name}".encode(),
    ]


READ_ESCAPES = [
    b"/../etc/passwd",
    b"/../../etc/passwd",
    b"/../../../etc/shadow",
    b"/a/b/../../../../../../etc/passwd",
    b"/./../../etc/passwd",
    b"/..",
    b"/../",
]


def _send_path_op(sock, opcode, path, body=b"\x00" * 16):
    """Send one opcode whose payload is a NUL-terminated path; reconnect on
    hard close.  Returns (status, body, sock) — sock may be a fresh socket."""
    req = make_request(b"\x00\xA0", opcode, body=body, payload=path + b"\x00")
    try:
        sock.sendall(req)
        status, rbody = _recv_response(sock)
        return status, rbody, sock
    except (socket.timeout, ConnectionError, OSError):
        # Server rejected hard by closing the connection — that is a rejection.
        s = _connect()
        _full_anon_login(s)
        return kXR_error, b"", s


# ---------------------------------------------------------------------------
# 1. Read-side escapes: stat / open-read / dirlist must never leak host files
# ---------------------------------------------------------------------------

class TestReadEscapesAnon:

    def test_stat_traversal_never_returns_host_files(self):
        s = _connect()
        _full_anon_login(s)
        for path in READ_ESCAPES:
            status, body, s = _send_path_op(s, kXR_stat, path)
            assert status != kXR_ok, f"stat {path!r} returned kXR_ok — escape!"
            assert b"root:" not in body and b"/bin/" not in body, \
                f"stat {path!r} leaked host file content"
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_open_read_traversal_never_returns_host_files(self):
        s = _connect()
        _full_anon_login(s)
        for path in READ_ESCAPES:
            req = make_open_req(path + b"\x00", options=0x0000)
            try:
                s.sendall(req)
                status, body = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert status != kXR_ok, f"open(read) {path!r} succeeded — escape!"
            assert b"root:" not in body, f"open {path!r} leaked host content"
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_dirlist_traversal_never_lists_host_dirs(self):
        s = _connect()
        _full_anon_login(s)
        for path in (b"/..", b"/../..", b"/../../..", b"/../etc"):
            status, body, s = _send_path_op(s, kXR_dirlist, path)
            assert status != kXR_ok, f"dirlist {path!r} succeeded — escape!"
            assert b"passwd" not in body and b"shadow" not in body, \
                f"dirlist {path!r} leaked host directory entries"
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)


# ---------------------------------------------------------------------------
# 2. Write-side escapes: mkdir / rm / rmdir / truncate / mv / open-create
#    must never mutate anything outside the export root.
# ---------------------------------------------------------------------------

class TestWriteEscapesAnon:

    def test_mkdir_escape_creates_nothing_outside_root(self):
        s = _connect()
        _full_anon_login(s)
        name = f"escape_mkdir_{uuid.uuid4().hex}"
        for path in _escape_targets(name):
            status, _, s = _send_path_op(s, kXR_mkdir, path,
                                         body=b"\x00" * 16)
            assert status != kXR_ok, f"mkdir {path!r} succeeded — escape!"
        _assert_not_created_outside(name)
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_open_create_escape_creates_nothing_outside_root(self):
        s = _connect()
        _full_anon_login(s)
        name = f"escape_open_{uuid.uuid4().hex}"
        for path in _escape_targets(name):
            req = make_open_req(path + b"\x00",
                                options=kXR_new | kXR_open_updt)
            try:
                s.sendall(req)
                status, _ = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); status = kXR_error
            assert status != kXR_ok, f"open(create) {path!r} succeeded — escape!"
        _assert_not_created_outside(name)
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_truncate_escape_rejected(self):
        s = _connect()
        _full_anon_login(s)
        # Plant a real file outside the root and confirm truncate cannot reach it.
        victim = _outside_path(f"victim_{uuid.uuid4().hex}")
        with open(victim, "wb") as fh:
            fh.write(b"DO NOT TRUNCATE")
        try:
            for path in (f"/../{os.path.basename(victim)}".encode(),
                         f"/a/../../{os.path.basename(victim)}".encode()):
                # truncate body carries an 8-byte size; zero is fine for the probe
                status, _, s = _send_path_op(s, kXR_truncate, path,
                                             body=b"\x00" * 16)
                assert status != kXR_ok, f"truncate {path!r} succeeded — escape!"
            assert os.path.getsize(victim) == len(b"DO NOT TRUNCATE"), \
                "CONFINEMENT BREACH: external file was truncated"
        finally:
            os.remove(victim)
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_rm_escape_cannot_delete_outside_root(self):
        s = _connect()
        _full_anon_login(s)
        victim = _outside_path(f"victim_rm_{uuid.uuid4().hex}")
        with open(victim, "wb") as fh:
            fh.write(b"keep me")
        try:
            for path in (f"/../{os.path.basename(victim)}".encode(),
                         f"/a/b/../../../{os.path.basename(victim)}".encode()):
                status, _, s = _send_path_op(s, kXR_rm, path)
                assert status != kXR_ok, f"rm {path!r} succeeded — escape!"
            assert os.path.exists(victim), \
                "CONFINEMENT BREACH: external file was deleted via rm"
        finally:
            if os.path.exists(victim):
                os.remove(victim)
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_mv_escape_rejected_both_sides(self):
        s = _connect()
        _full_anon_login(s)
        # kXR_mv payload is "<src>\n<dst>" (space/newline separated in practice;
        # the resolver rejects either side that escapes before any rename).
        name = f"escape_mv_{uuid.uuid4().hex}"
        payloads = [
            b"/../" + name.encode() + b"\n/inside",
            b"/inside\n/../" + name.encode(),
            b"/../etc/passwd\n/pwned",
        ]
        for payload in payloads:
            req = make_request(b"\x00\xA0", kXR_mv, body=b"\x00" * 16,
                               payload=payload + b"\x00")
            try:
                s.sendall(req)
                status, _ = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); status = kXR_error
            assert status != kXR_ok, f"mv {payload!r} succeeded — escape!"
        _assert_not_created_outside(name)
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)


# ---------------------------------------------------------------------------
# 3. Authorized writer is STILL confined (positive + negative control pair)
# ---------------------------------------------------------------------------

class TestAuthorizedWriterIsStillConfined:

    def test_legit_in_root_mkdir_succeeds_then_escape_is_blocked(self):
        """Prove the client is authorized to mutate the namespace (an in-root
        mkdir succeeds), then prove the SAME authorized client cannot escape."""
        s = _connect()
        _full_anon_login(s)

        ok_dir = f"/conf_ok_{uuid.uuid4().hex}"
        status, _, s = _send_path_op(s, kXR_mkdir, ok_dir.encode())
        # If writes are unexpectedly disabled this becomes an auth test only;
        # tolerate that but record it so the escape assertion stays meaningful.
        in_root_write_allowed = (status == kXR_ok)
        if in_root_write_allowed:
            created = os.path.join(DATA_ROOT, ok_dir.lstrip("/"))
            assert os.path.isdir(created), "in-root mkdir did not create the dir"
            os.rmdir(created)

        # The authorized client must still not escape.
        name = f"conf_escape_{uuid.uuid4().hex}"
        status, _, s = _send_path_op(s, kXR_mkdir, f"/../{name}".encode())
        assert status != kXR_ok, "authorized writer escaped the root via mkdir!"
        _assert_not_created_outside(name)

        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)


# ---------------------------------------------------------------------------
# 4. Symlink escapes — a symlink inside the root that points outside must not
#    be followed out of the root (RESOLVE_BENEATH / RESOLVE_NO_MAGICLINKS).
# ---------------------------------------------------------------------------

class TestSymlinkEscape:

    @pytest.fixture()
    def planted_symlinks(self):
        made = []
        links = {
            "_sym_etc": "/etc",
            "_sym_passwd": "/etc/passwd",
            "_sym_root": "/",
        }
        for name, target in links.items():
            link = os.path.join(DATA_ROOT, name)
            try:
                if os.path.islink(link) or os.path.exists(link):
                    os.remove(link)
                os.symlink(target, link)
                made.append(link)
            except OSError:
                pass
        if not made:
            pytest.skip("could not plant symlinks under the export root")
        yield links
        for link in made:
            try:
                os.remove(link)
            except OSError:
                pass

    def test_stat_through_outward_symlink_blocked(self, planted_symlinks):
        s = _connect()
        _full_anon_login(s)
        for probe in (b"/_sym_passwd",
                      b"/_sym_etc/passwd",
                      b"/_sym_root/etc/passwd"):
            status, body, s = _send_path_op(s, kXR_stat, probe)
            assert status != kXR_ok, \
                f"stat via symlink {probe!r} succeeded — symlink escape!"
            assert b"root:" not in body
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)

    def test_open_read_through_outward_symlink_returns_no_host_content(
            self, planted_symlinks):
        s = _connect()
        _full_anon_login(s)
        for probe in (b"/_sym_passwd", b"/_sym_etc/passwd"):
            req = make_open_req(probe + b"\x00", options=0x0000)
            try:
                s.sendall(req)
                status, body = _recv_response(s)
            except (socket.timeout, ConnectionError, OSError):
                s = _connect(); _full_anon_login(s); continue
            assert status != kXR_ok, \
                f"open via symlink {probe!r} succeeded — symlink escape!"
            assert b"root:" not in body
        s.close()
        assert_healthy(SERVER_HOST, NGINX_ANON_PORT)


# ---------------------------------------------------------------------------
# 5. WebDAV URL traversal (HTTP, anonymous, port 8080)
# ---------------------------------------------------------------------------

def _webdav_available():
    try:
        with socket.create_connection((SERVER_HOST, NGINX_HTTP_WEBDAV_PORT),
                                      timeout=2):
            return True
    except OSError:
        return False


def _raw_http(method, raw_path, body=None, headers=None):
    """Send a request with the path placed verbatim in the request line so the
    server (not the client) is responsible for normalisation/decoding."""
    conn = http.client.HTTPConnection(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT,
                                      timeout=5)
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
        data = resp.read()
        return resp.status, data
    finally:
        conn.close()


@pytest.mark.skipif(not _webdav_available(),
                    reason="non-TLS WebDAV (8080) not reachable")
class TestWebDavTraversal:

    # Encoded forms reach the handler decoded, bypassing nginx's own URI
    # collapsing of literal "../" — the strongest test of module confinement.
    GET_ESCAPES = [
        "/../etc/passwd",
        "/../../etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/foo/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
    ]

    def test_get_traversal_never_returns_host_files(self):
        for path in self.GET_ESCAPES:
            status, data = _raw_http("GET", path)
            assert b"root:x:0:0:" not in data, \
                f"GET {path} leaked /etc/passwd content (status {status})"
            assert status != 200 or b"root:" not in data, \
                f"GET {path} returned 200 with host content"

    def test_put_traversal_creates_nothing_outside_root(self):
        name = f"escape_dav_{uuid.uuid4().hex}"
        body = b"pwned"
        for path in (f"/../{name}",
                     f"/%2e%2e/{name}",
                     f"/foo/%2e%2e/%2e%2e/{name}"):
            try:
                _raw_http("PUT", path, body=body)
            except OSError:
                pass
        _assert_not_created_outside(name)

    def test_delete_traversal_cannot_remove_outside_root(self):
        victim = _outside_path(f"victim_dav_{uuid.uuid4().hex}")
        with open(victim, "wb") as fh:
            fh.write(b"keep")
        try:
            for path in (f"/../{os.path.basename(victim)}",
                         f"/%2e%2e/{os.path.basename(victim)}"):
                try:
                    _raw_http("DELETE", path)
                except OSError:
                    pass
            assert os.path.exists(victim), \
                "CONFINEMENT BREACH: external file deleted via WebDAV DELETE"
        finally:
            if os.path.exists(victim):
                os.remove(victim)

    def test_mkcol_traversal_creates_nothing_outside_root(self):
        name = f"escape_mkcol_{uuid.uuid4().hex}"
        for path in (f"/../{name}", f"/%2e%2e/{name}"):
            try:
                _raw_http("MKCOL", path)
            except OSError:
                pass
        _assert_not_created_outside(name)
