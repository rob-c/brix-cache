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
#
# `serial` (Phase-6): the module-scope `evil_symlinks` fixture plants a battery
# of escaping symlinks (and creates/removes probe files) directly under the
# SHARED export root DATA_ROOT — poisoning any parallel test that reads it — and
# the mock CMS manager binds an OS-ephemeral listen the node dials.  Neither is a
# fixed-port registry server, so both are documented port exemptions, not goal-1
# violations (see fleet_lifecycle_ports.py § "Phase-6 client-flood / mock-bind").
pytestmark = [pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-evil-cms-node")]

kXR_open = 3010
kXR_new = 0x0001
kXR_open_updt = 0x0002

OUTSIDE = TEST_ROOT          # one level above the export root

# A secret file outside the root we will repeatedly try (and must always fail)
# to read.  /etc/passwd is world-readable and its content is unmistakable.
HOST_SECRET = b"root:x:0:0:"

# Sentinel content for the write-confinement checks.  This lives in the
# continuation module because the write fixture is defined here, while the
# public test module re-exports the helpers.
ORIGINAL = b"ORIGINAL-DO-NOT-TOUCH"


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


def _plant_symlink(made, name, target):
    path = os.path.join(DATA_ROOT, name)
    try:
        if os.path.islink(path) or os.path.exists(path):
            os.remove(path)
        os.symlink(target, path)
        made.append(path)
        return True
    except OSError:
        return False


def _record_symlink(keys, made, key, name, target, suffix=""):
    if _plant_symlink(made, name, target):
        keys[key] = name + suffix


def _record_symlink_chain(keys, made):
    if not _plant_symlink(made, "evil_chainb", "/etc"):
        return
    if _plant_symlink(made, "evil_chaina", "evil_chainb"):
        keys["chain"] = "evil_chaina/passwd"


def _remove_paths(paths):
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass


@pytest.fixture(scope="module")
def evil_symlinks():
    """Plant a battery of escaping symlinks under DATA_ROOT.

    Returns a dict of {logical_key: description}.  logical_key is the path
    component clients will use; each is engineered to resolve OUT of the root
    if confinement is broken.
    """
    os.makedirs(DATA_ROOT, exist_ok=True)
    made = []
    keys = {}
    _record_symlink(keys, made, "dir_to_etc", "evil_etc", "/etc", "/passwd")
    _record_symlink(keys, made, "file_to_passwd", "evil_passwd", "/etc/passwd")
    _record_symlink(keys, made, "to_root", "evil_root", "/", "/etc/passwd")
    _record_symlink(keys, made, "relative", "evil_rel", "../../../../etc", "/passwd")
    _record_symlink_chain(keys, made)
    _record_symlink(keys, made, "loop", "evil_loop", "evil_loop")
    _record_symlink(keys, made, "proc_environ", "evil_proc", "/proc/self/environ")
    _record_symlink(
        keys, made, "proc_root", "evil_procroot", "/proc/self/root", "/etc/passwd"
    )

    # NOTE on in-root symlinks: the module's confined open path uses
    # openat2(RESOLVE_BENEATH) / O_NOFOLLOW, which refuses to follow ANY symlink
    # final component — even one whose target stays inside the root.  That is a
    # deliberate, strong posture (no symlink following at all), so we do not
    # assert that in-root symlinks resolve; the security contract this suite
    # enforces is only that NO symlink can ESCAPE the export root.

    if not keys:
        pytest.skip("could not plant any symlinks under the export root")

    yield keys
    _remove_paths(made)


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


def _assert_webdav_reads_confined(port, tls):
    for path in TRAVERSAL_HTTP_ENCODED:
        status, data = _raw(port, "GET", path, tls=tls)
        assert HOST_SECRET not in data, (
            f"GET {path} leaked host content ({status})"
        )


def _assert_webdav_creates_confined(port, tls):
    name = f"evildav_{uuid.uuid4().hex}"
    for path in (f"/../{name}", f"/%2e%2e/{name}", f"/foo/%2e%2e/%2e%2e/{name}"):
        try:
            _raw(port, "PUT", path, tls=tls, body=b"pwn")
            _raw(port, "MKCOL", path, tls=tls)
        except OSError:
            pass
    _assert_nothing_escaped(name)


def _assert_webdav_delete_confined(port, tls):
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


def _try_webdav_move(port, tls, source, method, header):
    try:
        _raw(
            port, method, source, tls=tls,
            headers={"Destination": header},
        )
    except OSError:
        pass


def _send_webdav_moves(port, tls, source, escaped):
    scheme = "https" if tls else "http"
    for method in ("MOVE", "COPY"):
        for destination in (f"/../{escaped}", f"/%2e%2e/{escaped}"):
            targets = (
                destination,
                f"{scheme}://{SERVER_HOST}:{port}{destination}",
            )
            for header in targets:
                _try_webdav_move(port, tls, source, method, header)


def _assert_webdav_moves_confined(port, tls):
    src = f"/movesrc_{uuid.uuid4().hex}"
    _raw(port, "PUT", src, tls=tls, body=b"src-bytes")
    esc = f"escaped_{uuid.uuid4().hex}"
    _send_webdav_moves(port, tls, src, esc)
    _assert_nothing_escaped(esc)
    status, _ = _raw(port, "GET", src, tls=tls)
    assert status in (200, 206), (
        f"MOVE with an escaping Destination lost the source ({status})"
    )


def _webdav_evil_suite(port, tls):
    """Run the full WebDAV path-confinement battery against one endpoint."""
    _assert_webdav_reads_confined(port, tls)
    _assert_webdav_creates_confined(port, tls)
    _assert_webdav_delete_confined(port, tls)
    _assert_webdav_moves_confined(port, tls)


def _webdav_symlink_suite(port, tls, evil_symlinks):
    for key, probe in evil_symlinks.items():
        st, data = _raw(port, "GET", "/" + probe, tls=tls)
        assert HOST_SECRET not in data, \
            f"WebDAV GET via symlink {key} ({probe}) leaked host content (st={st})"
        assert st in (403, 404), \
            f"WebDAV GET via symlink {key} should be 403/404, got {st}"


@pytest.mark.skipif(not _port_up(NGINX_HTTP_WEBDAV_PORT),
                    reason="http WebDAV (8080) not reachable")

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


from split_continuation import load as _load_continuation

_load_continuation(globals(), __file__, "_test_evil_paths_helpers_writes.py")


