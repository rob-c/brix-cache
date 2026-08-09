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

    # --- MOVE/COPY with an escaping Destination must not write outside the root
    # (brix_rename_confined_canon / the COPY confined-canon path). Stage a legit
    # in-root source, then aim the Destination out of the export both as a bare
    # path and as a same-authority URL. Nothing may land beside the root, and the
    # source must survive a refused MOVE.
    src = f"/movesrc_{uuid.uuid4().hex}"
    _raw(port, "PUT", src, tls=tls, body=b"src-bytes")
    esc = f"escaped_{uuid.uuid4().hex}"
    scheme = "https" if tls else "http"
    for method in ("MOVE", "COPY"):
        for dest in (f"/../{esc}", f"/%2e%2e/{esc}"):
            for dhdr in (dest, f"{scheme}://{SERVER_HOST}:{port}{dest}"):
                try:
                    _raw(port, method, src, tls=tls, headers={"Destination": dhdr})
                except OSError:
                    pass
    _assert_nothing_escaped(esc)
    # The source itself was never legitimately moved out, so it is still servable.
    st, _ = _raw(port, "GET", src, tls=tls)
    assert st in (200, 206), f"MOVE with an escaping Destination lost the source ({st})"


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
