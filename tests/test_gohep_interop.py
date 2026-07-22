"""go-hep interop regression guards.

Testing the go-hep XRootD client (an independent, stock-protocol, stat-before-open
Go implementation) against this module surfaced three real protocol bugs. These
tests make sure none of them silently reverts. See
docs/10-reference/comparison/gohep-interop-findings.md for the full write-up.

Three tiers, all self-provisioning (no shared fleet, no network):

  1. RAW-WIRE PROTOCOL GUARDS (always run) — a tiny in-process XRootD client speaks
     the wire to locally-started nginx-xrootd servers and asserts:
       * the server does NOT respond to kXR_sigver (bug #1: it was acking a
         request *prefix*, so stock clients read the empty ack as their reply);
       * a static brix_manager_map redirector redirects kXR_stat AND kXR_dirlist
         for CHILD paths (bug #2: only open/locate consulted the map; bug #3: the
         root "/" prefix matched only "/" not "/child").
  2. GO-HEP END-TO-END (skipped without a Go toolchain) — builds xrd-ls/xrd-cp and
     runs them anon, direct + through the mesh, with byte-integrity checks.
  3. SOURCE TRIPWIRES (always run) — fail loudly if any of the three fixes is
     removed from the source, even where no behavioral CI signal exists.

Run:
    PYTHONPATH=tests pytest tests/test_gohep_interop.py -v
"""

import os
import shutil
import socket
import struct
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIND = BIND_HOST

# Wire constants (stable XRootD protocol values).
kXR_dirlist = 3004
kXR_login = 3007
kXR_stat = 3017
kXR_sigver = 3029
kXR_ok = 0
kXR_redirect = 4004
kXR_SHA256_sig = 0x01

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-gohep")]


# --------------------------------------------------------------------------- #
# minimal raw-wire XRootD client
# --------------------------------------------------------------------------- #
def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed mid-response")
        buf += chunk
    return buf


def _read_response(sock):
    """Return (streamid, status, body) for one ServerResponseHeader+body."""
    hdr = _recv_exact(sock, 8)
    sid = hdr[0:2]
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return sid, status, body


def _connect(port):
    s = socket.create_connection((BIND, port), timeout=10)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))   # 20-byte handshake
    _sid, status, _body = _read_response(s)
    assert status == kXR_ok, "handshake rejected"
    return s


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI", streamid, kXR_login,
                      os.getpid() & 0x7fffffff, b"gohep\x00\x00\x00",
                      0, 0, 0, 0, 0)
    sock.sendall(req)
    _sid, status, _body = _read_response(sock)
    assert status == kXR_ok, "anon login rejected"


def _stat(sock, path, streamid=b"\x00\x02"):
    p = path.encode()
    sock.sendall(struct.pack("!2sH16sI", streamid, kXR_stat, b"\x00" * 16, len(p)) + p)


def _dirlist(sock, path, streamid=b"\x00\x03"):
    p = path.encode()
    sock.sendall(struct.pack("!2sH16sI", streamid, kXR_dirlist, b"\x00" * 16, len(p)) + p)


def _sigver(sock, expectrid, seqno=1, streamid=b"\x00\x09"):
    """Send a kXR_sigver frame prefixing the next request (24-byte hdr + 32B mac)."""
    hdr = struct.pack("!2sHHBBQB3sI", streamid, kXR_sigver, expectrid,
                      0, 0, seqno, kXR_SHA256_sig, b"\x00\x00\x00", 32)
    sock.sendall(hdr + b"\x00" * 32)


# --------------------------------------------------------------------------- #
# self-provisioned servers (anon data, static-map redirector → data)
# --------------------------------------------------------------------------- #
@pytest.fixture
def servers(lifecycle, tmp_path_factory):
    base = tmp_path_factory.mktemp("gohep")
    data = base / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hello from nginx-xrootd, go-hep!\n")
    blob = os.urandom(65536)
    (data / "blob.bin").write_bytes(blob)
    (data / "sub").mkdir()  # placeholder child for dirlist redirect

    # The redirector's backing data server; the anon role serves the same files
    # directly. Both share the same posix export dir.
    ds = lifecycle.start(NginxInstanceSpec(
        name="lc-gohep-ds",
        template="nginx_gohep_anon.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        reason="go-hep data server behind the static-map redirector.",
    ))
    anon = lifecycle.start(NginxInstanceSpec(
        name="lc-gohep-anon",
        template="nginx_gohep_anon.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        reason="go-hep anon direct data server (raw-wire sigver guard).",
    ))
    rdr = lifecycle.start(NginxInstanceSpec(
        name="lc-gohep-redirector",
        template="nginx_gohep_redirector.conf",
        protocol="root",
        readiness="tcp",
        template_values={"DATA_PORT": ds.port},
        reason="go-hep static manager_map redirector (child stat/dirlist).",
    ))

    return {"anon": anon.port, "rdr": rdr.port, "ds": ds.port,
            "data": str(data), "blob": blob}


# --------------------------------------------------------------------------- #
# Tier 1 — raw-wire protocol guards
# --------------------------------------------------------------------------- #
def test_sigver_no_ack(servers):
    """Bug #1: the server must NOT respond to kXR_sigver (a request prefix).

    We login anonymously, send a sigver frame, then the stat it signs, and read
    ONE response. If the server (wrongly) acks the sigver, that empty kXR_ok is
    the first thing on the wire and the statinfo parse below sees an empty body —
    exactly the go-hep `statinfo ""` failure.
    """
    s = _connect(servers["anon"])
    try:
        _login(s)
        _sigver(s, expectrid=kXR_stat, seqno=1, streamid=b"\x00\x09")
        _stat(s, "/", streamid=b"\x00\x02")
        _sid, status, body = _read_response(s)
        assert status == kXR_ok, f"stat status {status}, body={body!r}"
        statinfo = body.rstrip(b"\x00").decode("ascii", "replace").strip()
        fields = statinfo.split()
        assert len(fields) >= 4, (
            f"first post-sigver response is not a valid statinfo (got {statinfo!r}); "
            f"the server likely acked kXR_sigver again — bug #1 reverted")
    finally:
        s.close()


def test_static_map_redirects_stat_child(servers):
    """Bugs #2+#3: a static-map redirector must redirect a stat of a CHILD path."""
    s = _connect(servers["rdr"])
    try:
        _login(s)
        _stat(s, "/blob.bin", streamid=b"\x00\x02")
        _sid, status, _body = _read_response(s)
        assert status == kXR_redirect, (
            f"stat /blob.bin through static-map redirector returned {status}, "
            f"expected kXR_redirect ({kXR_redirect}) — stat no longer consults "
            f"manager_map (bug #2) or the root '/' prefix stopped matching "
            f"children (bug #3)")
    finally:
        s.close()


def test_static_map_redirects_dirlist_child(servers):
    """Bug #2: a static-map redirector must redirect a dirlist of a CHILD path."""
    s = _connect(servers["rdr"])
    try:
        _login(s)
        _dirlist(s, "/sub", streamid=b"\x00\x03")
        _sid, status, _body = _read_response(s)
        assert status == kXR_redirect, (
            f"dirlist /sub through static-map redirector returned {status}, "
            f"expected kXR_redirect ({kXR_redirect}) — dirlist no longer consults "
            f"manager_map (bug #2)")
    finally:
        s.close()


def test_static_map_redirects_stat_root(servers):
    """Sanity: the root path itself also redirects (pre-existing behavior)."""
    s = _connect(servers["rdr"])
    try:
        _login(s)
        _stat(s, "/", streamid=b"\x00\x02")
        _sid, status, _body = _read_response(s)
        assert status == kXR_redirect, f"stat / returned {status}"
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# Tier 2 — go-hep end-to-end (gated on a Go toolchain / prebuilt binaries)
# --------------------------------------------------------------------------- #
def _gohep_tool(name):
    """Locate a go-hep CLI tool: $TEST_GOHEP_BIN/<name>, /tmp/gohep-bin/<name>, PATH."""
    for cand in (os.path.join(os.environ.get("TEST_GOHEP_BIN", ""), name)
                 if os.environ.get("TEST_GOHEP_BIN") else None,
                 os.path.join("/tmp/gohep-bin", name),
                 shutil.which(name)):
        if cand and os.path.exists(cand):
            return cand
    return None


@pytest.mark.skipif(_gohep_tool("xrd-ls") is None or _gohep_tool("xrd-cp") is None,
                    reason="go-hep xrd-ls/xrd-cp not available "
                           "(build them or set TEST_GOHEP_BIN)")
def test_gohep_anon_direct(servers, tmp_path):
    """go-hep xrd-ls + xrd-cp anon, direct — exercises the sigver fix end to end."""
    ls, cp = _gohep_tool("xrd-ls"), _gohep_tool("xrd-cp")
    H = f"root://{BIND}:{servers['anon']}"
    r = subprocess.run([ls, "-l", f"{H}/"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"go-hep xrd-ls failed:\n{r.stdout}\n{r.stderr}"
    assert "blob.bin" in r.stdout, r.stdout
    dst = str(tmp_path / "blob.bin")
    r = subprocess.run([cp, f"{H}//blob.bin", dst], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"go-hep xrd-cp failed:\n{r.stdout}\n{r.stderr}"
    with open(dst, "rb") as f:
        assert f.read() == servers["blob"], "go-hep download integrity mismatch"


@pytest.mark.skipif(_gohep_tool("xrd-cp") is None,
                    reason="go-hep xrd-cp not available")
def test_gohep_through_mesh(servers, tmp_path):
    """go-hep xrd-cp through the static-map redirector — exercises bugs #2/#3 e2e."""
    cp = _gohep_tool("xrd-cp")
    R = f"root://{BIND}:{servers['rdr']}"
    dst = str(tmp_path / "mesh_blob.bin")
    r = subprocess.run([cp, f"{R}//blob.bin", dst], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"go-hep mesh xrd-cp failed:\n{r.stdout}\n{r.stderr}"
    with open(dst, "rb") as f:
        assert f.read() == servers["blob"], "go-hep mesh download integrity mismatch"


# --------------------------------------------------------------------------- #
# Tier 3 — source tripwires (always run)
# --------------------------------------------------------------------------- #
def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


def test_sigver_no_ack_tripwire():
    """Bug #1: the server's sigver success path must not send a response, and the
    client must not read one."""
    signing = _read("src/protocols/root/session/signing.c")
    # The function must end by returning NGX_OK (no send_ok) after logging SIGVER.
    tail = signing[signing.rindex('"SIGVER"'):]
    assert "brix_send_ok" not in tail, (
        "server sends a response to kXR_sigver again (bug #1) — stock/go-hep "
        "clients will read the empty ack as the signed request's reply")
    client = _read("client/lib/auth/sigver.c")  # phase-69 client reorg: flat lib/ -> lib/auth/
    assert "acks the sigver" not in client and "brix_recv(c, sid" not in client, (
        "client reads a kXR_sigver ack again (bug #1) — it will consume the "
        "covered request's response")


def test_static_map_redirect_tripwire():
    """Bug #2: stat and dirlist must consult the static manager_map."""
    assert "brix_find_manager_map" in _read("src/protocols/root/read/stat.c"), (
        "stat no longer consults the static manager_map (bug #2)")
    assert "brix_find_manager_map" in _read("src/protocols/root/dirlist/handler.c"), (
        "dirlist no longer consults the static manager_map (bug #2)")


def test_root_prefix_match_tripwire():
    """Bug #3: the prefix matcher must treat a trailing-'/' prefix as boundary-
    aligned, so the root '/' (and any '/dir/') matches everything beneath it."""
    fr = _read("src/auth/authz/find_rule.c")
    assert "prefix[prefix_len - 1] == '/'" in fr, (
        "brix_path_prefix_match no longer special-cases a trailing-'/' prefix "
        "(bug #3) — a root-level manager_map/VO/authdb/group rule will match only "
        "'/' and not its children")
