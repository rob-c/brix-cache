"""
test_audit15f_host_auth_crosses.py — `brix_auth host` under the roles a real
site actually gives a trusted node (audit §B1.9,
testsuite-combinatorial-coverage-audit 2026-08-15: "host auth × anything —
`brix_auth host` pairs only with authdb; host auth × {tls, cache, stage, tpc,
cms} are all zero.  Host-based trust plus TLS (the classic 'verify the
reverse-DNS matches the cert' interaction) is untested").

Host auth is socket trust: the client asserts nothing, and the identity is the
peer's reverse-DNS name matched against `brix_host_allow` (auth.c:
brix_acc_resolve_peer → brix_host_allowed, empty allowlist = deny all).  So the
question each cross asks is whether some OTHER subsystem's plumbing can carry a
session past that allowlist — a TLS tunnel, a cache fill, a staged upload, a
TPC pull, or mesh membership.

One instance (nginx_audit15f_hostx.conf) carries every plane behind the SAME
allowlist, plus an out-of-process CMS manager so the mesh join is a real login.
Every drive is raw wire: handshake → kXR_protocol → kXR_login → kXR_auth with
credtype "host" (payload "host\\0"+hostname, sec_host.c:50), because the point
is what the SERVER decides, not what a client library is willing to send.

Cases:
  * success        — host auth completes inside a genuine in-protocol TLS
                     upgrade and the session reads
  * security-neg   — the same TLS session from a peer outside the allowlist is
                     refused kXR_NotAuthorized, and its reads stay refused
  * security-neg   — a TLS session that never sends kXR_auth is gated out (the
                     dispatcher gates on auth_done, not on logged_in)
  * success        — a host-authenticated read through a cache tier fills the
                     spool from the http origin
  * security-neg   — an unauthenticated peer cannot drive that fill
  * success        — a host-authenticated write through the whole-object staged
                     writer commits to the origin and drains the spool
  * security-neg   — an unauthenticated write is refused before it stages
  * success        — a host-authenticated client drives a native TPC pull into
                     a host-auth destination
  * error/pin      — the destination's own pull leg cannot satisfy a host-auth
                     SOURCE (it speaks only ztn/gsi), so that pull fails closed
  * success        — a mesh member registers with the manager while still
                     gating its data plane on the allowlist
"""

import os
import re
import socket
import ssl
import struct
import time

import pytest

from _test_audit15f_helpers import mint_localhost_cert
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import (KXR_OK, _xrd_open, _xrd_read,
                                    _xrd_recv_status)

def _guard_hostx_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _guard_hostx_2(loopback):
    if not loopback:
        pytest.skip("the loopback address has no reverse-DNS name on this host")


pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15f-hostx")]

KXR_ERROR = 4003
kXR_NotAuthorized = 3010
kXR_auth, kXR_open, kXR_write, kXR_close = 3000, 3010, 3019, 3003
# The staged-writer open (proven combination from nginx_audit15e_uring_tiers):
# kXR_open_updt | kXR_new | kXR_delete.
STAGE_FLAGS = 0x0020 | 0x0008 | 0x0002
# The TPC destination open: kXR_new | kXR_open_wrto | kXR_mkpath.
TPC_FLAGS = 0x0008 | 0x4000 | 0x0100

SEED = b"audit15f-host-auth-tpc-source\n" * 8
TLS_BYTES = b"audit15f-bytes-behind-the-tls-plane\n" * 4
CMS_BYTES = b"audit15f-bytes-on-the-mesh-member\n" * 4
ORIGIN_BYTES = b"audit15f-origin-object\n" * 16
STAGED = b"audit15f-staged-upload-payload\n" * 32

REGISTERED = re.compile(r"CMS registered with (\S+) after (\d+) ms")


# --------------------------------------------------------------------------- #
# raw wire: handshake / login / kXR_auth("host") / file ops
# --------------------------------------------------------------------------- #

def _drain(s):
    hdr = s.recv(8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = b""
    while len(body) < dlen:
        body += s.recv(dlen - len(body))
    return status, body


def _send_initial(s):
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.recv(16)


def _send_protocol(s):
    """kXR_protocol advertising kXR_ableTLS (body[4]=0x02) — a brix_tls
    listener answers kXR_gotoTLS and switches to a server-side handshake."""
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520,
                          0x02, 0x03, 0))
    _drain(s)


def _send_login(s):
    """Anonymous kXR_login; returns the reply body (sessid + "&P=..." parms)."""
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    _status, body = _drain(s)
    return body


def _login(port, *, tls=False):
    """Log in on `port`; returns (socket, login parms).  With tls=True the
    genuine in-protocol upgrade runs first, so kXR_login and everything after
    it travel inside the tunnel exactly as a roots:// client leaves them."""
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(30)
    raw.connect((HOST, port))
    _send_initial(raw)
    _send_protocol(raw)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname=HOST)
    else:
        s = raw
    return s, _send_login(s)


def _auth_host(s, cred=None):
    """kXR_auth with the 4-byte credtype "host"; the payload merely tags the
    protocol ("host\\0" + the client's own hostname, which the server ignores
    in favour of the socket's reverse-DNS)."""
    if cred is None:
        cred = b"host\x00" + socket.gethostname().encode()
    s.sendall(struct.pack(">BBH", 0, 1, kXR_auth) + b"\x00" * 12 + b"host"
              + struct.pack(">I", len(cred)) + cred)
    return _xrd_recv_status(s)


def _session(port, *, tls=False, auth=True):
    """A logged-in (and by default host-authenticated) session."""
    s, parms = _login(port, tls=tls)
    if auth:
        status, body = _auth_host(s)
        assert status == KXR_OK, ("host auth refused", status, body, parms)
    return s


def _open_frame(s, path, flags, mode=0o644):
    payload = path.encode()
    s.sendall(struct.pack(">BBH", 0, 1, kXR_open)
              + struct.pack(">HH12s", mode, flags, b"\x00" * 12)
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _write_frame(s, fhandle, offset, payload):
    s.sendall(struct.pack(">BBH4sqiI", 0, 1, kXR_write, fhandle, offset, 0,
                          len(payload)) + payload)
    return _xrd_recv_status(s)


def _close_frame(s, fhandle):
    s.sendall(struct.pack(">BBH4s12sI", 0, 1, kXR_close, fhandle,
                          b"\x00" * 12, 0))
    return _xrd_recv_status(s)


def _read_object(port, path, size, *, tls=False, auth=True):
    s = _session(port, tls=tls, auth=auth)
    try:
        status, body = _xrd_open(s, path)
        if status != KXR_OK:
            return status, body
        return _xrd_read(s, body[:4], 0, size)
    finally:
        s.close()


def _errcode(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _loopback_name():
    """The name the SERVER will see: brix_acc_resolve_peer() reverse-resolves
    the peer socket with getnameinfo, so resolve it the same way here."""
    try:
        return socket.getnameinfo((HOST, 0), socket.NI_NAMEREQD)[0]
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# fixture
# --------------------------------------------------------------------------- #

@pytest.fixture()
def hostx(lifecycle, tmp_path):
    _guard_hostx_1()
    loopback = _loopback_name()
    _guard_hostx_2(loopback)

    cert, key = mint_localhost_cert(tmp_path, stem="hostx-listener")

    roots = {name: tmp_path / name for name in
             ("tls", "deny", "origin", "cache", "spool", "src", "tpc", "cms")}
    export = tmp_path / "export"
    for path in (*roots.values(), export / "cf", export / "st"):
        path.mkdir(parents=True)
    (roots["tls"] / "tls.bin").write_bytes(TLS_BYTES)
    (roots["deny"] / "tls.bin").write_bytes(TLS_BYTES)
    (roots["cms"] / "cms.bin").write_bytes(CMS_BYTES)
    (roots["origin"] / "obj.bin").write_bytes(ORIGIN_BYTES)
    (roots["src"] / "src.bin").write_bytes(SEED)
    # The master may run as root while the worker drops privilege, and every
    # export still needs its checkpoint-recovery lock created.
    for path in (tmp_path, export, export / "cf", export / "st",
                 *roots.values()):
        os.chmod(path, 0o777)

    mgr = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-hostmgr",
        template="nginx_cms_state_server.conf",
        protocol="root",
        readiness="tcp",
        reason="audit-15f cms manager for the host-auth mesh member"))

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-hostx",
        template="nginx_audit15f_hostx.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(roots["tls"]),
        template_values={
            "BIND_HOST": BIND_HOST,
            # The reverse-DNS names brix_host_allow matches the peer against.
            "ALLOWLIST": f"{loopback} localhost localhost.localdomain",  # net-literal-allow: allowlist payload under test
            "DENYLIST": "not-this-host.invalid .nope.example",
            "MANAGER_PORT": str(mgr.port),
            "CERT": str(cert),
            "KEY": str(key),
            "TLS_ROOT": str(roots["tls"]),
            "DENY_ROOT": str(roots["deny"]),
            "ORIGIN_ROOT": str(roots["origin"]),
            "EXPORT_ROOT": str(export),
            "CACHE_ROOT": str(roots["cache"]),
            "SPOOL_DIR": str(roots["spool"]),
            "SRC_ROOT": str(roots["src"]),
            "TPC_ROOT": str(roots["tpc"]),
            "CMS_ROOT": str(roots["cms"])},
        reason="audit-15f host auth x {tls, cache, stage, tpc, cms}"))
    return ep, roots


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _spooled(root):
    return [p for p in root.rglob("*") if p.is_file()]


# --------------------------------------------------------------------------- #
# host auth x TLS
# --------------------------------------------------------------------------- #

def test_host_auth_completes_inside_the_tls_tunnel(hostx):
    ep, _roots = hostx
    s, parms = _login(ep.port, tls=True)
    try:
        assert b"&P=host" in parms, \
            ("the TLS listener did not advertise host auth", parms)
        status, body = _auth_host(s)
        assert status == KXR_OK, ("host auth inside TLS was refused", status,
                                  body, _errlog(ep))
        status, body = _xrd_open(s, "/tls.bin")
        assert status == KXR_OK, (status, body)
        status, data = _xrd_read(s, body[:4], 0, len(TLS_BYTES))
        assert status == KXR_OK, (status, data)
        assert data == TLS_BYTES
    finally:
        s.close()


def test_tls_alone_confers_no_host_trust(hostx):
    """Security-negative: the SAME certificate, the same tunnel, the same
    loopback peer — but an allowlist that does not name it.  TLS establishes
    the channel; it must not establish the identity."""
    ep, roots = hostx
    deny_port = ep.extra_ports["DENY_PORT"]
    s, _parms = _login(deny_port, tls=True)
    try:
        status, body = _auth_host(s)
        assert status == KXR_ERROR, \
            ("a peer outside brix_host_allow authenticated over TLS", status,
             body)
        assert _errcode(body) == kXR_NotAuthorized, _errcode(body)
        # ... and the refused session cannot read afterwards either.
        status, body = _xrd_open(s, "/tls.bin")
        assert status != KXR_OK, "the denied session still opened a file"
    finally:
        s.close()
    assert (roots["deny"] / "tls.bin").read_bytes() == TLS_BYTES
    assert "host auth denied" in _errlog(ep), \
        "the denial was not logged with the resolved peer name"


def test_tls_session_without_kxr_auth_is_gated_out(hostx):
    """Security-negative: logging in is not authenticating.  The dispatcher
    gates on auth_done (dispatch.c:83), so a tunnel that skips kXR_auth is
    refused every data op even though its login succeeded."""
    status, body = _read_object(hostx[0].port, "/tls.bin", len(TLS_BYTES),
                                tls=True, auth=False)
    assert status != KXR_OK, \
        ("a session that never sent kXR_auth read a file", status, body)
    assert body != TLS_BYTES


# --------------------------------------------------------------------------- #
# host auth x cache tier
# --------------------------------------------------------------------------- #

def test_host_auth_gates_a_cache_tier_fill(hostx):
    ep, roots = hostx
    port = ep.extra_ports["CACHE_PORT"]
    status, data = _read_object(port, "/obj.bin", len(ORIGIN_BYTES))
    assert status == KXR_OK, (status, data, _errlog(ep))
    assert data == ORIGIN_BYTES, "the cache tier served different bytes"
    assert _spooled(roots["cache"]), \
        "the read-through returned bytes but nothing landed in the spool"


def test_unauthenticated_peer_cannot_drive_a_cache_fill(hostx):
    """Security-negative: the fill is the interesting half.  A refused open
    must not have reached the origin on the caller's behalf, so the spool must
    be untouched — otherwise an anonymous peer could warm (and size) the tier
    of a server that never authenticated it."""
    ep, roots = hostx
    port = ep.extra_ports["CACHE_PORT"]
    before = {p.name for p in _spooled(roots["cache"])}
    status, body = _read_object(port, "/never-cached.bin", 64, auth=False)
    assert status != KXR_OK, ("an unauthenticated peer read through the cache "
                              "tier", status, body)
    assert {p.name for p in _spooled(roots["cache"])} == before, \
        "the refused read still populated the cache spool"


# --------------------------------------------------------------------------- #
# host auth x whole-object staged writer
# --------------------------------------------------------------------------- #

def test_host_auth_gates_the_staged_writer(hostx):
    ep, roots = hostx
    port = ep.extra_ports["STAGE_PORT"]
    s = _session(port)
    try:
        status, body = _open_frame(s, "/staged.bin", STAGE_FLAGS)
        assert status == KXR_OK, ("staged write open refused", status, body,
                                  _errlog(ep))
        fhandle = body[:4]
        status, body = _write_frame(s, fhandle, 0, STAGED)
        assert status == KXR_OK, (status, body)
        status, body = _close_frame(s, fhandle)
        assert status == KXR_OK, (status, body)
    finally:
        s.close()
    assert (roots["origin"] / "staged.bin").read_bytes() == STAGED, \
        "the staged close did not commit the whole object to the origin"
    assert not _spooled(roots["spool"]), \
        "the staged writer left its spool copy behind after the commit"


def test_unauthenticated_write_never_stages(hostx):
    """Security-negative: refuse at the open, before a single byte is spooled
    — a staged writer that accepted the open would have an anonymous peer's
    bytes on local disk regardless of what the close decided."""
    ep, roots = hostx
    port = ep.extra_ports["STAGE_PORT"]
    s = _session(port, auth=False)
    try:
        status, body = _open_frame(s, "/intruder.bin", STAGE_FLAGS)
        assert status != KXR_OK, \
            ("the staged writer accepted an unauthenticated write open",
             status, body)
    finally:
        s.close()
    assert not (roots["origin"] / "intruder.bin").exists()
    assert not _spooled(roots["spool"]), \
        "the refused write open still spooled something locally"


# --------------------------------------------------------------------------- #
# host auth x native TPC
# --------------------------------------------------------------------------- #

def _arm(port, key, *, auth):
    """Client leg 1 of the native rendezvous: a read-open carrying tpc.key +
    tpc.dst registers the key on the source.  The socket must outlive the
    pull, so it is returned rather than closed."""
    s = _session(port, auth=auth)
    status, body = _xrd_open(
        s, f"/src.bin?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    assert status == KXR_OK, ("TPC source arm refused", status, body)
    return s


def _pull(ep, src_port, dest, key, *, arm_auth):
    armed = _arm(src_port, key, auth=arm_auth)
    s = _session(ep.extra_ports["TPC_PORT"])
    s.settimeout(30)
    try:
        opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}"
                  f"&tpc.lfn=/src.bin&tpc.stage=copy&oss.asize={len(SEED)}")
        status, body = _open_frame(s, dest + opaque, TPC_FLAGS)
        if status != KXR_OK:
            return status, body
        return _drive_pull(s, body[:4])
    finally:
        s.close()
        armed.close()


def _wait_bytes(path, want, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.read_bytes() == want:
            return True
        time.sleep(0.2)
    return False


def test_host_authenticated_client_drives_a_native_tpc_pull(hostx):
    """The client leg is host-authenticated on the destination; the pull leg
    is the server's own outbound session to an anonymous source."""
    ep, roots = hostx
    status, body = _pull(ep, ep.extra_ports["SRC_PORT"], "/pulled.bin",
                         "a15f-host-pull", arm_auth=False)
    assert status == KXR_OK, ("the pull into the host-auth destination failed",
                              status, body, _errlog(ep))
    assert _wait_bytes(roots["tpc"] / "pulled.bin", SEED), \
        "the pull reported ok but the destination export never matched"


def test_pull_leg_cannot_satisfy_a_host_auth_source(hostx):
    """Error case, and a DEFECT-CANDIDATE PIN.  A host-auth source would trust
    the destination by its socket — that is the whole premise of host auth —
    but the outbound leg only knows ztn and gsi
    (tpc/gsi/gsi_outbound_finish.c), so a "&P=host" source leaves it nothing to
    send and the pull fails closed.  Fail-closed is the right direction, so
    this pins the behaviour rather than the wish; invert it if the outbound
    leg learns host.  The arm proves the source's CLIENT plane is healthy:
    only the server-to-server leg cannot get in."""
    ep, roots = hostx
    status, body = _pull(ep, ep.extra_ports["SRCHOST_PORT"], "/hostsrc.bin",
                         "a15f-host-src", arm_auth=True)
    assert status != KXR_OK, \
        ("the outbound pull leg authenticated to a host-auth source — did it "
         "learn the protocol?  invert this pin", status, body)
    assert not (roots["tpc"] / "hostsrc.bin").exists() \
        or (roots["tpc"] / "hostsrc.bin").read_bytes() != SEED, \
        "the failed pull still left the source payload in the destination"


# --------------------------------------------------------------------------- #
# host auth x cms
# --------------------------------------------------------------------------- #

def _wait_registration(ep, timeout=15.0):
    deadline = time.time() + timeout
    seen = []
    while time.time() < deadline:
        seen = REGISTERED.findall(_errlog(ep))
        if seen:
            return seen
        time.sleep(0.05)
    return seen


def test_mesh_member_joins_while_gating_on_host_auth(hostx):
    ep, _roots = hostx
    seen = _wait_registration(ep)
    assert seen, ("the host-auth mesh member never registered with the "
                  "manager\n" + _errlog(ep)[-4000:])
    port = ep.extra_ports["CMS_PORT"]
    status, data = _read_object(port, "/cms.bin", len(CMS_BYTES))
    assert status == KXR_OK, (status, data, _errlog(ep))
    assert data == CMS_BYTES
    # Security-negative on the same plane: membership is not authentication.
    status, body = _read_object(port, "/cms.bin", len(CMS_BYTES), auth=False)
    assert status != KXR_OK, \
        ("mesh membership let an unauthenticated peer read the member's data",
         status, body)
    assert REGISTERED.findall(_errlog(ep)), \
        "the refused read cost the member its registration"
