"""
test_audit15f_sigver_crosses.py — request-signing policy across native TPC and
bound substreams (audit §B1.1 "sigver × TPC (native): the TPC control ops
(tpc.src/tpc.dst opens, sync/close) are exactly the mutating ops signing exists
to protect; no test signs them", and §B1.2 "sigver × substreams:
kXR_bind-attached data paths under brix_signing_required").

Only a GSI session ever arms a signing key (gsi_core.c; session/signing.c
accepts kXR_sigver from anyone else as an unverified no-op), so the reachable —
and operationally interesting — half of these crosses is the POLICY applied to
a session that CANNOT sign.  Two directives compose it:

  * `brix_security_level` picks the covered opcodes — 2/standard is kXR_open
    plus the mutation set, 3/intense is everything post-login, and
    login/protocol/auth/endsess/ping/sigver/**bind** are exempt at every level
    (brix_gsi_sigver_required);
  * `brix_signing_required` decides what happens to a covered opcode on an
    unsignable session: refuse with kXR_NotAuthorized, or accept it unsigned
    and say so once per connection (sigver.c brix_signing_unsignable_session).

Every cross therefore runs on a pair of planes identical but for that flag, so
each assertion isolates the policy rather than the plumbing.

Cases:
  * error        — the tpc.dst open is a kXR_open, so a required-signing
                   destination refuses it and nothing is pulled
  * success      — kXR_stat still answers on that same plane: the gate follows
                   the opcode table, it is not a blanket deny
  * error/pin    — defect candidate #15: kXR_sync (a TPC control op the
                   audit named) is NOT in the level-2 set, so `standard`
                   leaves the arm/start syncs unprotected; only `intense`
                   covers them
  * success      — with the flag off the pull completes UNSIGNED, which is the
                   bypass the audit called out, and the session says so
  * security-neg — a source that demands signing refuses the tpc.src arm, so
                   the rendezvous never forms and the destination stays empty
  * security-neg — kXR_bind is exempt, so a secondary still attaches to a
                   required-signing plane, but every op it sends is refused:
                   the policy is not lost across the bind
  * success      — on the advisory twin the bound secondary reads the primary's
                   handle byte-exact, while a bogus handle fails as a HANDLE
                   error (proving the refusals above came from the signing gate)
  * success      — each connection states its unsignable posture exactly once,
                   however many covered requests it sends
  * security-neg — bind exemption is not session-validation bypass: a forged
                   sessid is still refused on the required-signing plane
"""

import os
import socket
import struct
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from test_audit15c_tpc_token_exchange import _drive_pull, _sync
from test_phase25_ratelimit import (KXR_OK, _xrd_open, _xrd_read,
                                    _xrd_recv_status, _xrd_stat)

def _guard_sigx_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _check_test_each_connection_states_its_unsignable_posture_once_1(status, body):
    assert status == KXR_OK, (status, body)

def _check_test_each_connection_states_its_unsignable_posture_once_3(ep):
    assert _errlog(ep).count(UNSIGNED) == 1, \
        ("five covered requests on one connection did not produce exactly "
         "one posture line\n" + _errlog(ep)[-4000:])

def _check_test_each_connection_states_its_unsignable_posture_once_6(status, body):
    assert status == KXR_OK, (status, body)

def _check_test_each_connection_states_its_unsignable_posture_once_2(status, data):
    assert status == KXR_OK, (status, data)

def _check_test_each_connection_states_its_unsignable_posture_once_5(ep):
    assert _errlog(ep).count(UNSIGNED) == 2, \
        ("the bound secondary did not state its own posture exactly "
         "once\n" + _errlog(ep)[-4000:])

def _check_test_each_connection_states_its_unsignable_posture_once_4(status, data):
    assert status == KXR_OK, (status, data)


pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15f-sigx")]

KXR_ERROR = 4003
kXR_NotAuthorized = 3010
kXR_protocol, kXR_login, kXR_open, kXR_close, kXR_bind = 3006, 3007, 3010, 3003, 3024
# The TPC destination open: kXR_new | kXR_open_wrto | kXR_mkpath.
TPC_FLAGS = 0x0008 | 0x4000 | 0x0100

SEED = b"audit15f-sigver-source-payload\n" * 8
BOUND = b"audit15f-bytes-read-over-a-bound-substream\n" * 4
BOGUS = b"\xde\xad\xbe\xef"

REFUSED = "requests are REFUSED"
UNSIGNED = "requests are accepted UNSIGNED"


# --------------------------------------------------------------------------- #
# raw wire
# --------------------------------------------------------------------------- #

def _connect(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((HOST, port))
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.recv(16)
    return s


def _login(port):
    """Handshake + kXR_protocol + anonymous kXR_login; returns (socket,
    sessid).  All three opcodes are signing-exempt at every level, so this
    succeeds on the required-signing planes too — which is the point."""
    s = _connect(port)
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, kXR_protocol,
                          0x00000520, 0x00, 0x03, 0))
    status, _body = _xrd_recv_status(s)
    assert status == KXR_OK, ("kXR_protocol refused", status)
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, kXR_login, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    status, body = _xrd_recv_status(s)
    assert status == KXR_OK, ("kXR_login refused", status, body)
    assert len(body) >= 16, ("login reply carried no sessid", body)
    return s, body[:16]


def _bind(port, sessid, streamid=b"\x00\x02"):
    """A secondary connection attaching to `sessid`; returns (socket, status,
    body) so the negative cases can inspect the refusal."""
    s = _connect(port)
    s.sendall(streamid + struct.pack(">H", kXR_bind) + sessid.ljust(16, b"\x00")
              + struct.pack(">I", 0))
    status, body = _xrd_recv_status(s)
    return s, status, body


def _read(s, fhandle, offset, rlen, streamid=b"\x00\x02"):
    """kXR_read on an arbitrary stream id — the bound secondary uses its own."""
    body = fhandle[:4] + struct.pack(">q", offset) + struct.pack(">i", rlen)
    s.sendall(streamid + struct.pack(">H", 3013) + body + struct.pack(">I", 0))
    return _xrd_recv_status(s)


def _open_frame(s, path, flags, mode=0o644):
    payload = path.encode()
    s.sendall(struct.pack(">BBH", 0, 1, kXR_open)
              + struct.pack(">HH12s", mode, flags, b"\x00" * 12)
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _close_frame(s, fhandle):
    s.sendall(struct.pack(">BBH4s12sI", 0, 1, kXR_close, fhandle,
                          b"\x00" * 12, 0))
    return _xrd_recv_status(s)


def _errcode(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _refused(status, body):
    return status == KXR_ERROR and _errcode(body) == kXR_NotAuthorized


# --------------------------------------------------------------------------- #
# fixture
# --------------------------------------------------------------------------- #

@pytest.fixture()
def sigx(lifecycle, tmp_path):
    _guard_sigx_1()

    roots = {name: tmp_path / name for name in ("tpc", "lax", "src", "bind")}
    for path in roots.values():
        path.mkdir(parents=True)
    (roots["src"] / "src.bin").write_bytes(SEED)
    (roots["bind"] / "bound.bin").write_bytes(BOUND)
    # kXR_stat needs something to stat on the refusing plane; it is also the
    # witness that the destination export was not written by a refused pull.
    (roots["tpc"] / "probe.bin").write_bytes(b"probe\n")
    # The master may run as root while the worker drops privilege.
    for path in (tmp_path, *roots.values()):
        os.chmod(path, 0o777)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-sigx",
        template="nginx_audit15f_sigver.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(roots["tpc"]),
        template_values={
            "BIND_HOST": BIND_HOST,
            "TPC_ROOT": str(roots["tpc"]),
            "LAX_ROOT": str(roots["lax"]),
            "SRC_ROOT": str(roots["src"]),
            "BIND_ROOT": str(roots["bind"])},
        reason="audit-15f sigver x {native TPC, substreams}"))
    return ep, roots


def _errlog(ep):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _arm(src_port, key):
    """Client leg 1 of the native rendezvous: a read-open carrying tpc.key +
    tpc.dst registers the key on the source.  Returns (socket, status, body);
    the socket must outlive the pull, so it is never closed here."""
    s, _sessid = _login(src_port)
    status, body = _xrd_open(
        s, f"/src.bin?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    return s, status, body


def _dst_open(s, dest, src_port, key):
    opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}"
              f"&tpc.lfn=/src.bin&tpc.stage=copy&oss.asize={len(SEED)}")
    return _open_frame(s, dest + opaque, TPC_FLAGS)


def _wait_bytes(path, want, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.read_bytes() == want:
            return True
        time.sleep(0.2)
    return False


# --------------------------------------------------------------------------- #
# sigver x native TPC
# --------------------------------------------------------------------------- #

def test_tpc_destination_open_is_refused_when_signing_is_required(sigx):
    """The tpc.dst open is a kXR_open, which `standard` covers.  An unsignable
    client therefore cannot even ask for the transfer."""
    ep, roots = sigx
    armed, status, body = _arm(ep.extra_ports["SRC_PORT"], "a15f-sig-refuse")
    assert status == KXR_OK, ("the unpoliced source refused the arm", status,
                              body)
    s, _sessid = _login(ep.port)
    try:
        status, body = _dst_open(s, "/refused.bin",
                                 ep.extra_ports["SRC_PORT"], "a15f-sig-refuse")
        assert _refused(status, body), \
            ("a required-signing destination accepted an unsigned tpc.dst open",
             status, body, _errlog(ep))
    finally:
        s.close()
        armed.close()
    assert not (roots["tpc"] / "refused.bin").exists(), \
        "the refused open still created the destination object"
    assert REFUSED in _errlog(ep), \
        "the session was refused without stating why it could not sign"


def test_the_refusal_is_opcode_scoped_not_a_blanket_deny(sigx):
    """kXR_stat is not in the level-2 set, so it must still answer on the very
    plane that just refused an open — otherwise `standard` would be indis-
    tinguishable from "reject this session", and the pin below meaningless."""
    ep, _roots = sigx
    s, _sessid = _login(ep.port)
    try:
        status, body = _xrd_stat(s, "/probe.bin")
        assert status == KXR_OK, \
            ("kXR_stat was refused although level 2 does not cover it", status,
             body, _errlog(ep))
        status, body = _open_frame(s, "/probe.bin", 0x0010)
        assert _refused(status, body), \
            ("the same session's read-open was not refused", status, body)
    finally:
        s.close()


def test_standard_leaves_the_tpc_control_syncs_unprotected(sigx):
    """DEFECT-CANDIDATE PIN.  The audit named "tpc.src/tpc.dst opens, sync/
    close" as the ops signing exists to protect, but only kXR_open of those is
    in the level-2 table (gsi_core.c brix_gsi_sigver_required): at `standard`
    an unsignable session's kXR_sync reaches the TPC state machine and fails on
    its merits (a handle error), not on the signing policy.  Only `intense`
    covers it — the second half of this test is the contrast.  Pins today's
    behaviour; invert if sync/close join the level-2 set."""
    ep, _roots = sigx
    s, _sessid = _login(ep.port)
    try:
        status, body = _sync(s, BOGUS)
        assert not _refused(status, body), \
            ("kXR_sync is now covered at brix_security_level standard — the "
             "level-2 table changed, update this pin", status, body)
    finally:
        s.close()
    s, _sessid = _login(ep.extra_ports["BIND_PORT"])
    try:
        status, body = _sync(s, BOGUS)
        assert _refused(status, body), \
            ("kXR_sync escaped the signing gate at intense too — nothing "
             "post-login should", status, body, _errlog(ep))
    finally:
        s.close()


def test_unsigned_pull_completes_when_signing_is_only_advisory(sigx):
    """The bypass the audit named, pinned end to end: identical plane, flag
    off, and the whole rendezvous runs on a session that cannot sign a single
    request — while the log records exactly that."""
    ep, roots = sigx
    armed, status, body = _arm(ep.extra_ports["SRC_PORT"], "a15f-sig-lax")
    assert status == KXR_OK, (status, body)
    s, _sessid = _login(ep.extra_ports["LAX_PORT"])
    try:
        status, body = _dst_open(s, "/pulled.bin",
                                 ep.extra_ports["SRC_PORT"], "a15f-sig-lax")
        assert status == KXR_OK, ("the advisory destination refused the open",
                                  status, body, _errlog(ep))
        status, body = _drive_pull(s, body[:4])
        assert status == KXR_OK, ("the unsigned pull failed", status, body,
                                  _errlog(ep))
    finally:
        s.close()
        armed.close()
    assert _wait_bytes(roots["lax"] / "pulled.bin", SEED), \
        "the pull reported ok but the destination export never matched"
    log = _errlog(ep)
    assert UNSIGNED in log, \
        "an unsignable session was served without the operator being told"
    assert REFUSED not in log, ("the advisory plane refused something", log)


def test_source_that_demands_signing_refuses_the_arm(sigx):
    """Security-negative.  The source is the other half of the rendezvous: if
    it enforces signing, the client's tpc.src arm (a kXR_open) never registers
    the key, so no destination can be talked into pulling from it."""
    ep, roots = sigx
    armed, status, body = _arm(ep.extra_ports["SRCSIG_PORT"], "a15f-sig-src")
    try:
        assert _refused(status, body), \
            ("a required-signing source armed an unsigned TPC key", status,
             body, _errlog(ep))
        s, _sessid = _login(ep.extra_ports["LAX_PORT"])
        try:
            status, body = _dst_open(s, "/fromsig.bin",
                                     ep.extra_ports["SRCSIG_PORT"],
                                     "a15f-sig-src")
            if status == KXR_OK:
                status, body = _drive_pull(s, body[:4])
            assert status != KXR_OK, \
                ("a pull completed from a source that never armed the key",
                 status, body)
        finally:
            s.close()
    finally:
        armed.close()
    assert not (roots["lax"] / "fromsig.bin").exists() \
        or (roots["lax"] / "fromsig.bin").read_bytes() != SEED, \
        "the failed pull still left the source payload in the destination"


# --------------------------------------------------------------------------- #
# sigver x substreams
# --------------------------------------------------------------------------- #

def test_bind_attaches_but_the_bound_path_stays_refused(sigx):
    """Security-negative, and the §B1.2 question exactly: kXR_bind is exempt at
    every level, so the substream DOES attach to a required-signing session.
    The policy must survive that attachment — a secondary that inherited the
    session's auth state but not its signing posture would be a free data
    channel into a server configured to refuse one."""
    ep, _roots = sigx
    port = ep.extra_ports["BIND_PORT"]
    primary, sessid = _login(port)
    try:
        status, body = _open_frame(primary, "/bound.bin", 0x0010)
        assert _refused(status, body), \
            ("the primary opened a file on a required-signing plane", status,
             body, _errlog(ep))
        sec, status, body = _bind(port, sessid)
        try:
            assert status == KXR_OK, \
                ("kXR_bind is signing-exempt but was refused", status, body,
                 _errlog(ep))
            assert len(body) == 1 and 1 <= body[0] <= 253, \
                ("bind returned no usable pathid", body)
            status, data = _read(sec, BOGUS, 0, 64)
            assert _refused(status, data), \
                ("a bound secondary escaped the signing policy", status, data)
        finally:
            sec.close()
    finally:
        primary.close()


def test_bound_secondary_reads_the_primary_handle_when_advisory(sigx):
    """Success twin — and the control that proves the refusals above come from
    the signing gate rather than from the handle table: on this plane the SAME
    bogus-handle read fails as a handle error, not kXR_NotAuthorized."""
    ep, _roots = sigx
    port = ep.extra_ports["BINDLAX_PORT"]
    primary, sessid = _login(port)
    try:
        status, body = _xrd_open(primary, "/bound.bin")
        assert status == KXR_OK, ("the advisory plane refused the open", status,
                                  body, _errlog(ep))
        fhandle = body[:4]
        sec, status, body = _bind(port, sessid)
        try:
            assert status == KXR_OK, ("bind refused", status, body)
            status, data = _read(sec, fhandle, 0, len(BOUND))
            assert status == KXR_OK, ("the bound read was refused", status,
                                      data, _errlog(ep))
            assert data == BOUND, "the bound secondary served different bytes"
            status, data = _read(sec, BOGUS, 0, 64)
            assert status != KXR_OK and not _refused(status, data), \
                ("a bogus handle was refused as unauthorized on a plane that "
                 "requires no signing — the gate is misattributed", status,
                 data)
        finally:
            sec.close()
    finally:
        primary.close()


def test_each_connection_states_its_unsignable_posture_once(sigx):
    """The warning is the operator's only evidence that a configured
    `brix_security_level` is not actually protecting anything, so it must be
    both present and readable: once per connection (the condition cannot change
    mid-session), not once per covered request."""
    ep, _roots = sigx
    port = ep.extra_ports["BINDLAX_PORT"]
    primary, sessid = _login(port)
    try:
        status, body = _xrd_open(primary, "/bound.bin")
        _check_test_each_connection_states_its_unsignable_posture_once_1(status, body)
        fhandle = body[:4]
        for _ in range(3):
            status, data = _xrd_read(primary, fhandle, 0, len(BOUND))
            _check_test_each_connection_states_its_unsignable_posture_once_2(status, data)
        _check_test_each_connection_states_its_unsignable_posture_once_3(ep)
        sec, status, body = _bind(port, sessid)
        try:
            def _assert_test_each_connection_states_its_unsignable_posture_once_1():
                assert status == KXR_OK, ("bind refused", status, body)
                # kXR_bind is exempt, so the secondary is still silent here.
                assert _errlog(ep).count(UNSIGNED) == 1, \
                    "kXR_bind logged a posture line although it is exempt"

            _assert_test_each_connection_states_its_unsignable_posture_once_1()
            for _ in range(2):
                status, data = _read(sec, fhandle, 0, len(BOUND))
                _check_test_each_connection_states_its_unsignable_posture_once_4(status, data)
            _check_test_each_connection_states_its_unsignable_posture_once_5(ep)
        finally:
            sec.close()
        status, body = _close_frame(primary, fhandle)
        _check_test_each_connection_states_its_unsignable_posture_once_6(status, body)
    finally:
        primary.close()


def test_bind_exemption_is_not_a_session_validation_bypass(sigx):
    """Security-negative.  kXR_bind skips the signing gate by design; that must
    not become a way onto a required-signing server without a session at all,
    so a forged sessid is still refused and yields no pathid."""
    ep, _roots = sigx
    port = ep.extra_ports["BIND_PORT"]
    sec, status, body = _bind(port, b"\x11" * 16)
    try:
        assert status != KXR_OK, \
            ("a forged sessid bound to the required-signing plane", status,
             body)
        assert len(body) != 1 or not 1 <= body[0] <= 253, \
            ("the refused bind still handed out a pathid", body)
        status, data = _read(sec, BOGUS, 0, 64)
        assert status != KXR_OK, \
            ("the unbound secondary read anyway", status, data)
    finally:
        sec.close()
