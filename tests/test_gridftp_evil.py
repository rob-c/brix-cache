"""
GridFTP gateway — control-channel evil-actor lane (phase-82 P82.5).

Complements the MODE E offset corpus (``test_gridftp_mode_e.py``) with the
*control-channel* resource/robustness guards: an over-long command line, passive
listener reclaim under repetition (port-exhaustion defence), and a REST offset
past end-of-file.  All drive the cleartext gateway (``nginx_gridftp_plain.conf``)
— the security layer only frames the same reply bytes, so the command semantics
are identical GSS-wrapped or not.

Notes on this gateway's architecture (matters for what is and isn't testable):
  * Transfers run to completion *inline* (synchronous POC), so there is no
    in-flight transfer for ABOR to interrupt — the plan's "ABOR race" is not a
    live vector here; ABOR simply drops a dangling passive listener (226).
  * Each PASV/EPSV closes the previous listener fd before opening a new one
    (``ftp_do_pasv``), so repeated PASV cannot leak descriptors.
  * A REST offset past EOF clamps the read start to 0 (``ftp_retr_file``) rather
    than reading out of bounds — safe, if surprising (the whole file re-sends).

Covered:
  * an over-long command line (> the 128 KiB read buffer) is refused, not
    overflowed or hung                                    (security-negative)
  * 200 back-to-back PASV commands stay healthy — no fd leak (resource guard)
  * REST past EOF clamps safely and never reads OOB        (edge / safety)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_evil.py -v -p no:xdist
"""

import ftplib
import os
import socket

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

# The control read buffer is FTP_CMD_MAX (128 KiB); a line that never yields a
# newline before the buffer fills is rejected as "line too long".
CTRL_BUF = 128 * 1024


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


class _Gateway:
    """A registry-owned cleartext FTP gateway, torn down on close()."""

    def __init__(self, harness, name):
        endpoint = harness.start(NginxInstanceSpec(
            name=name,
            template="nginx_gridftp_plain.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST},
        ))
        self.harness = harness
        self.port = endpoint.port
        self.export = endpoint.data_root

    def close(self):
        self.harness.close()


@pytest.fixture(scope="module")
def gateway():
    _require()
    gw = _Gateway(LifecycleHarness(), "gridftp-evil")
    yield gw
    gw.close()


def _connect(gw):
    ftp = ftplib.FTP()
    ftp.connect("localhost", gw.port, timeout=30)
    ftp.login()
    return ftp


def _recv_reply(sock):
    """Read one FTP reply line and return its 3-digit code as int."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(256)
        if chunk == b"":
            return None
        buf += chunk
    return int(buf[:3])


def test_file_verb_before_login_rejected(gateway):
    """File/namespace verbs are refused with 530 until the client logs in.

    Security-negative for the pre-auth gate: a raw client that skips USER/PASS
    and jumps straight to RETR/LIST/STOR must be told to log in first, and only
    after a successful login does the same verb reach the filesystem (proven by
    the reply changing from 530 to 550 for a missing file)."""
    with open(os.path.join(gateway.export, "gated.bin"), "wb") as fh:
        fh.write(b"secret")
    raw = socket.create_connection(("localhost", gateway.port), timeout=30)
    try:
        raw.settimeout(30)
        assert raw.recv(256).startswith(b"220"), "expected 220 greeting"

        # Pre-login: every data/namespace verb is gated.
        for cmd in (b"RETR gated.bin\r\n", b"LIST\r\n", b"MDTM gated.bin\r\n"):
            raw.sendall(cmd)
            assert _recv_reply(raw) == 530, f"{cmd!r} must be gated pre-login"

        # Log in, then the same verb reaches the namespace (missing file → 550,
        # NOT 530 — proving the gate opened rather than the file being absent).
        raw.sendall(b"USER anonymous\r\n")
        assert _recv_reply(raw) == 331
        raw.sendall(b"PASS x\r\n")
        assert _recv_reply(raw) == 230
        raw.sendall(b"MDTM gated.bin\r\n")
        assert _recv_reply(raw) == 213, "post-login MDTM should succeed"
        raw.sendall(b"MDTM does-not-exist.bin\r\n")
        assert _recv_reply(raw) == 550, "post-login gate is open (550, not 530)"
    finally:
        raw.close()


def test_preauth_command_flood(gateway):
    """A burst of namespace/transfer verbs before login is each refused 530, and
    the gate still opens on a subsequent login.

    Where test_file_verb_before_login_rejected proves the gate exists for a
    handful of verbs, this drives it under repetition (the plan's "pre-auth
    flood"): 300 gated commands must each be rejected without the session
    wedging or leaking state, and a real login afterwards must still succeed —
    proving the rejections did not corrupt the pre-auth state machine."""
    raw = socket.create_connection(("localhost", gateway.port), timeout=30)
    try:
        raw.settimeout(30)
        assert raw.recv(256).startswith(b"220"), "expected 220 greeting"
        for i in range(300):
            raw.sendall(b"RETR flood.bin\r\n")
            assert _recv_reply(raw) == 530, f"pre-login verb #{i} must be gated"
        # The gate opens on a real login afterwards (missing file → 550, proving
        # the verb now reaches the namespace rather than the 530 pre-auth wall).
        raw.sendall(b"USER anonymous\r\n")
        assert _recv_reply(raw) == 331
        raw.sendall(b"PASS x\r\n")
        assert _recv_reply(raw) == 230
        raw.sendall(b"MDTM does-not-exist.bin\r\n")
        assert _recv_reply(raw) == 550, "gate opened after login (550, not 530)"
    finally:
        raw.close()


def test_oversize_command_line_refused(gateway):
    """A command line larger than the 128 KiB control buffer is refused without
    overflow or hang: the reader hits its ceiling and drops the connection.

    Driven on a raw socket (ftplib would never emit an unterminated line). The
    server either resets the socket (RST while our send is still in flight) or
    closes it cleanly after reaching the cap — both prove the line was rejected
    rather than buffered unboundedly."""
    raw = socket.create_connection(("localhost", gateway.port), timeout=30)
    try:
        raw.settimeout(30)
        assert raw.recv(256).startswith(b"220"), "expected 220 greeting"
        # 1.5× the buffer, no CRLF: the server can never frame a command.
        blob = b"A" * (CTRL_BUF + CTRL_BUF // 2)
        refused = False
        try:
            raw.sendall(blob)
            # Drain until the peer closes; a well-behaved reject closes promptly.
            while True:
                chunk = raw.recv(4096)
                if chunk == b"":
                    refused = True          # clean EOF after the cap
                    break
        except (BrokenPipeError, ConnectionResetError):
            refused = True                  # RST with our bytes still unread
        assert refused, "oversize line was neither rejected nor closed"
    finally:
        raw.close()


def test_repeated_pasv_no_fd_leak(gateway):
    """200 back-to-back PASV commands on one session stay healthy.

    Each PASV closes the prior listener before opening the next, so descriptors
    cannot accumulate; if they did, the session would eventually answer 425
    (cannot open passive connection) or the control channel would wedge."""
    ftp = _connect(gateway)
    try:
        for _ in range(200):
            assert ftp.sendcmd("PASV").startswith("227")
        # The control channel is still fully responsive afterwards.
        assert ftp.sendcmd("PWD").startswith("257")
    finally:
        ftp.quit()


def test_rest_beyond_eof_is_safe(gateway):
    """A REST offset past EOF clamps to the file start rather than reading OOB.

    Seeds a small file, then RETR with a restart offset far beyond its size.
    The read start clamps to 0 (ftp_retr_file), so the whole object comes back
    — the security property being that no out-of-bounds read or leak occurs."""
    payload = os.urandom(100)
    with open(os.path.join(gateway.export, "tiny.bin"), "wb") as fh:
        fh.write(payload)
    ftp = _connect(gateway)
    try:
        got = []
        ftp.retrbinary("RETR tiny.bin", got.append, rest=1_000_000)
        body = b"".join(got)
        # Clamped-to-start behaviour: the full object, never more, never OOB.
        assert body == payload, f"expected clamped full read, got {len(body)} bytes"
    finally:
        ftp.quit()
