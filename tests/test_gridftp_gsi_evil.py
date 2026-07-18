"""
GridFTP gateway — GSI/GSSAPI pre-auth evil-actor lane (phase-82 P82.5).

The RFC 2228 security handshake (``AUTH GSSAPI`` → ``ADAT`` …) runs in
*cleartext* on the control channel until the final ``235``, so every reject
path in the mem-BIO GSSAPI engine (``gsi_mech.c``) is reachable from a plain
socket with **no globus client and no user proxy** — only the gateway's own
host cert / grid CA.  This lane drives the malformed-handshake corpus the P82.3
exit criteria call for (unknown mechanism, out-of-order security verbs, ADAT
flood / oversize, a bogus handshake token) and pins that each is refused with
the correct RFC 2228 code and never advances the session to an authenticated
state.

Covered (all security-negative, all pre-auth):
  * AUTH with a non-GSSAPI mechanism             → 504  (unknown mechanism)
  * ADAT before AUTH                             → 503  (out of order)
  * a second AUTH while a handshake is live      → 534  (already in progress)
  * ADAT carrying a non-base64 token             → 501  (malformed token)
  * ADAT carrying a well-formed-but-bogus token  → 535  (engine rejects; the
                                                   session stays unauthenticated)
  * MIC (a protected command) before auth        → 503  (no security context)
  * PROT P before the GSI channel is up          → 536  (only Clear available)
  * an oversize ADAT token line (> control buf)  → connection dropped, not
                                                   buffered unboundedly

Requires the brix nginx build + the test PKI (host cert/key + grid CA).  Unlike
``test_gridftp_gsiftp.py`` it needs neither ``globus-url-copy`` nor a user proxy,
because it never completes a handshake — it only exercises the reject paths.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_gridftp_gsi_evil.py -v -p no:xdist
"""

import base64
import os
import socket

import pytest

from settings import BIND_HOST, NGINX_BIN, PKI_DIR
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
CA_DIR = os.path.join(PKI_DIR, "ca")

# The control read buffer is FTP_CMD_MAX (128 KiB); a line that never yields a
# newline before the buffer fills is rejected as "line too long".
CTRL_BUF = 128 * 1024


def _require():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    for p in (SERVER_CERT, SERVER_KEY, CA_DIR):
        if not os.path.exists(p):
            pytest.skip(f"test PKI incomplete: missing {p}")


@pytest.fixture(scope="module")
def gsi_port(tmp_path_factory):
    """A registry-owned GSI-enabled gsiftp gateway (host cert + grid CA), torn
    down on teardown.  Reuses the shared gsiftp template — only the handshake
    reject paths are exercised, so no user proxy is provisioned."""
    _require()
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="gridftp-gsi-evil",
        template="nginx_gridftp_gsiftp.conf",
        protocol="root",
        readiness="tcp",
        template_values={
            "BIND_HOST": BIND_HOST,
            "SERVER_CERT": SERVER_CERT,
            "SERVER_KEY": SERVER_KEY,
            "CA_DIR": CA_DIR,
        },
    ))
    try:
        yield endpoint.port
    finally:
        harness.close()


class _Ctrl:
    """A raw cleartext control connection; consumes the 220 greeting on open."""

    def __init__(self, port):
        self.sock = socket.create_connection(("localhost", port), timeout=30)
        self.sock.settimeout(30)
        self._buf = b""
        assert self._line().startswith("220"), "expected 220 greeting"

    def _line(self):
        while b"\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if chunk == b"":
                raise EOFError("control channel closed")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("latin-1").rstrip("\r")

    def cmd(self, line):
        """Send one command and return the 3-digit reply code."""
        self.sock.sendall(line.encode("latin-1") + b"\r\n")
        return int(self._line()[:3])

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def test_auth_unknown_mechanism_rejected(gsi_port):
    """AUTH naming a mechanism other than GSSAPI is declined 504 — the gateway
    speaks only GSI, so an attacker cannot negotiate a weaker mech."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("AUTH KERBEROS_V4") == 504
    finally:
        c.close()


def test_adat_before_auth_rejected(gsi_port):
    """ADAT with no security context started yet is refused 503 (send AUTH
    first) — no token reaches the engine out of sequence."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("ADAT " + _b64(b"premature")) == 503
    finally:
        c.close()


def test_double_auth_rejected(gsi_port):
    """A second AUTH GSSAPI while a handshake is already live is refused 534,
    rather than silently discarding the in-flight context."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("AUTH GSSAPI") == 334
        assert c.cmd("AUTH GSSAPI") == 534
    finally:
        c.close()


def test_adat_malformed_base64_rejected(gsi_port):
    """An ADAT argument that is not valid base64 is rejected 501 at the decode
    step — malformed input never reaches the TLS engine."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("AUTH GSSAPI") == 334
        assert c.cmd("ADAT @@not-valid-base64@@") == 501
    finally:
        c.close()


def test_adat_bogus_token_rejected(gsi_port):
    """A well-formed base64 token whose bytes are not a valid TLS ClientHello is
    rejected 535 by the mem-BIO engine (SSL_accept fails on the garbage record),
    and the session is left unauthenticated — a following file verb still 530s."""
    # Plain ASCII: the record-layer version field is nonsense, so OpenSSL fails
    # the handshake at the header (SSL_R_WRONG_VERSION_NUMBER) without waiting
    # for more bytes — a deterministic FAILED, not a WANT_READ continue.
    bogus = b"this is definitely not a TLS ClientHello record at all!!!"
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("AUTH GSSAPI") == 334
        assert c.cmd("ADAT " + _b64(bogus)) == 535
        # The failed handshake did not authenticate the session.
        assert c.cmd("RETR anything.bin") == 530
    finally:
        c.close()


def test_protected_command_before_auth_rejected(gsi_port):
    """A protected command (MIC-wrapped) before the security context exists is
    refused 503 — the gateway will not unwrap without an established context."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("MIC " + _b64(b"PWD\r\n")) == 503
    finally:
        c.close()


def test_prot_private_before_gsi_rejected(gsi_port):
    """PROT P before the GSI control channel is up is refused 536 (only Clear is
    available) — a client cannot demand an encrypted data channel it has not
    authenticated to establish."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("PROT P") == 536
    finally:
        c.close()


def test_oversize_adat_line_dropped(gsi_port):
    """An ADAT line larger than the 128 KiB control buffer is refused without
    overflow or unbounded buffering: the reader hits its ceiling and drops the
    connection (an oversize-token flood defence on the handshake path)."""
    c = _Ctrl(gsi_port)
    try:
        assert c.cmd("AUTH GSSAPI") == 334
        blob = b"ADAT " + b"A" * (CTRL_BUF + CTRL_BUF // 2)   # 1.5×, no CRLF
        refused = False
        try:
            c.sock.sendall(blob)
            while True:
                if c.sock.recv(4096) == b"":
                    refused = True          # clean EOF after the cap
                    break
        except (BrokenPipeError, ConnectionResetError):
            refused = True                  # RST with our bytes still unread
        assert refused, "oversize ADAT line neither rejected nor closed"
    finally:
        c.close()
