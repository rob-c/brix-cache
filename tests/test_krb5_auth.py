"""test_krb5_auth.py — Kerberos 5 (krb5) authentication for the root:// stream tier.

Exercises the nginx-xrootd krb5 acceptor (``src/auth/krb5/auth.c``) end to end against
the dedicated krb5 server tier provisioned by ``kdc_helpers.py`` (a throwaway MIT
KDC + service keytab + client ticket under TEST_ROOT/krb5).

The mandated three-cases-per-change shape:
  * success  — a kinit'd client authenticates and can stat/read.
  * error    — the same client with NO ticket is denied.
  * security — a malformed ``krb5`` credential on the wire is rejected
               (kXR_error), never silently accepted.

Every test takes the session-scoped ``requires_krb5`` fixture, which skips cleanly
unless the tier is actually up (krb5-server installed + an nginx binary built with
Kerberos).  Success/error use the system ``xrdfs``/``xrdcp`` client (it loads
``libXrdSeckrb5`` and does the AP-REQ exchange for us, driven by ``XrdSecPROTOCOL``
+ ``KRB5CCNAME``); the security-negative speaks the raw wire so it needs no ticket.
"""

import os
import socket
import struct
import subprocess

from settings import (
    KRB5_CCACHE,
    KRB5_CONF,
    NGINX_KRB5_PORT,
    SERVER_HOST,
)

KRB5_URL = f"root://{SERVER_HOST}:{NGINX_KRB5_PORT}"
TEST_FILE = "/test.txt"
TEST_CONTENT = b"hello from nginx-xrootd\n"  # written by start_dedicated_nginx

# XRootD wire constants (host byte order) — only what the negative test needs.
kXR_auth = 3000
kXR_login = 3007
kXR_protocol = 3006
kXR_ok = 0
kXR_error = 4003


# ---------------------------------------------------------------------------
# Client env (Pattern B: subprocess xrdfs/xrdcp + XrdSecPROTOCOL=krb5)
# ---------------------------------------------------------------------------

def _krb5_env(ccache=KRB5_CCACHE):
    """Environment that drives the XRootD client to use krb5 with a given ccache.

    ``ccache=None`` removes KRB5CCNAME entirely (no ticket at all).  X509 vars are
    stripped so a stray proxy in the ambient environment can't select GSI instead.
    """
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "krb5"
    env["KRB5_CONFIG"] = KRB5_CONF
    if ccache is None:
        env.pop("KRB5CCNAME", None)
    else:
        env["KRB5CCNAME"] = ccache
    env.pop("X509_USER_PROXY", None)
    env.pop("X509_USER_CERT", None)
    env.pop("X509_USER_KEY", None)
    return env


# ---------------------------------------------------------------------------
# Minimal raw-wire helpers for the security-negative (self-contained)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError("socket closed mid-response")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    """Read one XRootD response: 8-byte header + body, return (status, body)."""
    streamid, status, dlen = struct.unpack("!2sHI", _recv_exact(sock, 8))
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _handshake_login(sock):
    """Drive handshake -> kXR_protocol -> kXR_login so the next op is kXR_auth."""
    # 20-byte client hello.
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"handshake failed: status={status}"

    # kXR_protocol with kXR_secreqs so the login reply advertises &P=krb5.
    sock.sendall(struct.pack(
        "!2sH I BB 10s I", b"\x00\x01", kXR_protocol, 39, 0x01, 0x03,
        b"\x00" * 10, 0,
    ))
    status, _ = _read_response(sock)
    assert status == kXR_ok, f"kXR_protocol failed: status={status}"

    # kXR_login (anonymous username; auth happens in the following kXR_auth).
    sock.sendall(struct.pack(
        "!2sH I 8s B B B B I", b"\x00\x02", kXR_login,
        os.getpid() & 0xFFFFFFFF, b"pytest\x00\x00", 0, 0, 5, 0, 0,
    ))
    status, body = _read_response(sock)
    assert status == kXR_ok, f"kXR_login failed: status={status}"


def _send_auth_krb5(sock, cred_payload, streamid=b"\x00\x03"):
    """Send kXR_auth with credtype 'krb5' and an arbitrary (malformed) payload."""
    req = struct.pack("!2sH", streamid, kXR_auth)
    req += b"\x00" * 12          # reserved
    req += b"krb5"               # cred type tag in the request header
    req += struct.pack("!I", len(cred_payload))
    req += cred_payload
    sock.sendall(req)
    return _read_response(sock)


def _krb5_auth_attempt(cred_payload):
    """Full session up to a single malformed kXR_auth; return its status."""
    with socket.create_connection((SERVER_HOST, NGINX_KRB5_PORT), timeout=5) as sock:
        sock.settimeout(5)
        _handshake_login(sock)
        status, _ = _send_auth_krb5(sock, cred_payload)
        return status


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKrb5Auth:
    """root:// Kerberos 5 authentication: success, error, security-negative."""

    def test_authenticated_stat_succeeds(self, requires_krb5):
        """A valid client ticket authenticates and can stat a file."""
        r = subprocess.run(
            ["xrdfs", KRB5_URL, "stat", TEST_FILE],
            env=_krb5_env(), capture_output=True, timeout=30,
        )
        assert r.returncode == 0, f"krb5 stat failed: {r.stderr.decode()}"

    def test_authenticated_read_content(self, requires_krb5):
        """A valid client ticket can read the file's exact bytes."""
        r = subprocess.run(
            ["xrdcp", "-f", f"{KRB5_URL}/{TEST_FILE}", "-"],
            env=_krb5_env(), capture_output=True, timeout=30,
        )
        assert r.returncode == 0, f"krb5 read failed: {r.stderr.decode()}"
        assert r.stdout == TEST_CONTENT, f"unexpected content: {r.stdout!r}"

    def test_no_ticket_is_denied(self, requires_krb5, tmp_path):
        """With no Kerberos ticket the client cannot authenticate (error case)."""
        empty_ccache = str(tmp_path / "no_such_ccache")
        r = subprocess.run(
            ["xrdfs", KRB5_URL, "stat", TEST_FILE],
            env=_krb5_env(ccache=empty_ccache), capture_output=True, timeout=30,
        )
        assert r.returncode != 0, "stat without a Kerberos ticket must be denied"

    def test_malformed_credential_rejected(self, requires_krb5):
        """A too-short / mistagged 'krb5' credential is rejected on the wire.

        Exercises the input-validation guard in src/auth/krb5/auth.c
        (``cur_dlen <= 4 || strncmp(payload,"krb5",4) != 0`` -> kXR_NotAuthorized),
        i.e. the server never treats a malformed blob as authenticated.
        """
        # (a) exactly the 4-byte tag, no AP-REQ body -> cur_dlen <= 4.
        assert _krb5_auth_attempt(b"krb5") == kXR_error, \
            "4-byte 'krb5' credential must be rejected"
        # (b) wrong tag entirely -> strncmp(payload,'krb5',4) != 0.
        assert _krb5_auth_attempt(b"xxxx\x00\x01\x02\x03") == kXR_error, \
            "mistagged credential must be rejected"

    def test_garbage_ticket_rejected(self, requires_krb5):
        """A well-tagged but forged AP-REQ fails ticket verification (kXR_error).

        Passes the tag check so it reaches ``krb5_rd_req``; the garbage bytes can
        never decrypt against the service keytab, so auth is denied — confirming
        the server validates the ticket, not just the framing.
        """
        forged = b"krb5" + bytes(range(64))
        assert _krb5_auth_attempt(forged) == kXR_error, \
            "a forged krb5 AP-REQ must fail verification"
