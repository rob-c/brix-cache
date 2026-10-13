"""Phase-118 ROOT TLS success, paired-plane and hostname negatives."""
import json
import os
import socket
import ssl
import struct
import subprocess
from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import (
    PgOrigin, error_frame, kXR_auth, kXR_login, kXR_secreqs, ok_frame,
)
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 29 + 3) & 0xFF for index in range(8192))
KXR_HAVE_TLS = 0x80000000
KXR_GOTO_TLS = 0x40000000
SSL_OP_ALLOW_CLIENT_RENEGOTIATION = 1 << 8


def _certificate(tmp_path, san):
    cert = tmp_path / "tls-cert.pem"
    key = tmp_path / "tls-key.pem"
    ca_dir = tmp_path / "ca"
    ca_dir.mkdir()
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", "/CN=brix-conform-fixture",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", f"subjectAltName={san}"],
        check=True, capture_output=True,
    )
    trusted = ca_dir / "fixture.pem"
    trusted.write_bytes(cert.read_bytes())
    subprocess.run(["openssl", "rehash", str(ca_dir)], check=True,
                   capture_output=True)
    return cert, key, ca_dir


class TlsPgOrigin(PgOrigin):
    """The bounded PgOrigin data plane behind an in-protocol TLS upgrade."""

    def __init__(self, payload, cert, key, behaviour="ok"):
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._tls_context.load_cert_chain(cert, key)
        super().__init__(payload, behaviour=behaviour)

    def _flags(self):
        return super()._flags() | KXR_HAVE_TLS | KXR_GOTO_TLS

    def _serve(self, conn):
        conn.settimeout(15)
        try:
            self._exact(conn, 20)
            conn.sendall(struct.pack("!HHI", 0, 0, 8)
                         + struct.pack("!II", 0x00000310, 1))
            header = self._exact(conn, 24)
            sid = header[:2]
            request = struct.unpack("!H", header[2:4])[0]
            length = struct.unpack("!I", header[20:24])[0]
            if length:
                self._exact(conn, length)
            self._dispatch(conn, sid, request, header, False)
            if not (header[8] & kXR_secreqs):
                return
            conn = self._tls_context.wrap_socket(conn, server_side=True)
            authenticated = False
            while not self._closing:
                header = self._exact(conn, 24)
                sid = header[:2]
                request = struct.unpack("!H", header[2:4])[0]
                length = struct.unpack("!I", header[20:24])[0]
                if length:
                    self._exact(conn, length)
                authenticated = self._dispatch(
                    conn, sid, request, header, authenticated)
        except (OSError, ConnectionError, ssl.SSLError, struct.error):
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


class CleartextOverenforcingOrigin(PgOrigin):
    """Advertise no TLS class but refuse data as though TLS were required."""

    def _read(self, conn, sid, hdr, request_args=b""):
        conn.sendall(error_frame(sid, 3028, b"TLS required"))


class BrokenTlsFramingOrigin(TlsPgOrigin):
    """Truncate an encrypted response whose header promises two bytes."""

    def _read(self, conn, sid, hdr, request_args=b""):
        conn.sendall(sid + struct.pack("!HI", 0, 2) + b"x")
        conn.shutdown(socket.SHUT_WR)


class LegacyTlsOrigin(TlsPgOrigin):
    """Accept TLS 1.1 so the assessor must report a floor downgrade."""

    def __init__(self, payload, cert, key):
        super().__init__(payload, cert, key)
        self._tls_context.minimum_version = ssl.TLSVersion.TLSv1
        self._tls_context.maximum_version = ssl.TLSVersion.TLSv1_2
        self._tls_context.set_ciphers("ALL:@SECLEVEL=0")


class RenegotiatingTlsOrigin(TlsPgOrigin):
    """Permit client-initiated TLS-1.2 renegotiation for the hostile case."""

    def __init__(self, payload, cert, key):
        super().__init__(payload, cert, key)
        self._tls_context.maximum_version = ssl.TLSVersion.TLSv1_2
        self._tls_context.options &= ~ssl.OP_NO_RENEGOTIATION
        # Python does not name OpenSSL's server-side opt-in, but its stable
        # SSL_OP bit is required by OpenSSL 3 before a client may renegotiate.
        self._tls_context.options |= SSL_OP_ALLOW_CLIENT_RENEGOTIATION


class ResumingIdentityOrigin(TlsPgOrigin):
    """Resume TLS while incorrectly serving anonymous application requests."""

    def __init__(self, payload, cert, key):
        super().__init__(payload, cert, key)
        self._tls_context.maximum_version = ssl.TLSVersion.TLSv1_2

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_login:
            conn.sendall(ok_frame(sid, b"\x00" * 16 + b"&P=unix"))
            return authenticated
        if reqid == kXR_auth:
            conn.sendall(ok_frame(sid))
            return True
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


def _optional_args(also, noverifyhost):
    arguments = ["--noverifyhost"] if noverifyhost else []

    if also is not None:
        arguments.extend(["--also", f"root://{HOST}:{also.port}//fixture"])
    return arguments


def _run(tmp_path, primary, ca_dir, also=None, noverifyhost=False,
         verify_negative=None):
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / "report"
    target = f"root://{HOST}:{primary.port}//fixture"
    command = [
        str(XRD), "conform", "accept", target,
        "--profile", "tls", "--families", "TLS",
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "10", "--request-limit", "64",
        "--byte-limit", "4194304", "--out", str(output),
    ]
    command.extend(_optional_args(also, noverifyhost))
    if verify_negative is not None:
        command.extend(["--only", verify_negative,
                        "--verify-negative", verify_negative])
    environment = os.environ.copy()
    environment["X509_CERT_DIR"] = str(ca_dir)
    result = subprocess.run(command, text=True, capture_output=True,
                            timeout=15, check=False, env=environment)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_tls_upgrade_certificate_and_data_framing_are_proven(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with TlsPgOrigin(PAYLOAD, cert, key) as origin:
        result, rows = _run(tmp_path, origin, ca_dir)
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("TLS-001", "TLS-004", "TLS-007", "TLS-008"):
        assert rows[clause]["verdict"] == "conformant", rows[clause]
    assert not any(row["reason"] == "probe-not-executed"
                   for row in rows.values() if row["id"].startswith("TLS-"))


def test_paired_cleartext_and_tls_bytes_are_identical(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with TlsPgOrigin(PAYLOAD, cert, key) as secure, PgOrigin(PAYLOAD) as clear:
        result, rows = _run(tmp_path, secure, ca_dir, also=clear)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["TLS-003"]["verdict"] == "conformant"
    assert rows["TLS-005"]["verdict"] == "conformant"


def test_hostname_mismatch_is_a_divergence_even_when_run_relaxes_it(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, "DNS:not-the-target.invalid")
    with TlsPgOrigin(PAYLOAD, cert, key) as origin:
        result, rows = _run(tmp_path, origin, ca_dir, noverifyhost=True,
                            verify_negative="TLS-007")
    assert result.returncode == 1
    assert rows["TLS-007"]["verdict"] == "divergent"
    assert rows["TLS-007"]["reason"] == "certificate-verification-failed"


def test_claimed_upgrade_that_never_handshakes_is_divergent(tmp_path):
    _cert, _key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with PgOrigin(PAYLOAD, behaviour="claim_gototls_broken") as origin:
        result, rows = _run(
            tmp_path, origin, ca_dir, verify_negative="TLS-001",
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-001"]["verdict"] == "divergent"


def test_unadvertised_tls_class_cannot_be_over_enforced(tmp_path):
    _cert, _key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with CleartextOverenforcingOrigin(PAYLOAD) as origin:
        result, rows = _run(
            tmp_path, origin, ca_dir, verify_negative="TLS-003",
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-003"]["verdict"] == "divergent"


def test_encrypted_length_mismatch_is_a_framing_divergence(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with BrokenTlsFramingOrigin(PAYLOAD, cert, key) as origin:
        result, rows = _run(
            tmp_path, origin, ca_dir, verify_negative="TLS-004",
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-004"]["verdict"] == "divergent"


def test_paired_transport_byte_mismatch_is_divergent(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    changed = PAYLOAD[:-1] + bytes([PAYLOAD[-1] ^ 0x80])
    with TlsPgOrigin(PAYLOAD, cert, key) as secure, \
            PgOrigin(changed) as clear:
        result, rows = _run(
            tmp_path, secure, ca_dir, also=clear,
            verify_negative="TLS-005",
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-005"]["verdict"] == "divergent"


def test_legacy_tls11_acceptance_is_a_verified_floor_divergence(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with LegacyTlsOrigin(PAYLOAD, cert, key) as origin:
        result, rows = _run(
            tmp_path, origin, ca_dir, verify_negative="TLS-006",
        )
    if rows["TLS-006"]["verdict"] == "conformant":
        pytest.skip("host OpenSSL policy cannot exercise the TLS 1.1 negative fixture")
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-006"]["verdict"] == "divergent", rows["TLS-006"]
    assert rows["TLS-006"]["reason"] == "legacy-tls-clienthello-accepted"


def test_accepted_tls12_renegotiation_is_a_verified_divergence(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with RenegotiatingTlsOrigin(PAYLOAD, cert, key) as origin:
        result, rows = _run(
            tmp_path, origin, ca_dir, verify_negative="TLS-008",
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-008"]["verdict"] == "divergent", rows["TLS-008"]
    assert rows["TLS-008"]["reason"] == "tls12-renegotiation-accepted"


def test_resumed_tls_session_cannot_restore_application_identity(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with ResumingIdentityOrigin(PAYLOAD, cert, key) as origin:
        result, rows = _run(
            tmp_path, origin, ca_dir, verify_negative="TLS-009",
        )
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["TLS-009"]["verdict"] == "divergent", rows["TLS-009"]
    assert rows["TLS-009"]["reason"] == \
        "resumed-session-inherited-authorization"
