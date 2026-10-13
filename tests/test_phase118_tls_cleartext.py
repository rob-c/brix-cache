"""TLS-002 incapable-client fixtures stay anonymous and fail closed."""

import contextlib
import json
import subprocess

from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin, error_frame
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client/bin/xrd"
CONN = (ROOT / "client/lib/net/conn.c").read_text()
PROBE = (ROOT / "client/apps/diag/xrd_conform_root_tls.c").read_text()

TLS_BITS = {
    "data": 0x01000000,
    "gpf": 0x02000000,
    "login": 0x04000000,
    "session": 0x08000000,
    "tpc": 0x10000000,
}


class _TlsClassOrigin(PgOrigin):
    def __init__(self, payload, request_class, refuse=True):
        self.request_class = request_class
        self.refuse = refuse
        super().__init__(payload)

    def _flags(self):
        return super()._flags() | TLS_BITS[self.request_class]

    def _must_refuse(self, reqid, body):
        return (
            (self.request_class == "login" and reqid == 3007)
            or (self.request_class == "session" and reqid == 3017)
            or (self.request_class == "data" and reqid == 3013)
            or (self.request_class == "gpf" and reqid == 3005)
            or (self.request_class == "tpc" and reqid == 3010
                and b"tpc.key=" in body)
        )

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if self.refuse and self._must_refuse(reqid, body):
            conn.sendall(error_frame(sid, 3028, b"TLS required"))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


def _enter_tls_fixtures(stack, payload, broken_class):
    return {
        name: stack.enter_context(_TlsClassOrigin(
            payload, name, refuse=name != broken_class,
        ))
        for name in TLS_BITS
    }


def _extend_negative(command, broken_class):
    if broken_class is not None:
        command.extend(["--verify-negative", "TLS-002"])


def _extend_cleartext_fixtures(command, fixtures):
    for name, origin in fixtures.items():
        command.extend([
            "--tls-cleartext-fixture",
            f"{name}=root://{HOST}:{origin.port}//fixture",
        ])


def _run(tmp_path, broken_class=None):
    payload = bytes((index * 31 + 11) & 0xFF for index in range(4096))
    output = tmp_path / "report"
    with contextlib.ExitStack() as stack:
        baseline = stack.enter_context(PgOrigin(payload))
        fixtures = _enter_tls_fixtures(stack, payload, broken_class)
        target = f"root://{HOST}:{baseline.port}//fixture"
        command = [
            str(XRD), "conform", "full", target,
            "--profile", "full", "--only", "TLS-002",
            "--fail-on", "divergent", "--wall-seconds", "30",
            "--request-limit", "64", "--byte-limit", "1048576",
            "--out", str(output),
        ]
        _extend_negative(command, broken_class)
        _extend_cleartext_fixtures(command, fixtures)
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=40, check=False)
    report = json.loads((output / "report.json").read_text())
    row = next(item for item in report["results"] if item["id"] == "TLS-002")
    return result, row


def test_cleartext_diagnostic_cannot_select_credentials():
    """Security-negative: upgrade suppression is gated by forced anonymity."""
    assert "!c->opts.force_anon || c->opts.auth_force != NULL" in CONN
    assert "options.force_anon = 1" in PROBE
    assert "options.auth_force = NULL" in PROBE
    assert "status->kxr == kXR_TLSRequired" in PROBE


def test_all_five_advertised_classes_refuse_cleartext(tmp_path):
    """Success: each advertised request class returns exact TLSRequired."""
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    result, row = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["reason"] == "all-advertised-tls-classes-refused-cleartext"


def test_one_cleartext_acceptance_makes_tls002_divergent(tmp_path):
    """Error: accepting any advertised class cannot be hidden by four refusals."""
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    result, row = _run(tmp_path, broken_class="data")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert row["reason"] == "advertised-tls-class-accepted-cleartext"
