"""Phase-118 capability-claim audit success, error and security negatives."""
import json
import struct
import subprocess
from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin
from _test_phase115_pgread_verify_helpers import (
    error_frame, kXR_gpfile, kXR_login, kXR_stat, ok_frame,
)
from settings import HOST
from test_xrd_conform_http_semantics import _clean_environment


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 23 + 5) & 0xFF for index in range(8192))
kXR_auth = 3000
kXR_authmore = 4002
KXR_SUPPOSC = 0x00100000


class ClaimOrigin(PgOrigin):
    """Capability fixture whose POSC advertisement matches its open behavior."""

    def __init__(self, behaviour="ok", serve_unclaimed_posc=False,
                 gpfile_error=False):
        self.serve_unclaimed_posc = serve_unclaimed_posc
        self.gpfile_error = gpfile_error
        super().__init__(PAYLOAD, behaviour=behaviour)

    def _flags(self):
        flags = super()._flags()
        return flags if self.serve_unclaimed_posc else flags | KXR_SUPPOSC

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_gpfile and self.gpfile_error:
            conn.sendall(error_frame(sid, 3007, b"fixture unavailable"))
            return authenticated
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)


class AuthClaimOrigin(PgOrigin):
    """Advertise one mechanism and either complete or reject its exchange."""

    def __init__(self, protocol="unix", accept=True,
                 accept_unadvertised=False, bad_auth="reject",
                 login_redirect=None, security_override=None):
        self.protocol = protocol
        self.accept = accept
        self.accept_unadvertised = accept_unadvertised
        self.bad_auth = bad_auth
        self.login_redirect = login_redirect
        self.security_override = security_override
        super().__init__(PAYLOAD, behaviour="ok")

    def _dispatch(self, conn, sid, reqid, hdr, body=b"",
                  authenticated=False):
        if reqid == kXR_login:
            return self._login(conn, sid, hdr, authenticated)
        if reqid == kXR_auth:
            return self._auth(conn, sid, hdr, body, authenticated)
        if reqid == kXR_stat and not authenticated:
            return self._unauthenticated_stat(
                conn, sid, reqid, hdr, body, authenticated,
            )
        return super()._dispatch(conn, sid, reqid, hdr, body, authenticated)

    def _login(self, conn, sid, hdr, authenticated):
        username = hdr[8:16].rstrip(b"\x00")
        if username == b"conform" and self.login_redirect is not None:
            return self._redirect_login(conn, sid, authenticated)
        security = self.security_override
        if security is None:
            security = f"&P={self.protocol}".encode("ascii")
        conn.sendall(ok_frame(sid, b"\x00" * 16 + security))
        return authenticated

    def _redirect_login(self, conn, sid, authenticated):
        hosts = {
            "ipv6": b"[::1]\x00",  # net-literal-allow: literal IPv6 redirect wire fixture
            "malformed": b"",
        }
        host = hosts.get(self.login_redirect, b"127.0.0.1\x00")  # net-literal-allow: literal IPv4 redirect wire fixture
        body = struct.pack("!I", self.port) + host
        conn.sendall(sid + struct.pack("!HI", 4004, len(body)) + body)
        return authenticated

    def _auth(self, conn, sid, hdr, body, authenticated):
        offered = hdr[16:20].rstrip(b"\x00").decode("ascii", "replace")
        if body == b"brix-conform-garbage" and offered == self.protocol:
            self._reject_bad_auth(conn, sid)
            return authenticated
        if self.accept and (offered == self.protocol
                            or self.accept_unadvertised):
            conn.sendall(ok_frame(sid))
            return True
        conn.sendall(error_frame(sid, 3030, b"auth rejected"))
        return authenticated

    def _reject_bad_auth(self, conn, sid):
        if self.bad_auth == "loop":
            conn.sendall(sid + struct.pack("!HI", kXR_authmore, 1) + b"x")
            return
        if self.bad_auth == "server-error":
            conn.sendall(error_frame(sid, 3012, b"internal"))
            return
        conn.sendall(error_frame(sid, 3030, b"auth rejected"))

    def _unauthenticated_stat(self, conn, sid, reqid, hdr, body,
                              authenticated):
        if self.bad_auth == "retain-partial":
            return super()._dispatch(
                conn, sid, reqid, hdr, body, authenticated,
            )
        code = 3012 if self.bad_auth == "identity-server-error" else 3010
        message = b"internal" if code == 3012 else b"not authorized"
        conn.sendall(error_frame(sid, code, message))
        return authenticated


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _assert_login_rows_touched(rows):
    for row in rows:
        assert row["reason"] != "probe-not-executed"


def _assert_ztn_claim_absent(rows):
    row = next(row for row in rows if row["id"] == "LOG-021")
    assert row["reason"] == "claim-absent:ztn"


def _run(tmp_path, behaviour="ok"):
    _require_xrd()
    output = tmp_path / behaviour
    with ClaimOrigin(behaviour=behaviour) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "full", "--families", "CLM",
             "--allow-mutate", "--scratch", "/",
             "--budget", "boundary", "--fail-on", "divergent",
             "--wall-seconds", "10", "--request-limit", "128",
             "--byte-limit", "4194304", "--out", str(output)]
        negative_rows = {
            "claim_unknown_bit": "CLM-001",
            "claim_bad_manager": "CLM-002",
            "claim_bad_super": "CLM-003",
            "claim_supgpf_broken": "CLM-004",
            "claim_tls_broken": "CLM-005",
            "claim_anongpf_broken": "CLM-006",
            "claim_old_version": "CLM-010",
        }
        if behaviour in negative_rows:
            command.extend(["--verify-negative", negative_rows[behaviour]])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_consistent_data_server_claims_are_proven(tmp_path):
    result, rows = _run(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("CLM-001", "CLM-002", "CLM-003", "CLM-004",
                   "CLM-006", "CLM-007", "CLM-008", "CLM-010"):
        assert rows[clause]["verdict"] == "conformant"
    assert rows["CLM-005"]["reason"] == "claim-absent:kXR_haveTLS"
    assert rows["CLM-009"]["reason"] == \
        "fixture-required:tpc-and-checksum-claims"


def test_unknown_capability_bit_is_reported(tmp_path):
    result, rows = _run(tmp_path, "claim_unknown_bit")
    assert result.returncode == 1
    assert rows["CLM-001"]["verdict"] == "divergent"


def test_manager_claim_without_manager_behaviour_is_reported(tmp_path):
    result, rows = _run(tmp_path, "claim_bad_manager")
    assert result.returncode == 1
    assert rows["CLM-002"]["verdict"] == "divergent"


def test_supervisor_attribute_without_manager_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "claim_bad_super")
    assert result.returncode == 1
    assert rows["CLM-003"]["verdict"] == "divergent"


def test_claimed_but_unsupported_gpfile_is_reported(tmp_path):
    result, rows = _run(tmp_path, "claim_supgpf_broken")
    assert result.returncode == 1
    assert rows["CLM-004"]["verdict"] == "divergent"


def test_claimed_tls_without_tls_listener_is_reported(tmp_path):
    result, rows = _run(tmp_path, "claim_tls_broken")
    assert result.returncode == 1
    assert rows["CLM-005"]["verdict"] == "divergent"


def test_anonymous_gpfile_without_gpfile_support_is_reported(tmp_path):
    result, rows = _run(tmp_path, "claim_anongpf_broken")
    assert result.returncode == 1
    assert rows["CLM-006"]["verdict"] == "divergent"


def test_new_feature_on_old_protocol_version_is_reported(tmp_path):
    result, rows = _run(tmp_path, "claim_old_version")
    assert result.returncode == 1
    assert rows["CLM-010"]["verdict"] == "divergent"


def test_claim_skip_from_another_target_cannot_contradict_flags(tmp_path):
    _require_xrd()
    output = tmp_path / "contradictory-skip-ledger"
    with ClaimOrigin() as clear_origin, \
            ClaimOrigin(behaviour="claim_tls_broken") as tls_claim_origin:
        result = subprocess.run(
            [str(XRD), "conform", "accept",
             f"root://{HOST}:{clear_origin.port}//fixture",
                 "--also", f"root://{HOST}:{tls_claim_origin.port}//fixture",
                 "--profile", "full", "--families", "CLM",
                 "--budget", "boundary", "--verify-negative", "CLM-008",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "256", "--byte-limit", "8388608",
             "--out", str(output)],
            text=True, capture_output=True, timeout=30, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "CLM-008")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert row["reason"] == "claim-skip-does-not-match-protocol-flags"


def test_unadvertised_posc_cannot_be_quietly_served(tmp_path):
    _require_xrd()
    output = tmp_path / "unclaimed-posc"
    with ClaimOrigin(serve_unclaimed_posc=True) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "accept", target,
             "--profile", "full", "--only", "CLM-007",
             "--allow-mutate", "--scratch", "/",
             "--verify-negative", "CLM-007",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "128", "--byte-limit", "4194304",
             "--out", str(output)],
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "CLM-007")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == "unclaimed-feature-verb-served"


def test_clear_bit_audit_stays_honest_when_verb_cannot_be_classified(tmp_path):
    _require_xrd()
    output = tmp_path / "clear-bit-unavailable"
    with ClaimOrigin(gpfile_error=True) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "accept", target,
             "--profile", "full", "--only", "CLM-007",
             "--allow-mutate", "--scratch", "/",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "128", "--byte-limit", "4194304",
             "--out", str(output)],
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "CLM-007")
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "skipped"
    assert row["reason"] == "fixture-unavailable:clear-bit-verb"


def _run_login_claim(tmp_path, fixture="success"):
    output = tmp_path / f"login-{fixture}"
    with AuthClaimOrigin() as primary:
        target = f"root://{HOST}:{primary.port}//fixture"
        command = [
            str(XRD), "conform", "accept", target,
            "--profile", "data", "--only", "LOG-005",
            "--fail-on", "divergent", "--wall-seconds", "10",
            "--request-limit", "64", "--byte-limit", "65536",
            "--out", str(output),
        ]
        if fixture != "missing":
            with AuthClaimOrigin(accept=fixture == "success") as auth:
                command.extend([
                    "--auth-fixture",
                    f"unix=root://{HOST}:{auth.port}//fixture",
                ])
                if fixture == "reject":
                    command.extend(["--verify-negative", "LOG-005"])
                result = subprocess.run(
                    command, text=True, capture_output=True, timeout=15,
                    check=False, env=_clean_environment(),
                )
        else:
            result = subprocess.run(
                command, text=True, capture_output=True, timeout=15,
                check=False, env=_clean_environment(),
            )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def test_every_advertised_login_mechanism_completes(tmp_path):
    result, rows = _run_login_claim(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["LOG-005"]["verdict"] == "conformant"
    assert rows["LOG-005"]["reason"] == \
        "all-advertised-auth-protocols-complete"


def test_login_claim_without_fixture_is_inconclusive(tmp_path):
    result, rows = _run_login_claim(tmp_path, "missing")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["LOG-005"]["verdict"] == "inconclusive"
    assert rows["LOG-005"]["reason"] == \
        "fixture-required:advertised-auth-protocols"


def test_advertised_login_mechanism_cannot_hide_failed_auth(tmp_path):
    result, rows = _run_login_claim(tmp_path, "reject")
    assert result.returncode == 1
    assert rows["LOG-005"]["verdict"] == "divergent"
    assert rows["LOG-005"]["reason"] == \
        "advertised-auth-protocol-false-or-uncovered"


def test_security_continuation_without_a_mechanism_is_rejected(tmp_path):
    """Security-negative: a non-empty sec continuation must contain &P=."""
    output = tmp_path / "login-no-mechanism"
    with AuthClaimOrigin(security_override=b"&X=unix") as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "accept", target,
             "--profile", "data", "--only", "LOG-004",
             "--verify-negative", "LOG-004", "--fail-on", "divergent",
             "--wall-seconds", "10", "--request-limit", "64",
             "--byte-limit", "65536", "--out", str(output)],
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "LOG-004")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"


def test_working_bearer_fixture_must_be_advertised_as_ztn(tmp_path):
    """Security-negative: a usable ztn endpoint cannot be named only unix."""
    output = tmp_path / "login-ztn-misnamed"
    with AuthClaimOrigin(protocol="unix") as primary, \
            AuthClaimOrigin(protocol="ztn") as bearer:
        target = f"root://{HOST}:{primary.port}//fixture"
        environment = _clean_environment()
        environment["BEARER_TOKEN"] = \
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJwaGFzZTExOCJ9.signature"
        result = subprocess.run(
            [str(XRD), "conform", "accept", target,
             "--profile", "data", "--only", "LOG-021",
             "--auth-fixture", f"ztn=root://{HOST}:{bearer.port}//fixture",
             "--verify-negative", "LOG-021", "--fail-on", "divergent",
             "--wall-seconds", "10", "--request-limit", "64",
             "--byte-limit", "65536", "--out", str(output)],
            text=True, capture_output=True, timeout=15, check=False,
            env=environment,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "LOG-021")
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    assert row["reason"] == "working-bearer-fixture-not-advertised-as-ztn"


def _run_login_ability(tmp_path, redirect=None):
    output = tmp_path / f"login-ability-{redirect or 'ok'}"
    with AuthClaimOrigin(login_redirect=redirect) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "data", "--only", "LOG-025",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "32", "--byte-limit", "65536",
             "--out", str(output)]
        if redirect is not None:
            command.extend(["--verify-negative", "LOG-025"])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "LOG-025")
    return result, row


def test_zero_ability_login_is_not_redirected_to_ipv6(tmp_path):
    """Success: an ordinary login reply does not invent client abilities."""
    result, row = _run_login_ability(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"


def test_zero_ability_login_rejects_ipv6_only_redirect(tmp_path):
    """Security-negative: omitted hasipv64 cannot authorize an IPv6-only hop."""
    result, row = _run_login_ability(tmp_path, "ipv6")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == "zero-ability-login-received-ipv6-only-redirect"


def test_zero_ability_login_rejects_malformed_redirect(tmp_path):
    """Error: an empty redirect target never counts as safe evidence."""
    result, row = _run_login_ability(tmp_path, "malformed")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == "zero-ability-login-received-malformed-response"


def _run_nul_identity(tmp_path, behaviour="reject"):
    output = tmp_path / f"nul-identity-{behaviour}"
    with AuthClaimOrigin(bad_auth=behaviour) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "data", "--only", "LOG-008",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "32", "--byte-limit", "65536",
             "--out", str(output)]
        if behaviour != "reject":
            command.extend(["--verify-negative", "LOG-008"])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "LOG-008")
    return result, row


def test_nul_username_retains_no_default_identity(tmp_path):
    """Success: an empty username remains unauthorized before auth."""
    result, row = _run_nul_identity(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"


def test_nul_username_cannot_inherit_default_identity(tmp_path):
    """Security-negative: serving stat exposes a default-identity leak."""
    result, row = _run_nul_identity(tmp_path, "retain-partial")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == "nul-username-inherited-default-identity"


def test_nul_username_generic_server_error_is_not_auth_evidence(tmp_path):
    """Error: a generic server failure cannot prove identity isolation."""
    result, row = _run_nul_identity(tmp_path, "identity-server-error")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == "nul-username-returned-unclassified-error"


def _run_unadvertised_auth(tmp_path, origin, verify=False):
    output = tmp_path / "login-unadvertised"
    with origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "data", "--only", "LOG-006",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "64", "--byte-limit", "65536",
             "--out", str(output)]
        if verify:
            command.extend(["--verify-negative", "LOG-006"])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "LOG-006")
    return result, row


def test_unadvertised_login_mechanism_is_refused(tmp_path):
    result, row = _run_unadvertised_auth(tmp_path, AuthClaimOrigin())
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"
    assert row["reason"] == "unadvertised-auth-mechanism-refused"


def test_unadvertised_login_mechanism_is_claim_skipped_when_auth_absent(
        tmp_path):
    result, row = _run_unadvertised_auth(tmp_path, PgOrigin(PAYLOAD))
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "skipped"
    assert row["reason"] == "claim-absent:security-mechanism"


def test_unadvertised_login_mechanism_acceptance_is_detected(tmp_path):
    result, row = _run_unadvertised_auth(
        tmp_path, AuthClaimOrigin(accept_unadvertised=True), verify=True)
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == "unadvertised-auth-mechanism-accepted"


def _run_auth_negative(tmp_path, clause, bad_auth="reject"):
    output = tmp_path / f"login-{clause.lower()}-{bad_auth}"
    with AuthClaimOrigin(bad_auth=bad_auth) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "data", "--only", clause,
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "96", "--byte-limit", "65536",
             "--out", str(output)]
        if bad_auth != "reject":
            command.extend(["--verify-negative", clause])
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == clause)
    return result, row


@pytest.mark.parametrize("clause", ["LOG-015", "LOG-016", "LOG-017"])
def test_bad_auth_continuation_is_bounded_classified_and_unprivileged(
        tmp_path, clause):
    result, row = _run_auth_negative(tmp_path, clause)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"


def test_auth_continuation_loop_is_detected(tmp_path):
    result, row = _run_auth_negative(tmp_path, "LOG-015", "loop")
    assert result.returncode == 1
    assert row["reason"] == "auth-continuation-exceeded-round-bound"


def test_garbage_auth_server_error_is_detected(tmp_path):
    result, row = _run_auth_negative(tmp_path, "LOG-016", "server-error")
    assert result.returncode == 1
    assert row["reason"] == "garbage-auth-continuation-wrong-result"


def test_failed_auth_cannot_retain_partial_identity(tmp_path):
    result, row = _run_auth_negative(tmp_path, "LOG-017", "retain-partial")
    assert result.returncode == 1
    assert row["reason"] == "failed-auth-session-retained-privilege"


def test_authenticated_login_family_has_no_untouched_rows(tmp_path):
    output = tmp_path / "login-complete-reasons"
    with AuthClaimOrigin() as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        result = subprocess.run(
            [str(XRD), "conform", "accept", target,
             "--profile", "data", "--families", "LOG",
             "--auth-fixture", f"unix={target}",
             "--fail-on", "divergent", "--wall-seconds", "10",
             "--request-limit", "256", "--byte-limit", "1048576",
             "--out", str(output)],
            text=True, capture_output=True, timeout=15, check=False,
            env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = [row for row in report["results"] if row["id"].startswith("LOG-")]
    assert result.returncode == 1
    _assert_login_rows_touched(rows)
    _assert_ztn_claim_absent(rows)
