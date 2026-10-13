"""Phase-118 redirect/wait/attention wire success, error and security tests."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin
from settings import HOST
from test_xrd_conform_tls import TlsPgOrigin, _certificate


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 17 + 11) & 0xFF for index in range(8192))


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _extend_verification(command, verify_negative):
    verification = ((verify_negative,) if isinstance(verify_negative, str)
                    else verify_negative or ())
    for clause in verification:
        command.extend(["--verify-negative", clause])


def _run(tmp_path, behaviour, redirect_port=None, verify_negative=None):
    _require_xrd()
    output = tmp_path / behaviour
    with PgOrigin(PAYLOAD, behaviour=behaviour,
                  redirect_port=redirect_port) as origin:
        target = f"root://{HOST}:{origin.port}//fixture"
        command = [str(XRD), "conform", "accept", target,
             "--profile", "full", "--families", "RDR,WAI,ATN",
             "--allow-disrupt", "--confirm-target", target,
             "--budget", "boundary", "--fail-on", "divergent",
             "--wall-seconds", "10", "--request-limit", "256",
             "--byte-limit", "4194304", "--out", str(output)]
        _extend_verification(command, verify_negative)
        result = subprocess.run(
            command,
            text=True, capture_output=True, timeout=15, check=False,
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _run_tls_redirect(tmp_path, source, ca_dir):
    output = tmp_path / "tls-redirect-downgrade"
    target = f"roots://{HOST}:{source.port}//fixture"
    command = [
        str(XRD), "conform", "accept", target,
        "--profile", "manager", "--families", "RDR",
        "--only", "RDR-004", "--verify-negative", "RDR-004",
        "--budget", "boundary", "--fail-on", "divergent",
        "--wall-seconds", "10", "--request-limit", "64",
        "--byte-limit", "4194304", "--out", str(output),
    ]
    environment = os.environ.copy()
    environment["X509_CERT_DIR"] = str(ca_dir)
    result = subprocess.run(command, text=True, capture_output=True,
                            timeout=20, check=False, env=environment)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


def _assert_explicit_skip(row):
    assert row["verdict"] == "skipped"
    assert row["reason"] != "probe-not-executed"


def _assert_fixture_skip_reasons(rows):
    assert rows["RDR-006"]["reason"] == "response-not-observed"
    assert rows["WAI-004"]["reason"] == "fixture-required:load-shedding"


def test_redirect_target_is_parsed_and_serves_path(tmp_path):
    with PgOrigin(PAYLOAD) as target:
        result, rows = _run(tmp_path, "redirect", target.port)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["RDR-001"]["verdict"] == "conformant"
    assert rows["RDR-002"]["verdict"] == "conformant"
    assert rows["RDR-003"]["verdict"] == "conformant"


def test_redirect_target_that_does_not_serve_path_is_reported(tmp_path):
    with PgOrigin(PAYLOAD, behaviour="stat_not_found") as target:
        result, rows = _run(tmp_path, "redirect", target.port,
                            ("RDR-002",))
    assert result.returncode == 1
    assert rows["RDR-002"]["verdict"] == "divergent"


def test_redirect_opaque_is_replayed_to_target(tmp_path):
    with PgOrigin(PAYLOAD) as target:
        result, rows = _run(tmp_path, "redirect_opaque", target.port)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["RDR-005"]["verdict"] == "conformant"


def test_redirect_target_cannot_reject_required_opaque(tmp_path):
    with PgOrigin(PAYLOAD, behaviour="reject_opaque") as target:
        result, rows = _run(tmp_path, "redirect_opaque", target.port,
                            ("RDR-005",))
    assert result.returncode == 1
    assert rows["RDR-005"]["verdict"] == "divergent"


def test_redirect_cycle_is_bounded_and_reported(tmp_path):
    with PgOrigin(PAYLOAD, behaviour="redirect_always") as first:
        with PgOrigin(PAYLOAD, behaviour="redirect_always",
                      redirect_port=first.port) as second:
            first.redirect_port = second.port
            result, rows = _run(tmp_path, "redirect", second.port,
                                ("RDR-003",))
    assert result.returncode == 1
    assert rows["RDR-003"]["verdict"] == "divergent"


def test_roots_redirect_to_clear_only_peer_is_a_verified_downgrade(tmp_path):
    cert, key, ca_dir = _certificate(tmp_path, f"IP:{HOST}")
    with PgOrigin(PAYLOAD) as clear_target, TlsPgOrigin(
            PAYLOAD, cert, key, behaviour="redirect",
    ) as secure_source:
        secure_source.redirect_port = clear_target.port
        result, rows = _run_tls_redirect(tmp_path, secure_source, ca_dir)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows["RDR-004"]["verdict"] == "divergent", rows["RDR-004"]
    assert rows["RDR-004"]["reason"] == "redirect-downgraded-tls"
    assert "verify-negative=RDR-004 result=passed" in result.stdout


def test_wait_is_bounded_and_retry_makes_progress(tmp_path):
    result, rows = _run(tmp_path, "wait_once")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["WAI-001"]["verdict"] == "conformant"
    assert rows["WAI-002"]["verdict"] == "conformant"
    assert rows["WAI-004"]["verdict"] == "conformant"


def test_empty_manager_returns_a_defined_error(tmp_path):
    result, rows = _run(tmp_path, "empty_manager")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["RDR-006"]["verdict"] == "conformant"


def test_empty_manager_cannot_return_an_empty_redirect(tmp_path):
    result, rows = _run(tmp_path, "bad_empty_manager",
                        verify_negative=("RDR-006",))
    assert result.returncode == 1
    assert rows["RDR-006"]["verdict"] == "divergent"


def test_load_shedding_wait_must_have_a_bounded_delay(tmp_path):
    result, rows = _run(tmp_path, "bad_wait",
                        verify_negative=("WAI-001", "WAI-004"))
    assert result.returncode == 1
    assert rows["WAI-001"]["verdict"] == "divergent"
    assert rows["WAI-004"]["verdict"] == "divergent"


def test_waitresp_is_bound_to_deferred_stream(tmp_path):
    result, rows = _run(tmp_path, "waitresp")
    assert result.returncode == 0, result.stderr + result.stdout
    for clause in ("WAI-003", "ATN-001", "ATN-003"):
        assert rows[clause]["verdict"] == "conformant"


def test_async_message_is_bounded_and_does_not_poison_stream(tmp_path):
    result, rows = _run(tmp_path, "asyncms")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["ATN-002"]["verdict"] == "conformant"


def test_malformed_redirect_is_reported(tmp_path):
    result, rows = _run(tmp_path, "bad_redirect",
                        verify_negative=("RDR-001",))
    assert result.returncode == 1
    assert rows["RDR-001"]["verdict"] == "divergent"


def test_identical_wait_retry_is_reported(tmp_path):
    result, rows = _run(tmp_path, "wait_repeat",
                        verify_negative=("WAI-002",))
    assert result.returncode == 1
    assert rows["WAI-002"]["verdict"] == "divergent"


def test_forged_waitresp_stream_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "bad_waitresp_sid",
                        verify_negative=("WAI-003", "ATN-001", "ATN-003"))
    assert result.returncode == 1
    for clause in ("WAI-003", "ATN-001", "ATN-003"):
        assert rows[clause]["verdict"] == "divergent"


def test_unterminated_async_message_is_rejected(tmp_path):
    result, rows = _run(tmp_path, "bad_asyncms",
                        verify_negative=("ATN-002",))
    assert result.returncode == 1
    assert rows["ATN-002"]["verdict"] == "divergent"


def test_unobserved_conditional_responses_are_explicitly_skipped(tmp_path):
    result, rows = _run(tmp_path, "ok")
    assert result.returncode == 0, result.stderr + result.stdout
    selected = [row for clause, row in rows.items()
                if clause.startswith(("RDR-", "WAI-", "ATN-"))]
    for row in selected:
        _assert_explicit_skip(row)
    _assert_fixture_skip_reasons(rows)
