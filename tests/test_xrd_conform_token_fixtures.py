"""Phase-118 LOG-022..024 controlled ztn claim-negative fixtures."""
import contextlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from settings import HOST
from test_xrd_conform_claims import AuthClaimOrigin


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJwaGFzZTExOCJ9.signature"


def _add_token_fixtures(stack, command, needed, accepted_kind):
    for kind in needed:
        fixture = stack.enter_context(AuthClaimOrigin(
            protocol="ztn", accept=kind == accepted_kind,
        ))
        command.extend([
            "--token-fixture",
            f"{kind}=root://{HOST}:{fixture.port}//fixture",
        ])


def _token_environment():
    environment = os.environ.copy()
    environment["BEARER_TOKEN"] = TOKEN
    environment.pop("BEARER_TOKEN_FILE", None)
    return environment


def _extend_token_command(stack, command, needed, include, accepted_kind,
                          clause):
    if include:
        _add_token_fixtures(stack, command, needed, accepted_kind)
    if accepted_kind is not None:
        command.extend(["--verify-negative", clause])


def _run(tmp_path, clause, accepted_kind=None, include=True):
    output = tmp_path / f"token-{clause}-{accepted_kind or 'reject'}"
    needed = {
        "LOG-022": ("audience",),
        "LOG-023": ("expired", "not-yet-valid"),
        "LOG-024": ("issuer",),
    }[clause]
    with contextlib.ExitStack() as stack:
        primary = stack.enter_context(AuthClaimOrigin(protocol="ztn"))
        target = f"root://{HOST}:{primary.port}//fixture"
        command = [
            str(XRD), "conform", "accept", target,
            "--profile", "data", "--only", clause,
            "--fail-on", "divergent", "--wall-seconds", "10",
            "--request-limit", "64", "--byte-limit", "262144",
            "--out", str(output),
        ]
        _extend_token_command(
            stack, command, needed, include, accepted_kind, clause,
        )
        result = subprocess.run(
            command, text=True, capture_output=True, timeout=15,
            check=False, env=_token_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == clause)
    return result, row


@pytest.mark.parametrize("clause", ["LOG-022", "LOG-023", "LOG-024"])
def test_invalid_token_claims_return_exact_authfailed(tmp_path, clause):
    """Success: every labelled invalid claim is rejected as AuthFailed."""
    result, row = _run(tmp_path, clause)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "conformant"


def test_invalid_audience_token_cannot_be_accepted(tmp_path):
    """Security-negative: accepting the audience fixture is divergent."""
    result, row = _run(tmp_path, "LOG-022", accepted_kind="audience")
    assert result.returncode == 1
    assert row["verdict"] == "divergent"
    assert row["reason"] == \
        "invalid-token-claim-was-accepted-or-misclassified"


@pytest.mark.parametrize(("clause", "accepted_kind"), [
    ("LOG-023", "expired"),
    ("LOG-023", "not-yet-valid"),
    ("LOG-024", "issuer"),
])
def test_invalid_time_or_issuer_token_cannot_be_accepted(
        tmp_path, clause, accepted_kind):
    """Security-negative: every invalid token-claim class owns a red case."""
    result, row = _run(tmp_path, clause, accepted_kind=accepted_kind)
    assert result.returncode == 1, result.stderr + result.stdout
    assert row["verdict"] == "divergent"
    expected = "token-time-bound-was-accepted-or-misclassified" \
        if clause == "LOG-023" \
        else "invalid-token-claim-was-accepted-or-misclassified"
    assert row["reason"] == expected


def test_missing_token_fixture_remains_inconclusive(tmp_path):
    """Error honesty: an advertised ztn mechanism is not negative evidence."""
    result, row = _run(tmp_path, "LOG-024", include=False)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "inconclusive"
    assert row["reason"] == "fixture-required:token-claim-negative"
