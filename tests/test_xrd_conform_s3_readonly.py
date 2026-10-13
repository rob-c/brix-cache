"""Controlled paired-plane fixtures for Phase-118 S3-009."""
import json
import subprocess

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin
from settings import HOST
from test_xrd_conform_http_semantics import (
    PAYLOAD, SemanticOrigin, XRD, _clean_environment, _conform_command,
)


def _run_readonly(tmp_path, s3_behaviour="s3_readonly",
                  root_behaviour="readonly", clause="S3-009",
                  verify_negative=None):
    """Run one policy clause against controlled S3 and ROOT twins."""
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")
    output = tmp_path / f"{s3_behaviour}-{root_behaviour}"
    with SemanticOrigin(s3_behaviour) as s3_origin, \
            PgOrigin(PAYLOAD, behaviour=root_behaviour) as root_origin:
        command = _conform_command(s3_origin, output, "s3")
        command[command.index("s3")] = "full"
        _extend_readonly_command(command, clause, root_origin, verify_negative)
        result = subprocess.run(
            command, text=True, capture_output=True, timeout=20,
            check=False, env=_clean_environment(),
        )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in report["results"]}
    return result, rows


def _extend_readonly_command(command, clause, root_origin, verify_negative):
    if clause.startswith("XPR-"):
        command[command.index("HTR,S3")] = "HTR,S3,XPR"
    command.extend([
        "--only", clause, "--also",
        f"root://{HOST}:{root_origin.port}//bucket/fixture",
    ])
    if verify_negative is not None:
        command.extend(["--verify-negative", verify_negative])


def test_readonly_s3_and_root_twin_agree(tmp_path):
    """Exact AccessDenied and fsReadOnly spellings make S3-009 conformant."""
    result, rows = _run_readonly(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["S3-009"]["verdict"] == "conformant"


def test_cross_plane_readonly_policy_agrees(tmp_path):
    """The same paired observation resolves the general XPR policy row."""
    result, rows = _run_readonly(tmp_path, clause="XPR-006")
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows["XPR-006"]["verdict"] == "conformant"


def test_cross_plane_readonly_wrong_s3_code_is_detected(tmp_path):
    result, rows = _run_readonly(
        tmp_path, "s3_readonly_wrong_code", clause="XPR-006",
        verify_negative="XPR-006",
    )
    assert result.returncode == 1
    assert rows["XPR-006"]["verdict"] == "divergent"


def test_readonly_s3_wrong_xml_code_is_detected(tmp_path):
    """A generic S3 error cannot stand in for the AccessDenied contract."""
    result, rows = _run_readonly(tmp_path, "s3_readonly_wrong_code",
                                 verify_negative="S3-009")
    assert result.returncode == 1
    assert rows["S3-009"]["verdict"] == "divergent"


def test_readonly_refusal_cannot_hide_an_s3_mutation(tmp_path):
    """A 403 response that nevertheless creates the object is divergent."""
    result, rows = _run_readonly(tmp_path, "s3_readonly_mutates",
                                 verify_negative="S3-009")
    assert result.returncode == 1
    assert rows["S3-009"]["verdict"] == "divergent"


def test_root_authorization_error_is_not_readonly_evidence(tmp_path):
    """NotAuthorized on the ROOT twin cannot substitute for fsReadOnly."""
    result, rows = _run_readonly(tmp_path, root_behaviour="readonly_auth",
                                 verify_negative="S3-009")
    assert result.returncode == 1
    assert rows["S3-009"]["verdict"] == "divergent"
