"""Executable Phase-118 locate refresh and nowait fixture evidence."""
import json
import subprocess
from pathlib import Path

import pytest

from _test_phase115_pgread_verify_helpers import PgOrigin
from settings import HOST


ROOT = Path(__file__).resolve().parents[1]
XRD = ROOT / "client" / "bin" / "xrd"
PAYLOAD = bytes((index * 13 + 5) & 0xFF for index in range(8192))


def _require_xrd():
    if not XRD.exists():
        pytest.skip(f"native xrd client is not built: {XRD}")


def _extend_fixture_command(command, clause, fixture_target, include_fixture):
    if not include_fixture:
        return
    kind = "refresh" if clause == "LOC-005" else "slow"
    command.extend(["--locate-fixture", f"{kind}={fixture_target}"])


def _extend_verification(command, clause, verify):
    if verify:
        command.extend(["--verify-negative", clause])


def _run(tmp_path, clause, behaviour, include_fixture=True, verify=False):
    _require_xrd()
    output = tmp_path / f"{clause}-{behaviour}"
    with PgOrigin(PAYLOAD) as primary, PgOrigin(
            PAYLOAD, behaviour=behaviour) as fixture:
        target = f"root://{HOST}:{primary.port}//fixture"
        fixture_target = f"root://{HOST}:{fixture.port}//fixture"
        command = [
            str(XRD), "conform", "accept", target,
            "--profile", "data", "--families", "LOC",
            "--only", clause, "--budget", "boundary",
            "--fail-on", "divergent", "--wall-seconds", "10",
            "--request-limit", "64", "--byte-limit", "4194304",
            "--out", str(output),
        ]
        _extend_fixture_command(
            command, clause, fixture_target, include_fixture,
        )
        _extend_verification(command, clause, verify)
        result = subprocess.run(command, text=True, capture_output=True,
                                timeout=20, check=False)
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    return result, {row["id"]: row for row in report["results"]}


@pytest.mark.parametrize(
    ("clause", "behaviour"),
    (("LOC-005", "locate_refresh_changes"),
     ("LOC-006", "locate_nowait_fast")),
)
def test_locate_controlled_fixtures_prove_positive_contract(
        tmp_path, clause, behaviour):
    result, rows = _run(tmp_path, clause, behaviour)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows[clause]["verdict"] == "conformant", rows[clause]


@pytest.mark.parametrize(
    ("clause", "behaviour", "reason"),
    (("LOC-005", "locate_refresh_stale",
      "refresh-returned-cached-locate-answer"),
     ("LOC-006", "locate_nowait_slow", "nowait-blocked-on-slow-member")),
)
def test_locate_hostile_fixtures_are_verified_divergences(
        tmp_path, clause, behaviour, reason):
    result, rows = _run(tmp_path, clause, behaviour, verify=True)
    assert result.returncode == 1, result.stderr + result.stdout
    assert rows[clause]["verdict"] == "divergent", rows[clause]
    assert rows[clause]["reason"] == reason
    assert f"verify-negative={clause} result=passed" in result.stdout


@pytest.mark.parametrize("clause", ("LOC-005", "LOC-006"))
def test_locate_fixture_absence_stays_honestly_inconclusive(tmp_path, clause):
    result, rows = _run(tmp_path, clause, "ok", include_fixture=False)
    assert result.returncode == 0, result.stderr + result.stdout
    assert rows[clause]["verdict"] == "inconclusive", rows[clause]
    assert rows[clause]["reason"].startswith("fixture-required:")
