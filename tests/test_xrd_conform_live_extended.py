"""Extended Phase-118 live ROOT conformance probes."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from settings import DATA_ROOT, HOST, NGINX_ANON_PORT, SERVER_HOST
from test_xrd_conform_live import (
    XRD,
    basic_results,
    namespace_results,
    readv_chunked_results,
    readv_results,
    write_results,
)


pytestmark = pytest.mark.xdist_group("xrd-conform-live")


def test_offline_usage_errors_use_phase_exit_code():
    """Error contract: every offline conform usage failure exits with 4."""
    commands = (
        ("plan", "--budget", "invalid"),
        ("plant",),
        ("adopt",),
        ("verify",),
        ("unknown",),
    )
    for command in commands:
        result = subprocess.run(
            [str(XRD), "conform", *command], text=True,
            capture_output=True, timeout=10, check=False,
        )
        assert result.returncode == 4, (command, result.stderr, result.stdout)


def test_open_fixture_rejects_unknown_and_duplicate_authority(tmp_path):
    """Error/security-negative: fixture labels cannot widen or alias authority."""
    base = [str(XRD), "conform", "accept", f"root://{HOST}:1//x",
            "--only", "OPN-020", "--allow-disrupt", "--confirm-target",
            f"root://{HOST}:1//x", "--out", str(tmp_path)]
    unknown = subprocess.run(
        base + ["--open-fixture", f"unknown=root://{HOST}:1//x"],
        text=True, capture_output=True, timeout=10, check=False,
    )
    duplicate = subprocess.run(
        base + ["--open-fixture", f"staged-nowait=root://{HOST}:1//x",
                "--open-fixture", f"staged-nowait=root://{HOST}:2//x"],
        text=True, capture_output=True, timeout=10, check=False,
    )
    assert unknown.returncode == 4
    assert duplicate.returncode == 4


def test_optional_queries_are_explicitly_handled(basic_results):
    assert basic_results["QRY-010"]["verdict"] == "conformant"


def test_checksum_scan_returns_target_state(basic_results):
    assert basic_results["QRY-007"]["verdict"] == "conformant"
    assert basic_results["QRY-005"]["verdict"] == "conformant"


def test_query_xattr_returns_metadata(basic_results):
    assert basic_results["QRY-009"]["verdict"] == "conformant"


def test_query_stats_has_document_framing(basic_results):
    assert basic_results["QRY-012"]["verdict"] == "conformant"


def test_unknown_query_infotype_is_argument_error(basic_results):
    assert basic_results["QRY-013"]["verdict"] == "conformant"


def test_session_envelope_family_is_complete(basic_results):
    for index in range(1, 6):
        clause = f"ENV-{index:03d}"
        assert basic_results[clause]["verdict"] == "conformant"


def test_readv_descriptors_handles_and_limits(readv_results):
    for clause in ("RDV-001", "RDV-002", "RDV-003", "RDV-004", "RDV-005",
                   "RDV-006", "RDV-007", "RDV-008", "RDV-009", "RDV-010",
                   "RDV-011", "RDV-014", "RDV-015", "RDV-016", "RDV-017",
                   "RDV-020"):
        assert readv_results[clause]["verdict"] == "conformant"


def test_complete_readv_family_with_chunked_corpus(readv_chunked_results):
    for index in range(1, 21):
        clause = f"RDV-{index:03d}"
        assert readv_chunked_results[clause]["verdict"] == "conformant"


def test_chunked_read_framing_and_boundary(readv_chunked_results):
    for clause in ("CHU-001", "CHU-002", "CHU-003", "CHU-004"):
        assert readv_chunked_results[clause]["verdict"] == "conformant"


def test_namespace_mutation_basics(namespace_results):
    clauses = (
        "DIR-001", "DIR-004", "DIR-005", "DIR-007", "DIR-008",
        "MKD-001", "MKD-002", "MKD-003", "MKD-004", "MKD-006",
        "MV-001", "MV-002", "MV-003", "MV-004", "MV-007",
        "RM-001", "RM-002", "RM-003", "RM-004", "RM-005", "RM-006",
        "CHM-001", "CHM-002", "CHM-004",
    )
    for clause in clauses:
        assert namespace_results[clause]["verdict"] == "conformant"


def _run_dir_10000(tmp_path):
    output = tmp_path / "dir-10000-report"
    target = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}//test.txt"
    result = subprocess.run(
        [str(XRD), "conform", "full", target, "--only", "DIR-010",
         "--allow-mutate", "--scratch", "/", "--fail-on", "divergent",
         "--wall-seconds", "30", "--request-limit", "128",
         "--byte-limit", "8388608", "--out", str(output)],
        text=True, capture_output=True, timeout=45, check=False,
    )
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    row = next(item for item in report["results"] if item["id"] == "DIR-010")
    return result, row


def _plant_dir_10000(extra=None):
    fixture = Path(DATA_ROOT) / "brix-conform-dir-10000"
    shutil.rmtree(fixture, ignore_errors=True)
    fixture.mkdir()
    for index in range(10000):
        (fixture / f"{index:05d}").touch()
    if extra is not None:
        (fixture / extra).touch()
    return fixture


def test_dir_10000_lists_exactly_twice(tmp_path):
    fixture = _plant_dir_10000()
    try:
        result, row = _run_dir_10000(tmp_path)
        assert result.returncode == 0, result.stderr + result.stdout
        assert row["verdict"] == "conformant"
        assert row["reason"] == "two-exact-10000-entry-listings"
    finally:
        shutil.rmtree(fixture, ignore_errors=True)


def test_dir_10000_missing_fixture_is_inconclusive(tmp_path):
    fixture = Path(DATA_ROOT) / "brix-conform-dir-10000"
    shutil.rmtree(fixture, ignore_errors=True)
    result, row = _run_dir_10000(tmp_path)
    assert result.returncode == 0, result.stderr + result.stdout
    assert row["verdict"] == "inconclusive"
    assert row["reason"] == "fixture-missing:dir-10000"


def test_dir_10000_rejects_foreign_superset_entry(tmp_path):
    fixture = _plant_dir_10000("foreign-entry")
    try:
        result, row = _run_dir_10000(tmp_path)
        assert result.returncode != 0
        assert row["verdict"] == "divergent"
        assert row["reason"] == "10000-entry-listing-mismatch"
    finally:
        shutil.rmtree(fixture, ignore_errors=True)


def test_write_plane_mutation_basics(write_results):
    clauses = (
        "WRT-001", "WRT-002", "WRT-003", "WRT-004", "WRT-005", "WRT-009",
        "WRT-008", "WRT-010", "WRT-011",
        "WVC-001", "WVC-002", "WVC-003", "WVC-004", "SYN-001", "SYN-002",
        "TRN-001", "TRN-002", "TRN-003", "TRN-004", "TRN-005", "TRN-007",
        "PGW-001", "PGW-002", "PGW-003", "PGW-004", "PGW-005", "PGW-006",
        "PGW-007", "PGW-008", "PGW-009", "PGW-010", "PGW-011", "PGW-012",
        "FAT-001", "FAT-002", "FAT-003", "FAT-004", "FAT-005", "FAT-006",
        "FAT-007",
    )
    for clause in clauses:
        assert write_results[clause]["verdict"] == "conformant"


def test_writev_unsupported_clause_is_conditionally_skipped(write_results):
    """Conditional error: supported writev makes its unsupported row inapplicable."""
    assert write_results["WVC-005"]["verdict"] == "skipped"
    assert write_results["WVC-005"]["reason"] == "capability-present:writev"
