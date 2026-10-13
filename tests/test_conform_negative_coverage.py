"""Phase-118 §40 evidence aggregation fails closed and excludes accidents."""

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/diag/conform_negative_coverage.py"
SPEC = importlib.util.spec_from_file_location("conform_negative_coverage", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _ledger(path, *rows):
    path.write_text("\n".join(
        f'BRIX_CONFORM_CLAUSE("{clause}", "T", R, O, P, "{fixture}", "x", "s")'
        for clause, fixture in rows
    ))


def _report(path, requested, passed, verdict="divergent", fixture="fixture/A-001"):
    timestamp = "2026-10-07T00:00:00Z"
    tool_version = "test-version"
    path.write_text(json.dumps({
        "schema": "brix.conform.v1",
        "timestamp": timestamp,
        "tool_version": tool_version,
        "negative_verification": {"requested": requested, "passed": passed},
        "results": [{"id": "A-001", "verdict": verdict,
                     "negative_fixture": fixture}],
    }))
    path.with_name(MODULE.BUNDLE_MARKER).write_text(json.dumps({
        "schema": "brix.conform.bundle.v1",
        "timestamp": timestamp,
        "tool_version": tool_version,
    }))
    for name in MODULE.BUNDLE_REPORTS[1:]:
        path.with_name(name).write_text("test report\n")


def test_passing_declared_divergence_counts_as_evidence(tmp_path):
    """Success: exact fixture identity plus red verdict covers the live row."""
    ledger = tmp_path / "ledger.inc"
    report = tmp_path / "report.json"
    _ledger(ledger, ("A-001", "fixture/A-001"),
            ("R-001", "not-applicable/retracted/R-001"))
    _report(report, ["A-001"], True)
    result = MODULE.audit([report], ledger)
    assert result["covered"] == ["A-001"]
    assert result["missing"] == []
    assert result["errors"] == []


def test_ordinary_or_unverified_divergence_never_counts(tmp_path):
    """Error honesty: red without a passing declaration is not §40 evidence."""
    ledger = tmp_path / "ledger.inc"
    report = tmp_path / "report.json"
    _ledger(ledger, ("A-001", "fixture/A-001"))
    _report(report, [], True)
    result = MODULE.audit([report], ledger)
    assert result["covered"] == []
    assert result["missing"] == ["A-001"]

    _report(report, ["A-001"], False)
    failed = MODULE.audit([report], ledger)
    assert failed["covered"] == []
    assert failed["errors"] == []


def test_forged_pass_with_green_row_or_wrong_fixture_is_rejected(tmp_path):
    """Security-negative: report metadata cannot override row-level evidence."""
    ledger = tmp_path / "ledger.inc"
    report = tmp_path / "report.json"
    _ledger(ledger, ("A-001", "fixture/A-001"))
    _report(report, ["A-001"], True, verdict="conformant",
            fixture="fixture/other")
    result = MODULE.audit([report], ledger)
    assert result["covered"] == []
    assert result["errors"] == [f"{report}: A-001 is not divergent"]


def test_duplicate_requests_and_results_are_rejected(tmp_path):
    """Security-negative: contradictory duplicate evidence cannot be selected."""
    ledger = tmp_path / "ledger.inc"
    report = tmp_path / "report.json"
    _ledger(ledger, ("A-001", "fixture/A-001"))
    _report(report, ["A-001", "A-001"], True)
    duplicate_request = MODULE.audit([report], ledger)
    assert duplicate_request["covered"] == []
    assert duplicate_request["errors"] == [
        f"{report}: duplicate negative-verification request"
    ]

    document = json.loads(report.read_text())
    document["negative_verification"]["requested"] = ["A-001"]
    document["results"].append({
        "id": "A-001", "verdict": "conformant",
        "negative_fixture": "fixture/A-001",
    })
    report.write_text(json.dumps(document))
    duplicate_result = MODULE.audit([report], ledger)
    assert duplicate_result["covered"] == []
    assert duplicate_result["errors"] == [
        f"{report}: duplicate result row A-001"
    ]


def test_malformed_results_fail_closed(tmp_path):
    """Error: missing, non-list or structurally invalid results prove nothing."""
    ledger = tmp_path / "ledger.inc"
    report = tmp_path / "report.json"
    _ledger(ledger, ("A-001", "fixture/A-001"))
    _report(report, ["A-001"], True)
    for results, message in (
        ({}, "malformed results array"),
        (["A-001"], "malformed result row"),
    ):
        report.write_text(json.dumps({
            "schema": "brix.conform.v1",
            "timestamp": "2026-10-07T00:00:00Z",
            "tool_version": "test-version",
            "negative_verification": {
                "requested": ["A-001"], "passed": True,
            },
            "results": results,
        }))
        result = MODULE.audit([report], ledger)
        assert result["covered"] == []
        assert result["errors"] == [f"{report}: {message}"]


def test_missing_or_mismatched_bundle_marker_is_rejected(tmp_path):
    """Security-negative: partial and stale bundles prove no ledger rows."""
    ledger = tmp_path / "ledger.inc"
    report = tmp_path / "report.json"
    marker = report.with_name(MODULE.BUNDLE_MARKER)
    _ledger(ledger, ("A-001", "fixture/A-001"))
    _report(report, ["A-001"], True)

    marker.unlink()
    missing = MODULE.audit([report], ledger)
    assert missing["covered"] == []
    assert len(missing["errors"]) == 1
    assert "incomplete report bundle" in missing["errors"][0]

    _report(report, ["A-001"], True)
    document = json.loads(marker.read_text())
    document["timestamp"] = "2026-10-06T23:59:59Z"
    marker.write_text(json.dumps(document))
    stale = MODULE.audit([report], ledger)
    assert stale["covered"] == []
    assert stale["errors"] == [f"{report}: report bundle generation mismatch"]

    _report(report, ["A-001"], True)
    missing_member = report.with_name("report.sarif")
    missing_member.unlink()
    partial = MODULE.audit([report], ledger)
    assert partial["covered"] == []
    assert len(partial["errors"]) == 1
    assert "incomplete report bundle: report.sarif" in partial["errors"][0]
