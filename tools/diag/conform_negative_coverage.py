#!/usr/bin/env python3
"""Audit fresh ``xrd conform --verify-negative`` report bundles for §40.

Only an explicit, passing negative-verification declaration counts. An ordinary
divergence may be accidental and is therefore never treated as hostile-fixture
evidence. The default mode prints the honest gap; ``--require-complete`` turns
that gap into a release gate.
"""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.logging_support import diagnostic


LEDGER = ROOT / "client/lib/conform/ledger_rows.inc"
BUNDLE_MARKER = "report.complete.json"
BUNDLE_REPORTS = (
    "report.json",
    "report.md",
    "report.html",
    "report.sarif",
    "report.ecs.jsonl",
    "report.diff.json",
)
ROW_RE = re.compile(
    r'^BRIX_CONFORM_CLAUSE\("(?P<id>[^"]+)", "[^"]+", .*?'
    r'"(?P<fixture>[^"]+)",'
)


def executable_clauses(ledger: Path = LEDGER) -> dict[str, str]:
    """Return stable clause-to-fixture mappings, excluding true retractions."""
    clauses: dict[str, str] = {}
    for line in ledger.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line)
        if match is None:
            continue
        fixture = match.group("fixture")
        if not fixture.startswith("not-applicable/retracted/"):
            clauses[match.group("id")] = fixture
    return clauses


def report_paths(inputs: list[Path]) -> list[Path]:
    """Resolve files and recursively discover canonical report filenames."""
    found: set[Path] = set()
    for candidate in inputs:
        if candidate.is_file():
            found.add(candidate)
        elif candidate.is_dir():
            found.update(candidate.rglob("report.json"))
    return sorted(found)


def _load_regular_json(path: Path, description: str) -> tuple[object | None, str | None]:
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            return None, f"{description} is not a regular file"
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"{description} is unreadable: {error}"


def _bundle_problem(path: Path, report: dict[str, object]) -> str | None:
    marker, problem = _load_regular_json(path.with_name(BUNDLE_MARKER), "completion marker")
    if problem:
        return f"{path}: incomplete report bundle: {problem}"
    if not isinstance(marker, dict) or marker.get("schema") != "brix.conform.bundle.v1":
        return f"{path}: unsupported bundle marker schema"
    if (marker.get("timestamp"), marker.get("tool_version")) != (
            report.get("timestamp"), report.get("tool_version")):
        return f"{path}: report bundle generation mismatch"
    for name in BUNDLE_REPORTS:
        try:
            if not stat.S_ISREG(path.with_name(name).lstat().st_mode):
                return f"{path}: non-regular bundle member {name}"
        except OSError as error:
            return f"{path}: incomplete report bundle: {name}: {error}"
    return None


def _requested_clauses(path: Path, report: dict[str, object]) -> tuple[list[str], str | None]:
    verification = report.get("negative_verification")
    if not isinstance(verification, dict):
        return [], None
    requested = verification.get("requested")
    if not isinstance(requested, list) or not all(isinstance(item, str) for item in requested):
        return [], f"{path}: malformed negative-verification request"
    if len(requested) != len(set(requested)):
        return [], f"{path}: duplicate negative-verification request"
    if requested and verification.get("passed") is not True:
        return [], None
    return requested, None


def _result_rows(path: Path, report: dict[str, object]) -> tuple[dict[str, dict[str, object]], str | None]:
    raw_results = report.get("results")
    if not isinstance(raw_results, list):
        return {}, f"{path}: malformed results array"
    rows: dict[str, dict[str, object]] = {}
    for row in raw_results:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            return {}, f"{path}: malformed result row"
        clause_id = row["id"]
        if clause_id in rows:
            return {}, f"{path}: duplicate result row {clause_id}"
        rows[clause_id] = row
    return rows, None


def _evaluate_requested(path: Path, requested: list[str], rows: dict[str, dict[str, object]],
                        clauses: dict[str, str]) -> tuple[set[str], list[str]]:
    proven: set[str] = set()
    errors: list[str] = []
    for clause_id in requested:
        row = rows.get(clause_id)
        if clause_id not in clauses:
            errors.append(f"{path}: unknown or retracted clause {clause_id}")
        elif row is None or row.get("verdict") != "divergent":
            errors.append(f"{path}: {clause_id} is not divergent")
        elif row.get("negative_fixture") != clauses[clause_id]:
            errors.append(f"{path}: {clause_id} fixture identity drifted")
        else:
            proven.add(clause_id)
    return proven, errors


def _validated_report(path: Path) -> tuple[dict[str, object] | None, str | None]:
    report, problem = _load_regular_json(path, "report")
    if problem:
        return None, f"{path}: {problem}"
    if not isinstance(report, dict) or report.get("schema") != "brix.conform.v1":
        return None, f"{path}: unsupported report schema"
    return report, _bundle_problem(path, report)


def evidence_from_report(path: Path, clauses: dict[str, str]) -> tuple[set[str], list[str]]:
    """Validate one report and return proven clause IDs plus diagnostics."""
    if path.name != BUNDLE_REPORTS[0]:
        return set(), [f"{path}: non-canonical report filename"]
    report, problem = _validated_report(path)
    if problem:
        return set(), [problem]
    assert report is not None
    requested, problem = _requested_clauses(path, report)
    if problem or not requested:
        return set(), [problem] if problem else []
    rows, problem = _result_rows(path, report)
    if problem:
        return set(), [problem]
    return _evaluate_requested(path, requested, rows, clauses)


def audit(inputs: list[Path], ledger: Path = LEDGER) -> dict[str, object]:
    """Return deterministic coverage and integrity findings for report inputs."""
    clauses = executable_clauses(ledger)
    covered: set[str] = set()
    errors: list[str] = []
    reports = report_paths(inputs)
    for path in reports:
        report_covered, report_errors = evidence_from_report(path, clauses)
        covered.update(report_covered)
        errors.extend(report_errors)
    return {
        "schema": "brix.conform.negative-coverage.v1",
        "reports": len(reports),
        "executable": len(clauses),
        "covered": sorted(covered),
        "missing": sorted(set(clauses) - covered),
        "errors": errors,
    }


def _render(result: dict[str, object]) -> None:
    print(f"reports={result['reports']} covered={len(result['covered'])}/"
          f"{result['executable']} missing={len(result['missing'])}")
    if result["missing"]:
        print("missing: " + " ".join(result["missing"]))
    for error in result["errors"]:
        diagnostic("ERROR", "tools/diag/conform_negative_coverage.py", "main", error)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    result = audit(args.inputs)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        _render(result)
    if result["errors"]:
        return 2
    return 1 if args.require_complete and result["missing"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
