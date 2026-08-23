"""Repository-wide Python complexity contracts."""

from __future__ import annotations

from collections import Counter
from itertools import islice
from pathlib import Path

import pytest
import python_quality_lib as quality


@pytest.mark.timeout(300)
def test_full_brix_cache_python_complexity_limits() -> None:
    report = quality.score_repository()
    assert report.errors == (), "Python metric analysis failed:\n" + "\n".join(report.errors)
    failed = quality.violations(report.scores)
    summary = _violation_summary(failed)
    details = "\n".join(_violation_samples(failed))
    assert failed == [], (
        f"{len(failed)} Python complexity limits exceeded ({summary}):\n{details}"
    )


def _violation_summary(failed: list[str]) -> str:
    counts = Counter(message.split(" ", 1)[0] for message in failed)
    return ", ".join(f"{metric}={counts[metric]}" for metric in quality.LIMITS)


def _violation_samples(failed: list[str]) -> list[str]:
    samples = []
    for metric in quality.LIMITS:
        matching = (message for message in failed if message.startswith(f"{metric} "))
        samples.extend(islice(matching, 25))
    return samples


def test_python_quality_scan_covers_the_full_repository() -> None:
    covered = {path.relative_to(quality.ROOT).parts[0] for path in quality.python_files()}
    expected = {"tests", "tools", "utils", "client", "k8s-tests", "docs"}
    assert expected <= covered
    assert {"tests", "client", "shared", "src"} <= set(quality.SCAN_ROOTS)
    # brixtest/ ships its own wheel and its own copy of this contract at
    # equal-or-tighter limits; scoring it twice lets the two gates drift.
    assert "brixtest" not in quality.SCAN_ROOTS


def test_python_quality_scans_every_required_tree(tmp_path: Path) -> None:
    required = {"tests", "client", "shared", "src"}
    for name in required:
        path = tmp_path / name / "probe.py"
        path.parent.mkdir()
        path.write_text("def probe():\n    return 1\n")
    found = {path.relative_to(tmp_path).parts[0] for path in quality.python_files(tmp_path)}
    assert required <= found


def test_duplicate_declarations_have_distinct_stable_identities(tmp_path: Path) -> None:
    path = tmp_path / "duplicates.py"
    path.write_text("def same():\n    pass\n\ndef same():\n    pass\n")
    assert [item.symbol for item in quality._functions(path)] == ["same", "same#2"]


def test_all_python_quality_metrics_score_functions() -> None:
    source = """\
def sample(items):
    for item in items:
        if item and item.ready:
            return item.value + 1
    return 0
"""
    scores = quality.source_scores(source)
    assert set(scores) == set(quality.LIMITS)
    assert all(value > 0 for value in scores.values())


def test_npath_multiplies_sequential_branches() -> None:
    function = _function(
        """\
def sample(a, b):
    if a:
        pass
    if a and b:
        pass
"""
    )
    assert quality.NPathScorer().block(function.body) == 6


def test_npath_does_not_extend_paths_after_return() -> None:
    function = _function(
        "def sample(a, b):\n    if a:\n        return 1\n    if b:\n        return 2\n    return 3\n"
    )
    assert quality.NPathScorer().block(function.body) == 3


def test_assertions_are_counted_as_executable_failure_paths() -> None:
    function = _function("def sample(a, b):\n    assert a and b\n")
    assert quality.NPathScorer().block(function.body) == 3


def test_ccn_counts_independent_boolean_and_control_paths() -> None:
    scores = quality.source_scores(
        "def sample(a, b):\n    if a and b:\n        return 1\n    return 0\n"
    )
    assert scores["ccn"] == 3


def test_nesting_treats_elif_as_a_peer_branch() -> None:
    function = _function(
        """\
def sample(value):
    if value == 1:
        return 1
    elif value == 2:
        return 2
    return 0
"""
    )
    assert quality.NestingScorer().score(function) == 1


def test_cognitive_complexity_charges_for_nested_decisions() -> None:
    scores = quality.source_scores(
        "def sample(a, b):\n    if a:\n        while b:\n            break\n"
    )
    assert scores["cognitive"] == 3


def test_halstead_difficulty_uses_operator_and_operand_vocabulary() -> None:
    scores = quality.source_scores("def sample(left, right):\n    return left + right\n")
    assert scores["halstead"] == pytest.approx(0.5)


def test_halstead_does_not_invent_compound_expression_operands() -> None:
    scores = quality.source_scores("def sample(a, b, c):\n    return a + b * c\n")
    assert scores["halstead"] == pytest.approx(1.0)


def test_lambda_control_flow_is_visible_to_authoritative_analyzers() -> None:
    scores = quality.source_scores(
        "def sample(items):\n    return filter(lambda item: item.ready and item.valid, items)\n"
    )
    assert scores["npath"] == 2
    assert scores["ccn"] == 2
    assert scores["cognitive"] == 1


def test_quality_limits_reject_every_hotspot_without_exemptions() -> None:
    score = quality.Score("npath", "tests/example.py", 7, "sample", 600.0)
    assert quality.violations((score,)) == [
        "npath limit: tests/example.py:7:sample (600 > 15)"
    ]


def _function(source: str):
    import ast

    return next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef))
