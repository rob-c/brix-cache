"""Tests for tools/ci/check_metric_naming.py — the phase-110 W12 metric-surface
governance guard (M1 latency-unit lint + M2 self-deleting deprecation pin).

Hermetic: each case points the checker at a tiny fixture emitter tree
(BRIX_METRIC_SRC) and/or a fixture refactor-docs dir (BRIX_METRIC_REFACTOR_DOCS)
so the assertions never depend on the real tree's current state.

  * success   — the real tree passes --fail (every latency histogram is
                `_seconds` or a registered deprecation)
  * error M1  — a `_usec` latency histogram fixture is a finding
  * error M2  — a deprecated family whose removal phase is IMPLEMENTED and is
                still emitted is a finding (fires exactly when cleanup is due)
"""
import importlib.util as _ilu
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECK = os.path.join(ROOT, "tools", "ci", "check_metric_naming.py")


def _load():
    spec = _ilu.spec_from_file_location("cmn", CHECK)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_real_tree_passes_under_fail():
    """(success) The shipped emitters satisfy M1/M2: brix_io_latency_seconds is
    the canonical unit and brix_io_latency_usec is a registered deprecation."""
    r = subprocess.run([sys.executable, CHECK, "--fail"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


def test_m1_flags_a_usec_latency_histogram(tmp_path):
    """(error M1) A new `_usec` latency histogram, not registered deprecated,
    is a finding — it re-fragments the unified latency unit."""
    cmn = _load()
    src = tmp_path / "m"
    src.mkdir()
    (src / "x.c").write_text(
        '# HELP brix_frob_latency_usec frobs\\n'
        '# TYPE brix_frob_latency_usec histogram\\n')
    cmn.METRICS_DIR = str(src)
    cmn.DEPRECATED_METRICS = {}
    findings = cmn._rule_m1(cmn._metric_types())
    assert any(n == "brix_frob_latency_usec" for _, n, _ in findings), findings


def test_m1_exempts_a_seconds_histogram_and_a_gauge(tmp_path):
    """(success / non-vacuity) A `_seconds` latency histogram passes, and a
    `_usec` GAUGE (a config threshold, not a measurement) is not a finding."""
    cmn = _load()
    src = tmp_path / "m"
    src.mkdir()
    (src / "x.c").write_text(
        '# HELP brix_io_latency_seconds ok\\n'
        '# TYPE brix_io_latency_seconds histogram\\n'
        '# HELP brix_slowop_threshold_usec cfg\\n'
        '# TYPE brix_slowop_threshold_usec gauge\\n')
    cmn.METRICS_DIR = str(src)
    cmn.DEPRECATED_METRICS = {}
    assert cmn._rule_m1(cmn._metric_types()) == []


def test_m2_self_deleting_pin(tmp_path):
    """(error M2) A deprecated family still emitted after its removal phase is
    IMPLEMENTED is a finding; silent while the phase is unwritten/PLANNED."""
    cmn = _load()
    src = tmp_path / "m"
    src.mkdir()
    (src / "x.c").write_text(
        '# HELP brix_io_latency_usec dep\\n'
        '# TYPE brix_io_latency_usec histogram\\n')
    docs = tmp_path / "refactor"
    docs.mkdir()
    cmn.METRICS_DIR = str(src)
    cmn.REFACTOR_DOCS = str(docs)
    cmn.DEPRECATED_METRICS = {"brix_io_latency_usec": "phase-112"}
    # phase-112 absent -> dormant
    assert cmn._rule_m2(cmn._emitted_families()) == []
    # phase-112 IMPLEMENTED + still emitted -> fires
    (docs / "phase-112-x.md").write_text("**Status:** IMPLEMENTED\\n")
    findings = cmn._rule_m2(cmn._emitted_families())
    assert len(findings) == 1 and findings[0][0] == "M2", findings
