"""Unit + integration guards for the B-2 ASan+UBSan CI lane (tools/ci/asan.py).

The lane's load-bearing new logic is (1) the report scanner that decides
pass/fail — a false negative here lets an A-2-class heap corruption reach main,
a false positive reddens every PR on the LSan suppression-accounting noise — and
(2) the sanitizer runtime env that filters the curated third-party leaks and
routes findings to files rather than crashing the fleet mid-test. Both are
tested hermetically (no sanitizer build) by importing the module directly, the
same pattern test_ci_guards.py uses for check_file_size.

A slow, self-skipping runner test drives the *real* orchestrator end to end
(build + fleet + scan) when the configured nginx tree is present — nightly
territory, exactly like test_ci_coverage_runner_green.

Since 2026-08-09 the lane is also a REQUIRED status check on main, which makes
its self-skips load-bearing in the other direction: a required check that exits
0 for a missing prerequisite is indistinguishable from one that passed, and
that is exactly how a sanitized fleet which could not boot stayed invisible.
The BRIX_CI_STRICT section below guards the conversion of every such skip into
a failure on the workflow — and only there, so a laptop without a compiler
still skips rather than failing.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

def _expression_1(lines, helper_start, helper_end):
    return (
        [
                (n, line.strip())
                for n, line in enumerate(lines, 1)
                if "asan: SKIP" in line and not helper_start < n < helper_end
            ]
    )


def _check_test_the_workflow_sets_the_strict_flag_on_the_driver_step_1(drivers):
    assert drivers, "no step runs tools/ci/asan.py"

def _check_test_the_workflow_sets_the_strict_flag_on_the_driver_step_2(step):
    assert str((step.get("env") or {}).get("BRIX_CI_STRICT")) == "1"

def _check_test_no_skip_path_bypasses_the_helper_3(stray):
    assert not stray, f"skip printed outside skip_or_fail(): {stray}"


CI = Path(__file__).resolve().parents[1] / "tools" / "ci"
ASAN_YML = Path(__file__).resolve().parents[1] / ".github/workflows/asan.yml"


def _load_asan():
    spec = importlib.util.spec_from_file_location("ci_asan", CI / "asan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


asan = _load_asan()


# --- report scanner: real findings are flagged -------------------------------
@pytest.mark.parametrize(
    "body",
    [
        "==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x...",
        "==999==ERROR: LeakSanitizer: detected memory leaks\nDirect leak of 40 byte(s)",
        "src/fs/vfs/vfs_io_core.c:88:12: runtime error: signed integer overflow",
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior vfs_io_core.c:88:12",
        "SUMMARY: AddressSanitizer: heap-buffer-overflow (/objs/nginx+0x...)",
    ],
)
def test_scanner_flags_real_findings(tmp_path, body):
    (tmp_path / "asan.12345").write_text(body)
    hits = asan._reports_with_findings(str(tmp_path))
    assert len(hits) == 1, f"real sanitizer finding not flagged:\n{body}"
    assert hits[0][0].endswith("asan.12345")


# --- report scanner: benign / suppression-only files are NOT flagged ---------
@pytest.mark.parametrize(
    "body",
    [
        "-----------------------------------------------------\n"
        "Suppressions used:\n  count      bytes template\n     3        128 libcrypto.so\n",
        "SANITIZE=1: leak/UBSan logs -> /tmp/xrd-test/sanitize/asan.<pid>\n",
        "",  # ASan opened the log but wrote nothing worth failing on
    ],
)
def test_scanner_ignores_clean_reports(tmp_path, body):
    (tmp_path / "asan.777").write_text(body)
    assert asan._reports_with_findings(str(tmp_path)) == [], (
        "benign/suppression-only report must not fail the lane"
    )


def test_scanner_empty_dir_is_clean(tmp_path):
    assert asan._reports_with_findings(str(tmp_path)) == []


# --- sanitizer env: findings are logged, not fatal; leaks are suppressed -----
def test_sanitizer_env_logs_and_suppresses(tmp_path):
    supp = str(tmp_path / "lsan.supp")
    env = asan._sanitizer_env({"PATH": "/usr/bin"}, str(tmp_path), supp)

    assert env["SANITIZE"] == "1"
    assert env["SANITIZE_LOG_DIR"] == str(tmp_path)
    # A finding must be RECORDED (log_path) and NON-fatal (abort_on_error=0,
    # exitcode=0) so the fleet keeps serving and every report is scannable —
    # the scan, not an abort, is the gate.
    assert "abort_on_error=0" in env["ASAN_OPTIONS"]
    assert "exitcode=0" in env["ASAN_OPTIONS"]
    assert f"log_path={tmp_path}/asan" in env["ASAN_OPTIONS"]
    assert "detect_leaks=1" in env["ASAN_OPTIONS"]
    # UBSan continues + records; LSan uses the curated suppressions and stays
    # quiet about accounting so clean runs leave no false-positive report.
    assert "halt_on_error=0" in env["UBSAN_OPTIONS"]
    assert f"suppressions={supp}" in env["LSAN_OPTIONS"]
    assert "print_suppressions=0" in env["LSAN_OPTIONS"]
    # Base env is preserved, not clobbered.
    assert env["PATH"] == "/usr/bin"


def test_error_signatures_cover_all_three_sanitizers():
    joined = "\n".join(asan.ERROR_SIGNATURES)
    assert "AddressSanitizer" in joined
    assert "UndefinedBehaviorSanitizer" in joined
    assert "LeakSanitizer" in joined
    assert "runtime error:" in joined  # UBSan's per-site form


# --- the workflow lane is wired -----------------------------------------------
def test_asan_workflow_present_and_invokes_runner():
    wf = (Path(__file__).resolve().parents[1] / ".github/workflows/asan.yml").read_text()
    assert "tools/ci/asan.py" in wf, "asan.yml must invoke the orchestrator"
    assert "pull_request" in wf and "schedule" in wf, "PR gate + nightly cron both required"


# --- the second driver leg (write-mirror disconnect suite) is wired ----------
def test_asan_runner_supports_second_driver_leg():
    """asan.py reads ASAN_TEST_CMD2 so the nightly can run the SERIAL write-mirror
    suite that the 'not serial' fast tier drops. Guarded by source inspection
    (running the real leg needs a sanitizer build — the slow runner covers that)."""
    src = (CI / "asan.py").read_text()
    assert 'os.environ.get("ASAN_TEST_CMD2")' in src, \
        "asan.py must honour ASAN_TEST_CMD2 (second sanitized driver leg)"
    # A non-zero exit from EITHER leg must fail the job — the OR keeps the first
    # failure visible rather than letting the second leg mask it.
    assert "suite_rc = suite_rc or rc2" in src, \
        "either driver leg failing must fail the lane"


def test_asan_nightly_drives_write_mirror_disconnect_suite():
    """The nightly cron must point ASAN_TEST_CMD2 at the write-mirror data-write
    suite — that is the phase-88 audit § 4 residual (the disconnect-mid-write
    UAF / heap-ownership replay paths run under ASan only via this suite)."""
    wf = (Path(__file__).resolve().parents[1] / ".github/workflows/asan.yml").read_text()
    assert "ASAN_TEST_CMD2" in wf, "nightly must set the second driver leg"
    assert "test_phase24_mirror.py" in wf and "data_write" in wf, \
        "nightly ASAN_TEST_CMD2 must drive the write-mirror data-write suite"


# --- BRIX_CI_STRICT: on the gating lane, a skip is not a pass ----------------
# The tolerant default is preserved for interactive runs; the workflow opts in.
def test_skip_is_still_a_pass_for_an_unset_strict_flag(monkeypatch, capsys):
    monkeypatch.delenv("BRIX_CI_STRICT", raising=False)
    assert asan.skip_or_fail("no nginx source") == 0
    assert "asan: SKIP — no nginx source" in capsys.readouterr().out


def test_missing_nginx_source_skips_a_local_run(monkeypatch, tmp_path, capsys):
    """The whole lane, driven for real: absent prerequisite, tolerant mode."""
    monkeypatch.delenv("BRIX_CI_STRICT", raising=False)
    monkeypatch.setenv("NGINX_SRC", str(tmp_path / "no-such-nginx"))
    assert asan.main() == 0
    assert "SKIP" in capsys.readouterr().out


def test_strict_turns_every_skip_into_a_failure(monkeypatch, capsys):
    monkeypatch.setenv("BRIX_CI_STRICT", "1")
    assert asan.skip_or_fail("sanitized fleet failed to boot") == 1
    out = capsys.readouterr().out
    assert "asan: FAIL — sanitized fleet failed to boot" in out
    assert "not a pass" in out
    assert "asan: SKIP" not in out


def test_missing_nginx_source_fails_the_ci_lane(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BRIX_CI_STRICT", "1")
    monkeypatch.setenv("NGINX_SRC", str(tmp_path / "no-such-nginx"))
    assert asan.main() == 1
    assert "FAIL" in capsys.readouterr().out


def test_the_workflow_sets_the_strict_flag_on_the_driver_step():
    """The flag has to reach the step that runs the lane, not merely the file."""
    workflow = yaml.safe_load(ASAN_YML.read_text(encoding="utf-8"))
    drivers = [
        step
        for job in workflow["jobs"].values()
        for step in job["steps"]
        if "tools/ci/asan.py" in (step.get("run") or "")
    ]
    _check_test_the_workflow_sets_the_strict_flag_on_the_driver_step_1(drivers)
    for step in drivers:
        _check_test_the_workflow_sets_the_strict_flag_on_the_driver_step_2(step)


@pytest.mark.parametrize("value", ["", "0", "false", "yes", "TRUE", " 1"])
def test_only_an_exact_one_enables_strict_mode(monkeypatch, value):
    """A typo'd flag must fail open (tolerant), never silently half-enable."""
    monkeypatch.setenv("BRIX_CI_STRICT", value)
    assert asan.strict() is False


def test_no_skip_path_bypasses_the_helper():
    """Every 'SKIP' the lane can print must come from ``skip_or_fail``.

    A new prerequisite written as ``print("asan: SKIP …"); return 0`` would
    restore the exact pathology this section exists to prevent, and would do so
    without touching a single test.
    """
    lines = (CI / "asan.py").read_text().splitlines()
    helper_start = next(
        n for n, line in enumerate(lines, 1) if line.startswith("def skip_or_fail")
    )
    helper_end = next(
        (n for n, line in enumerate(lines, 1)
         if n > helper_start and line and not line[0].isspace()),
        len(lines),
    )
    stray = _expression_1(lines, helper_start, helper_end)
    _check_test_no_skip_path_bypasses_the_helper_3(stray)


def test_no_unconditional_return_zero_guards_a_prerequisite():
    """``return 0`` may only appear as the lane's single success verdict.

    main() delegates its terminal verdict to _scan_verdict(); scan from that
    helper to end-of-file (both _scan_verdict and main), where exactly one
    unconditional ``return 0`` — the success verdict — is allowed. Every other
    early exit must route through skip_or_fail() (checked separately)."""
    text = (CI / "asan.py").read_text()
    anchor = "def _scan_verdict(" if "def _scan_verdict(" in text else "def main("
    body = text.split(anchor)[1]
    returns = [line.strip() for line in body.splitlines() if line.strip() == "return 0"]
    assert len(returns) == 1, (
        "the success path has more than one 'return 0' — a prerequisite is "
        "short-circuiting to success again; route it through skip_or_fail()"
    )


# --- real orchestrator, end to end (nightly, self-skipping) ------------------
# asan.py self-skips (exit 0) when the compiler / configured nginx source / a
# bootable fleet are absent, and otherwise does a full sanitized build + fleet
# boot + I/O drive + report scan — minutes, memory-hungry, nightly territory.
@pytest.mark.slow
@pytest.mark.suite_job
@pytest.mark.timeout(2400)
def test_ci_asan_runner_green():
    # Explicitly tolerant: this test asserts the orchestrator's own health, not
    # whether THIS host can host a sanitized fleet. An inherited BRIX_CI_STRICT
    # (a shell left over from reproducing the CI lane) would otherwise turn a
    # legitimate local skip into a spurious failure.
    env = {k: v for k, v in os.environ.items() if k != "BRIX_CI_STRICT"}
    p = subprocess.run(
        [sys.executable, str(CI / "asan.py")], capture_output=True, text=True, env=env
    )
    assert p.returncode == 0, (
        f"tools/ci/asan.py failed (exit {p.returncode}):\n{p.stdout}\n{p.stderr}"
    )
