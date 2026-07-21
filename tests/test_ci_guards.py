"""Execute the real ``tools/ci`` Python guards inside the pytest suite.

``test_source_guards.py`` asserts the pure-Python *verdict twins* and drives
their injected-tree negatives; this module runs the actual ``tools/ci/*.py``
guard scripts — the exact artifacts ``.github/workflows/guards.yml`` invokes —
so a guard that reddens in CI reddens the local suite too. The fleet was ported
``.sh`` → ``.py`` on 2026-07-21; no bash is involved.

Lanes:
  - fast static guards — text scans, well under the 30s cap; asserted green.
  - lizard-backed guards (CCN + copy-paste) — skipped when the analyzer is
    absent (CI pip-installs it); given headroom past the default timeout.
  - analyzer/coverage runners — need a configured nginx build plus an external
    tool and run for minutes, so they are ``slow`` (nightly) and self-skip when
    their prerequisites are missing.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

CI = Path(__file__).resolve().parents[1] / "tools" / "ci"


def _run(name: str) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(CI / f"{name}.py")],
        capture_output=True,
        text=True,
    )
    return p.returncode, p.stdout + p.stderr


def _have(tool: str) -> bool:
    return bool(shutil.which(tool) or shutil.which(str(Path.home() / ".local/bin" / tool)))


# --- fast static guards -------------------------------------------------------
# The blocking guards.yml set (plus the shm-mutex/sd-driver/vfs guards): pure
# text scans that must exit 0 on the tree.
_FAST = [
    "check_config_coverage",
    "check_http_helper_reimpl",
    "check_metric_cardinality",
    "check_auth_verdict_sentinel",
    "check_shm_mutex",
    "check_sd_driver_conformance",
    "check_file_size",
    "check_todo_fixme",
    "check_doc_paths",
    "check_doc_links",
    "check_readme_coverage",
    "check_ports_doc",
    "check_vfs_seam",
    "check_vfs_identity_branch",
]


@pytest.mark.parametrize("guard", _FAST)
def test_ci_guard_green(guard: str) -> None:
    rc, out = _run(guard)
    assert rc == 0, f"tools/ci/{guard}.py failed (exit {rc}):\n{out}"


# --- lizard-backed ratchets ---------------------------------------------------
# check_duplication runs lizard over three trees (~18s here), so lift the cap.
@pytest.mark.skipif(not _have("lizard"), reason="lizard not installed (pip install --user lizard)")
@pytest.mark.timeout(120)
@pytest.mark.parametrize("guard", ["check_complexity", "check_duplication"])
def test_ci_lizard_guard_green(guard: str) -> None:
    rc, out = _run(guard)
    assert rc == 0, f"tools/ci/{guard}.py failed (exit {rc}):\n{out}"


# --- static-analysis / coverage runners (nightly) -----------------------------
# Need the configured build at /tmp/nginx-1.28.3 and an external analyzer; they
# run for minutes. Marked slow and self-skipping so the fast lane never pays for
# them, while ``run_suite --nightly`` still exercises the real Python runner.
_NGX_BUILD = Path("/tmp/nginx-1.28.3/objs/Makefile")


@pytest.mark.slow
@pytest.mark.timeout(1800)
@pytest.mark.parametrize(
    "runner,tool",
    [("run_fanalyzer", "gcc"), ("run_codechecker", "CodeChecker")],
)
def test_ci_analyzer_runner_green(runner: str, tool: str) -> None:
    if not _NGX_BUILD.exists():
        pytest.skip("configured nginx build tree absent (/tmp/nginx-1.28.3)")
    if not _have(tool):
        pytest.skip(f"{tool} not installed")
    rc, out = _run(runner)
    assert rc == 0, f"tools/ci/{runner}.py failed (exit {rc}):\n{out}"


@pytest.mark.slow
@pytest.mark.timeout(1800)
def test_ci_coverage_runner_green() -> None:
    # coverage.py self-skips (exit 0) when lcov/gcov or the build are absent, and
    # otherwise does a full instrumented build + suite run — nightly territory.
    rc, out = _run("coverage")
    assert rc == 0, f"tools/ci/coverage.py failed (exit {rc}):\n{out}"
