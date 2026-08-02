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
    "check_brix_namespace",
    "check_gridftp_interop_image",
]


@pytest.mark.parametrize("guard", _FAST)
def test_ci_guard_green(guard: str) -> None:
    rc, out = _run(guard)
    assert rc == 0, f"tools/ci/{guard}.py failed (exit {rc}):\n{out}"


# --- brix-namespace guard: negative (drift is actually caught) ----------------
# The green assertion above proves the tree is clean today; this proves the guard
# would redden if a pre-rebrand token crept back in (the exact P44 `xrdc_aconn`
# comment drift found in the phase-88 §5 reconciliation, 2026-07-30). Injects a
# residual into a scanned tree, asserts non-zero exit, and always cleans up.
_REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "rel,content",
    [
        ("src/core/_brix_ns_probe.h", "int xrootd_probe_symbol;\n"),
        ("client/lib/_brix_ns_probe.h", "struct xrdc_probe { int x; };\n"),
    ],
)
def test_brix_namespace_guard_catches_drift(rel: str, content: str) -> None:
    probe = _REPO / rel
    probe.write_text(content)
    try:
        rc, out = _run("check_brix_namespace")
    finally:
        probe.unlink()
    assert rc != 0, f"guard missed injected residual in {rel}:\n{out}"
    assert "_brix_ns_probe" in out, out


# --- file-size guard: client/ coverage + client/tests carve-out --------------
# The green assertion above proves the live tree is clean; this proves the
# Phase-38 extension that widened the scan from src/ to *also* cover client/
# (the ngx-free CLI + libbrix) while excluding client/tests/. Driven off an
# injected temp tree via list_oversized(root=...), so it is hermetic and
# independent of whatever the real backlog currently freezes.
def _load_check_file_size():
    import importlib.util

    path = CI / "check_file_size.py"
    spec = importlib.util.spec_from_file_location("check_file_size", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_file_size_guard_scans_client_and_excludes_client_tests(tmp_path) -> None:
    cfs = _load_check_file_size()
    big = "x();\n" * (cfs.CAP + 5)   # 605 newlines > cap
    small = "y();\n" * 10
    files = {
        "src/core/big_src.c": big,             # src offender  -> listed
        "client/apps/big_client.c": big,       # client offender -> listed (NEW)
        "client/lib/small_client.c": small,    # under cap -> absent
        "client/tests/c/big_test.c": big,      # excluded tree -> absent
        "client/tests/big_test.h": big,        # excluded tree -> absent
    }
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    listed = {path for path, _ in cfs.list_oversized(root=tmp_path)}
    assert "client/apps/big_client.c" in listed, "guard must now scan client/"
    assert "src/core/big_src.c" in listed, "guard must still scan src/"
    assert "client/lib/small_client.c" not in listed
    assert "client/tests/c/big_test.c" not in listed, "client/tests/ must be carved out"
    assert "client/tests/big_test.h" not in listed, "client/tests/ must be carved out"


# --- lizard-backed ratchets ---------------------------------------------------
# check_duplication runs lizard over three trees: ~18s on an 8-core CI runner
# but ~130s on a 4-core box, so the cap has to clear the slowest hardware we run
# on. (guards.yml invokes the guard directly, without this pytest timeout.)
@pytest.mark.skipif(not _have("lizard"), reason="lizard not installed (pip install --user lizard)")
@pytest.mark.timeout(300)
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
