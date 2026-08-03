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

import os
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
    "check_client_build_coverage",
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
    "check_python_deps",
    "check_version_sync",
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


# --- every guard is executable + reachable from guards.yml -------------------
# A guard is only as good as CI's ability to RUN it: `.github/workflows/guards.yml`
# invokes each one as a bare `tools/ci/check_*.py`, so a script committed without
# its mode bit fails with "Permission denied" and the check it owns silently stops
# being enforced. That is exactly how check_gridftp_interop_image.py stopped
# running (found 2026-08-03), and nothing in the suite would have caught it.


def _load(stem: str):
    """Import a tools/ci module by path — that tree has no ``__init__.py``."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(stem, CI / f"{stem}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_GUARD_SET = _load("guard_set")


def _ci_guard_scripts() -> list[Path]:
    return _GUARD_SET.guard_scripts()


@pytest.mark.parametrize("script", _ci_guard_scripts(), ids=lambda p: p.name)
def test_ci_guard_script_is_executable(script: Path) -> None:
    assert os.access(script, os.X_OK), (
        f"{script.relative_to(CI.parents[1])} is not executable — guards.yml runs it "
        f"as a bare path, so it would fail with 'Permission denied' and stop "
        f"enforcing anything. Fix with: chmod +x {script.relative_to(CI.parents[1])}"
    )


def test_ci_guard_scripts_have_a_shebang(script_dir: Path = CI) -> None:
    """A bare `tools/ci/foo.py` invocation also needs the interpreter line."""
    missing = [
        p.name
        for p in _ci_guard_scripts()
        if not p.read_text().startswith("#!/usr/bin/env python3")
    ]
    assert not missing, f"guards missing a python3 shebang: {missing}"


# Guards that deliberately do NOT block CI. Each needs a reason: an exemption
# without one is how a guard quietly stops mattering.
_NOT_IN_CI = {
    # Copy-paste detector. Its backlog ratchet is behind the tree (100+ frozen
    # clones, several in generated/ported code), so it runs advisory-only until
    # that backlog is burned down; wiring it in today would redden every PR.
    "check_duplication.py",
}


def test_workflow_runs_every_guard_script() -> None:
    """Every tools/ci/check_*.py is wired into the guards workflow.

    A guard nobody invokes is documentation, not enforcement — this catches the
    other half of the same failure mode as the mode-bit test above."""
    wired = {p.name for p in _GUARD_SET.ci_guards()}
    unwired = [
        p.name for p in _ci_guard_scripts() if p.name not in wired | _NOT_IN_CI
    ]
    assert not unwired, (
        f"guards not referenced by .github/workflows/guards.yml: {unwired}"
    )


# --- python dependency guard: negatives ---------------------------------------
# The green assertion in the fast lane proves the tree is clean; these prove each
# of the three rules actually bites. Every case is a synthetic root, so nothing
# here depends on the real requirements files staying as they are today.
_DEPS = _load("check_python_deps")


def _deps_tree(tmp_path: Path, required: str, optional: str, source: str) -> Path:
    (tmp_path / "tests").mkdir(parents=True)
    (tmp_path / "requirements.txt").write_text(required)
    (tmp_path / "requirements-optional.txt").write_text(optional)
    (tmp_path / "requirements-dev.txt").write_text("lizard>=1.17,<2\n")
    (tmp_path / "k8s-tests/pytests").mkdir(parents=True)
    (tmp_path / "k8s-tests/pytests/requirements.txt").write_text("pytest>=7.0,<10\n")
    (tmp_path / "tests/test_thing.py").write_text(source)
    return tmp_path


def test_python_deps_guard_accepts_a_bounded_declared_tree(tmp_path) -> None:
    root = _deps_tree(
        tmp_path,
        "requests>=2.25,<3\n",
        "zstandard>=0.18,<1\n",
        "import pytest\nimport requests\n\nz = pytest.importorskip('zstandard')\n",
    )
    ok, findings = _DEPS.run(root)
    assert ok, findings


def test_python_deps_guard_rejects_a_one_sided_bound(tmp_path) -> None:
    """R2: an open-ended `>=` is how a new major enters CI unreviewed."""
    root = _deps_tree(tmp_path, "requests>=2.25\n", "", "import requests\n")
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("upper bound missing" in f for f in findings), findings


def test_python_deps_guard_rejects_an_undeclared_import(tmp_path) -> None:
    """R1: a package nobody wrote down is an ImportError in a fresh clone."""
    root = _deps_tree(tmp_path, "requests>=2.25,<3\n", "", "import paramiko\n")
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("paramiko" in f and "no requirements file" in f for f in findings), findings


def test_python_deps_guard_rejects_optional_imported_at_module_scope(tmp_path) -> None:
    """R3: the real bug this guard found — optional silently becoming required."""
    root = _deps_tree(
        tmp_path, "", "zstandard>=0.18,<1\n", "import zstandard\n"
    )
    ok, findings = _DEPS.run(root)
    assert not ok
    assert any("declared optional but imported" in f for f in findings), findings


def test_python_deps_guard_accepts_guarded_optional_imports(tmp_path) -> None:
    """A try/except or in-function import cannot break collection — allowed."""
    root = _deps_tree(
        tmp_path,
        "",
        "zstandard>=0.18,<1\n",
        "try:\n    import zstandard\nexcept ImportError:\n    zstandard = None\n\n"
        "def helper():\n    import zstandard as z\n    return z\n",
    )
    ok, findings = _DEPS.run(root)
    assert ok, findings


def test_python_deps_guard_ignores_stdlib_and_local_modules(tmp_path) -> None:
    """Only third-party names need declaring — no false positives on our own."""
    root = _deps_tree(tmp_path, "", "", "import json\nimport settings\n")
    (root / "tests/settings.py").write_text("HOST = 'localhost'\n")
    ok, findings = _DEPS.run(root)
    assert ok, findings


# --- version sync guard: negatives --------------------------------------------
# The fast lane proves the tree agrees with itself today. These prove the guard
# would have caught the drift that motivated it: the server reported 1.3.0 while
# CHANGELOG.md stopped at 1.0.8 and nothing failed. Synthetic roots throughout,
# so a future release does not have to edit these tests.
_VSYNC = _load("check_version_sync")


def _vsync_tree(
    tmp_path: Path,
    ident: str = "1.4.0",
    spec_fallback: str = "1.4.0",
    spec_changelog: str = "1.4.0-1\n- notes\n",
    changelog: str = "## v1.4.0 — 2026-08-03\n",
) -> Path:
    (tmp_path / "src/core").mkdir(parents=True)
    (tmp_path / "src/core/ident.h").write_text(
        f'#define BRIX_SERVER_VERSION_BARE  "{ident}"\n'
    )
    (tmp_path / "packaging/rpm").mkdir(parents=True)
    (tmp_path / "packaging/rpm/nginx-mod-brix-cache.spec").write_text(
        "%global upstream_version %{?version_override}"
        f"%{{!?version_override:{spec_fallback}}}\n"
        "Version:        %{upstream_version}\n\n"
        f"%changelog\n* Mon Aug 03 2026 Rob Currie <r@e> - {spec_changelog}"
    )
    (tmp_path / "CHANGELOG.md").write_text(f"# Changelog\n\n{changelog}\nnotes\n")
    return tmp_path


def test_version_sync_guard_accepts_an_aligned_tree(tmp_path) -> None:
    ok, lines = _VSYNC.run(_vsync_tree(tmp_path))
    assert ok, lines


def test_version_sync_guard_rejects_a_stale_spec_fallback(tmp_path) -> None:
    """The dangerous one: only a bare rpmbuild reads it, so drift ships a
    wrongly labelled RPM instead of failing."""
    ok, lines = _VSYNC.run(_vsync_tree(tmp_path, spec_fallback="1.3.0"))
    assert not ok
    assert any("upstream_version fallback is 1.3.0" in l for l in lines), lines


def test_version_sync_guard_rejects_a_changelog_that_stopped(tmp_path) -> None:
    """The literal reported defect: ident.h at 1.4.0, CHANGELOG.md at 1.0.8."""
    ok, lines = _VSYNC.run(
        _vsync_tree(tmp_path, changelog="## v1.0.8 — BriX namespace rebrand\n")
    )
    assert not ok
    assert any("newest entry is v1.0.8" in l for l in lines), lines


def test_version_sync_guard_rejects_a_missing_spec_changelog_entry(tmp_path) -> None:
    ok, lines = _VSYNC.run(_vsync_tree(tmp_path, spec_changelog="1.3.0-1\n- old\n"))
    assert not ok
    assert any("newest %changelog entry is 1.3.0-1" in l for l in lines), lines


def test_version_sync_guard_rejects_out_of_order_changelog(tmp_path) -> None:
    """Newest-first is what makes "the top entry" a meaningful anchor."""
    ok, lines = _VSYNC.run(
        _vsync_tree(tmp_path, changelog="## v1.4.0 — a\n\n## v1.3.0 — b\n\n## v1.9.0 — c\n")
    )
    assert not ok
    assert any("not newest-first at v1.9.0" in l for l in lines), lines


def test_version_sync_guard_compares_numerically_not_lexically(tmp_path) -> None:
    """1.10.0 is above 1.9.0; a string compare says otherwise and would redden
    a perfectly ordered changelog on the tenth minor release."""
    ok, lines = _VSYNC.run(
        _vsync_tree(
            tmp_path,
            ident="1.10.0",
            spec_fallback="1.10.0",
            spec_changelog="1.10.0-1\n- notes\n",
            changelog="## v1.10.0 — a\n\n## v1.9.0 — b\n",
        )
    )
    assert ok, lines


def test_version_sync_guard_reports_a_missing_source_of_truth(tmp_path) -> None:
    """No ident.h means nothing to synchronise against — fail loudly rather than
    silently passing a tree with no version at all."""
    (tmp_path / "CHANGELOG.md").write_text("## v1.4.0 — a\n")
    ok, lines = _VSYNC.run(tmp_path)
    assert not ok
    assert any("nothing to synchronise against" in l for l in lines), lines


# --- pre-push hook: it must run the guards it claims to run -------------------
# The hook globbed `tools/ci/check_*.sh` long after the fleet became Python. That
# matched nothing, so its "static invariant guards first" step enforced NOTHING —
# and since bash leaves an unmatched glob literal, the loop then tried to execute
# the pattern string and failed every push with "guard failed: check_*.sh". Both
# halves are regression-tested here: no filename patterns in the hook, and the
# resolver it calls returns a non-empty set.
_HOOK = CI.parents[1] / "tools" / "git-hooks" / "pre-push"


def test_prepush_hook_does_not_pattern_match_guard_filenames() -> None:
    """The hook asks guard_set.py for the list; it never globs for guards."""
    body = _HOOK.read_text()
    assert "check_*.sh" not in body, (
        "pre-push still globs check_*.sh — the guard fleet has been Python "
        "since 2026-07-21, so that matches nothing and enforces nothing"
    )
    assert "check_*" not in body, (
        "pre-push must not pattern-match guard filenames at all — ask "
        "tools/ci/guard_set.py, the single source of truth"
    )
    assert "guard_set.py" in body, "pre-push no longer invokes tools/ci/guard_set.py"


def test_prepush_guard_set_is_not_empty() -> None:
    """A resolver that returns nothing is the bug, not a clean tree."""
    rc, out = _run("guard_set")
    assert rc == 0, f"tools/ci/guard_set.py failed (exit {rc}):\n{out}"
    resolved = [Path(line) for line in out.splitlines() if line.strip()]
    assert resolved, "guard_set.py resolved an empty pre-push set"
    for p in resolved:
        assert p.is_file() and os.access(p, os.X_OK), f"{p} is not an executable guard"


def test_prepush_skips_are_ci_guards_with_a_reason() -> None:
    """Every documented skip names a guard CI still runs, and says why.

    A skip whose target no longer exists is a stale exemption; one without a
    reason is how a guard quietly stops mattering."""
    ci_names = {p.name for p in _GUARD_SET.ci_guards()}
    for name, reason in _GUARD_SET.PREPUSH_SKIP.items():
        assert name in ci_names, f"PREPUSH_SKIP names {name}, which CI does not run"
        assert reason.strip(), f"PREPUSH_SKIP[{name}] has no reason"


# --- pre-push hook: drive the real hook against a synthetic repo --------------
# The assertions above are textual; these execute tools/git-hooks/pre-push itself
# so the loop, the fail-closed branches and the guard exit-code plumbing are all
# covered. No git is involved: a stub `git` on PATH answers rev-parse, and a stub
# `cmdscripts.operator_runtime` makes the ~4min test tier a no-op.


def _hook_repo(tmp_path: Path, resolver: str, guards: dict[str, str]) -> Path:
    """A minimal tree the pre-push hook accepts, wired to fake guards."""
    repo = tmp_path / "repo"
    (repo / "tools/ci").mkdir(parents=True)
    (repo / "tests/cmdscripts").mkdir(parents=True)
    (repo / "tests/cmdscripts/operator_runtime.py").write_text("")

    for name, body in guards.items():
        g = repo / "tools/ci" / name
        g.write_text(body)
        g.chmod(0o755)

    rs = repo / "tools/ci/guard_set.py"
    rs.write_text(resolver)
    rs.chmod(0o755)

    fake_git = tmp_path / "bin" / "git"
    fake_git.parent.mkdir()
    fake_git.write_text(f'#!/bin/sh\necho "{repo}"\n')
    fake_git.chmod(0o755)
    return repo


def _run_hook(repo: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": f"{repo.parent / 'bin'}:{os.environ['PATH']}"}
    env.pop("SKIP_FAST_TESTS", None)
    return subprocess.run(
        ["bash", str(_HOOK)], cwd=repo, env=env, capture_output=True, text=True
    )


_RESOLVER = "#!/usr/bin/env python3\nprint({paths!r})\n"


def test_prepush_hook_runs_the_resolved_guards(tmp_path) -> None:
    stamp = tmp_path / "ran"
    repo = _hook_repo(
        tmp_path,
        _RESOLVER.format(paths=f"{tmp_path}/repo/tools/ci/check_ok.py"),
        {"check_ok.py": f"#!/bin/sh\necho ok > {stamp}\nexit 0\n"},
    )
    p = _run_hook(repo)
    assert p.returncode == 0, p.stdout + p.stderr
    assert stamp.exists(), "the hook did not execute the guard it resolved"


def test_prepush_hook_blocks_on_a_failing_guard(tmp_path) -> None:
    repo = _hook_repo(
        tmp_path,
        _RESOLVER.format(paths=f"{tmp_path}/repo/tools/ci/check_bad.py"),
        {"check_bad.py": "#!/bin/sh\nexit 3\n"},
    )
    p = _run_hook(repo)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "guard failed: check_bad.py" in p.stdout


@pytest.mark.parametrize(
    "resolver, expect",
    [
        # The original bug's shape: the guard set resolves to nothing. A hook
        # that shrugs here silently stops gating — it must fail closed.
        ("#!/usr/bin/env python3\npass\n", "resolved to nothing"),
        # Resolver itself broken/absent: likewise no evidence of a clean tree.
        ("#!/usr/bin/env python3\nraise SystemExit(2)\n", "cannot resolve"),
    ],
    ids=["empty-set", "resolver-error"],
)
def test_prepush_hook_fails_closed_without_a_guard_set(
    tmp_path, resolver: str, expect: str
) -> None:
    p = _run_hook(_hook_repo(tmp_path, resolver, {}))
    assert p.returncode == 1, p.stdout + p.stderr
    assert expect in p.stdout


def test_guard_set_selects_only_workflow_wired_guards(tmp_path) -> None:
    """CI-enforced is defined by guards.yml naming the script, nothing else."""
    (tmp_path / "tools/ci").mkdir(parents=True)
    (tmp_path / ".github/workflows").mkdir(parents=True)
    for name in ("check_wired.py", "check_orphan.py"):
        (tmp_path / "tools/ci" / name).write_text("#!/usr/bin/env python3\n")
    (tmp_path / ".github/workflows/guards.yml").write_text(
        "jobs:\n  guards:\n    steps:\n      - run: tools/ci/check_wired.py\n"
    )
    assert [p.name for p in _GUARD_SET.guard_scripts(tmp_path)] == [
        "check_orphan.py",
        "check_wired.py",
    ]
    assert [p.name for p in _GUARD_SET.ci_guards(tmp_path)] == ["check_wired.py"]
    assert [p.name for p in _GUARD_SET.prepush_guards(tmp_path)] == ["check_wired.py"]


def test_guard_set_errors_when_the_fleet_is_missing(tmp_path) -> None:
    """Finding no guards means a broken checkout, never a pass — exit non-zero.

    This is the failure the shell glob swallowed for weeks."""
    ci = tmp_path / "tools/ci"
    ci.mkdir(parents=True)
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/workflows/guards.yml").write_text("jobs: {}\n")
    shutil.copy(CI / "guard_set.py", ci / "guard_set.py")

    p = subprocess.run(
        [sys.executable, str(ci / "guard_set.py")], capture_output=True, text=True
    )
    assert p.returncode == 1, p.stdout + p.stderr
    assert "guard fleet is" in p.stderr
    assert not p.stdout.strip(), "an empty fleet must not print a usable guard list"


def test_fast_lane_covers_the_prepush_guard_set() -> None:
    """This module asserts green on exactly what the hook will run."""
    expected = {p.stem for p in _GUARD_SET.prepush_guards()}
    assert set(_FAST) == expected, (
        f"_FAST has drifted from the pre-push set: "
        f"missing={sorted(expected - set(_FAST))} extra={sorted(set(_FAST) - expected)}"
    )
