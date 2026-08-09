from split_continuation import reexport as _reexport
_reexport(globals(), "_test_ci_guards_helpers")

def test_python_deps_guard_ignores_stdlib_and_local_modules(tmp_path) -> None:
    """Only third-party names need declaring — no false positives on our own."""
    root = _deps_tree(tmp_path, "", "", "import json\nimport settings\n")
    (root / "tests/settings.py").write_text("HOST = 'localhost'\n")  # net-literal-allow: synthetic settings.py in a fixture repo tree
    ok, findings = _DEPS.run(root)
    assert ok, findings


# --- version sync guard: negatives --------------------------------------------
# The fast lane proves the tree agrees with itself today. These prove the guard
# would have caught the drift that motivated it: the server reported 1.3.0 while
# CHANGELOG.md stopped at 1.0.8 and nothing failed. Synthetic roots throughout,
# so a future release does not have to edit these tests.
_VSYNC = _load("check_version_sync")



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
