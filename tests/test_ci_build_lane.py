"""Guards the "main compiles and runs" lane — .github/workflows/build.yml.

Before this lane existed, every CI job was either static (guards, loc), analyzer-
only (fanalyzer/codechecker compile but never link a runnable tree), or tolerant
of not running at all (asan/coverage exit 0 when a prerequisite is missing). Two
whole classes of breakage could therefore reach main with a green tick:

  1. does not COMPILE from a clean checkout — the shape of the missing
     `shared/xrdproto/libxrdproto.a` rule that kept `asan` red for weeks, and
     which no developer tree reproduces because it always carries the artefact;
  2. compiles but does not RUN — nothing executed the module end to end.

build.yml closes both, and tools/ci/smoke.py is the "it runs" half. The value of
both rests on properties that are easy to delete by accident — a
`continue-on-error:` here, a silent skip there — so they are asserted, not
assumed. The last group also holds every lane to the same operational hygiene:
a job with no timeout can pin a runner for six hours, and a workflow with no
`permissions:` inherits a write-scoped token it has no use for.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
BUILD_YML = WORKFLOWS / "build.yml"
SMOKE = ROOT / "tools" / "ci" / "smoke.py"

# Lanes that must gate a PR. A lane not in this set may be cron-only; one in it
# that stops running per-PR stops protecting main.
BLOCKING_LANES = ("build.yml", "guards.yml", "loc.yml", "fuzz.yml")


def _doc(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    # PyYAML parses the bare `on:` key as boolean True under YAML 1.1.
    return doc.get("on", doc.get(True, {}))


def _steps(doc: dict) -> list[dict]:
    return [s for job in doc["jobs"].values() for s in job.get("steps", [])]


def _run_text(doc: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps(doc))


# --- success: the lane exists and does what it claims -------------------------


def test_the_build_lane_gates_every_pull_request() -> None:
    doc = _doc(BUILD_YML)
    triggers = _triggers(doc)
    assert "pull_request" in triggers, "build.yml no longer runs on PRs"
    assert "main" in (triggers.get("push") or {}).get("branches", []), (
        "build.yml no longer runs on pushes to main"
    )


def test_the_build_lane_actually_builds_both_halves() -> None:
    """Module and client: a lane that builds one half misses the other's breaks."""
    run = _run_text(_doc(BUILD_YML))
    assert "./configure" in run and "--add-module=" in run, (
        "build.yml must configure nginx WITH the module — that is the compile "
        "surface a bare nginx build never touches"
    )
    assert "-C /tmp/nginx-1.28.3" in run, "build.yml no longer makes the module"
    assert "-C client" in run, "build.yml no longer builds the client"


def test_the_build_lane_asks_the_clean_tree_question() -> None:
    """The regression that motivated the lane: a link with no rule to rebuild.

    An incremental developer tree cannot see it; only deleting the artefact and
    rebuilding at -j1 (so it is about the graph, not a race) can."""
    run = _run_text(_doc(BUILD_YML))
    assert "libxrdproto.a" in run and "rm -f" in run, (
        "build.yml no longer deletes the protocol archive before rebuilding — "
        "the exact hole that let a broken clean build reach main"
    )
    assert "-j1" in run, "the clean rebuild must be serial to test the graph"


def test_the_build_lane_runs_the_smoke() -> None:
    """Compiling is not running."""
    assert "tools/ci/smoke.py" in _run_text(_doc(BUILD_YML)), (
        "build.yml no longer executes the module it just built"
    )


# --- error / security-negative: the lane cannot be quietly defanged -----------


@pytest.mark.parametrize("name", BLOCKING_LANES)
def test_blocking_lanes_are_not_advisory(name: str) -> None:
    """`continue-on-error` turns a gate into a decoration."""
    doc = _doc(WORKFLOWS / name)
    for job_name, job in doc["jobs"].items():
        # corpus-writeback is a nightly write-back job, not a gate.
        if job_name == "corpus-writeback":
            continue
        assert not job.get("continue-on-error"), (
            f"{name}:{job_name} is continue-on-error — it reports failure as success"
        )
        for step in job.get("steps", []):
            assert not step.get("continue-on-error"), (
                f"{name}:{job_name} has a continue-on-error step: {step.get('name')}"
            )


def test_the_smoke_has_no_silent_skip_path() -> None:
    """A lane that skips proves nothing — and skipping counts as passing.

    This is the exact pathology that made `asan` green while booting no fleet
    (2026-08-06): every prerequisite of this script is an output of the job that
    runs it, so a missing one is a broken build, never an unsuitable runner."""
    source = SMOKE.read_text(encoding="utf-8")
    for forbidden in ("pytest.skip", "SKIP", "sys.exit(0)"):
        assert forbidden not in source, (
            f"tools/ci/smoke.py contains {forbidden!r} — the smoke must fail, "
            f"not skip, when it cannot run"
        )


def test_a_missing_artefact_fails_the_smoke(tmp_path: Path, monkeypatch) -> None:
    """Drive the real resolver: absent binaries must exit non-zero, not skip."""
    spec = importlib.util.spec_from_file_location("ci_smoke", SMOKE)
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)

    monkeypatch.setenv("TEST_NGINX_BIN", str(tmp_path / "no-such-nginx"))
    monkeypatch.setenv("TEST_XRDCP_BIN", str(tmp_path / "no-such-xrdcp"))
    with pytest.raises(SystemExit) as exit_info:
        smoke._resolve_binaries()
    assert exit_info.value.code == 1

    # A file that exists but is not executable is the subtler case: the build
    # produced something, and the lane must still refuse it.
    dud = tmp_path / "dud"
    dud.write_text("#!/bin/sh\n")
    os.chmod(dud, 0o644)
    monkeypatch.setenv("TEST_NGINX_BIN", str(dud))
    monkeypatch.setenv("TEST_XRDCP_BIN", str(dud))
    with pytest.raises(SystemExit) as exit_info:
        smoke._resolve_binaries()
    assert exit_info.value.code == 1


def test_the_smoke_verifies_the_bytes_not_just_the_exit_code() -> None:
    """A handshake that transfers nothing must not pass for a working read."""
    source = SMOKE.read_text(encoding="utf-8")
    assert "sha256" in source, "the smoke no longer compares payload digests"


# --- hygiene: every lane, not just this one -----------------------------------


@pytest.mark.parametrize(
    "workflow", sorted(p.name for p in WORKFLOWS.glob("*.yml")),
)
def test_every_job_has_a_timeout(workflow: str) -> None:
    """A hung job holds a runner until GitHub's 6h ceiling and blocks the queue."""
    doc = _doc(WORKFLOWS / workflow)
    for job_name, job in doc["jobs"].items():
        assert job.get("timeout-minutes"), (
            f"{workflow}:{job_name} has no timeout-minutes"
        )


@pytest.mark.parametrize(
    "workflow", sorted(p.name for p in WORKFLOWS.glob("*.yml")),
)
def test_every_workflow_declares_a_token_scope(workflow: str) -> None:
    """Least privilege: a lane that only reads code must not hold a write token."""
    doc = _doc(WORKFLOWS / workflow)
    assert "permissions" in doc, (
        f"{workflow} declares no top-level permissions — it inherits the "
        f"repository default, which may be write"
    )
