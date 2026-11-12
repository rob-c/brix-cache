"""Guards for the B-3 corpus write-back bot (tools/ci/fuzz_corpus_writeback.py).

The bot's load-bearing new logic is the git-write path: it must (1) only ever
stage the tests/fuzz/corpus_* directories, refusing to commit if anything else
is staged, and (2) never run at all on pull_request. A regression here would let
a fuzz-lane job push arbitrary tree changes, or let an untrusted PR trigger a
push. Both are tested hermetically — the module is imported directly and the
git path is driven against a throwaway repo — the same pattern
test_ci_asan_lane.py uses. A slow, self-skipping test drives the real
minimization end to end when clang+libFuzzer are present.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "tools" / "ci"


def _load_writeback():
    # The module imports cmdscripts.fuzz_all, which lives under tests/.
    sys.path.insert(0, str(ROOT / "tests"))
    spec = importlib.util.spec_from_file_location(
        "fuzz_corpus_writeback", CI / "fuzz_corpus_writeback.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


wb = _load_writeback()


@pytest.fixture(autouse=True)
def isolated_git_configuration(monkeypatch):
    """No checkout routing, identity or hooks may escape into fixture repos."""
    for key in list(os.environ):
        if key.startswith("GIT_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setattr(wb, "_push", lambda: pytest.fail("fixture must never push"))


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "tests" / "fuzz" / "corpus_demo").mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "seed").write_text("x")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


# --- git guard: only corpus paths, never anything else --------------------- #

def test_commit_refuses_non_corpus_staged(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    monkeypatch.setattr(wb, "REPO_ROOT", repo)
    monkeypatch.setattr(wb, "FUZZ_DIR", repo / "tests" / "fuzz")

    # A stray non-corpus change is already staged when the bot runs.
    (repo / "evil.txt").write_text("owned")
    _git(repo, "add", "evil.txt")

    with pytest.raises(SystemExit, match="non-corpus"):
        wb.commit_corpora(["fuzz_demo"])

    # The guard must have unstaged everything rather than committing.
    staged = _git(repo, "diff", "--cached", "--name-only").stdout.split()
    assert staged == [], f"guard left files staged: {staged}"
    # No new commit was created.
    assert _git(repo, "rev-list", "--count", "HEAD").stdout.strip() == "1"


def test_commit_noop_when_nothing_changed(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    monkeypatch.setattr(wb, "REPO_ROOT", repo)
    monkeypatch.setattr(wb, "FUZZ_DIR", repo / "tests" / "fuzz")
    # No changes in the corpus dir → nothing to commit, no error.
    msg = wb.commit_corpora(["fuzz_demo"])
    assert "nothing to commit" in msg
    assert _git(repo, "rev-list", "--count", "HEAD").stdout.strip() == "1"


def test_commit_empty_target_list_is_noop(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    monkeypatch.setattr(wb, "REPO_ROOT", repo)
    monkeypatch.setattr(wb, "FUZZ_DIR", repo / "tests" / "fuzz")
    assert "nothing to commit" in wb.commit_corpora([])


def test_corpus_dir_naming_matches_fuzz_all():
    # The bot and the smoke runner must agree on corpus directory names.
    assert wb._corpus_dir("fuzz_root_frame").name == "corpus_root_frame"


# --- workflow wiring: writeback never runs on PR --------------------------- #

def test_fuzz_workflow_writeback_job_gated():
    doc = yaml.safe_load((ROOT / ".github/workflows/fuzz.yml").read_text())
    jobs = doc["jobs"]
    assert "corpus-writeback" in jobs, "writeback job missing from fuzz.yml"
    job = jobs["corpus-writeback"]
    cond = job["if"]
    assert "schedule" in cond and "workflow_dispatch" in cond, cond
    assert "pull_request" not in cond, "writeback must NOT run on pull_request"
    assert job["permissions"]["contents"] == "write"
    steps = " ".join(str(s.get("run", "")) for s in job["steps"])
    assert "fuzz_corpus_writeback.py --commit" in steps
    assert "--review-branch" in steps
    assert "github.event.repository.default_branch" in cond
    assert "pull-requests" not in job["permissions"]


def _publication_fixture(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    remote = tmp_path / "remote.git"
    _git(repo, "init", "--bare", "-q", str(remote))
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "origin", "HEAD:main")
    monkeypatch.setattr(wb, "REPO_ROOT", repo)
    monkeypatch.setattr(wb, "FUZZ_DIR", repo / "tests/fuzz")
    for name, value in (("GITHUB_RUN_ID", "123"), ("GITHUB_RUN_ATTEMPT", "2"),
                        ("GITHUB_REF_NAME", "main"), ("BRIX_FUZZ_BASE_BRANCH", "main")):
        monkeypatch.setenv(name, value)
    (repo / "tests/fuzz/corpus_demo/input").write_bytes(b"seed")
    return repo, remote


def _reject_pushes(remote, expression):
    hook = remote / "hooks/update"
    hook.write_text('#!/bin/sh\n' + expression + '\n')
    hook.chmod(0o755)


def _record_publication(monkeypatch):
    original = wb._run
    calls = []

    def run(command, cwd):
        calls.append(command)
        return original(command, cwd)

    monkeypatch.setattr(wb, "_run", run)
    return calls


def test_corpus_publication_leaves_protected_main_unchanged(tmp_path, monkeypatch):
    repo, remote = _publication_fixture(tmp_path, monkeypatch)
    initial = _git(remote, "rev-parse", "main").stdout
    _reject_pushes(remote, '[ "$1" != refs/heads/main ]')
    calls = _record_publication(monkeypatch)
    message = wb.commit_corpora(["fuzz_demo"], review_branch=True)
    assert "published corpus review branch" in message
    assert _git(remote, "rev-parse", "main").stdout == initial
    branch = "automation/fuzz-corpora-123-2"
    assert _git(remote, "rev-parse", branch).stdout == _git(repo, "rev-parse", "HEAD").stdout
    assert _git(remote, "diff", "--name-only", "main", branch).stdout.splitlines() == [
        "tests/fuzz/corpus_demo/input"]
    pushes = [call for call in calls if call[:2] == ['git', 'push']]
    assert pushes == [["git", "push", "origin", f"HEAD:refs/heads/{branch}"]]


def test_corpus_publication_stops_after_rejected_push(tmp_path, monkeypatch):
    _, remote = _publication_fixture(tmp_path, monkeypatch)
    _reject_pushes(remote, "exit 1")
    calls = _record_publication(monkeypatch)
    with pytest.raises(SystemExit, match="corpus publication failed"):
        wb.commit_corpora(["fuzz_demo"], review_branch=True)
    assert calls[-1][:2] == ['git', 'push']


@pytest.mark.parametrize("variable,value", [
    ("GITHUB_RUN_ID", ""), ("GITHUB_RUN_ATTEMPT", "../../main"),
    ("GITHUB_REF_NAME", "untrusted-branch"), ("BRIX_FUZZ_BASE_BRANCH", ""),
])
def test_corpus_publication_refuses_untrusted_context(monkeypatch, variable, value):
    for name, setting in (("GITHUB_RUN_ID", "123"), ("GITHUB_RUN_ATTEMPT", "1"),
                          ("GITHUB_REF_NAME", "main"), ("BRIX_FUZZ_BASE_BRANCH", "main")):
        monkeypatch.setenv(name, setting)
    monkeypatch.setenv(variable, value)
    monkeypatch.setattr(wb, "_run", lambda *args, **kwargs: pytest.fail("must not publish"))
    with pytest.raises(SystemExit):
        wb._publish_review_branch()


# --- slow end-to-end: real minimization is a no-op on committed corpora ----- #

@pytest.mark.slow
@pytest.mark.suite_job
def test_dry_run_minimizes_without_touching_tree():
    import shutil
    if shutil.which("clang") is None:
        pytest.skip("clang not available")
    # Dry run over the real repo: must exit 0 and leave the working tree clean of
    # any *tracked* corpus modification (untracked new-harness corpora are fine).
    before = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--name-only", "--", "tests/fuzz"],
        capture_output=True, text=True).stdout
    rc = wb.entry([])  # dry run, no --commit
    assert rc == 0
    after = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--name-only", "--", "tests/fuzz"],
        capture_output=True, text=True).stdout
    assert before == after, "dry run modified tracked corpus files"
