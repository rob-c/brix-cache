#!/usr/bin/env python3
"""Corpus write-back bot for the libFuzzer lane (hyper-hardening B-3, Fix 2).

WHAT: minimizes every tests/fuzz harness's committed corpus with libFuzzer's
      `-merge=1` (keep only inputs that add coverage), replaces the committed
      corpus with that coverage-minimal set, and — only under --commit — git
      commits the reduced corpora back so nightly fuzzing compounds coverage
      instead of re-discovering the same inputs each run.

WHY:  B-3 Fix 1 (smoke) and the nightly soak already run; Fix 2 ("corpus
      minimization committed back so coverage compounds") was deferred because it
      is a git-write automation that must live under its own review rather than
      folded into the fuzz scaffold. This is that automation: a bot, not a
      developer, performs the write, and only on the nightly/dispatch job on main.

SAFETY (why this is not a HARD-BLOCK git-write by the agent):
  * The git path runs ONLY under --commit, which the workflow passes solely on
    `schedule`/`workflow_dispatch` for `main` — never on pull_request, so an
    untrusted PR can never drive a push.
  * It stages ONLY the tests/fuzz/corpus_* directories (asserted before commit);
    a stray change anywhere else aborts the commit rather than sweeping it in.
  * Default (no --commit) is a dry run: it minimizes into scratch and reports the
    coverage delta without touching the working tree, so the same code path is
    unit-testable with zero git side effects.

HOW:  reuses cmdscripts.fuzz_all.BUILD_ARGS as the single build-recipe source of
      truth (CI, local pytest, and this bot all build identically), so a new
      harness is picked up here the moment it is registered there.

Usage:
    tools/ci/fuzz_corpus_writeback.py             # dry run: report deltas only
    tools/ci/fuzz_corpus_writeback.py --commit    # minimize + git commit/push (CI)
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "tests"

# Import the shared build recipes (single source of truth with the fuzz smoke).
sys.path.insert(0, str(TESTS_DIR))
from cmdscripts.fuzz_all import BUILD_ARGS, FUZZ_DIR  # noqa: E402

BOT_NAME = "brix-fuzz-corpus-bot"
BOT_EMAIL = "brix-fuzz-corpus-bot@users.noreply.github.com"


def _corpus_dir(target: str) -> Path:
    """Committed corpus directory for a harness, matching fuzz_all's convention."""
    return FUZZ_DIR / f"corpus_{target.removeprefix('fuzz_')}"


def _run(argv: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True)


def minimize_one(target: str, build_args: list[str], write: bool = False) -> tuple[bool, bool, str]:
    """Build `target` and minimize its corpus.

    Returns (ok, changed, message). `changed` is True when the coverage-minimal
    set differs from the committed set (files added or dropped). The committed
    corpus is overwritten with the minimal set only when `write` is True; a dry
    run (`write=False`) reports the delta without touching the working tree.
    """
    built = _run(build_args, cwd=FUZZ_DIR)
    if built.returncode != 0:
        return False, False, f"build {target} failed: {(built.stderr or built.stdout)[-800:]}"

    corpus = _corpus_dir(target)
    corpus.mkdir(exist_ok=True)
    before = {p.name for p in corpus.iterdir() if p.is_file()}

    with tempfile.TemporaryDirectory(prefix=f"merge_{target}.") as tmp:
        merged = Path(tmp)
        # `-merge=1 DEST SRC` keeps only the SRC inputs that add coverage in DEST.
        # Merging the committed corpus into an empty DEST yields the minimal set.
        run = _run([str(FUZZ_DIR / target), "-merge=1", str(merged), str(corpus)], cwd=FUZZ_DIR)
        if run.returncode != 0:
            return False, False, f"merge {target} failed: {(run.stderr or run.stdout)[-800:]}"

        after = {p.name for p in merged.iterdir() if p.is_file()}
        changed = after != before
        # Persist the minimized set over the committed corpus only when writing
        # back; a dry run leaves the working tree untouched.
        if write:
            _replace_corpus(corpus, merged)

    added = len(after - before)
    dropped = len(before - after)
    msg = f"{target}: {len(after)} inputs (+{added}/-{dropped}){' [changed]' if changed else ''}"
    return True, changed, msg


def _replace_corpus(corpus: Path, minimized: Path) -> None:
    """Replace the contents of `corpus` with the files in `minimized`."""
    for p in corpus.iterdir():
        if p.is_file():
            p.unlink()
    for p in minimized.iterdir():
        if p.is_file():
            (corpus / p.name).write_bytes(p.read_bytes())


def _staged_paths() -> list[str]:
    out = _run(["git", "diff", "--cached", "--name-only"], cwd=REPO_ROOT)
    return [ln for ln in out.stdout.splitlines() if ln.strip()]


def commit_corpora(changed_targets: list[str]) -> str:
    """Stage the corpus dirs of changed targets and commit/push them.

    Aborts (raising) if anything OUTSIDE tests/fuzz/corpus_* is staged — the bot
    commits corpora and nothing else.
    """
    if not changed_targets:
        return "no corpus changes — nothing to commit"

    for target in changed_targets:
        _run(["git", "add", "--", str(_corpus_dir(target).relative_to(REPO_ROOT))], cwd=REPO_ROOT)

    staged = _staged_paths()
    stray = [p for p in staged if not p.startswith("tests/fuzz/corpus_")]
    if stray:
        _run(["git", "reset", "-q"], cwd=REPO_ROOT)
        raise SystemExit(f"refusing to commit: non-corpus paths staged: {stray}")
    if not staged:
        return "no corpus changes after staging — nothing to commit"

    msg = (
        "chore(fuzz): auto-minimize libFuzzer corpora\n\n"
        "Coverage-minimal corpora from the nightly -merge=1 pass "
        f"({len(changed_targets)} target(s) changed). Bot-generated; "
        "see tools/ci/fuzz_corpus_writeback.py (hyper-hardening B-3)."
    )
    commit = _run(
        ["git", "-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}",
         "commit", "-m", msg],
        cwd=REPO_ROOT,
    )
    if commit.returncode != 0:
        raise SystemExit(f"commit failed: {(commit.stderr or commit.stdout)[-800:]}")
    push = _run(["git", "push"], cwd=REPO_ROOT)
    if push.returncode != 0:
        raise SystemExit(f"push failed: {(push.stderr or push.stdout)[-800:]}")
    return f"committed + pushed {len(staged)} corpus file change(s)"


def entry(argv: list[str]) -> int:
    commit = "--commit" in argv
    results: list[tuple[bool, str]] = []
    changed_targets: list[str] = []

    for target, build_args in BUILD_ARGS.items():
        ok, changed, msg = minimize_one(target, build_args, write=commit)
        results.append((ok, msg))
        if ok and changed:
            changed_targets.append(target)

    for ok, msg in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {msg}")

    if not all(ok for ok, _ in results):
        return 1

    if commit:
        print(commit_corpora(changed_targets))
    else:
        print(
            f"dry run: {len(changed_targets)} target(s) would change corpus "
            f"({', '.join(changed_targets) or 'none'}); pass --commit to write back"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(entry(sys.argv[1:]))
