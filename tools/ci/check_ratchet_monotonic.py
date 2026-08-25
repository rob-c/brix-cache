#!/usr/bin/env python3
#
# WHAT: Fail CI when a quality ratchet's own backlog file GROWS — a new
#       grandfathered entry, or a raised allowance on an existing one.
#
# WHY:  check_file_size.py, check_todo_fixme.py,
#       check_vfs_seam.py, lint_loc and friends all compare the live tree
#       against a frozen backlog. That makes each of them trivially defeatable
#       in the one direction nobody notices: append the offending file to the
#       backlog (or bump its recorded number) and the guard goes green while the
#       codebase gets worse. The ratchets are only ratchets if the backlogs can
#       move in exactly one direction, so this guards the guards: every listed
#       backlog may shrink freely and may never grow.
#
#       Deliberately NOT covered: the analyzer baselines (fanalyzer_baseline.txt,
#       codechecker_baseline.txt). They legitimately gain entries when new code
#       produces a new false positive, and they carry their own review
#       discipline (`--regen` with a reviewed diff). A ratchet that fires on
#       honest work gets regenerated blindly, which is worse than not having it.
#       check_duplication.py needs no entry here: its backlog was burned down
#       and deleted 2026-08-24 — the guard is zero-tolerance with no file to
#       grow.
#
# HOW:  Read each backlog at the base revision and in the working tree, parse
#       both into {entry -> allowance}, and report
#         - an entry present now and absent at the base            -> FAIL
#         - an entry whose numeric allowance went up               -> FAIL
#       "path<TAB>number" lines (file_size, complexity, todo_fixme, loc) carry
#       an allowance; every other non-comment line is an opaque entry whose mere
#       presence is the allowance. Comments and blanks are ignored, so
#       documenting a backlog is always free.
#
#       A backlog that does not exist at the base revision is a NEW ratchet
#       being adopted: reported, not failed — it starts governing from the next
#       commit.
#
# USAGE:
#   tools/ci/check_ratchet_monotonic.py                  # vs origin/main, else HEAD~1
#   tools/ci/check_ratchet_monotonic.py --base <rev>     # CI passes the PR base sha

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Ratchets whose backlog may only ever shrink, with the guard each one arms.
RATCHETS = {
    "tools/ci/file_size_backlog.txt": "check_file_size.py (600-line cap)",
    "tools/ci/todo_fixme_backlog.txt": "check_todo_fixme.py (deferred-work markers)",
    "tools/ci/template_refs_backlog.txt": "check_template_refs.py (unreferenced templates)",
    "tools/ci/doc_links_backlog.txt": "check_doc_links.py (broken relative links)",
    "tools/ci/metric_names_backlog.txt": "check_metric_names.py (metric families/labels the docs invent)",
    "tools/ci/vfs_seam_backlog.txt": "check_vfs_seam.py (INVARIANT 12, src/)",
    "tools/ci/vfs_seam_backlog_client.txt": "check_vfs_seam.py (INVARIANT 12, client/)",
    "tools/ci/vfs_seam_backlog_ns.txt": "check_vfs_seam.py (INVARIANT 12, namespace)",
    "tools/ci/vfs_identity_backlog.txt": "check_vfs_identity_branch.py (per-identity forks)",
    "tests/loc_baseline.txt": "lint_loc --strict (800-line hard cap)",
}


def parse(text: str) -> dict[str, float]:
    """Turn a backlog file into {entry -> allowance}.

    WHAT: maps each meaningful line to a number; opaque lines get 1.0 so their
    presence alone is the allowance.
    WHY: one parser has to serve both shapes — "path<TAB>count" ratchets and
    plain one-entry-per-line lists — or each new backlog format silently falls
    out of the guard.
    HOW: strip comments/blanks; if the last tab-separated field is a number,
    the rest of the line is the key and that number is the allowance.
    """
    entries: dict[str, float] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, allowance = line, 1.0
        if "\t" in line:
            head, _, tail = line.rpartition("\t")
            try:
                allowance = float(tail.strip())
                key = head.strip()
            except ValueError:
                pass
        entries[key] = max(allowance, entries.get(key, allowance))
    return entries


def compare(base_text: str, head_text: str) -> list[str]:
    """Report every way `head_text` is a widening of `base_text`."""
    base, head = parse(base_text), parse(head_text)
    findings = []
    for key, allowance in sorted(head.items()):
        if key not in base:
            findings.append(f"NEW entry grandfathered: {key}")
        elif allowance > base[key]:
            findings.append(
                f"allowance RAISED: {key} — was {base[key]:g}, now {allowance:g}"
            )
    return findings


def _at(rev: str, path: str) -> str | None:
    """Read `path` as of `rev`; None when it did not exist there."""
    proc = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=ROOT, capture_output=True, text=True, check=False,
    )
    return proc.stdout if proc.returncode == 0 else None


def _default_base() -> str | None:
    """Pick a base revision: the shared branch if present, else the parent commit."""
    for rev in ("origin/main", "HEAD~1"):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", rev],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        if probe.returncode == 0:
            return rev
    return None


def run(root: Path, read_base: Callable[[str], str | None]) -> int:
    """Compare every ratchet in `root` against its baseline and report a verdict.

    WHAT: prints one line per ratchet and returns the process exit code.
    WHY: the git lookup is the one part that needs a repository, so it enters as
    a callable — the verdict logic is then exercisable against a synthetic tree
    with no git, no network and no risk of a negative test damaging a tracked
    backlog (the 2026-08 guard-negative lesson: mutate a copy, never the file).
    HOW: `read_base(path)` returns the file's content at the base revision, or
    None when it did not exist there.
    """
    failed = False
    for path, guard in sorted(RATCHETS.items()):
        head_file = root / path
        if not head_file.is_file():
            print(f"  skip  {path} — not in this tree ({guard})")
            continue
        base_text = read_base(path)
        if base_text is None:
            print(f"  new   {path} — no baseline to compare; governed from the next commit")
            continue
        findings = compare(base_text, head_file.read_text(encoding="utf-8"))
        if not findings:
            print(f"  ok    {path}")
            continue
        failed = True
        print(f"FAIL  {path} grew — it arms {guard}", file=sys.stderr)
        for finding in findings:
            print(f"        {finding}", file=sys.stderr)

    if failed:
        print(
            "\nA ratchet backlog may only shrink. Fix the code (split the file, cut the\n"
            "complexity, remove the marker) rather than widening the ceiling — that is\n"
            "the whole mechanism by which these numbers trend to zero.",
            file=sys.stderr,
        )
        return 1
    print("check_ratchet_monotonic: OK (no ratchet backlog grew)")
    return 0


def main() -> int:
    """Resolve the base revision from the CLI/environment and run the check."""
    ap = argparse.ArgumentParser(description="ratchet backlogs may shrink, never grow")
    ap.add_argument("--base", help="revision to compare against (default: origin/main, else HEAD~1)")
    args = ap.parse_args()

    base = args.base or _default_base()
    # An all-zero sha is what GitHub sends for a branch's first push, and an
    # empty string is what the workflow's `||` fallback yields when neither
    # event field is set. Neither is a revision; there is nothing to compare.
    if not base or set(base) == {"0"}:
        print("check_ratchet_monotonic: no base revision to compare against — nothing to check")
        return 0
    return run(ROOT, lambda path: _at(base, path))


if __name__ == "__main__":
    sys.exit(main())
