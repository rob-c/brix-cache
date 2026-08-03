#!/usr/bin/env python3
#
# guard_set.py — which tools/ci guards run where. One source of truth.
#
# WHAT: Resolves three sets and prints one of them, one absolute path per line:
#         - every `tools/ci/check_*.py` on disk,
#         - the CI-enforced subset (those `.github/workflows/guards.yml` names),
#         - the pre-push subset (CI-enforced minus PREPUSH_SKIP).
#       Exits non-zero — loudly — if the tree contains no guards at all, so a
#       caller can never mistake "found nothing" for "nothing to do".
#
# WHY:  `tools/git-hooks/pre-push` used to glob `tools/ci/check_*.sh`. The guard
#       fleet was ported .sh -> .py on 2026-07-21 and that glob silently stopped
#       matching, so the hook's advertised "static invariant guards first" step
#       enforced NOTHING; worse, bash leaves an unmatched glob literal, so the
#       loop then tried to execute the pattern string itself and every push died
#       on a misleading "guard failed: check_*.sh". A hook that both skips its
#       guards and blocks its user is the worst of both. Filename patterns are
#       how that drift got in, so nothing may pattern-match guard filenames on
#       its own any more — hook, CI-wiring test and docs all ask this module.
#
# HOW:  A guard is CI-enforced iff guards.yml mentions its basename; that is the
#       same relation `test_workflow_runs_every_guard_script` asserts, reused
#       rather than re-derived. PREPUSH_SKIP then subtracts the guards too slow
#       for a push gate, each with a written reason — a skip is a decision, not
#       an accident, and the suite checks every entry still names a real guard.
#
# USAGE:
#   tools/ci/guard_set.py                 # pre-push set (what the hook runs)
#   tools/ci/guard_set.py --ci            # every CI-enforced guard
#   tools/ci/guard_set.py --all           # every check_*.py on disk
#   tools/ci/guard_set.py --explain       # the sets + why anything is excluded

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "tools" / "ci"
WORKFLOW = ROOT / ".github" / "workflows" / "guards.yml"

# --- guards the pre-push hook deliberately does NOT run (name -> reason) ------
# CI still runs these; the hook does not, because it advertises a seconds-long
# static pass in front of a ~4min test tier. Keep this list tiny and justified.
PREPUSH_SKIP: dict[str, str] = {
    "check_complexity.py": (
        "lizard walks the whole tree (minutes, and needs the lizard package "
        "installed); CI runs it — a push gate that doubles the hook's runtime "
        "gets bypassed with --no-verify, which enforces nothing"
    ),
}


def guard_scripts(root: Path = ROOT) -> list[Path]:
    """Every guard script on disk, sorted. The raw population, no policy."""
    return sorted((root / "tools/ci").glob("check_*.py"))


def ci_guards(root: Path = ROOT) -> list[Path]:
    """The guards `.github/workflows/guards.yml` actually invokes."""
    workflow = (root / ".github/workflows/guards.yml").read_text()
    return [p for p in guard_scripts(root) if p.name in workflow]


def prepush_guards(root: Path = ROOT) -> list[Path]:
    """The CI-enforced guards fast enough to gate a push."""
    return [p for p in ci_guards(root) if p.name not in PREPUSH_SKIP]


def _explain(root: Path) -> None:
    on_disk = guard_scripts(root)
    wired = {p.name for p in ci_guards(root)}
    print(f"{len(on_disk)} guard script(s) in tools/ci")
    for p in on_disk:
        if p.name not in wired:
            print(f"  {p.name}: not in guards.yml — advisory only")
        elif p.name in PREPUSH_SKIP:
            print(f"  {p.name}: CI only — {PREPUSH_SKIP[p.name]}")
        else:
            print(f"  {p.name}: CI + pre-push")


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else ""
    if mode == "--explain":
        _explain(ROOT)
        return 0

    chooser = {
        "": prepush_guards,
        "--prepush": prepush_guards,
        "--ci": ci_guards,
        "--all": guard_scripts,
    }.get(mode)
    if chooser is None:
        print(f"guard_set: unknown mode {mode!r}", file=sys.stderr)
        return 2

    if not guard_scripts(ROOT):
        print(
            f"guard_set: no check_*.py under {CI_DIR} — the guard fleet is "
            f"missing, not empty",
            file=sys.stderr,
        )
        return 1

    for p in chooser(ROOT):
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
