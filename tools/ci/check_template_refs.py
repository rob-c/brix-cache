#!/usr/bin/env python3
#
# check_template_refs.py — no NEW unreferenced config template.
#
# WHAT: Fails (exit 1) when a template under tests/configs/ is named by nothing
#       in the repo and is not already listed in template_refs_backlog.txt, or
#       when a backlog entry has become referenced/deleted (the ratchet only
#       turns one way: regenerate to shrink it, never to grow it).
#
# WHY:  The 2026-08-04 combinatorial coverage audit found 53 templates that no
#       test, script or doc mentions — several of them pre-lifecycle duplicates
#       whose `nginx_lc_*` twin is the live one (`nginx_native_sss.conf` and
#       `nginx_pwd_auth.conf` are dead while their `_lc_` twins are used). A dead
#       template is worse than no template: it reads as coverage that exists,
#       and the next author copies it. This guard stops the pile growing while
#       the existing pile is burned down, rather than deleting 53 files whose
#       last reader is gone.
#
# HOW:  A template counts as referenced if its basename appears anywhere in the
#       repo outside tests/configs/ itself. Names built at runtime (f-strings)
#       are invisible to that scan by construction — which is exactly why the
#       backlog is an allowlist and not a delete-list.
#
# USAGE:
#   tools/ci/check_template_refs.py
#   tools/ci/check_template_refs.py --regen     # after removing/wiring one up

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "tests" / "configs"
BACKLOG = Path(__file__).resolve().parent / "template_refs_backlog.txt"

# Directories worth scanning for a mention. Everything that can name a template:
# the tests themselves, the guard/CI tooling, the docs, the k8s suite.
SCAN = ("tests", "tools", "docs", "k8s-tests", "client", "src", "packaging",
        "shared", ".github")


def _templates() -> list[str]:
    return sorted(p.name for p in CONFIG_DIR.glob("*.conf"))


def _mentioned(root: Path) -> set[str]:
    """Every `*.conf` basename named anywhere outside tests/configs/."""
    dirs = [str(root / d) for d in SCAN if (root / d).is_dir()]
    proc = subprocess.run(
        ["grep", "-rhoI", "-e", r"[A-Za-z0-9_.-]*\.conf", *dirs,
         "--exclude-dir=configs", "--exclude-dir=.git",
         "--exclude-dir=__pycache__",
         # This guard and its backlog name templates in order to complain about
         # them; counting that as a reference would empty the backlog on sight.
         "--exclude=check_template_refs.py",
         "--exclude=template_refs_backlog.txt"],
        capture_output=True, text=True)
    return {os.path.basename(tok) for tok in proc.stdout.split()}


def _backlog(path: Path = BACKLOG) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")]


def run(root: Path = ROOT) -> tuple[bool, list[str], list[str]]:
    """(ok, messages, current) — `current` is the regen payload."""
    mentioned = _mentioned(root)
    unreferenced = [t for t in _templates() if t not in mentioned]
    allowed = set(_backlog())

    messages = _new_template_messages(unreferenced, allowed)
    messages.extend(_stale_template_messages(unreferenced, allowed))
    return not messages, messages, unreferenced


def _new_template_messages(unreferenced, allowed):
    return [
        f"FAIL new unreferenced template: tests/configs/{name} — wire it up from "
        "a test, or delete it (do NOT add it to the backlog)"
        for name in unreferenced if name not in allowed
    ]


def _stale_template_messages(unreferenced, allowed):
    return [
        f"FAIL stale backlog entry: {name} is referenced or gone — rerun with "
        "--regen to shrink the backlog"
        for name in sorted(allowed - set(unreferenced))
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--regen", action="store_true",
                    help="rewrite the backlog from the current tree "
                         "(shrink-only: refuses to add entries)")
    args = ap.parse_args()
    os.chdir(ROOT)

    ok, messages, current = run()
    if args.regen:
        before = set(_backlog())
        added = sorted(set(current) - before)
        if added:
            print("REFUSED --regen would ADD entries (the ratchet only shrinks):")
            for name in added:
                print(f"  {name}")
            return 1
        BACKLOG.write_text(
            "# Templates under tests/configs/ that nothing in the repo names.\n"
            "# Shrink-only: wire one up or delete it, then rerun with --regen.\n"
            "# See docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-04.md\n"
            + "".join(f"{name}\n" for name in current))
        print(f"check_template_refs: backlog regenerated ({len(current)} entries)")
        return 0

    for line in messages:
        print(line)
    if ok:
        print(f"check_template_refs: OK ({len(current)} in the burn-down backlog)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
