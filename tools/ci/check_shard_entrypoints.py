#!/usr/bin/env python3
"""Guard #10 — a CLI must not live in a shard that only runs under ``exec``.

``tests/split_continuation.py`` composes a module from shards by compiling each
one into the parent's globals.  A shard therefore sees the parent's
``__name__``, so an ``if __name__ == "__main__":`` block at the foot of the
*last* shard runs when someone executes the *parent*.  That is how thirteen
``cmdscripts`` entry points and both forges were written.

The arrangement is correct while the composition stands and silently wrong the
moment it is replaced by real imports: the guard then belongs to the shard,
never fires for a caller running the parent, and the parent becomes a script
that does nothing.  TS-5 hit this twice.  The token forge's ``fleet-artifacts``
subcommand is invoked by ``brix_suite/prep_steps.py`` with ``tolerate=True``,
so the moved stack **exited 0 while writing no JWKS and no scitokens.cfg** --
every fleet would have booted misconfigured with no step reporting a problem.

So this guard does not ask modules to stop doing it.  It pins the pairing: a
shard that carries a ``__main__`` guard must still be exec-composed by a parent
that still calls ``_load_continuations``.  Break the composition without moving
the entry point and the guard fails, which is exactly the moment a reviewer
needs to be told.

Fix, when it fires: give the entry point a named ``main()`` in the module that
now owns it, and have every spelling that used to be a script call it -- see
``brix_suite/security/tokens/__main__.py`` and
``brix_suite/security/x509/__main__.py`` for the shape, and the shims in
``tests/tokenforge.py`` and ``tests/x509forge.py`` for the caller side.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2] / "tests"

#: `split_continuation.load(globals(), __file__, "a_part2.py", ...)`
_LOAD = re.compile(r"_load_continuations\(\s*globals\(\)\s*,\s*__file__\s*,(.*?)\)",
                   re.S)
#: `cmdscripts/operator_runtime.py` predates the shared helper and open-codes
#: the same composition: a loop over shard names feeding `exec(..., globals())`.
#: Semantically identical, so it counts.  Matching the whole statement with one
#: regex is brittle, so the two halves are looked for independently -- a module
#: that execs into its own globals and names shard files is composing them.
_INLINE_EXEC = re.compile(r"exec\(\s*compile\(.*?globals\(\)", re.S)
_SHARD = re.compile(r'"([^"]+\.py)"')
_MAIN = re.compile(r'^if\s+__name__\s*==\s*["\']__main__["\']\s*:', re.M)

#: Directories whose shards are deliberately not composed.
#:
#: `_legacy` holds byte-for-byte archives of pre-move flat stacks -- they exist
#: to be diffed against, never imported, so their `__main__` guards are history
#: rather than a live entry point.
#:
#: `userns/` is a true positive that predates this guard: `e2e_redteam_part77`
#: is reached by `from e2e_redteam_part77 import *`, a real import, so its
#: entry point already cannot fire.  That whole suite is separately recorded as
#: inert -- 78 files that never execute -- and repairing it is its own piece of
#: work, tracked outside TS-5.  It is listed here so the finding stays visible
#: instead of being silently dropped.
_NOT_COMPOSED = ("brix_suite/_legacy/", "userns/")


def _composed_shards(tree_root: Path) -> dict:
    """Map shard path -> the parent that exec-composes it."""
    owners = {}
    for parent in sorted(tree_root.rglob("*.py")):
        text = parent.read_text(errors="replace")
        match = _LOAD.search(text)
        if match:
            names = _SHARD.findall(match.group(1))
        elif _INLINE_EXEC.search(text):
            names = [n for n in _SHARD.findall(text) if "_part" in n]
        else:
            continue
        for name in names:
            owners[(parent.parent / name).resolve()] = parent
    return owners


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=TESTS,
                    help="tree to scan (the negative test points this at a "
                         "scratch copy; damaging the real tree to prove a "
                         "guard fires is never acceptable)")
    args = ap.parse_args(argv)
    root = args.root.resolve()

    owners = _composed_shards(root)
    orphaned = []
    for path in sorted(root.rglob("*_part*.py")):
        rel = path.relative_to(root).as_posix()
        if rel.startswith(_NOT_COMPOSED):
            continue
        text = path.read_text(errors="replace")
        if not _MAIN.search(text):
            continue
        if path.resolve() not in owners:
            orphaned.append(path)

    if orphaned:
        print("check_shard_entrypoints: FAIL — a shard holds a `__main__` "
              "guard but is no longer exec-composed, so its entry point can "
              "never run:")
        for path in orphaned:
            print(f"  {path.relative_to(root.parent)}")
        print("Move the entry point into a named `main()` the new owner "
              "exports, and call it from every spelling that used to be a "
              "script.  See this file's docstring.")
        return 1

    # A parent may still name shards that the move relocated; those paths are
    # gone, which is fine -- only shards that exist can hold an entry point.
    guarded = sum(1 for p in owners
                  if p.exists() and _MAIN.search(p.read_text(errors="replace")))
    print(f"check_shard_entrypoints: OK ({guarded} shard entry point(s) still "
          f"exec-composed, {len(owners)} shard(s) scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
