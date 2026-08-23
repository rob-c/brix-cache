#!/usr/bin/env python3
"""Guard #11 — a §10.2 shim must not lose the CLI its flat body had.

The migration replaces a grown flat module with a package plus a
self-replacement shim: ``tests/x.py`` imports the canonical module and rebinds
its own ``sys.modules`` entry to it.  Names survive that (guard #3 pins them);
``if __name__ == "__main__":`` blocks do not.  A guard is not a name — it is a
property of *how the interpreter was started* — so the moment the body lives in
a package that the shim merely imports, the block moves to a file nobody ever
executes and ``python3 tests/x.py`` becomes a script that exits 0 having done
nothing.

That is the same trap guard #10 pins for ``exec``-composed shards, arriving by
the other road.  It matters most exactly where it is hardest to notice: nine of
the callers reach these files by *absolute path* from a spec catalogue or a
``cmdscripts`` runner, and three of those runners are behind an opt-in
environment variable, so their pytest wrappers SKIP.  A stranded entry point
there is not a red test — it is a green one.

HOW: ``brix_suite/_legacy/*_flat.py`` holds the byte-identical pre-move body of
every shimmed module.  If an archive carries a top-level ``__main__`` guard,
its flat stack HAD a CLI; the live head of that stack must therefore carry a
``__main__`` guard that still calls something.  Both sides are read with
``ast``, so a ``__main__`` mentioned in a docstring or a comment — every one of
these shims explains itself at length — is not mistaken for the real thing.

Stack head: an archive named ``x509forge_part3_flat.py`` or
``_tokenforge_part2_mixina_flat.py`` belongs to the module a caller actually
runs (``x509forge``, ``tokenforge``), not to the shard that happened to hold
the last line of the file.  The head is resolved by *asking the tree*, not by
name arithmetic, because a name settles neither of the two things that vary:
mixins are spelled ``_tokenforge_part2_mixina`` while their parent is
``tokenforge``, so a leading underscore usually has to go — but a module may
legitimately be private (``_xrdcl_worker``); and a shim need not sit at the
top level — the eight stub servers are shimmed at ``tests/lib/``.  Both were
guessed once, and both guesses failed the same way: the guard hunting a file
that never existed and calling a correct module stranded.

Fix, when it fires: give the entry point a named ``main()`` in the module that
now owns it and call it from the shim's ``__main__`` block, *before* the
``sys.modules`` self-replacement — see ``tests/kdc_helpers.py`` for the shape.
Rebinding ``__main__`` itself is wrong: that entry belongs to the script being
run, not to the package.

USAGE:
  tools/ci/check_shim_entrypoints.py             # non-zero exit on violation
  tools/ci/check_shim_entrypoints.py --root DIR  # check a scratch tree instead
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2] / "tests"

#: `x509forge_part3` and `_tokenforge_part2_mixina` are shards of `x509forge`
#: and `tokenforge`; the CLI belongs to the name a caller runs.
_SHARD_SUFFIX = re.compile(r"_part\d+.*$")


#: Where a shim may live.  Top level first, then the suite's package
#: directories — the stub servers are shimmed at `tests/lib/`, not `tests/`.
_SHIM_DIRS = ("", "lib", "lib_py", "cmdscripts")


def _stack_head(flat_name: str, root: Path) -> Path:
    """The file a caller runs, for an archive's name.

    Drop the shard suffix, then let the tree settle the two things a name
    cannot: the leading underscore (`_tokenforge_part2_mixina` is a slice of
    `tokenforge`, but `_xrdcl_worker` is simply private and its own head) and
    the directory (`guard_stub_server` is shimmed at `lib/`, not at the top).
    Both were guessed once and both guesses produced the same failure — the
    guard hunting a file that never existed, and reporting it as a stranded
    CLI on a module that was correct.

    Returns the path it would run, existing or not; the caller reports the
    non-existent case, since that is a real violation when no spelling hits.
    """
    head = _SHARD_SUFFIX.sub("", flat_name)
    for name in (head, head.lstrip("_")):
        for directory in _SHIM_DIRS:
            candidate = (root / directory / f"{name}.py") if directory else (root / f"{name}.py")
            if candidate.is_file():
                return candidate
    return root / f"{head}.py"


def _main_block(path: Path):
    """The body of the module's top-level ``__main__`` guard, or None.

    Read with `ast` rather than a regex: every shim in this cluster discusses
    `__main__` in its docstring, and a guard that fires on prose would train
    people to write around it.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return None
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
                and any(isinstance(c, ast.Constant) and c.value == "__main__"
                        for c in test.comparators)):
            return node.body
    return None


def _calls_something(body) -> bool:
    return any(isinstance(n, ast.Call)
               for stmt in body for n in ast.walk(stmt))


def check(root: Path) -> int:
    legacy = root / "brix_suite" / "_legacy"
    if not legacy.is_dir():
        print("check_shim_entrypoints: no %s — nothing to check" % legacy)
        return 0
    return _check_legacy(root, legacy)


def _check_legacy(root, legacy):
    archives = [path for path in sorted(legacy.glob("*_flat.py")) if _main_block(path)]
    violations = [
        violation for archive in archives
        for violation in _archive_violation(archive, root)
    ]
    return _report_result(archives, violations)


def _report_result(archives, violations):
    if violations:
        _report_violations(violations)
        return 1
    print("check_shim_entrypoints: OK (%d archived CLI(s), every stack head "
          "still runs one)" % len(archives))
    return 0


def _archive_violation(archive, root):
    flat = archive.name[:-len("_flat.py")]
    live = _stack_head(flat, root)
    head = live.relative_to(root).as_posix()[:-len(".py")]
    if not live.is_file():
        return [
            f"{archive.name} carried a CLI, but its stack head tests/{head}.py "
            "no longer exists — the entry point has nowhere left to live"
        ]
    body = _main_block(live)
    if body is None:
        return [
            f"{archive.name} carried a CLI; tests/{head}.py does not. Running "
            "that path now exits 0 without doing the work"
        ]
    if not _calls_something(body):
        return [
            f"tests/{head}.py has a __main__ guard that calls nothing — "
            f"{archive.name}'s entry point did work this one does not"
        ]
    return []


def _report_violations(violations):
    print("check_shim_entrypoints: %d shim CLI(s) stranded by a move:" % len(violations))
    for violation in violations:
        print("  - %s" % violation)
    print("\nGive the entry point a named main() in the module that owns the body now, "
          "and call it from the shim's __main__ block (before the sys.modules self-replacement).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=TESTS,
                    help="tests/ tree to check (default: this repo's)")
    args = ap.parse_args(argv)
    return check(args.root.resolve())


if __name__ == "__main__":
    sys.exit(main())
