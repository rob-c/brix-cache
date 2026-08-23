#!/usr/bin/env python3
"""Guard #12 — one composed module, one namespace: no duplicate top-level names.

``tests/split_continuation.py`` composes a module from shards by compiling each
one into the *parent's* globals.  That is one namespace, not several: a
``def`` in shard 2 with the same name as a ``def`` in the parent does not
shadow it locally, it **rebinds** it for the whole module.  Python function
bodies resolve globals at call time, so the parent's own call sites -- written
and reviewed against the parent's definition -- then reach the shard's.

This is not a style complaint.  The complexity burndown hoisted expression
bodies out of long runners under mechanical names (``_expression_1`` ..
``_expression_6``), numbered per FILE, and three composed units ended up with
the same number used twice:

  * ``c_auth_units``      -- ``run_deleg_gate`` called a three-argument helper
    that the shard had rebound to a one-argument one: ``TypeError`` at runtime,
    the whole ``deleg_gate`` unit red.
  * ``client_features``   -- ``_expression_1(proc)`` (combined stdout+stderr)
    rebound to ``_expression_1(failed)`` (an exit code).  No exception: the
    journal assertions just compared against an integer and quietly failed.
  * ``gsi_trust_live``    -- the ``make_proxy.py`` failure path returned an
    HTTP-code parse of the wrong object instead of a skip.

Two of the three were SILENT.  A name that is merely redundant today (two
byte-identical copies) is the same defect waiting for one of the copies to be
edited, so the guard admits no "identical bodies are fine" exemption.

Fix, when it fires: give the colliding definitions names that say what they
do -- they are different functions, or they are one function that belongs in
exactly one file of the unit and is called from the others.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_shard_entrypoints import _parent_shards  # noqa: E402  (same tree walk)

TESTS = Path(__file__).resolve().parents[2] / "tests"


def _top_level_names(path: Path) -> dict[str, list[int]]:
    """name -> the line(s) of every top-level def/class binding it.

    Only module level counts: a method or a nested helper lives in its own
    namespace and cannot collide across shards.  A file that does not parse is
    reported as empty -- syntax is somebody else's guard.
    """
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except SyntaxError:
        return {}
    names: dict[str, list[int]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.setdefault(node.name, []).append(node.lineno)
    return names


def _unit_files(parent: Path) -> list[Path]:
    """The parent plus every shard it composes that still exists on disk."""
    files = [parent] + [parent.parent / name for name in _parent_shards(parent)]
    return [path for path in files if path.is_file()]


def _collisions(files: list[Path]) -> dict[str, list[tuple[Path, int]]]:
    """name -> [(file, line), ...] for every name bound more than once in the
    unit, including twice within one file (a redefinition Python accepts and
    nobody intends)."""
    bound: dict[str, list[tuple[Path, int]]] = {}
    for path in files:
        for name, lines in _top_level_names(path).items():
            bound.setdefault(name, []).extend((path, line) for line in lines)
    return {name: sites for name, sites in bound.items() if len(sites) > 1}


def _report(root: Path, parent: Path, collisions: dict) -> None:
    print(f"  {parent.relative_to(root.parent)}")
    for name, sites in sorted(collisions.items()):
        where = ", ".join(f"{path.name}:{line}" for path, line in sites)
        print(f"      {name}  ({where})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=TESTS,
                    help="tree to scan (the negative test points this at a "
                         "scratch copy; damaging the real tree to prove a "
                         "guard fires is never acceptable)")
    args = ap.parse_args(argv)
    root = args.root.resolve()

    units = 0
    failed = []
    for parent in sorted(root.rglob("*.py")):
        files = _unit_files(parent)
        if len(files) < 2:
            continue
        units += 1
        collisions = _collisions(files)
        if collisions:
            failed.append((parent, collisions))

    if failed:
        print("check_shard_name_collisions: FAIL — a shard rebinds a name its "
              "composed unit already defines, so call sites reach the wrong "
              "function:")
        for parent, collisions in failed:
            _report(root, parent, collisions)
        print("Rename them to say what they do; see this file's docstring.")
        return 1

    print(f"check_shard_name_collisions: OK ({units} composed unit(s) scanned, "
          f"no duplicate top-level names)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
