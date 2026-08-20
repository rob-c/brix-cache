#!/usr/bin/env python3
#
# WHAT: Fail CI when any module under brixtest/src/brixtest/ imports
#       brix_suite — at module level, inside a function, or via importlib with
#       a literal name.  (Guard #8, testsuite-modernization-plan §7.2/§12.)
#
# WHY:  brixtest is the generic pytest-harness core; brix_suite is the
#       nginx-xrootd adapter.  The §7.2 genericity contract is enforced by
#       import DIRECTION: the adapter registers its knowledge into the core at
#       activation time, never the reverse.  One core-side import of the
#       adapter quietly collapses the boundary — the core stops being reusable
#       and the promotion rule (adapter-by-default, promote when generic) stops
#       meaning anything.  Reviewers should not have to police this by eye.
#
# HOW:  AST-walk every *.py under brixtest/src/brixtest/: any Import/
#       ImportFrom whose target is brix_suite (or a submodule), plus any string
#       literal "brix_suite..." passed to importlib.import_module /
#       __import__, is a failure naming file:line.  There is no backlog — the
#       boundary starts clean and stays clean.
#
# USAGE:
#   tools/ci/check_import_direction.py     # non-zero exit on violation

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "brixtest" / "src" / "brixtest"
FORBIDDEN = "brix_suite"


def _violations_in(path: Path) -> list[tuple[int, str]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError as exc:
        return [(exc.lineno or 0, f"unparseable module: {exc.msg}")]
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == FORBIDDEN:
                    out.append((node.lineno, f"import {alias.name}"))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module and \
                    node.module.split(".")[0] == FORBIDDEN:
                out.append((node.lineno, f"from {node.module} import ..."))
        elif isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name in ("import_module", "__import__") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and \
                        isinstance(arg.value, str) and \
                        arg.value.split(".")[0] == FORBIDDEN:
                    out.append((node.lineno, f"{name}({arg.value!r})"))
    return out


def main() -> int:
    if not CORE.is_dir():
        print(f"check_import_direction: FAIL — core tree missing: {CORE}",
              file=sys.stderr)
        return 1
    failures = []
    for path in sorted(CORE.rglob("*.py")):
        for lineno, what in _violations_in(path):
            failures.append(
                f"FAIL {path.relative_to(ROOT).as_posix()}:{lineno}: "
                f"core imports the adapter ({what}) — brixtest must stay "
                f"generic; move the dependency into brix_suite (§7.2)")
    for line in failures:
        print(line)
    if failures:
        return 1
    print("check_import_direction: OK (brixtest never imports brix_suite)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
