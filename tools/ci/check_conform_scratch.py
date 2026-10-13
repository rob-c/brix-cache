#!/usr/bin/env python3
"""Enforce Phase-118's prefix-bound mutation-path capability."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.logging_support import diagnostic

RUNNER_GLOB = "client/apps/diag/xrd_conform*.c"
MUTATORS = (
    "brix_file_open_write",
    "brix_file_open_update",
    "brix_rm",
    "brix_rmdir",
    "brix_mkdir",
    "brix_mv",
    "brix_chmod",
    "brix_trunc",
    "brix_setattr",
    "brix_symlink",
    "brix_link",
)
CALL_RE = re.compile(r"\b(" + "|".join(MUTATORS) + r")\s*\(")
NONCODE_RE = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:[^"\\\n]|\\.)*"', re.S)
CAP_DECL_RE = re.compile(r"\bxrd_conform_scratch_object\s+([^;]+);")
CAP_PTR_RE = re.compile(r"\bxrd_conform_scratch_object\s*\*\s*(\w+)")


def _blank(match: re.Match[str]) -> str:
    return "".join("\n" if char == "\n" else " " for char in match.group(0))


def _arguments(code: str, open_paren: int) -> str:
    depth = 0
    for index in range(open_paren, len(code)):
        if code[index] == "(":
            depth += 1
        elif code[index] == ")":
            depth -= 1
            if depth == 0:
                return code[open_paren + 1:index]
    return ""


def _capability_names(code: str) -> set[str]:
    """Return local/parameter names carrying the typed scratch capability."""
    names = set(CAP_PTR_RE.findall(code))
    for match in CAP_DECL_RE.finditer(code):
        for declaration in match.group(1).split(","):
            name = re.search(r"([A-Za-z_]\w*)\s*$", declaration.strip())
            if name is not None:
                names.add(name.group(1))
    return names


def _uses_capability_path(args: str, names: set[str]) -> bool:
    """Recognize only `.path` access on a statically typed capability."""
    return any(re.search(rf"\b{re.escape(name)}\s*(?:->|\.)\s*path\b", args)
               is not None for name in names)


def violations_for_text(path: str, text: str) -> list[str]:
    """Return path-source violations in one conformance runner source."""
    code = NONCODE_RE.sub(_blank, text)
    lines = text.splitlines()
    capability_names = _capability_names(code)
    violations: list[str] = []
    for match in CALL_RE.finditer(code):
        args = _arguments(code, match.end() - 1)
        if _uses_capability_path(args, capability_names):
            continue
        line = code.count("\n", 0, match.start()) + 1
        source = lines[line - 1].strip() if line <= len(lines) else match.group(1)
        violations.append(
            f"{path}:{line}: {match.group(1)} lacks a prefix-bound scratch path: {source}"
        )
    return violations


def current_violations(root: Path = ROOT) -> list[str]:
    violations: list[str] = []
    for source in sorted(root.glob(RUNNER_GLOB)):
        violations.extend(
            violations_for_text(str(source.relative_to(root)), source.read_text(encoding="utf-8"))
        )
    return violations


def main() -> int:
    violations = current_violations()
    if violations:
        diagnostic("ERROR", "tools/ci/check_conform_scratch.py", "main",
                   "mutation path bypasses scratch capability")
        for violation in violations:
            diagnostic("ERROR", "tools/ci/check_conform_scratch.py", "main",
                       violation)
        return 1
    print("check_conform_scratch: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
