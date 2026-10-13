#!/usr/bin/env python3
"""Report explicit unsupported results owned by the Darwin PAL.

The report is generated from production source so build output and platform
documentation cannot silently claim that a stubbed feature works. It is a
diagnostic, not a gate: the Phase 119 residue contains legitimate limitations.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DARWIN_ROOTS = (
    ROOT / "src/platform/darwin",
    ROOT / "client/lib/platform/darwin",
)
UNSUPPORTED = re.compile(
    r"\b(?:ENOSYS|ENOTSUP|EOPNOTSUPP|NGX_DECLINED|NGX_HTTP_NOT_IMPLEMENTED)\b"
)


def residue(root: Path = ROOT) -> list[tuple[str, int, str]]:
    """Return stable file, line, and statement rows for explicit residue."""
    rows: list[tuple[str, int, str]] = []
    for platform_root in DARWIN_ROOTS:
        for path in sorted(platform_root.glob("*.c")):
            if path.name.endswith("_unittest.c"):
                continue
            rows.extend(_file_residue(path, root))
    return rows


def _file_residue(path: Path, root: Path) -> list[tuple[str, int, str]]:
    rows = []
    for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        statement = line.strip()
        if statement.startswith(("errno =", "return ")) and UNSUPPORTED.search(statement):
            rows.append((str(path.relative_to(root)), number, statement))
    return rows


def render_text(rows: list[tuple[str, int, str]]) -> str:
    """Render compact terminal rows and an explicit count."""
    lines = [f"  - {path}:{line}: {statement}" for path, line, statement in rows]
    lines.append(f"  Darwin explicit unsupported residue: {len(rows)} site(s)")
    return "\n".join(lines)


def render_markdown(rows: list[tuple[str, int, str]]) -> str:
    """Render a documentation-ready residue table."""
    lines = ["| Source | Line | Explicit result |", "|---|---:|---|"]
    lines.extend(
        f"| `{path}` | {line} | `{statement.replace('|', '&#124;')}` |"
        for path, line, statement in rows
    )
    return "\n".join(lines)


def main() -> int:
    """Parse output selection and print the current source-derived residue."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("text", "markdown"), default="text")
    arguments = parser.parse_args()
    rows = residue()
    print(render_markdown(rows) if arguments.format == "markdown" else render_text(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
