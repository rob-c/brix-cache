#!/usr/bin/env python3
#
# check_readme_coverage.py — substantial src/ directories must carry a README.
#
# WHAT: Fails (exit 1) when a directory at depth 1–2 under src/ contains two
#       or more C sources (*.c/*.h, non-recursive) but no README.md.
#
# WHY:  READMEs are the orientation layer for auditors; coverage decayed
#       exactly on the hardest directories (protocols/root, auth/authz,
#       tpc/*) until 2026-07-07. This makes coverage a ratchet: a new
#       subsystem directory ships with its README or CI is red.
#
# HOW:  find depth-1/2 dirs, count immediate C sources, require README.md
#       when the count is >= 2. Depth-3+ (e.g. protocols/root/*) is
#       encouraged but not gated.
#
# USAGE:
#   tools/ci/check_readme_coverage.py

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _dirs_depth_1_2(src: Path) -> list[Path]:
    """Directories at depth 1–2 under src/, sorted by full path string to match
    `find ... | sort` byte order."""
    dirs: list[Path] = []
    for depth1 in src.iterdir():
        if not depth1.is_dir():
            continue
        dirs.append(depth1)
        for depth2 in depth1.iterdir():
            if depth2.is_dir():
                dirs.append(depth2)
    return sorted(dirs, key=lambda p: str(p))


def _c_source_count(d: Path) -> int:
    """Immediate *.c/*.h entries (non-recursive), like find -maxdepth 1."""
    return sum(1 for e in d.iterdir() if e.suffix in (".c", ".h"))


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Returns (ok, fail_messages). ok is False when any substantial directory
    is missing its README.md."""
    messages: list[str] = []
    for d in _dirs_depth_1_2(root / "src"):
        n = _c_source_count(d)
        if n >= 2 and not (d / "README.md").is_file():
            rel = d.relative_to(root)
            messages.append(f"FAIL missing README.md: {rel}/ ({n} C sources)")
    return (not messages, messages)


def main() -> int:
    os.chdir(ROOT)
    ok, messages = run()
    for msg in messages:
        print(msg)
    if ok:
        print("check_readme_coverage: OK")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
