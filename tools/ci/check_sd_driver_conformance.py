#!/usr/bin/env python3
#
# WHAT: Verify every storage driver declared in the fs_list.h registry actually
#       ships a conforming brix_sd_driver_t, and emit a driver x vtable-op
#       coverage matrix so a reviewer can see at a glance which backends
#       implement which operations (and diff drivers concern-by-concern).
#
# WHY:  The SD backends (fs/backend/*/sd_*.c) are a structurally-parallel cluster
#       — 10+ files, ~900-1500 LOC each, all implementing the same vtable.
#       Reviewing "did this new/changed driver wire up the registry correctly and
#       implement the ops it claims?" was an eyeball exercise across the whole
#       cluster.  This turns it red/green:
#         - fs_list.h row  ->  brix_sd_<sym>_driver struct MUST exist
#         - the struct's .name MUST match the registry name (INVARIANT #8:
#           low-cardinality, stable backend names)
#         - a registered driver MUST implement at least one data op (.open or
#           .stat) — a driver that wires up nothing is a bug
#       The coverage matrix is informational (printed always); the gates fail CI.
#
# HOW:  Parse BRIX_FS_DRIVER_LIST_* rows from fs_list.h for (sym, name); for each,
#       locate `brix_sd_<sym>_driver = {` in fs/backend/<dir>/sd_<sym>.c and scan
#       its initializer for `.<slot> =` assignments.  No compiler needed.
#
#       Faithful Python port of tools/ci/check_sd_driver_conformance.py — same
#       parsing rules, ordering, message wording and exit code, byte-for-byte.
#
# USAGE: tools/ci/check_sd_driver_conformance.py

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FS_LIST = ROOT / "src/core/types/fs_list.h"
BACKEND = ROOT / "src/fs/backend"

# vtable ops shown in the matrix (a representative, high-signal subset of the 31).
MATRIX_OPS = [
    "init", "open", "close", "pread", "preadv", "pwrite", "copy_range",
    "read_sendfile_fd", "fstat", "stat", "opendir", "readdir", "getxattr",
    "setxattr", "staged_open", "staged_commit", "recall",
]

# A registered driver must implement at least one of these data/namespace ops.
DATA_OPS = {
    "open", "stat", "pread", "preadv", "pwrite", "fstat", "opendir",
    "staged_open", "recall",
}

# X(ID, sym, "name", KIND) rows — mirrors the shell grep -oE + sed exactly.
_ROW_RE = re.compile(
    r'X\([A-Z0-9_]+, *([a-z0-9_]+), *"([a-z0-9_]+)", *'
    r'(?:BACKEND|ORIGIN|DECORATOR|NEARLINE)\)'
)
# `.<slot> =` designated initializers (grep -oE '\.[a-z_]+[[:space:]]*=').
_SLOT_RE = re.compile(r'\.[a-z_]+\s*=')
# `.name = "..."` extraction.
_NAME_RE = re.compile(r'\.name\s*=\s*"([^"]*)"')


def _parse_rows(fs_list: Path) -> list[tuple[str, str]]:
    """(sym, name) per driver row, in fs_list.h file order."""
    rows: list[tuple[str, str]] = []
    for line in fs_list.read_text().splitlines():
        for m in _ROW_RE.finditer(line):
            rows.append((m.group(1), m.group(2)))
    return rows


def _find_driver_file(sym: str) -> Path | None:
    """First *.c under fs/backend defining `brix_sd_<sym>_driver = {` (grep -rl | head -1)."""
    decl = re.compile(r'brix_sd_' + re.escape(sym) + r'_driver\s*=\s*\{')
    matches: list[Path] = []
    for dirpath, _dirs, files in os.walk(BACKEND):
        for fname in files:
            if not fname.endswith(".c"):
                continue
            path = Path(dirpath) / fname
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if any(decl.search(ln) for ln in text.splitlines()):
                matches.append(path)
    return sorted(matches)[0] if matches else None


def _initializer_block(path: Path, sym: str) -> list[str]:
    """Lines from the `brix_sd_<sym>_driver = {` decl through the first `};` line."""
    decl = re.compile(r'brix_sd_' + re.escape(sym) + r'_driver\s*=\s*\{')
    block: list[str] = []
    started = False
    for line in path.read_text().splitlines():
        if decl.search(line):
            started = True
        if started:
            block.append(line)
            if line.startswith("};"):
                break
    return block


def _slots(block: list[str]) -> set[str]:
    """Unique designated-initializer slot names in the block."""
    slots: set[str] = set()
    for line in block:
        for m in _SLOT_RE.findall(line):
            slots.add(m.replace(" ", "").replace("=", "").replace(".", ""))
    return slots


def _name_val(block: list[str]) -> str:
    """First `.name = "..."` string value in the block, or "" if absent."""
    for line in block:
        m = _NAME_RE.search(line)
        if m:
            return m.group(1)
    return ""


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Compute the verdict and the full stdout report (header + coverage matrix
    + any inline FAIL lines + trailing blank + OK line when passing).

    Returns (ok, stdout_lines). An empty list signals the "no rows parsed" early
    exit — main() emits the corresponding stderr diagnostic in that case."""
    rows = _parse_rows(FS_LIST)
    if not rows:
        return False, []

    fail = False
    out: list[str] = []

    header = "%-11s %-10s %-6s" % ("driver", "name", "#ops")
    for op in MATRIX_OPS:
        header += " %s" % op[:3]
    out.append(header)

    for sym, name in rows:
        if not sym:
            continue
        path = _find_driver_file(sym)
        if path is None:
            out.append(
                "FAIL driver '%s' (name=%s): registered in fs_list.h but no "
                "brix_sd_%s_driver struct defined" % (sym, name, sym)
            )
            fail = True
            continue

        block = _initializer_block(path, sym)
        slots = _slots(block)
        nops = len(slots)

        name_val = _name_val(block)
        if not name_val:
            namestat = "NO-NAME"
            fail = True
        elif name_val != name:
            namestat = "!=%s" % name_val
            fail = True
        else:
            namestat = "ok"

        if not (slots & DATA_OPS):
            out.append(
                "FAIL driver '%s': implements no data/namespace op "
                "(dead driver struct)" % sym
            )
            fail = True

        line = "%-11s %-10s %-6s" % (sym, namestat, str(nops))
        for op in MATRIX_OPS:
            line += " %3s" % (" x" if op in slots else " .")
        out.append(line)

    out.append("")
    if not fail:
        out.append("check_sd_driver_conformance: OK (every registered driver "
                   "has a matching struct + a data op)")
    return (not fail), out


def main() -> int:
    # Run from the repo root so relative paths resolve identically regardless of cwd.
    os.chdir(ROOT)
    ok, out = run()

    if not out:
        print("check_sd_driver_conformance: FAIL — no driver rows parsed from %s"
              % FS_LIST, file=sys.stderr)
        return 1

    for line in out:
        print(line)

    if not ok:
        print("check_sd_driver_conformance: FAILED — see lines above", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
