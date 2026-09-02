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

# The two DECORATOR drivers wrap the same source and compose in either order, so
# a NAMESPACE slot published by one and not the other silently changes what an
# export supports depending on which tier happened to end up on top. That is not
# hypothetical: `truncate_path` was relayed by `stage` and not by `cache`, so a
# cache-fronted root:// export lost the path-native truncate and fell back into
# the whole-file staging round trip the slot exists to avoid. The BYTE plane is
# deliberately excluded — the cache serves reads from its store and the stage
# tier owns writes, so their data slots differ by design — with one exception:
# `reserve` (phase-107 C5) is object-keyed but must exist on BOTH decorators (a
# spool relay on stage, an honest EOPNOTSUPP pass-through answer on cache),
# because a slot relayed by one and absent on the other is the truncate_path
# asymmetry again.
DECORATORS = ("cache", "stage")
_PARITY_BASE = (
    "stat", "unlink", "unlink_many", "mkdir", "rename", "setattr",
    "truncate_path", "server_copy", "space", "opendir", "readdir", "closedir",
    "getxattr", "listxattr", "setxattr", "removexattr", "reserve", "evict",
    "exchange",   # phase-107 C6: relayed by both decorators (ENOTSUP downward)
)
PARITY_OPS = frozenset(_PARITY_BASE) | frozenset(
    op + "_cred" for op in _PARITY_BASE
)

# X(ID, sym, "name", KIND) rows — mirrors the shell grep -oE + sed exactly.
_ROW_RE = re.compile(
    r'X\([A-Z0-9_]+, *([a-z0-9_]+), *"([a-z0-9_]+)", *'
    r'(?:BACKEND|ORIGIN|DECORATOR|NEARLINE)\)'
)
# `.<slot> =` designated initializers. The digit matters: `.preadv2` is a real
# slot, and a name class without [0-9] matched `.preadv` and then failed on the
# `2`, so the slot was invisible to the matrix, the #ops count and every gate.
_SLOT_RE = re.compile(r'\.[a-z0-9_]+\s*=')
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
    matches = [path for path in _backend_c_files() if _defines_driver(path, decl)]
    return sorted(matches)[0] if matches else None


def _backend_c_files():
    for dirpath, _dirs, files in os.walk(BACKEND):
        for fname in files:
            if fname.endswith(".c"):
                yield Path(dirpath) / fname


def _defines_driver(path: Path, declaration: re.Pattern) -> bool:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return False
    return any(declaration.search(line) for line in text.splitlines())


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
    return _render_rows(rows)


def _render_rows(rows):
    header = "%-11s %-10s %-6s" % ("driver", "name", "#ops")
    header += "".join(" %s" % op[:3] for op in MATRIX_OPS)
    results = list(_driver_reports(rows))
    parity = _decorator_parity(rows)
    fail = _any_failed(results) or bool(parity)
    out = [header]
    out.extend(_result_lines(results))
    out.extend(parity)
    out.append("")
    out.extend(_success_lines(fail))
    return (not fail), out


def _parity_slots(rows) -> dict[str, set[str]]:
    """The namespace slot set each decorator publishes, or {} if either struct
    cannot be located (the per-driver report already fails on that)."""
    out: dict[str, set[str]] = {}
    for sym, _name in rows:
        if sym not in DECORATORS:
            continue
        path = _find_driver_file(sym)
        if path is None:
            return {}
        out[sym] = _slots(_initializer_block(path, sym)) & PARITY_OPS
    return out if len(out) == len(DECORATORS) else {}


def _decorator_parity(rows) -> list[str]:
    """FAIL lines for every namespace slot one decorator relays and the other
    does not — see DECORATORS above for why that asymmetry is a live defect."""
    sets = _parity_slots(rows)
    if not sets:
        return []
    first, second = DECORATORS
    lines = []
    for op in sorted(sets[first] ^ sets[second]):
        has, lacks = (first, second) if op in sets[first] else (second, first)
        lines.append(
            "FAIL decorator parity: '%s' relays .%s and '%s' does not — a "
            "namespace slot must be published by both or by neither" %
            (has, op, lacks)
        )
    return lines


def _any_failed(results):
    return any(failed for failed, _lines in results)


def _result_lines(results):
    out = []
    for _failed, lines in results:
        out.extend(lines)
    return out


def _success_lines(failed):
    if failed:
        return []
    return ["check_sd_driver_conformance: OK (every registered driver "
            "has a matching struct + a data op)"]


def _driver_reports(rows):
    for sym, name in rows:
        if sym:
            yield _driver_report(sym, name)


def _driver_report(sym: str, name: str) -> tuple[bool, list[str]]:
    path = _find_driver_file(sym)
    if path is None:
        return True, [
            "FAIL driver '%s' (name=%s): registered in fs_list.h but no "
            "brix_sd_%s_driver struct defined" % (sym, name, sym)
        ]
    block = _initializer_block(path, sym)
    slots = _slots(block)
    name_status, name_failed = _name_status(_name_val(block), name)
    lines = []
    data_failed = not bool(slots & DATA_OPS)
    if data_failed:
        lines.append("FAIL driver '%s': implements no data/namespace op "
                     "(dead driver struct)" % sym)
    lines.append(_matrix_line(sym, name_status, slots))
    return name_failed or data_failed, lines


def _name_status(actual: str, expected: str) -> tuple[str, bool]:
    if not actual:
        return "NO-NAME", True
    if actual != expected:
        return "!=%s" % actual, True
    return "ok", False


def _matrix_line(sym: str, name_status: str, slots: set[str]) -> str:
    line = "%-11s %-10s %-6s" % (sym, name_status, str(len(slots)))
    return line + "".join(
        " %3s" % (" x" if op in slots else " .") for op in MATRIX_OPS
    )


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
