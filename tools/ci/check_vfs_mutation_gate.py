#!/usr/bin/env python3
#
# check_vfs_mutation_gate.py — enforce "an export mutation is gated by the
# endpoint's read-only policy" (phase-105 §4.1).
#
# WHAT: Fails (exit 1) when code OUTSIDE the VFS/storage layer (src/fs/) reaches
#       exported storage through a CONFINEMENT-ONLY mutator:
#         brix_vfs_unlink_path / _unlink_at / _rmdir_path / _mkdir_path /
#         brix_vfs_backend_mkpath / brix_vfs_rename_path / brix_vfs_copyfile /
#         brix_vfs_copytree, and any brix_vfs_open_fd[_at]() whose flags include
#         O_CREAT / O_WRONLY / O_RDWR / O_TRUNC.
#       Those helpers confine a path beneath the export root; they do not ask
#       whether the endpoint is allowed to write at all. The policy-bearing
#       twins — brix_vfs_export_*() in src/fs/vfs/vfs_policy_export.c — take a
#       brix_vfs_export_op_ctx_t and refuse a read-only endpoint with EROFS
#       before touching the filesystem.
#
# WHY:  Phase-105 makes read-only an immutable, VFS-authoritative property. That
#       only holds while every mutation route runs through it: a single raw
#       unlink in a protocol handler, a TPC cleanup, or a CMS-forwarded op is a
#       hole a client can drive through, and the protocol-edge allow_write gate
#       cannot see it. A same-line 'vfs-seam-allow' marker waives the SEAM rule
#       (is this storage reached through the VFS?) — it never waives this one
#       (may this endpoint write at all?), so the two guards are independent.
#
# HOW:  Scan src/**.c, drop the VFS/storage layer and unit tests, and report any
#       remaining call. A genuinely service-owned mutation — reclaiming a temp
#       or a journal record THIS server created under a write the endpoint had
#       already authorised — carries a
#           /* vfs-mutation-gate-allow: <reason> */
#       marker on the call's line or in the comment block directly above it.
#       tools/ci/vfs_mutation_gate_backlog.txt grandfathers 'path:' prefixes; it
#       ships EMPTY and must stay that way (§4.1: "Finish with an empty
#       exception/backlog file").
#
# USAGE:
#   tools/ci/check_vfs_mutation_gate.py            # check; exit 1 on a new hole
#   tools/ci/check_vfs_mutation_gate.py --regen    # rewrite the backlog (only
#                                                  # after a deliberate migration)

import bisect
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

BACKLOG = "tools/ci/vfs_mutation_gate_backlog.txt"

MARKER = "vfs-mutation-gate-allow"

# Confinement-only mutators: every one of these has a brix_vfs_export_* twin.
_MUTATORS = (
    "brix_vfs_unlink_path|brix_vfs_unlink_at"
    "|brix_vfs_rmdir_path|brix_vfs_mkdir_path|brix_vfs_backend_mkpath"
    "|brix_vfs_rename_path|brix_vfs_copyfile|brix_vfs_copytree"
)
MUTATOR_RE = re.compile(r"\b(" + _MUTATORS + r")\s*\(")

# open_fd[_at] is dual-use: only a CREATE/WRITE/TRUNC open is a mutation, and a
# read-only open must NOT be gated (refusing it would break reads on a read-only
# export — the exact opposite of the policy).
OPEN_RE = re.compile(r"\bbrix_vfs_open_fd(_at)?\s*\(")
WRITE_FLAG_RE = re.compile(r"\bO_(CREAT|WRONLY|RDWR|TRUNC)\b")

# The layer that DEFINES the helpers and the storage below them, plus the unit
# tests that drive them directly.
ALLOW_RE = re.compile(r"^src/fs/|unittest|_test\.c$")


def _c_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".c"):
                yield os.path.join(dirpath, name)


def _call_args(text, open_paren):
    """Return the text between `open_paren` and its matching ')' (or '' when the
    call is unterminated), so a call split across lines is judged whole."""
    depth = 0
    for i in range(open_paren, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
    return ""


# One pass over comments and string literals: a block comment, a line comment,
# or a "..." literal. Blanking them (newlines preserved, so offsets still map to
# their real line) is what stops prose that NAMES a helper — an #include
# trailer, a WHAT block — from reading as a call.
_NONCODE_RE = re.compile(r'''/\*.*?\*/|//[^\n]*|"(?:[^"\\\n]|\\.)*"''', re.S)


def _blanked(match):
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _blank_noncode(text):
    """`text` with every comment/string byte replaced by a space, in place."""
    return _NONCODE_RE.sub(_blanked, text)


def _is_comment_line(line):
    stripped = line.lstrip()
    return stripped.startswith(("*", "//", "/*"))


def _waived(lines, lineno):
    """True when the call carries a mutation-gate marker: on its own line, or in
    the comment block that runs directly above it."""
    idx = lineno - 1
    if MARKER in lines[idx]:
        return True
    idx -= 1
    while idx >= 0 and _is_comment_line(lines[idx]):
        if MARKER in lines[idx]:
            return True
        idx -= 1
    return False


def _line_starts(lines):
    """Byte offset of each line, so an offset can be mapped without rescanning."""
    starts, pos = [], 0
    for line in lines:
        starts.append(pos)
        pos += len(line) + 1
    return starts


def _raw_hits(code):
    """(lineno-less) offset+symbol pairs for every mutating call in `code`."""
    hits = [(m.start(), m.group(1)) for m in MUTATOR_RE.finditer(code)]
    for match in OPEN_RE.finditer(code):
        if WRITE_FLAG_RE.search(_call_args(code, match.end() - 1)):
            hits.append((match.start(),
                         "brix_vfs_open_fd" + (match.group(1) or "")))
    return hits


def _read(path):
    try:
        with open(path, "r", encoding="latin-1") as fh:
            return fh.read()
    except OSError:
        return None


def _hits_in_file(path):
    text = _read(path)
    if text is None:
        return []

    lines = text.split("\n")
    starts = _line_starts(lines)
    hits = {(bisect.bisect_right(starts, offset), sym)
            for offset, sym in _raw_hits(_blank_noncode(text))}

    return [f"{path}:{lineno}: {sym}(): {lines[lineno - 1].strip()}"
            for lineno, sym in sorted(hits)
            if not _waived(lines, lineno)]


def current_violations():
    out = []
    for path in _c_files("src"):
        if ALLOW_RE.search(path):
            continue
        out.extend(_hits_in_file(path))
    return sorted(set(out))


def _prefixes(lines):
    return sorted(set(line.split(":", 1)[0] + ":" for line in lines))


def _backlog_patterns():
    try:
        with open(BACKLOG, "r", encoding="utf-8") as fh:
            data = fh.read()
    except OSError:
        return None
    return [line for line in data.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


BACKLOG_HEADER = (
    "# vfs_mutation_gate_backlog.txt — grandfathered UNGATED export mutations\n"
    "# (phase-105 §4.1). Each entry is a 'path:' prefix whose confinement-only\n"
    "# mutator calls the guard still tolerates.\n"
    "#\n"
    "# This file is EMPTY BY CONTRACT: phase-105 landed with every export-storage\n"
    "# caller on a brix_vfs_export_* wrapper and every service-owned reclaim\n"
    "# carrying a per-call '/* vfs-mutation-gate-allow: <reason> */' marker.\n"
    "# Adding a line here re-opens a read-only export to writes — migrate the\n"
    "# caller or justify it with a marker instead.\n"
)


def regen():
    violations = current_violations()
    with open(BACKLOG, "w", encoding="utf-8") as fh:
        fh.write(BACKLOG_HEADER)
        for entry in _prefixes(violations):
            fh.write(entry + "\n")
    print(f"check_vfs_mutation_gate: regenerated {BACKLOG} "
          f"({len(_prefixes(violations))} files)")
    return 0


def check():
    patterns = _backlog_patterns()
    if patterns is None:
        print(f"check_vfs_mutation_gate: missing {BACKLOG} "
              "(run with --regen to seed it)", file=sys.stderr)
        return 2

    violations = [v for v in current_violations()
                  if not any(p in v for p in patterns)]
    if violations:
        print("ERROR: ungated export mutation — a read-only endpoint could be "
              "written through this call.", file=sys.stderr)
        print("       Use the policy-bearing twin (brix_vfs_export_*, "
              "fs/vfs/vfs_policy.h), which refuses", file=sys.stderr)
        print("       a read-only export with EROFS before touching the "
              "filesystem:", file=sys.stderr)
        for line in violations:
            print("    " + line, file=sys.stderr)
        print("", file=sys.stderr)
        print("If the mutation is SERVICE-OWNED — reclaiming a temp or journal "
              "record this server", file=sys.stderr)
        print("itself created under an already-authorised write — add a "
              "'/* vfs-mutation-gate-allow:", file=sys.stderr)
        print("<reason> */' marker on the call or in the comment block above "
              "it. A 'vfs-seam-allow'", file=sys.stderr)
        print("marker does NOT waive mutation policy (phase-105 §4.1).",
              file=sys.stderr)
        return 1

    print(f"check_vfs_mutation_gate: OK — every export mutation outside src/fs/ "
          f"is policy-gated or explicitly service-owned "
          f"({len(patterns)} files grandfathered)")
    return 0


def main():
    os.chdir(ROOT)
    if len(sys.argv) > 1 and sys.argv[1] == "--regen":
        return regen()
    return check()


if __name__ == "__main__":
    sys.exit(main())
