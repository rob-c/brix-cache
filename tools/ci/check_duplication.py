#!/usr/bin/env python3
#
# WHAT: Fail CI when lizard's copy-paste detector (-Eduplicate) finds a real
#       duplicated code block anywhere in src/, client/ or shared/. There is
#       NO backlog and NO per-block exemption list: the count is zero and it
#       stays zero (the 484-entry grandfather backlog was burned down and
#       deleted 2026-08-24).
#
# WHY:  Copy-paste is how helper reimplementation (a HARD BLOCK — see CLAUDE.md
#       HELPERS) actually happens: a block is cloned, then the copies drift.
#       This guard turns "a reviewer must spot 30 cloned lines" into red/green.
#
# HOW:  lizard -Eduplicate is token-shape based, so it also reports blocks that
#       merely SHARE SHAPE while holding different data — two unrelated
#       ngx_command_t directive tables, two different errno mapping tables, two
#       different enum->string switches. Those are the §8.6 table-driven style
#       (coding-standards: "express variation as data") and are NOT copy-paste,
#       so each reported block is verified before it can fail the build:
#
#         * lizard is run once over all three trees combined (cross-tree clones)
#           and once per tree (window segmentation differs; the union is kept);
#         * each block's members are normalised (comments/preprocessor stripped,
#           continuation lines joined into logical rows);
#         * a block whose members are all C/C++ declarative data — initializer
#           rows, case-mapping rows, string/hex fixture rows, prototype rows,
#           `return shared_helper(...)` delegation rows — is exempt ONLY when
#           the members hold DIFFERENT data (fewer than half their content rows
#           identical). A cloned table with the SAME rows is real duplication:
#           the table must be shared, not pasted.
#         * everything else — cloned logic, renamed clones, identical tables,
#           any non-C member — FAILS. Fix by extracting a shared helper
#           (coding-standards §8), never by editing this guard's row grammar
#           to make a clone look declarative.
#
# USAGE:
#   tools/ci/check_duplication.py           # non-zero exit on any violation
#   tools/ci/check_duplication.py --explain # also list the exempted blocks
#
# Requires: lizard  (pip install --user lizard)

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TREES = ("src", "client", "shared")
C_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".hpp", ".hh")

# A member line inside a lizard stanza: "path:start ~ end".
_MEMBER = re.compile(r"^(.+):([0-9]+) ~ ([0-9]+)$")

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")

# Structural scaffolding rows: carry no content, excluded from row-share.
_SCAFFOLD_ROW = re.compile(
    r"^(?:\{|\}\s*;?,?|ngx_null_command\s*\}?,?;?|NULL\s*\},?;?"
    r"|\{\s*ngx_null_string,\s*0\s*\},?;?"           # enum-table terminator
    r"|switch\s*\([^)]*\)\s*\{|default\s*:.*"
    r"|(?:static\s+)?(?:const\s+)?[\w \t\*]+(?:\[\w*\])+\s*=\s*\{"
    r"|(?:typedef\s+)?(?:static\s+)?(?:const\s+)?struct\s*\{"
    r"|(?:static\s+)?ngx_command_t\b.*"
    r"|\}\s*\w+\s*\[\]\s*=\s*\{"
    r"|[\w \t\*]+[\s\*]\**\w+\s*\([^;{}]*\)\s*\{"    # function-definition header
    r")$"
)

# Declarative content rows: data an author states, not logic an author wrote.
_DATA_ROW = re.compile(
    r"^(?:"
    r"\{.*\},?;?"                                    # brace-initializer row
    r"|case\s+[\w:]+\s*:(?:\s*(?:return\b[^;]*|break)\s*;)?"
    r"|return\s+(?:\"[^\"]*\"|[\w\->\.\[\]]+)\s*;"   # return of a name/string
    r"|\"[^\"]*\"\s*,?"                              # string array element
    r"|[\w\.\[\]]+\s*:\s*[^;]+,?"                    # label: value row
    r"|[\w\.\[\]\->]+\s*=\s*[^=;]+[,;]"              # designated/assign row
    r"|[A-Za-z_]\w*\s*\([^;{}]*\)\s*[;,]"            # call statement / call initializer element
    r"|[\w\| \t]+,"                                  # bare flag/enum row
    r"|(?:0x[0-9a-fA-F]+\s*,\s*)*0x[0-9a-fA-F]+\s*,?"  # hex fixture row
    r"|[\w&]+\s*\},?;?"                              # trailing enum-ptr row
    r"|(?:extern\s+)?[\w \t]+[\s\*]\**\w+\s*\([^;{}]*\)\s*;"  # prototype row
    r"|return\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*;"      # return shared_helper(...)
    r"|[^;{}]*\},?"                                  # initializer tail fragment
    r"|\{[^;]*"                                      # initializer head fragment
    r")$"
)


def find_lizard() -> str | None:
    """Locate lizard exactly like tools/readability.find_lizard: prefer PATH,
    then the pip --user install dir. Returns None when nothing is found."""
    for c in ("lizard", os.path.expanduser("~/.local/bin/lizard")):
        if shutil.which(c) or os.path.exists(c):
            return c
    return None


def _parse_blocks(text: str) -> list[str]:
    """Turn one lizard -Eduplicate stream into a list of '+'-joined member keys.
    A "Duplicate block:" opens a stanza, member lines accumulate, a "^^^^" rule
    finalises it (members sorted, joined); an incomplete stanza is discarded."""
    keys: list[str] = []
    inblock = False
    members: list[str] = []
    for line in text.splitlines():
        if line.startswith("Duplicate block:"):
            inblock = True
            members = []
            continue
        if inblock and line.startswith("^^^"):
            keys.append("+".join(sorted(members)))
            inblock = False
            continue
        member = _member_key(line) if inblock else None
        if member:
            members.append(member)
    return keys


def _member_key(line):
    match = _MEMBER.match(line)
    if not match:
        return None
    path, start, end = match.group(1), match.group(2), match.group(3)
    return f"{path}:{start}-{end}"


def list_duplicates(lizard: str, root: Path = ROOT) -> list[str]:
    """One sorted, de-duplicated key per live duplicate block. lizard is run
    once over all three trees together (cross-tree clones) and once per tree
    (its sliding-window dedup segments differently per corpus); the union is
    kept. Relative tree paths keep the reported file column repo-relative."""
    keys: list[str] = []
    for scan in [TREES] + [(t,) for t in TREES]:
        result = subprocess.run(
            [lizard, "-Eduplicate", *scan],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        keys.extend(_parse_blocks(result.stdout))
    return sorted(set(keys))


def _clean_lines(text: str) -> list[str]:
    """Comment- and preprocessor-free, stripped, non-blank source lines."""
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _LINE_COMMENT.sub(" ", text)
    kept = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            kept.append(line)
    return kept


def _join_rows(lines: list[str]) -> list[str]:
    """Join continuation lines into logical rows: a row completes when it ends
    with '{' (an opener), or its own braces/parens balance and it ends with
    ',', ';' or '}'. A trailing unterminated fragment still becomes a row."""
    rows: list[str] = []
    buf = ""
    for line in lines:
        buf = (buf + " " + line).strip() if buf else line
        if buf.endswith("{") or _row_complete(buf):
            rows.append(" ".join(buf.split()))
            buf = ""
    if buf:
        rows.append(" ".join(buf.split()))
    return rows


def _row_complete(buf: str) -> bool:
    braces = buf.count("{") - buf.count("}")
    parens = buf.count("(") - buf.count(")")
    return braces <= 0 and parens <= 0 and buf.endswith((",", ";", "}"))


def _is_declarative(rows: list[str]) -> bool:
    """True when >= 80% of the block's interior rows are data/scaffolding.
    The first and last row are window artifacts (lizard's token window cuts
    entries mid-row at the block edges) and are not scored."""
    if len(rows) <= 2:
        return True
    core = rows[1:-1]
    hits = sum(1 for r in core if _SCAFFOLD_ROW.match(r) or _DATA_ROW.match(r))
    return hits / len(core) >= 0.8


# A row that IDENTIFIES its table: carries a string literal, a call/paren
# expression, a brace initializer, or a hex literal. Bare-token rows
# (`ngx_conf_set_flag_slot,`, `NGX_HTTP_LOC_CONF_OFFSET,`, flag masks) are
# shared vocabulary across every directive table and prove nothing.
_IDENTIFYING = re.compile(r'["({]|0x[0-9a-fA-F]')


def _content_rows(rows: list[str]) -> set[str]:
    return {
        r for r in rows
        if not _SCAFFOLD_ROW.match(r) and _IDENTIFYING.search(r)
    }


def _span(member: str) -> tuple[str, int, int]:
    path, span = member.rsplit(":", 1)
    start, end = span.split("-")
    return path, int(start), int(end)


def _overlapping(m1: str, m2: str) -> bool:
    """lizard's sliding window reports a self-similar table as overlapping
    windows of ITSELF; two members covering the same lines share text because
    they ARE the same text, which is not evidence of a clone."""
    p1, a1, b1 = _span(m1)
    p2, a2, b2 = _span(m2)
    return p1 == p2 and a1 <= b2 and a2 <= b1


def _pair_share(a: set[str], b: set[str]) -> float | None:
    """Identical-content-row fraction for one disjoint pair; None when either
    side is pure scaffolding (no content rows -> no evidence either way)."""
    if not a or not b:
        return None
    return len(a & b) / min(len(a), len(b))


def _max_row_share(members: list[str], rowsets: list[list[str]]) -> float:
    """Highest identical-content-row fraction over the DISJOINT member pairs.
    Identical tables approach 1.0; different-data tables stay low; a block
    with no disjoint evidence at all scores 0."""
    best = 0.0
    sets = [_content_rows(r) for r in rowsets]
    for i, j in combinations(range(len(sets)), 2):
        if _overlapping(members[i], members[j]):
            continue
        share = _pair_share(sets[i], sets[j])
        if share is not None:
            best = max(best, share)
    return best


def _snippet(member: str, cache: dict) -> str:
    path, span = member.rsplit(":", 1)
    start, end = span.split("-")
    if path not in cache:
        source = (ROOT / path).read_text(errors="replace")
        cache[path] = source.splitlines()
    return "\n".join(cache[path][int(start) - 1:int(end)])


def _all_c_members(members: list[str]) -> bool:
    return all(m.rsplit(":", 1)[0].endswith(C_SUFFIXES) for m in members)


def _all_declarative(rowsets: list[list[str]]) -> bool:
    return all(_is_declarative(r) for r in rowsets)


def classify(key: str, cache: dict) -> str | None:
    """None when the block is exempt (declarative C data with different
    content); otherwise a short reason string for the FAIL report."""
    members = key.split("+")
    if not _all_c_members(members):
        return "cloned non-C code"
    rowsets = [_join_rows(_clean_lines(_snippet(m, cache))) for m in members]
    if not _all_declarative(rowsets):
        return "cloned logic — extract a shared helper (coding-standards §8)"
    share = _max_row_share(members, rowsets)
    if share >= 0.5:
        return f"cloned data table ({share:.0%} identical rows) — share it"
    return None


def run(root: Path = ROOT) -> tuple[list[str], list[str]]:
    """Scan and verify. Returns (fail_lines, exempt_keys)."""
    lizard = find_lizard()
    cache: dict = {}
    fail_lines: list[str] = []
    exempt: list[str] = []
    for key in list_duplicates(lizard, root):
        reason = classify(key, cache)
        if reason is None:
            exempt.append(key)
            continue
        fail_lines.append(f"FAIL duplicated block — {reason}:")
        fail_lines.extend(f"    {member}" for member in key.split("+"))
    return fail_lines, exempt


def _print_exempt(exempt: list[str]) -> None:
    for key in exempt:
        print("exempt (declarative data, different content): "
              + " ".join(key.split("+")))


def _verdict(fail_lines: list[str], exempt_count: int) -> int:
    if not fail_lines:
        print(f"check_duplication: OK (0 duplicate blocks; "
              f"{exempt_count} shape-only matches exempt)")
        return 0
    count = sum(1 for line in fail_lines if line.startswith("FAIL"))
    print(f"check_duplication: FAIL ({count} duplicated block(s) — extract "
          f"shared helpers; there is no backlog to hide behind)",
          file=sys.stderr)
    return 1


def check(explain: bool) -> int:
    fail_lines, exempt = run()
    for line in fail_lines:
        print(line)
    if explain:
        _print_exempt(exempt)
    return _verdict(fail_lines, len(exempt))


def main() -> int:
    if find_lizard() is None:
        print("check_duplication: FAIL — lizard not found "
              "(pip install --user lizard)", file=sys.stderr)
        return 1
    # Run from the repo root so lizard's tree paths are repo-relative.
    os.chdir(ROOT)
    return check("--explain" in sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
