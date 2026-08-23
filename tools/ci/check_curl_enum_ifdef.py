#!/usr/bin/env python3
#
# WHAT: Fail CI when any C source/header under src/, client/ or shared/ tests a
#       CURLOPT_*/CURLINFO_* name with the preprocessor (`#ifdef CURLOPT_X`,
#       `#if defined(CURLINFO_Y)`).
#
# WHY:  curl's option and info names are ENUM CONSTANTS, not macros, so every
#       such test is unconditionally false. The branch it guards silently never
#       compiles: the 2026-08 asan-lane failure was exactly this — an
#       `#ifdef CURLOPT_PROTOCOLS_STR` fallback that always selected the
#       deprecated CURLOPT_PROTOCOLS and died under
#       -Werror=deprecated-declarations, and the same latent pattern had
#       disabled the TPC progress callback (CURLOPT_XFERINFOFUNCTION), the
#       pmark socket callbacks, and connection-age recycling for years.
#       Feature-gate on the release that introduced the symbol instead:
#       `#if CURL_AT_LEAST_VERSION(maj, min, patch)`.
#
# HOW:  Pure text scan of *.c/*.h. Only preprocessor lines are examined, so doc
#       comments discussing the anti-pattern never false-positive. Backlog
#       target = 0 — there is no legitimate use; new hits must be converted to
#       CURL_AT_LEAST_VERSION gates.

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SCAN_TREES = ("src", "client", "shared")

# An #ifdef/#ifndef naming a curl enum constant, or an #if/#elif applying
# defined() to one. Both are always-false (the names are enumerators).
IFDEF = re.compile(r"^\s*#\s*(ifdef|ifndef)\s+CURL(OPT|INFO)_\w+")
DEFINED = re.compile(
    r"^\s*#\s*(if|elif)\b.*\bdefined\s*\(\s*CURL(OPT|INFO)_\w+"
)


def _hits(root: Path) -> list[str]:
    return [
        hit
        for tree in SCAN_TREES
        for path in _source_files(root / tree)
        for hit in _file_hits(root, path)
    ]


def _source_files(base):
    if not base.is_dir():
        return []
    return [
        path for path in sorted(base.rglob("*"))
        if path.suffix in (".c", ".h") and path.is_file()
    ]


def _file_hits(root, path):
    text = path.read_bytes().decode("utf-8", "surrogateescape")
    return [
        f"{path.relative_to(root)}:{lineno}:{line.strip()}"
        for lineno, line in enumerate(text.split("\n"), start=1)
        if IFDEF.search(line) or DEFINED.search(line)
    ]


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Returns (passed, stdout_lines)."""
    hits = _hits(root)
    if hits:
        return False, [
            f"check_curl_enum_ifdef: {len(hits)} preprocessor test(s) on a "
            "curl enum constant — these are ALWAYS false (CURLOPT_*/CURLINFO_* "
            "are enumerators, not macros), so the guarded branch never "
            "compiles:",
            *hits,
            "Gate on the introducing release instead: "
            "#if CURL_AT_LEAST_VERSION(maj, min, patch).",
        ]
    return True, ["check_curl_enum_ifdef: OK (no preprocessor tests on curl "
                  "enum constants)"]


def main() -> int:
    os.chdir(ROOT)
    passed, lines = run()
    for line in lines:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
