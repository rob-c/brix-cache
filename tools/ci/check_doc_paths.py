#!/usr/bin/env python3
#
# check_doc_paths.py — repo paths referenced by the navigation docs must exist.
#
# WHAT: Fails (exit 1) when CLAUDE.md, README.md, or docs/index.md references
#       a repo-relative path (src/…, tools/…, tests/…, docs/…, …) that does
#       not exist in the working tree, or exists but is NOT git-tracked (a
#       gitignore casualty: present locally, absent in every fresh clone —
#       exactly how the fail2ban configs and tools/ci guards went missing).
#
# WHY:  The OP→FILE tables in CLAUDE.md are the fastest entry point into the
#       codebase for humans and agents. After tree-reorganization phases
#       (66/67/69 moved nearly every file) these references rot silently and
#       send readers to dead paths — the opposite of a fast entry point.
#
# HOW:  Extract path-shaped tokens rooted at a known top-level directory
#       (negative lookbehind so /tmp/foo/src/x.h does not match src/x.h),
#       drop globs/ellipses/placeholders, then test each against the repo.
#       Regions between `<!-- doc-paths:off -->` and `<!-- doc-paths:on -->`
#       are skipped — use ONLY for deliberate references to paths that no
#       longer exist (e.g. the deprecated-path migration table in
#       docs/index.md), never to silence a genuinely stale reference.
#
# USAGE:
#   tools/ci/check_doc_paths.py    # exit 0 = clean, exit 1 = stale reference
#
# Faithful port of check_doc_paths.sh — byte-identical stdout and exit code.

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ("CLAUDE.md", "README.md", "docs/index.md")

# Path-shaped token rooted at a known top-level directory. The negative
# lookbehind stops /tmp/foo/src/x.h from matching src/x.h. re.ASCII pins \w to
# [A-Za-z0-9_] to mirror grep -P under the C locale.
_TOKEN = re.compile(
    r"(?<![\w./-])"
    r"(?:src|shared|client|tools|tests|docs|deploy|contrib|packaging|k8s-tests|utils)"
    r"/[\w./*-]+",
    re.ASCII,
)
_TRAILING = re.compile(r"[).,:;]*$")   # sed 's/[).,:;]*$//'
_REJECT = re.compile(r"[*<>]|…|\.\.\.")  # grep -vE '[*<>]|…|\.\.\.'


def _extract(doc: Path) -> list[str]:
    """Sorted-unique path tokens from a doc, honouring doc-paths:off/on regions.

    Mirrors the shell pipeline: sed range-delete, grep -oP, sed trim, grep -v,
    sort -u — the trailing-slash tolerance happens later, at check time, exactly
    as in the bash while-loop."""
    tokens = {
        token
        for line in _visible_lines(doc.read_text().splitlines())
        for token in _line_tokens(line)
    }
    return sorted(tokens)


def _visible_lines(lines):
    skipping = False
    for line in lines:
        # sed '/<!-- doc-paths:off/,/<!-- doc-paths:on/d'
        if skipping:
            skipping = "<!-- doc-paths:on" not in line
            continue
        if "<!-- doc-paths:off" in line:
            skipping = True
            continue
        yield line


def _line_tokens(line):
    return [
        trimmed
        for match in _TOKEN.findall(line)
        for trimmed in [_TRAILING.sub("", match)]
        if not _REJECT.search(trimmed)
    ]


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Scan the navigation docs. Returns (clean, violation_lines).

    clean is True when every referenced path exists and is git-tracked."""
    messages = [
        message
        for relative in DOCS
        for message in _document_messages(root, relative)
    ]
    return not messages, messages


def _document_messages(root, relative):
    document = root / relative
    if not document.is_file():
        return []
    return [
        message
        for token in _extract(document)
        for message in _path_message(root, relative, token)
    ]


def _path_message(root, relative, token):
    path = token[:-1] if token.endswith("/") else token
    if not (root / path).exists():
        return [f"FAIL {relative} references missing path: {path}"]
    if not _tracked(root, path):
        return [f"FAIL {relative} references untracked (gitignored?) path: {path}"]
    return []


def _tracked(root: Path, path: str) -> bool:
    """True when `git ls-files -- path` reports at least one tracked entry."""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--", path],
        capture_output=True,
        text=True,
    )
    return bool(result.stdout)


def main() -> int:
    os.chdir(ROOT)
    clean, messages = run()
    for line in messages:
        print(line)
    if clean:
        print("check_doc_paths: OK")
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
