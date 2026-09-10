#!/usr/bin/env python3
#
# check_doc_paths.py — repo paths referenced by the docs must exist.
#
# WHAT: Fails (exit 1) when a scanned document references a repo-relative path
#       (src/…, tools/…, tests/…, docs/…, …) that does not exist in the working
#       tree, or exists but is NOT git-tracked (a gitignore casualty: present
#       locally, absent in every fresh clone — exactly how the fail2ban configs
#       and tools/ci guards went missing).
#
#       Two scopes, deliberately different:
#         NAV_DOCS   — CLAUDE.md, README.md, docs/index.md. Every path-shaped
#                      token is checked. These are curated navigation tables;
#                      an unresolvable token there is always a defect.
#         TREE_DOCS  — every .md under docs/01-getting-started …
#                      docs/08-metrics-monitoring. Prose here legitimately
#                      contains slashes that are not paths ("client/server
#                      ecosystem", "shared/mounted", "deploy/doc"), so a token
#                      must additionally LOOK like a path: a known file
#                      extension, three or more segments, or a trailing slash.
#                      docs/09..11 are excluded on purpose — they are
#                      developer history, refactor phase records and reference
#                      archaeology, where naming a path that has since been
#                      deleted IS the content.
#
# WHY:  The OP→FILE tables in CLAUDE.md are the fastest entry point into the
#       codebase for humans and agents. After tree-reorganization phases
#       (66/67/69 moved nearly every file) these references rot silently and
#       send readers to dead paths — the opposite of a fast entry point. The
#       same rot reached the user-facing operator tree: a 2.0 doc sweep found
#       run_*.sh runners, a deleted webdav proxy.c and a test file that never
#       existed being cited as evidence, none of which the three-doc scope saw.
#
# HOW:  Expand brace lists (`src/foo.{c,h}` → two tokens), then extract
#       path-shaped tokens rooted at a known top-level directory (negative
#       lookbehind so /tmp/foo/src/x.h does not match src/x.h), drop
#       globs/ellipses/placeholders, then test each against the repo.
#       Regions between `<!-- doc-paths:off -->` and `<!-- doc-paths:on -->`
#       are skipped — use ONLY for deliberate references to paths that no
#       longer exist (a migration table, a verbatim historical transcript, or
#       paths that live inside some OTHER tree such as an upstream checkout or
#       a CVMFS repository), never to silence a genuinely stale reference.
#
# USAGE:
#   tools/ci/check_doc_paths.py    # exit 0 = clean, exit 1 = stale reference

import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
NAV_DOCS = ("CLAUDE.md", "README.md", "docs/index.md")

# User-facing trees. 09/10/11 are excluded: see the HOW note above.
TREE_ROOTS = (
    "docs/01-getting-started",
    "docs/02-concepts",
    "docs/03-configuration",
    "docs/04-protocols",
    "docs/05-operations",
    "docs/06-authentication",
    "docs/07-security",
    "docs/08-metrics-monitoring",
)

# Build products: gitignored on purpose, so the tracked-ness test would flag
# every doc that names one, and the existence test would flag them in a clean
# checkout. `client/bin/xrdcp` is what the docs tell a user to RUN — the right
# reference, produced by `make -C client`. Prefix match, so a token must sit
# inside one of these directories.
BUILD_OUTPUT_PREFIXES = ("client/bin/", "client/lib/libbrix", "objs/")
BUILD_OUTPUT_DIRS = frozenset(("client/bin",))

# Extensions that make a slashed token unambiguously a file reference. Prose
# never writes "client/server.c"; it does write "client/server ecosystem".
KNOWN_SUFFIXES = frozenset((
    ".1", ".8", ".astro", ".c", ".cc", ".cfg", ".cmake", ".conf", ".cpp",
    ".crt", ".css", ".csv", ".diff", ".env", ".fc", ".go", ".h", ".hh",
    ".html", ".if", ".in", ".ini", ".js", ".json", ".key", ".ko", ".lua",
    ".markdown", ".md", ".mk", ".patch", ".pc", ".pem", ".pp", ".py", ".repo",
    ".rs", ".service",
    ".sh", ".so", ".spec", ".sql", ".te", ".toml", ".ts", ".tsv", ".txt",
    ".xml", ".yaml", ".yml",
))

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


# Prefix, the alternatives, and whatever trails the brace — `src/net/cms/` +
# `connect,recv` + `.c`. The trailing group matters: without it the expansion
# of `src/net/cms/{connect,recv}.c` loses the extension and every branch
# resolves to nothing.
_BRACES = re.compile(r"([\w./-]+)\{([\w.,+-]+)\}([\w.]*)")


def _expand_braces(line: str) -> str:
    """`src/auth/gsi.{c,h}` -> `src/auth/gsi.c src/auth/gsi.h`.

    Docs abbreviate a sibling pair this way constantly. Un-expanded, the token
    regex stops at the `{` and yields `src/auth/gsi`, which resolves to nothing
    — so the guard either false-fails or (worse, before this) was quietly given
    a `doc-paths:off` fence that then hid the real references beside it."""
    return _BRACES.sub(_expand_one, line)


def _expand_one(match: "re.Match") -> str:
    prefix, body, suffix = match.group(1), match.group(2), match.group(3)
    return " ".join(prefix + part + suffix for part in body.split(","))


def _looks_like_path(token: str) -> bool:
    """True when a slashed token is a file reference rather than English prose.

    Applied only in TREE_ROOTS. `docs/index.md` and `src/fs/vfs/vfs_policy.c`
    qualify; `client/server ecosystem`, `shared/mounted` and `deploy/doc` do
    not. Cost: a real two-segment extensionless path (`tests/fuzz`) is not
    checked in that scope — deliberate, since the false-positive rate of the
    unfiltered rule on prose is far higher."""
    return (
        token.endswith("/")
        or token.count("/") >= 2
        or PurePosixPath(token).suffix in KNOWN_SUFFIXES
    )


def _extract(doc: Path, strict: bool) -> list[str]:
    """Sorted-unique path tokens from a doc, honouring doc-paths:off/on regions.

    `strict` (the navigation docs) keeps every token; otherwise only tokens
    that pass `_looks_like_path`."""
    tokens = {
        token
        for line in _visible_lines(doc.read_text().splitlines())
        for token in _line_tokens(_expand_braces(line))
        if strict or _looks_like_path(token)
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


def scanned_documents(root: Path = ROOT) -> list[tuple[str, bool]]:
    """Every document this guard reads, as (repo-relative path, strict).

    Exposed so a test can pin the guard's REACH: the 2.0 sweep found stale
    paths in the operator tree precisely because the scope was three files, and
    a scope regression is invisible from the guard's own exit code."""
    nav = [(name, True) for name in NAV_DOCS if (root / name).is_file()]
    return nav + sorted(
        (path.relative_to(root).as_posix(), False)
        for tree in TREE_ROOTS
        for path in (root / tree).rglob("*.md")
    )


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Scan the navigation docs and the user-facing trees.

    Returns (clean, violation_lines); clean is True when every referenced path
    exists and is git-tracked."""
    messages = [
        message
        for relative, strict in scanned_documents(root)
        for message in _document_messages(root, relative, strict)
    ]
    return not messages, messages


def _document_messages(root, relative, strict):
    document = root / relative
    if not document.is_file():
        return []
    return [
        message
        for token in _extract(document, strict)
        for message in _path_message(root, relative, token)
    ]


def _is_build_output(path: str) -> bool:
    return path in BUILD_OUTPUT_DIRS or path.startswith(BUILD_OUTPUT_PREFIXES)


def _path_message(root, relative, token):
    path = token[:-1] if token.endswith("/") else token
    if _is_build_output(path):
        return []
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
