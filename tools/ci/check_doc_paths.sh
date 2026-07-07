#!/usr/bin/env bash
#
# check_doc_paths.sh — repo paths referenced by the navigation docs must exist.
#
# WHAT: Fails (exit 1) when CLAUDE.md, README.md, or docs/index.md references
#       a repo-relative path (src/…, tools/…, tests/…, docs/…, …) that does
#       not exist in the working tree.
#
# WHY:  The OP→FILE tables in CLAUDE.md are the fastest entry point into the
#       codebase for humans and agents. After tree-reorganization phases
#       (66/67/69 moved nearly every file) these references rot silently and
#       send readers to dead paths — the opposite of a fast entry point.
#
# HOW:  Extract path-shaped tokens rooted at a known top-level directory
#       (negative lookbehind so /tmp/foo/src/x.h does not match src/x.h),
#       drop globs/ellipses/placeholders, `test -e` each against the repo.
#       Regions between `<!-- doc-paths:off -->` and `<!-- doc-paths:on -->`
#       are skipped — use ONLY for deliberate references to paths that no
#       longer exist (e.g. the deprecated-path migration table in
#       docs/index.md), never to silence a genuinely stale reference.
#
# USAGE:
#   tools/ci/check_doc_paths.sh    # exit 0 = clean, exit 1 = stale reference
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCS=("$REPO/CLAUDE.md" "$REPO/README.md" "$REPO/docs/index.md")

viol=0
for doc in "${DOCS[@]}"; do
    [ -f "$doc" ] || continue
    rel="${doc#"$REPO"/}"
    while IFS= read -r p; do
        p="${p%/}"                       # tolerate trailing slash on dir refs
        if [ ! -e "$REPO/$p" ]; then
            echo "FAIL $rel references missing path: $p"
            viol=1
        fi
    done < <(
        sed '/<!-- doc-paths:off/,/<!-- doc-paths:on/d' "$doc" \
        | grep -oP '(?<![\w./-])(src|shared|client|tools|tests|docs|deploy|contrib|packaging|k8s-tests|utils)/[\w./*-]+' \
        | sed 's/[).,:;]*$//' \
        | grep -vE '[*<>]|…|\.\.\.' \
        | sort -u
    )
done

[ "$viol" -eq 0 ] && echo "check_doc_paths: OK"
exit "$viol"
