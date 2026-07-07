#!/usr/bin/env bash
#
# check_doc_links.sh — relative markdown links must resolve.
#
# WHAT: Fails (exit 1) when a relative link target in docs/**/*.md, README.md,
#       or any src/**/README.md does not exist on disk OR exists but is not
#       git-tracked (a gitignore casualty: resolves locally, dead in every
#       fresh clone). Pre-existing dead links are frozen in
#       doc_links_backlog.txt (ratchet: entries may only disappear as links
#       are fixed); anything NEW fails.
#
# WHY:  447+ markdown files and heavy cross-linking (docs/index.md routes by
#       link); nothing enforced link integrity, so every file move quietly
#       broke an unknown number of routes.
#
# HOW:  python3 stdlib walk; extract ](target) tokens; skip absolute URLs,
#       mailto:, in-page #anchors; resolve against the linking file's dir;
#       diff dead set against the backlog. Excluded: docs/_archive (archived
#       rot is accepted), docs/doxygen (generated), docs/superpowers
#       (plans/specs quote illustrative links inside code blocks).
#
# USAGE:
#   tools/ci/check_doc_links.sh            # gate; exit 1 on a NEW dead link
#   tools/ci/check_doc_links.sh --regen    # rewrite the backlog (review diff!)
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKLOG="$REPO/tools/ci/doc_links_backlog.txt"
MODE="${1:-check}"

python3 - "$REPO" "$BACKLOG" "$MODE" <<'PY'
import os, re, subprocess, sys

repo, backlog_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
link_re = re.compile(r'\]\(([^)\s]+)\)')

# Snapshot the git index once: a target that exists on disk but is untracked
# is dead in every fresh clone (gitignore casualty) — treat it as dead here.
tracked = set()
tracked_dirs = set()
try:
    out = subprocess.run(['git', '-C', repo, 'ls-files', '-z'],
                         capture_output=True, check=True)
    for f in out.stdout.decode().split('\0'):
        if not f:
            continue
        tracked.add(f)
        d = os.path.dirname(f)
        while d and d not in tracked_dirs:
            tracked_dirs.add(d)
            d = os.path.dirname(d)
except Exception:
    tracked = None          # no git available: fall back to disk-only checks

def is_tracked(relpath, isdir):
    if tracked is None:
        return True
    return (relpath in tracked_dirs) if isdir else (relpath in tracked)
SKIP_PREFIX = ('http://', 'https://', 'mailto:', '#', '/')
EXCLUDED = (os.path.join('docs', '_archive'), os.path.join('docs', 'doxygen'),
            os.path.join('docs', 'superpowers'))

def md_files():
    yield os.path.join(repo, 'README.md')
    for root in ('docs', 'src'):
        for base, _dirs, files in os.walk(os.path.join(repo, root)):
            rel = os.path.relpath(base, repo)
            if any(rel == e or rel.startswith(e + os.sep) for e in EXCLUDED):
                continue
            for f in files:
                if f.endswith('.md') and (root == 'docs' or f == 'README.md'):
                    yield os.path.join(base, f)

dead = set()
for path in md_files():
    if not os.path.isfile(path):
        continue
    rel = os.path.relpath(path, repo)
    with open(path, encoding='utf-8', errors='replace') as fh:
        text = fh.read()
    for m in link_re.finditer(text):
        target = m.group(1).split('#', 1)[0]
        if not target or target.startswith(SKIP_PREFIX) or '://' in target:
            continue
        if target.strip('.') == '':          # literal "](...)" used as prose
            continue
        resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
        if not os.path.exists(resolved):
            dead.add(f"{rel}\t{target}")
            continue
        rel_target = os.path.relpath(resolved, repo)
        if not rel_target.startswith('..') and \
           not is_tracked(rel_target, os.path.isdir(resolved)):
            dead.add(f"{rel}\t{target}")

if mode == '--regen':
    with open(backlog_path, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(sorted(dead)) + ('\n' if dead else ''))
    print(f"check_doc_links: wrote {len(dead)} frozen dead link(s) to backlog")
    sys.exit(0)

backlog = set()
if os.path.isfile(backlog_path):
    with open(backlog_path, encoding='utf-8') as fh:
        backlog = {l.rstrip('\n') for l in fh if l.strip()}

new = sorted(dead - backlog)
for entry in new:
    src, tgt = entry.split('\t', 1)
    print(f"FAIL new dead link: {src} -> {tgt}")
if new:
    print("check_doc_links: fix the link, or (pre-existing only) --regen after review")
    sys.exit(1)
print(f"check_doc_links: OK ({len(dead)} frozen in backlog)")
PY
