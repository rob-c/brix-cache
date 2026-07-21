#!/usr/bin/env python3
#
# check_doc_links.py — relative markdown links must resolve.
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
#   tools/ci/check_doc_links.py            # gate; exit 1 on a NEW dead link
#   tools/ci/check_doc_links.py --regen    # rewrite the backlog (review diff!)

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKLOG = ROOT / "tools/ci/doc_links_backlog.txt"

LINK_RE = re.compile(r'\]\(([^)\s]+)\)')
SKIP_PREFIX = ('http://', 'https://', 'mailto:', '#', '/')
EXCLUDED = (os.path.join('docs', '_archive'), os.path.join('docs', 'doxygen'),
            os.path.join('docs', 'superpowers'))


def git_tracked(repo: str):
    """Snapshot the git index once: a target that exists on disk but is
    untracked is dead in every fresh clone (gitignore casualty) — treat it as
    dead here. Returns (tracked, tracked_dirs), or (None, None) when git is
    unavailable (fall back to disk-only checks)."""
    tracked = set()
    tracked_dirs = set()
    try:
        out = subprocess.run(['git', '-C', repo, 'ls-files', '-z'],
                             capture_output=True, check=True)
    except Exception:
        return None, None
    for f in out.stdout.decode().split('\0'):
        if not f:
            continue
        tracked.add(f)
        d = os.path.dirname(f)
        while d and d not in tracked_dirs:
            tracked_dirs.add(d)
            d = os.path.dirname(d)
    return tracked, tracked_dirs


def md_files(repo: str):
    yield os.path.join(repo, 'README.md')
    for root in ('docs', 'src'):
        for base, _dirs, files in os.walk(os.path.join(repo, root)):
            rel = os.path.relpath(base, repo)
            if any(rel == e or rel.startswith(e + os.sep) for e in EXCLUDED):
                continue
            for f in files:
                if f.endswith('.md') and (root == 'docs' or f == 'README.md'):
                    yield os.path.join(base, f)


def dead_links(repo: str) -> set:
    tracked, tracked_dirs = git_tracked(repo)

    def is_tracked(relpath, isdir):
        if tracked is None:
            return True
        return (relpath in tracked_dirs) if isdir else (relpath in tracked)

    dead = set()
    for path in md_files(repo):
        if not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, repo)
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
        for m in LINK_RE.finditer(text):
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
    return dead


def read_backlog() -> set:
    backlog = set()
    if os.path.isfile(BACKLOG):
        with open(BACKLOG, encoding='utf-8') as fh:
            backlog = {l.rstrip('\n') for l in fh if l.strip()}
    return backlog


def regen(root: Path = ROOT) -> int:
    dead = dead_links(str(root))
    with open(BACKLOG, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(sorted(dead)) + ('\n' if dead else ''))
    print(f"check_doc_links: wrote {len(dead)} frozen dead link(s) to backlog")
    return 0


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Check mode: (passed, stdout_lines)."""
    dead = dead_links(str(root))
    backlog = read_backlog()
    new = sorted(dead - backlog)
    lines = []
    for entry in new:
        src, tgt = entry.split('\t', 1)
        lines.append(f"FAIL new dead link: {src} -> {tgt}")
    if new:
        lines.append("check_doc_links: fix the link, or (pre-existing only) --regen after review")
        return False, lines
    lines.append(f"check_doc_links: OK ({len(dead)} frozen in backlog)")
    return True, lines


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode == "--regen":
        return regen(ROOT)
    passed, lines = run(ROOT)
    for line in lines:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
