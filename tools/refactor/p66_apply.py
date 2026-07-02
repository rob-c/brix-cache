#!/usr/bin/env python3
"""p66_apply.py — phase-66 topology-move executor (docs/refactor/phase-66-src-conceptual-realignment.md).

WHAT: Three operations, all driven by docs/refactor/phase-66-map.tsv:
  --normalize        Step 0: rewrite every quoted #include in src/ to canonical form
                     against the CURRENT tree (same-dir -> bare, cross-dir -> src-rooted).
                     No files move. Idempotent.
  --step NAME        Execute one bucket: git mv per the map subset, then fix every
                     include (src/ + cross-tree C files) whose target just moved,
                     then apply path-string substitution to build/guard/doc files.
  --verify           Check the .c/.h content-identity invariant: the working diff
                     touches nothing outside #include lines in .c/.h files.

WHY: 955 files move across 8 commits; every surface (includes, ./config, Makefiles,
     seam guard, docs) is path-coupled. One map + one mechanical tool keeps each
     commit reviewable and the invariant checkable.

HOW: Include resolution mirrors C semantics: includer-relative first, then the single
     -I root (src/). Bare includes are rewritten only when they no longer resolve
     in the includer's directory. Slashed includes are interpreted src-rooted
     (guaranteed by step 0). Text substitution uses word-boundary-guarded regexes,
     longest-old-first, and never touches .c/.h (those only ever get include edits)
     nor the phase-66 docs (which record the mapping itself).
"""

import argparse
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAP_TSV = os.path.join(REPO, "docs", "refactor", "phase-66-map.tsv")
SRC = os.path.join(REPO, "src")

INC_RE = re.compile(r'^(\s*#\s*include\s+")([^"]+)(".*)$')


def load_map():
    """Return {step: [(kind, old, new), ...]} from the TSV (paths repo-relative)."""
    steps = {}
    with open(MAP_TSV) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            step, kind, old, new = line.split("\t")
            steps.setdefault(step, []).append((kind, old, new))
    return steps


def file_map_for(entries):
    """Expand dir entries to per-file old->new using the current tree."""
    fmap = {}
    for kind, old, new in entries:
        if kind == "file":
            fmap[old] = new
        else:
            root = os.path.join(REPO, old)
            for dirpath, _, files in os.walk(root):
                for fn in files:
                    op = os.path.relpath(os.path.join(dirpath, fn), REPO)
                    fmap[op] = os.path.join(new, os.path.relpath(os.path.join(dirpath, fn), root))
    return fmap


def iter_src_files(exts=(".c", ".h")):
    for dirpath, _, files in os.walk(SRC):
        for fn in files:
            if fn.endswith(exts):
                yield os.path.join(dirpath, fn)


def cross_tree_c_files():
    """C files outside src/ that include into src/ (tracked or not — keep them working)."""
    out = subprocess.run(
        ["grep", "-rlE", r'#\s*include\s+"[^"]*(src/|\.\./)', "tests", "client", "tools",
         "--include=*.c", "--include=*.h"],
        cwd=REPO, capture_output=True, text=True)
    return [os.path.join(REPO, p) for p in out.stdout.split() if p]


def canonical_include(includer_abs, target_abs):
    """bare if same dir, else path relative to src/ (the single -I root)."""
    if os.path.dirname(includer_abs) == os.path.dirname(target_abs):
        return os.path.basename(target_abs)
    return os.path.relpath(target_abs, SRC)


def rewrite_includes_in_file(path, transform):
    """Apply transform(includer_abs, inc_string) -> new_string|None to each include line."""
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        lines = f.readlines()
    changed = False
    for i, line in enumerate(lines):
        m = INC_RE.match(line)
        if not m:
            continue
        new = transform(path, m.group(2))
        if new is not None and new != m.group(2):
            lines[i] = m.group(1) + new + m.group(3) + ("\n" if line.endswith("\n") else "")
            changed = True
    if changed:
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.writelines(lines)
    return changed


# ---------------------------------------------------------------- normalize

def do_normalize():
    unresolved = []
    n_changed = 0

    def transform(includer, inc):
        d = os.path.dirname(includer)
        cand1 = os.path.normpath(os.path.join(d, inc))
        cand2 = os.path.normpath(os.path.join(SRC, inc))
        if os.path.isfile(cand1) and cand1.startswith(SRC):
            return canonical_include(includer, cand1)
        if os.path.isfile(cand2):
            return canonical_include(includer, cand2)
        unresolved.append((os.path.relpath(includer, REPO), inc))
        return None

    for path in iter_src_files():
        if rewrite_includes_in_file(path, transform):
            n_changed += 1
    print(f"normalize: rewrote includes in {n_changed} files")
    if unresolved:
        print(f"normalize: {len(unresolved)} unresolved quoted includes (left untouched):")
        for f, inc in sorted(set(unresolved)):
            print(f"  {f}: \"{inc}\"")


# ---------------------------------------------------------------- step apply

TEXT_EXCLUDE = ("docs/refactor/phase-66-src-conceptual-realignment.md",
                "docs/refactor/phase-66-map.tsv")
TEXT_EXTS = (".md", ".sh", ".py", ".yml", ".yaml", ".txt", ".conf", ".cfg", ".service")
TEXT_NAMES = ("Makefile", "config", "CLAUDE.md", "Dockerfile")


def tracked_text_files():
    out = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True)
    rels = out.stdout.splitlines()
    # load-bearing but untracked (tools/ is gitignored): the seam guard + backlogs
    for extra_dir in ("tools/ci",):
        full = os.path.join(REPO, extra_dir)
        if os.path.isdir(full):
            rels += [os.path.join(extra_dir, fn) for fn in os.listdir(full)]
    for rel in rels:
        if rel.startswith("src/") and rel.endswith((".c", ".h")):
            continue
        if rel in TEXT_EXCLUDE or rel == os.path.relpath(MAP_TSV, REPO):
            continue
        base = os.path.basename(rel)
        if rel.endswith(TEXT_EXTS) or base in TEXT_NAMES:
            yield os.path.join(REPO, rel)


def file_map_applied(entries):
    """Per-file old->new for entries whose mv already happened (walk NEW dirs)."""
    fmap = {}
    for kind, old, new in entries:
        if kind == "file":
            fmap[old] = new
        else:
            root = os.path.join(REPO, new)
            for dirpath, _, files in os.walk(root):
                for fn in files:
                    np = os.path.relpath(os.path.join(dirpath, fn), REPO)
                    fmap[os.path.join(old, os.path.relpath(os.path.join(dirpath, fn), root))] = np
    return fmap


def do_step(step, dry_run=False, fixup=False):
    steps = load_map()
    if step not in steps:
        sys.exit(f"step {step}: not in {os.path.relpath(MAP_TSV, REPO)} "
                 f"(available: {', '.join(sorted(steps))})")
    entries = steps[step]
    if fixup:
        fmap = file_map_applied(entries)
    else:
        fmap = file_map_for(entries)  # must run BEFORE the mv (walks old dirs)
    if not fmap:
        sys.exit(f"step {step}: empty file map — already applied?")

    # 1. git mv
    if not fixup:
        for kind, old, new in entries:
            if not os.path.exists(os.path.join(REPO, old)):
                sys.exit(f"step {step}: {old} does not exist — already applied?")
            if dry_run:
                print(f"git mv {old} {new}")
                continue
            os.makedirs(os.path.dirname(os.path.join(REPO, new)), exist_ok=True)
            subprocess.run(["git", "mv", old, new], cwd=REPO, check=True)
        if dry_run:
            return

    # 2. include fixups across src/ + cross-tree C files
    moved = {old: new for old, new in fmap.items()}          # repo-relative
    rmoved = {new: old for old, new in fmap.items()}
    n_fixed = 0

    def transform(includer, inc):
        d = os.path.dirname(includer)
        inc_repo = None
        if "/" not in inc:
            if os.path.isfile(os.path.join(d, inc)):
                return None                                   # still resolves
            # bare include broken by this step: where did it live before?
            # (a) next to the includer's OLD location, or (b) src-rooted —
            # a file at the src root itself, e.g. "ngx_xrootd_module.h".
            includer_rel = os.path.relpath(includer, REPO)
            old_includer = rmoved.get(includer_rel, includer_rel)
            inc_repo = os.path.join(os.path.dirname(old_includer), inc)
            if inc_repo not in moved:
                if "src/" + inc in moved:
                    inc_repo = "src/" + inc
                elif os.path.isfile(os.path.join(REPO, inc_repo)):
                    # includer moved, neighbor stayed behind: src-rooted old home
                    return os.path.relpath(os.path.join(REPO, inc_repo), SRC)
        elif "src/" in inc:                                   # cross-tree ../../src/... form
            tail = inc.split("src/", 1)[1]
            if "src/" + tail in moved:
                return inc.split("src/", 1)[0] + "src/" + moved["src/" + tail][len("src/"):]
            return None
        else:
            # src-rooted (post step-0). Skip if it resolves includer-relative
            # (client -Ilib locals) or still resolves under src/.
            if os.path.isfile(os.path.join(d, inc)) or os.path.isfile(os.path.join(SRC, inc)):
                return None
            inc_repo = "src/" + inc
        if inc_repo in moved:
            new_abs = os.path.join(REPO, moved[inc_repo])
            if includer.startswith(SRC):
                return canonical_include(includer, new_abs)
            return None if "/" in inc else os.path.relpath(new_abs, SRC)
        return None

    targets = list(iter_src_files()) + cross_tree_c_files()
    # client sources use src-rooted includes with -I$(REPO)/src
    for dirpath, _, files in os.walk(os.path.join(REPO, "client")):
        for fn in files:
            if fn.endswith((".c", ".h")):
                targets.append(os.path.join(dirpath, fn))
    seen = set()
    for path in targets:
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        if rewrite_includes_in_file(path, transform):
            n_fixed += 1
    print(f"step {step}: includes fixed in {n_fixed} files")

    # 3. path-string substitution in build/guard/doc/text files
    pats = []
    for kind, old, new in sorted(entries, key=lambda e: -len(e[1])):
        pats.append((re.compile(re.escape(old) + r"(?![a-zA-Z0-9_])"), new))
    n_text = 0
    for path in tracked_text_files():
        try:
            with open(path, encoding="utf-8", errors="surrogateescape") as f:
                body = f.read()
        except (OSError, UnicodeError):
            continue
        orig = body
        for rx, new in pats:
            body = rx.sub(new, body)
        if body != orig:
            with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
                f.write(body)
            n_text += 1
    print(f"step {step}: path strings rewritten in {n_text} text files")


# ---------------------------------------------------------------- verify

def do_verify():
    out = subprocess.run(["git", "diff", "HEAD", "--", "*.c", "*.h"],
                         cwd=REPO, capture_output=True, text=True)
    bad = []
    for line in out.stdout.splitlines():
        if not line or line[0] not in "+-" or line.startswith(("+++", "---")):
            continue
        if re.match(r'^[+-]\s*#\s*include\s+"', line):
            continue
        if line[1:].strip() == "":
            continue  # blank line folded into a changed run — content-identical
        bad.append(line)
    if bad:
        print("verify: NON-INCLUDE content changes in .c/.h files:")
        for line in bad[:40]:
            print(" ", line)
        sys.exit(1)
    print("verify: OK — .c/.h diffs touch only #include lines")


def main():
    global MAP_TSV
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--normalize", action="store_true")
    g.add_argument("--step")
    g.add_argument("--fixup",
                   help="re-run include/text rewrites for an already-moved step")
    g.add_argument("--verify", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--map", default=MAP_TSV,
                    help="move-map TSV (default: phase-66 map)")
    args = ap.parse_args()
    MAP_TSV = os.path.abspath(args.map)
    if args.normalize:
        do_normalize()
    elif args.verify:
        do_verify()
    elif args.fixup:
        do_step(args.fixup, fixup=True)
    else:
        do_step(args.step, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
