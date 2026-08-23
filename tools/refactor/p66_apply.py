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
    return _expanded_file_map(entries, applied=False)


def _expanded_file_map(entries, applied):
    mapping = {}
    for kind, old, new in entries:
        if kind == "file":
            mapping[old] = new
        else:
            _map_directory(mapping, old, new, applied)
    return mapping


def _map_directory(mapping, old, new, applied):
    source = new if applied else old
    root = os.path.join(REPO, source)
    for dirpath, _, files in os.walk(root):
        for filename in files:
            relative = os.path.relpath(os.path.join(dirpath, filename), root)
            mapping[os.path.join(old, relative)] = os.path.join(new, relative)


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

    transform = lambda includer, include: _normalized_include(
        includer, include, unresolved,
    )

    for path in iter_src_files():
        if rewrite_includes_in_file(path, transform):
            n_changed += 1
    print(f"normalize: rewrote includes in {n_changed} files")
    if unresolved:
        print(f"normalize: {len(unresolved)} unresolved quoted includes (left untouched):")
        for f, inc in sorted(set(unresolved)):
            print(f"  {f}: \"{inc}\"")


def _normalized_include(includer, include, unresolved):
    directory = os.path.dirname(includer)
    local = os.path.normpath(os.path.join(directory, include))
    rooted = os.path.normpath(os.path.join(SRC, include))
    if os.path.isfile(local) and local.startswith(SRC):
        return canonical_include(includer, local)
    if os.path.isfile(rooted):
        return canonical_include(includer, rooted)
    unresolved.append((os.path.relpath(includer, REPO), include))
    return None


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
    for relative in rels:
        if _tracked_text(relative):
            yield os.path.join(REPO, relative)


def _tracked_text(relative):
    if relative.startswith("src/") and relative.endswith((".c", ".h")):
        return False
    if relative in TEXT_EXCLUDE or relative == os.path.relpath(MAP_TSV, REPO):
        return False
    return relative.endswith(TEXT_EXTS) or os.path.basename(relative) in TEXT_NAMES


def file_map_applied(entries):
    """Per-file old->new for entries whose mv already happened (walk NEW dirs)."""
    return _expanded_file_map(entries, applied=True)


def do_step(step, dry_run=False, fixup=False):
    entries, file_map = _step_inputs(step, fixup)
    if not fixup:
        _move_entries(step, entries, dry_run)
        if dry_run:
            return
    fixed = _fix_includes(file_map)
    print(f"step {step}: includes fixed in {fixed} files")
    rewritten = _rewrite_text_paths(entries)
    print(f"step {step}: path strings rewritten in {rewritten} text files")


def _step_inputs(step, fixup):
    steps = load_map()
    if step not in steps:
        sys.exit(f"step {step}: not in {os.path.relpath(MAP_TSV, REPO)} "
                 f"(available: {', '.join(sorted(steps))})")
    entries = steps[step]
    file_map = file_map_applied(entries) if fixup else file_map_for(entries)
    if not file_map:
        sys.exit(f"step {step}: empty file map — already applied?")
    return entries, file_map


def _move_entries(step, entries, dry_run):
    for _kind, old, new in entries:
        if not os.path.exists(os.path.join(REPO, old)):
            sys.exit(f"step {step}: {old} does not exist — already applied?")
        if dry_run:
            print(f"git mv {old} {new}")
            continue
        os.makedirs(os.path.dirname(os.path.join(REPO, new)), exist_ok=True)
        subprocess.run(["git", "mv", old, new], cwd=REPO, check=True)


def _fix_includes(file_map):
    moved = dict(file_map)
    reverse = {new: old for old, new in file_map.items()}
    transform = lambda includer, include: _moved_include(
        includer, include, moved, reverse,
    )
    fixed = 0
    seen = set()
    for path in _include_targets():
        if path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        if rewrite_includes_in_file(path, transform):
            fixed += 1
    return fixed


def _include_targets():
    targets = list(iter_src_files()) + cross_tree_c_files()
    for dirpath, _, files in os.walk(os.path.join(REPO, "client")):
        targets.extend(
            os.path.join(dirpath, filename)
            for filename in files if filename.endswith((".c", ".h"))
        )
    return targets


def _moved_include(includer, include, moved, reverse):
    if "/" not in include:
        repo_path, replacement = _bare_include(includer, include, moved, reverse)
        if replacement is not None:
            return replacement
    elif "src/" in include:
        return _cross_tree_include(include, moved)
    else:
        repo_path = _rooted_include(includer, include)
    return _mapped_include(includer, include, repo_path, moved)


def _bare_include(includer, include, moved, reverse):
    directory = os.path.dirname(includer)
    if os.path.isfile(os.path.join(directory, include)):
        return None, None
    includer_rel = os.path.relpath(includer, REPO)
    old_includer = reverse.get(includer_rel, includer_rel)
    repo_path = os.path.join(os.path.dirname(old_includer), include)
    if repo_path in moved:
        return repo_path, None
    rooted = "src/" + include
    if rooted in moved:
        return rooted, None
    if os.path.isfile(os.path.join(REPO, repo_path)):
        replacement = os.path.relpath(os.path.join(REPO, repo_path), SRC)
        return None, replacement
    return repo_path, None


def _cross_tree_include(include, moved):
    prefix, tail = include.split("src/", 1)
    source = "src/" + tail
    if source not in moved:
        return None
    return prefix + "src/" + moved[source][len("src/"):]


def _rooted_include(includer, include):
    directory = os.path.dirname(includer)
    local = os.path.isfile(os.path.join(directory, include))
    rooted = os.path.isfile(os.path.join(SRC, include))
    return None if local or rooted else "src/" + include


def _mapped_include(includer, include, repo_path, moved):
    if repo_path not in moved:
        return None
    target = os.path.join(REPO, moved[repo_path])
    if includer.startswith(SRC):
        return canonical_include(includer, target)
    return None if "/" in include else os.path.relpath(target, SRC)


def _rewrite_text_paths(entries):
    patterns = [
        (re.compile(re.escape(old) + r"(?![a-zA-Z0-9_])"), new)
        for _kind, old, new in sorted(entries, key=lambda entry: -len(entry[1]))
    ]
    return sum(_rewrite_text_file(path, patterns) for path in tracked_text_files())


def _rewrite_text_file(path, patterns):
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as stream:
            original = stream.read()
    except (OSError, UnicodeError):
        return 0
    body = original
    for pattern, replacement in patterns:
        body = pattern.sub(replacement, body)
    if body == original:
        return 0
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as stream:
        stream.write(body)
    return 1


# ---------------------------------------------------------------- verify

def do_verify():
    out = subprocess.run(["git", "diff", "HEAD", "--", "*.c", "*.h"],
                         cwd=REPO, capture_output=True, text=True)
    bad = [line for line in out.stdout.splitlines() if _non_include_change(line)]
    if bad:
        _fail_verification(bad)
    print("verify: OK — .c/.h diffs touch only #include lines")


def _non_include_change(line):
    if not line or line[0] not in "+-" or line.startswith(("+++", "---")):
        return False
    if re.match(r'^[+-]\s*#\s*include\s+"', line):
        return False
    return bool(line[1:].strip())


def _fail_verification(lines):
    print("verify: NON-INCLUDE content changes in .c/.h files:")
    for line in lines[:40]:
        print(" ", line)
    sys.exit(1)


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
