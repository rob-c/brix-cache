#!/usr/bin/env python3
#
# check_client_build_coverage.py — every client/shared source is built, or says why not.
#
# WHAT: Fails (exit 1) when a `.c` file under client/ (or under the ngx-free
#       shared/ trees that only the client links: shared/cvmfs, shared/cache)
#       is neither
#         (a) named in client/Makefile — as `<stem>.c`, `<stem>.o` or
#             `<stem>.pic.o`, directly or through a $(VAR) list,
#         (b) a standalone-built unit driver (`*_unittest.c`, `*_unit.c`,
#             anything under client/tests/ or client/examples/), nor
#         (c) on the reasoned ALLOWLIST below;
#       There is deliberately no reverse (stale-entry) check: unlike ./config,
#       where an entry for a deleted file is silently ignored, a Makefile
#       prerequisite with no source is already a hard `make` error naming the
#       file. Only the forward direction fails silently.
#
#       It also fails when a HAND-WRITTEN rebuild of the same objects cannot
#       link: tests/cmdscripts/*.py compile the brixcvmfs split themselves (one
#       gcc line each, no make) and tests/c/*.c include a member outright, so a
#       TU added to client/Makefile's BRIXCVMFS_SPLIT and to none of them links
#       fine under `make` and fails only in whichever suite rebuilds it. Each
#       site is judged by the symbols it compiles a call to, not by a list
#       comparison: a site may legitimately omit a member it never calls, and
#       shards composed with `_load_continuation` are read as one site.
#
# WHY:  client/Makefile says of itself "every .c must be listed (no wildcards)",
#       and that promise had silently rotted: 33 client TUs and 8 shared CVMFS
#       TUs — every one of them a phase-38/-69 split sibling whose parent WAS
#       listed — were compiled by nothing. The breakage surfaced only as a
#       link-time `undefined reference` in whichever binary happened to call
#       into the orphaned half, so `make` was red on main with no guard naming
#       the cause. This is the client-side twin of check_config_coverage.py,
#       which has guarded the same promise for src/ + ./config since phase-56.
#       The hand-written-build half was added 2026-09-06 after phase-116 split
#       the libcurl address pin into its own TU: `make` and every unit lane
#       stayed green while live brixMount scenarios failed to link with
#       `undefined reference to cvmfs_curl_perform_pinned`, because only the
#       Makefile knew about the new file. Its first form compared ONE list
#       against the Makefile, which still missed five sites (the two
#       cvmfs_driver_units lists, cvmfs_live_ext, tap_proxy_live_part2 and the
#       tests/c unit that includes the transport) — a union of lists answers
#       "is this TU named anywhere", not "does this site link".
#
# HOW:  Walk the trees, subtract the conventions and the allowlist, and check
#       each remaining stem against the Makefile text. Matching on the STEM
#       (not the whole line) is deliberate: the Makefile reaches sources
#       through $(SHARED_DIR), pattern rules and per-binary _OBJS variables, so
#       a naive line parse would need a make-expander to be right, while a stem
#       hit is exact enough to catch the only failure mode that matters — a
#       file no list mentions at all.
#
# USAGE:
#   tools/ci/check_client_build_coverage.py   # exit 0 = clean, exit 1 = violations
#
# A parallel in-pytest twin lives in tests/source_guards_lib.py
# (client_build_coverage); the verdict is kept in lockstep.

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Trees whose sources the client Makefile is the sole build owner of. shared/
# is deliberately narrowed: shared/xrdproto has its own Makefile, and the rest
# of shared/ is linked by the nginx module via ./config (check_config_coverage).
SCAN = ("client", "shared/cvmfs", "shared/cache")

# --- ALLOWLIST: intentionally-unbuilt sources (path + reason, keep sorted) ----
# Each entry is a file client/Makefile deliberately does NOT name. The reason
# must say where it IS built (or why it is built nowhere yet). Empty today —
# every client source is built; keep it that way rather than growing this list.
ALLOWLIST: tuple[str, ...] = ()


# `*_unit.c` is the client's own standalone-C-driver convention (built + run by
# tools/ci/c_regression_units.py, never linked into a CLI); `*_unittest.c` is
# the repo-wide one. Whole directories of drivers/demos are excused wholesale.
_EXCUSED_DIRS = ("client/tests/", "client/examples/", "client/bin/")


def _is_driver(rel: str, name: str) -> bool:
    return (
        name.endswith("_unittest.c")
        or "_unittest_" in name
        or name.endswith("_unit.c")
        or rel.startswith(_EXCUSED_DIRS)
    )


def _tree_files(root: Path) -> list[str]:
    """Every buildable `.c` under the scanned trees, minus the driver conventions."""
    out = []
    for top in SCAN:
        for p in (root / top).rglob("*.c"):
            rel = str(p.relative_to(root))
            if not _is_driver(rel, p.name):
                out.append(rel)
    return sorted(out)


def _makefile(root: Path) -> str:
    return (root / "client/Makefile").read_text()


def _named(makefile: str, rel: str) -> bool:
    """True when client/Makefile names this source, as .c, .o or .pic.o.

    Paths in the Makefile are relative to client/, and reach shared/ either as
    `../shared/...` or as `$(SHARED_DIR)/...`, so compare on the tail below
    those roots rather than on the repo-relative path."""
    stem = rel[: -len(".c")]
    for prefix in ("client/", "shared/"):
        if stem.startswith(prefix):
            stem = stem[len(prefix) :]
            break
    return any(f"{stem}{ext}" in makefile for ext in (".c", ".o", ".pic.o"))


def _included_sources(root: Path) -> set[str]:
    """Return `.c` continuation files compiled through a direct include."""
    included: set[str] = set()
    for top in SCAN:
        for owner in (root / top).rglob("*.c"):
            text = owner.read_text(errors="replace")
            for name in re.findall(r'^\s*#\s*include\s+"([^"]+\.c)"', text,
                                   re.MULTILINE):
                target = (owner.parent / name).resolve()
                try:
                    included.add(str(target.relative_to(root.resolve())))
                except ValueError:
                    continue
    return included


# --- hand-written rebuilds of the split: a link check, not a list check ------
# `make` is not the only build of the brixcvmfs driver. tests/cmdscripts/*.py
# rebuild the split by hand (one gcc line each, no make) and tests/c/*.c include
# a member outright with its externals stubbed. Phase-116 moved the libcurl
# address pin into its own TU, and only client/Makefile plus ONE of those sites
# learned about it: `make` and every unit lane stayed green while five other
# sites failed to link with `undefined reference to cvmfs_curl_perform_pinned`.
#
# Comparing a hand-written list against a Makefile variable cannot see that —
# it says nothing about the five other lists, and a site legitimately omits
# members it never calls into. What actually breaks a build site is a symbol it
# compiles a *call* to and links no definition for, so that is what is checked,
# per site: every site that compiles a split TU must also name the TU (or a
# stub) defining each split symbol that TU calls.
def _read(path: Path) -> str:
    """Byte-tolerant read — sources may carry stray bytes in comments."""
    return path.read_text(errors="ignore")


SPLIT_VARS = ("BRIXCVMFS_SPLIT",)
SITE_GLOBS = ("tests/cmdscripts/*.py", "tests/c/*.c")
# The split does not stand alone: its TUs call into the client's own net layer
# (the phase-116 DNS seam among them), and those are separate .c files too.
SEAM_DIR = "client/lib/net"
_ARCHIVE_RE = re.compile(r"[\"\'][\w./-]+\.a[\"\']")
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
_CALL_RE = re.compile(r"\b(\w+)\s*\(")
# Two definition shapes live in this tree: the client's same-line
# `void pf_start(...) {` and the server-style return type on its own line.
_DEF_SAME_RE = re.compile(r"^[A-Za-z_][\w\s\*]*[\s\*](\w+)\s*\(")
_DEF_SPLIT_RE = re.compile(r"^([A-Za-z_]\w*)\s*\(")
_SOURCE_RE = re.compile(r"[\"\']([\w./-]+\.c)[\"\']")
_ASSIGN_RE = re.compile(r"^(\w+)\s*=\s*\[(.*?)\]", re.MULTILINE | re.DOTALL)
_WORD_RE = re.compile(r"\b\w+\b")


def _make_var(makefile: str, name: str) -> list[str]:
    """The whitespace-separated words of a `NAME := ...` list, continuations joined."""
    m = re.search(rf"^{re.escape(name)}\s*:?=\s*((?:[^\n\\]*\\\n)*[^\n]*)",
                  makefile, re.MULTILINE)
    if m is None:
        return []
    return m.group(1).replace("\\\n", " ").split()


def _defines(text: str) -> set[str]:
    """The non-static function names this translation unit defines.

    A definition is a name at column 0 (or a name preceded on the same line by
    its return type), with no trailing `;` — a prototype, a macro line and an
    indented call all fail one of those, and `static` never exports.
    """
    names: set[str] = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.rstrip().endswith(";") or line.startswith(("static", "typedef", "#")):
            continue
        same = _DEF_SAME_RE.match(line)
        if same is not None:
            names.add(same.group(1))
            continue
        split = _DEF_SPLIT_RE.match(line)
        if split is not None and _type_line_above(lines, i):
            names.add(split.group(1))
    return names


def _type_line_above(lines: list[str], i: int) -> bool:
    """True when the line above `i` is a bare return type (so `i` names a function)."""
    prev = next((p.strip() for p in reversed(lines[:i]) if p.strip()), "")
    return bool(prev) and not prev.startswith("static") and prev[-1] not in ";,{}()/#"


def _split_sources(root: Path, makefile: str) -> list[str]:
    """The split's translation units, as repo-relative sources."""
    return [src for var in SPLIT_VARS for obj in _make_var(makefile, var)
            if obj.endswith(".o")
            for src in (f"client/{obj[: -len('.o')]}.c",)
            if (root / src).is_file()]


def _resolve(root: Path, rels: list[str]) -> list[str]:
    """Repo-relative, de-duplicated, existing sources.

    A cmdscripts list names them from the repo root; a tests/c unit includes
    them relative to client/ (`#include "apps/fs/..."`), so both are tried.
    """
    found: list[str] = []
    for rel in rels:
        for cand in (rel, f"client/{rel}"):
            if cand not in found and (root / cand).is_file():
                found.append(cand)
                break
    return found


def _lists(text: str) -> dict[str, list[str]]:
    """`NAME = [... ".c" ...]` bindings — the shape a source list is written in."""
    return {m.group(1): _SOURCE_RE.findall(m.group(2))
            for m in _ASSIGN_RE.finditer(text)}


def _loose(text: str) -> list[str]:
    """Sources named outside any list — an inline gcc argv, or a `#include`."""
    bound = {src for srcs in _lists(text).values() for src in srcs}
    return [src for src in _SOURCE_RE.findall(text) if src not in bound]


_LOAD_RE = re.compile(
    r"_load_continuations?\(\s*globals\(\)\s*,\s*__file__\s*,(.*?)\)",
    re.DOTALL)
_PY_RE = re.compile(r"[\"\']([\w.]+\.py)[\"\']")


def _parents(root: Path) -> dict[str, list[str]]:
    """child shard -> the cmdscripts modules that exec it into their namespace.

    A shard loaded with `_load_continuation(globals(), __file__, ...)` runs in
    its loader's namespace, so the gcc line it calls is composed from both
    files: the build site is the whole chain, not the file the call sits in.
    """
    edges: dict[str, list[str]] = {}
    for path in sorted(root.glob("tests/cmdscripts/*.py")):
        parent = str(path.relative_to(root))
        for call in _LOAD_RE.findall(_read(path)):
            for child in _PY_RE.findall(call):
                edges.setdefault(f"tests/cmdscripts/{child}", []).append(parent)
    return edges


def _site_named(root: Path, site: str, parents: dict[str, list[str]]) -> list[str]:
    """Every source one build site compiles.

    A shard's own bindings come first and SHADOW the loader's list of the same
    name — rebinding BRIXCVMFS_DRIVER_SRCS replaces it, it does not extend it —
    while a list the shard never rebinds (the loader's own split, prepended by
    its builder helper) still reaches the gcc line.
    """
    queue, seen, bound, out = [site], set(), set(), []
    while queue:
        rel = queue.pop(0)
        if rel in seen or not (root / rel).is_file():
            continue
        seen.add(rel)
        text = _read(root / rel)
        lists = _lists(text)
        out.extend(src for name, srcs in lists.items() if name not in bound
                   for src in srcs)
        out.extend(_loose(text))
        bound |= set(lists)
        queue.extend(parents.get(rel, ()))
    return _resolve(root, out)


def _site_linked(root: Path, site: str, named: list[str],
                 absolved: set[str]) -> set[str]:
    """Every symbol this site links a definition for — a `.c` unit's own stubs
    count, since a unit that `#include`s a TU stubs the siblings it does not want,
    and a site that links `client/libbrix.a` gets the whole client library from it
    (the archive holds lib/net/*, never the app-side split)."""
    text = _read(root / site)
    linked = _defined_by(root, named)
    if site.endswith(".c"):
        linked |= _defines(text)
    if _ARCHIVE_RE.search(text):
        linked |= absolved
    return linked


def _calls(text: str) -> set[str]:
    """Every name this source CALLS. Comments are stripped first: the transport
    names brix_resolve() twice in prose, and a mention is not a call."""
    return set(_CALL_RE.findall(_COMMENT_RE.sub(" ", text)))


def _src_gaps(root: Path, site: str, src: str, owner: dict[str, str],
              linked: set[str]) -> list[str]:
    """The split symbols one compiled TU calls that this site never links."""
    called = _calls(_read(root / src)) & set(owner) - linked
    return [
        f"LINK GAP: {site} builds {src}, which calls {sym}(), but names "
        f"neither {owner[sym]} (which defines it) nor a stub — that "
        f"build fails to link"
        for sym in sorted(called) if owner[sym] != src
    ]


def _site_gaps(root: Path, site: str, named: list[str], owner: dict[str, str],
               absolved: set[str]) -> list[str]:
    """The split symbols this site compiles a call to and links no definition for."""
    built = [src for src in named if src in set(owner.values())]
    if not built:
        return []
    linked = _site_linked(root, site, named, absolved)
    return [msg for src in built
            for msg in _src_gaps(root, site, src, owner, linked)]


def _seam_owner(root: Path) -> dict[str, str]:
    """Symbol -> the `client/lib/net` TU that defines it."""
    net: dict[str, str] = {}
    for path in sorted((root / SEAM_DIR).glob("*.c")):
        rel = str(path.relative_to(root))
        for sym in _defines(_read(path)):
            net.setdefault(sym, rel)
    return net


def _seam_wanted(root: Path, rel: str, net: dict[str, str],
                 have: set[str]) -> list[str]:
    """The seam TUs one source calls into that nothing in the world defines."""
    return [net[sym] for sym in sorted(_calls(_read(root / rel)) & set(net))
            if sym not in have]


def _defined_by(root: Path, rels: list[str]) -> set[str]:
    """Every symbol this set of sources defines."""
    return {sym for rel in rels for sym in _defines(_read(root / rel))}


def _unseen(world: list[str], wanted: list[str]) -> list[str]:
    """The entries of `wanted` the world does not hold yet, in first-seen order."""
    return [rel for rel in dict.fromkeys(wanted) if rel not in world]


def _seam_step(root: Path, world: list[str], frontier: list[str],
               net: dict[str, str]) -> list[str]:
    """The seam TUs this frontier calls into and the world does not yet define."""
    have = _defined_by(root, world)
    return _unseen(world, [src for rel in frontier
                           for src in _seam_wanted(root, rel, net, have)])


def _seam_world(root: Path, split: list[str]) -> list[str]:
    """The split plus the `client/lib/net` TUs it calls into, transitively.

    phase-116 amendment 13: the pin resolves every name through the client DNS
    seam, so a site that compiles the split and stops at the split links against
    brix_resolve()/brix_netpref_family() and fails one TU further down. The walk
    stops at that directory on purpose — a whole-tree closure drags the entire
    client world in and judges nothing.
    """
    net = _seam_owner(root)
    world, frontier = list(split), list(split)
    while frontier:
        frontier = _seam_step(root, world, frontier, net)
        world += frontier
    return world


def _split_owner(root: Path, makefile: str) -> dict[str, str]:
    """Symbol -> the TU that defines it, over the split and the seam it needs."""
    return {sym: src for src in _seam_world(root, _split_sources(root, makefile))
            for sym in _defines(_read(root / src))}


def _sites(root: Path) -> list[str]:
    """Every hand-written build site in the tree, repo-relative."""
    return [str(path.relative_to(root)) for glob in SITE_GLOBS
            for path in sorted(root.glob(glob))]


def _live_link_gaps(root: Path, makefile: str) -> list[str]:
    """Every hand-written rebuild of the split, checked against its own symbols."""
    split = _split_sources(root, makefile)
    owner = _split_owner(root, makefile)
    if not owner:
        return []
    absolved = {sym for sym, src in owner.items() if src not in split}
    parents = _parents(root)
    return [msg for site in _sites(root)
            for msg in _site_gaps(root, site, _site_named(root, site, parents),
                                  owner, absolved)]


def run(root: Path = ROOT) -> tuple[bool, list[str]]:
    """Return (ok, messages) — one message per violation, in emission order."""
    makefile = _makefile(root)
    included = _included_sources(root)
    allow_set = set(ALLOWLIST)
    msgs: list[str] = []

    for rel in _tree_files(root):
        if rel not in allow_set and rel not in included and not _named(makefile, rel):
            msgs.append(
                f"NOT BUILT: {rel} — add it to client/Makefile, or allowlist it "
                f"here with a reason"
            )

    for a in ALLOWLIST:
        if not (root / a).is_file():
            msgs.append(
                f"STALE ALLOWLIST: {a} no longer exists — remove it from this script"
            )

    msgs.extend(_live_link_gaps(root, makefile))

    return (not msgs, msgs)


def main() -> int:
    os.chdir(ROOT)
    ok, msgs = run(ROOT)
    for m in msgs:
        print(m, file=sys.stderr)
    if not ok:
        print("check_client_build_coverage: FAIL", file=sys.stderr)
        return 1
    print(
        f"check_client_build_coverage: OK ({len(_tree_files(ROOT))} sources, "
        f"{len(ALLOWLIST)} allowlisted)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
