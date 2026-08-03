#!/usr/bin/env python3
#
# check_version_sync.py — every copy of the release version agrees with ident.h.
#
# WHAT: Reads BRIX_SERVER_VERSION_BARE from src/core/ident.h and fails (exit 1)
#       unless each derived copy matches it:
#         S1  the RPM spec's %global upstream_version literal fallback
#         S2  the version on the spec's newest %changelog entry
#         S3  the version of the newest CHANGELOG.md entry
#       Plus two shape rules that keep the history readable:
#         S4  CHANGELOG.md entries are strictly descending by version
#         S5  the spec %changelog is descending by (version, release)
#
# WHY:  These four files drifted apart in the wild: the server reported 1.3.0
#       while CHANGELOG.md stopped at 1.0.8, so neither an operator reading the
#       repo nor a packager reading the spec could tell what a build actually
#       was. The spec fallback is the dangerous one — it is only consulted on a
#       bare `rpmbuild` (the build scripts sed ident.h and pass
#       --define version_override), so a stale value produces a *wrongly
#       labelled RPM* rather than an error, and nothing downstream notices.
#
# HOW:  Regex out each literal, compare against ident.h. Version comparison is
#       on the integer tuple, so 1.10.0 sorts above 1.9.0. Nothing here parses
#       git tags: the tag is created after CI is green, so requiring it would
#       deadlock the very push that introduces the bump.
#
# USAGE:
#   tools/ci/check_version_sync.py           # exit 0 clean, 1 with findings
#   tools/ci/check_version_sync.py --show    # print the resolved versions

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

IDENT = "src/core/ident.h"
SPEC = "packaging/rpm/nginx-mod-brix-cache.spec"
CHANGELOG = "CHANGELOG.md"

RE_IDENT = re.compile(r'#define\s+BRIX_SERVER_VERSION_BARE\s+"([^"]+)"')
# %global upstream_version %{?version_override}%{!?version_override:1.4.0}
RE_SPEC_FALLBACK = re.compile(
    r"%global\s+upstream_version\s+.*%\{!\?version_override:([^}]+)\}"
)
# * Mon Aug 03 2026 Rob Currie <rob.currie@ed.ac.uk> - 1.4.0-1
RE_SPEC_ENTRY = re.compile(r"^\*\s+.*?-\s+(\d+(?:\.\d+)*)-(\d+)\s*$")
# ## v1.4.0 — 2026-08-03   (trailing prose after the version is allowed)
RE_CL_ENTRY = re.compile(r"^##\s+v(\d+(?:\.\d+)*)\b")


def _key(version):
    """Integer tuple so 1.10.0 > 1.9.0, unlike a string compare."""
    return tuple(int(p) for p in version.split("."))


def _read(root, rel):
    path = root / rel
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _spec_changelog_entries(spec_text):
    """(version, release) pairs from the spec's %changelog, newest first."""
    entries = []
    in_changelog = False
    for line in spec_text.splitlines():
        if line.startswith("%changelog"):
            in_changelog = True
            continue
        if not in_changelog:
            continue
        m = RE_SPEC_ENTRY.match(line)
        if m:
            entries.append((m.group(1), int(m.group(2))))
    return entries


def _changelog_entries(cl_text):
    """Versions from CHANGELOG.md's `## vX.Y.Z` headings, newest first."""
    return [m.group(1) for m in (RE_CL_ENTRY.match(l) for l in cl_text.splitlines()) if m]


def _descending(items, key):
    """Index of the first item that is not strictly below its predecessor."""
    for i in range(1, len(items)):
        if key(items[i]) >= key(items[i - 1]):
            return i
    return None


def run(root):
    root = Path(root)
    out = []

    ident_text = _read(root, IDENT)
    if ident_text is None:
        return False, [f"{IDENT}: missing — nothing to synchronise against"]
    m = RE_IDENT.search(ident_text)
    if not m:
        return False, [f"{IDENT}: no BRIX_SERVER_VERSION_BARE define found"]
    version = m.group(1)

    spec_text = _read(root, SPEC)
    if spec_text is None:
        out.append(f"{SPEC}: missing")
    else:
        m = RE_SPEC_FALLBACK.search(spec_text)
        if not m:
            out.append(f"{SPEC}: no '%global upstream_version' fallback literal found")
        elif m.group(1) != version:
            out.append(
                f"{SPEC}: upstream_version fallback is {m.group(1)}, "
                f"{IDENT} says {version} — a bare rpmbuild would mislabel the RPM"
            )

        entries = _spec_changelog_entries(spec_text)
        if not entries:
            out.append(f"{SPEC}: %changelog has no parseable entries")
        else:
            if entries[0][0] != version:
                out.append(
                    f"{SPEC}: newest %changelog entry is {entries[0][0]}-{entries[0][1]}, "
                    f"{IDENT} says {version} — add an entry for this release"
                )
            bad = _descending(entries, lambda e: (_key(e[0]), e[1]))
            if bad is not None:
                out.append(
                    f"{SPEC}: %changelog is not newest-first at entry "
                    f"{entries[bad][0]}-{entries[bad][1]} (after "
                    f"{entries[bad - 1][0]}-{entries[bad - 1][1]})"
                )

    cl_text = _read(root, CHANGELOG)
    if cl_text is None:
        out.append(f"{CHANGELOG}: missing")
    else:
        entries = _changelog_entries(cl_text)
        if not entries:
            out.append(f"{CHANGELOG}: no '## vX.Y.Z' entries found")
        else:
            if entries[0] != version:
                out.append(
                    f"{CHANGELOG}: newest entry is v{entries[0]}, {IDENT} says "
                    f"{version} — write the release notes before bumping"
                )
            bad = _descending(entries, _key)
            if bad is not None:
                out.append(
                    f"{CHANGELOG}: entries are not newest-first at v{entries[bad]} "
                    f"(after v{entries[bad - 1]})"
                )

    if out:
        return False, out
    return True, [f"check_version_sync: OK ({version} in ident.h, spec and CHANGELOG)"]


def _show(root):
    root = Path(root)
    ident_text = _read(root, IDENT) or ""
    spec_text = _read(root, SPEC) or ""
    cl_text = _read(root, CHANGELOG) or ""
    m = RE_IDENT.search(ident_text)
    print(f"{IDENT:<44} {m.group(1) if m else '-'}")
    m = RE_SPEC_FALLBACK.search(spec_text)
    print(f"{SPEC + ' (fallback)':<44} {m.group(1) if m else '-'}")
    entries = _spec_changelog_entries(spec_text)
    print(f"{SPEC + ' (%changelog)':<44} {'-'.join(map(str, entries[0])) if entries else '-'}")
    entries = _changelog_entries(cl_text)
    print(f"{CHANGELOG:<44} {entries[0] if entries else '-'}")


def main():
    if "--show" in sys.argv[1:]:
        _show(ROOT)
        return 0
    ok, lines = run(ROOT)
    for line in lines:
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
