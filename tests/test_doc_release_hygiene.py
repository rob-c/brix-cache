"""Release hygiene of the user-facing docs: versions and post-rebrand names.

Two classes of rot that a path guard cannot see, because every string involved
is a perfectly valid English word or a file that does exist somewhere:

1. **Version drift.** `docs/05-operations/remote-host-test-suite.md` told an
   operator to `dnf install` `brix-cache-*-1.1.1-20.el9.rpm` while the tree had
   been 2.0.0 for weeks. The command fails on a real host with "No match for
   argument", and the first thing a 2.0 evaluator does is follow that page.

2. **Pre-rebrand client artifacts.** The client rebranded `libxrdc*` ->
   `libbrix*`, `xrdc.h` -> `brix.h`, `xrdc_*` -> `brix_*`,
   `libxrdposix_preload.so` -> `libbrixposix_preload.so`. A user-facing doc that
   still says `-lxrdc` or `#include <xrdc.h>` hands the reader a link line that
   cannot work. Some `xrd`-prefixed names are NOT part of that rename and must
   survive untouched: the binary `xrdcp`, the capability file suffix `.xrdcap`,
   and the error code `XRDC_ERESOLVE` — a rename sweep that eats those is the
   failure mode this module's negatives pin.

Scope is docs/01..08 plus the three navigation docs. docs/09..11 are developer
history and reference archaeology, where the OLD names are the record.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
IDENT_H = REPO / "src" / "core" / "ident.h"
SPEC = REPO / "packaging" / "rpm" / "nginx-mod-brix-cache.spec"

USER_TREES = tuple(f"docs/0{n}-" for n in range(1, 9))
NAV_DOCS = ("CLAUDE.md", "README.md", "docs/index.md")


def _user_trees() -> list[Path]:
    """The `docs/01-`…`docs/08-` directories, whatever they are named this month."""
    return [
        directory
        for directory in sorted(REPO.glob("docs/0*-*"))
        if directory.is_dir()
        and directory.relative_to(REPO).as_posix().startswith(USER_TREES)
    ]


def _user_facing_docs() -> list[Path]:
    docs = [REPO / name for name in NAV_DOCS]
    for directory in _user_trees():
        docs += sorted(directory.rglob("*.md"))
    return [path for path in docs if path.is_file()]


DOCS = _user_facing_docs()


def _relative(path: Path) -> str:
    return path.relative_to(REPO).as_posix()


# --- the canonical version --------------------------------------------------

def test_canonical_version_is_readable_from_one_place():
    """Everything below is measured against ident.h, never a literal."""
    assert CANONICAL_VERSION.count(".") == 2, CANONICAL_VERSION


def _canonical_version() -> str:
    match = re.search(
        r'#define\s+BRIX_SERVER_VERSION_BARE\s+"([0-9]+\.[0-9]+\.[0-9]+)"',
        IDENT_H.read_text(),
    )
    assert match, "BRIX_SERVER_VERSION_BARE is no longer a bare X.Y.Z in src/core/ident.h"
    return match.group(1)


CANONICAL_VERSION = _canonical_version()

# `nginx-mod-brix-cache-2.0.0-1.el9.x86_64.rpm`, `brix-cache-tests-2.0.0-1.el9.noarch.rpm`
_PACKAGE_FILE = re.compile(
    r"\b([a-z][a-z0-9-]*?)-([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)\.(el|fc)[0-9]+",
    re.ASCII,
)
# Only OUR packages carry OUR version. `wlcg-repo-1.0.0-1.el9.noarch.rpm` is
# CERN's and is correctly at its own version — a pin that flagged it would be
# telling the reader to falsify a third party's filename.
_SPEC_PACKAGE = re.compile(
    r"^(?:Name:\s+|%package(?:\s+-n)?\s+)(\S+)", re.M | re.ASCII)


def _our_packages() -> frozenset:
    """Every subpackage `packaging/rpm/nginx-mod-brix-cache.spec` builds.

    `%package selinux` (no -n) is a SUFFIX of Name:, so expand both forms."""
    names = set(_SPEC_PACKAGE.findall(SPEC.read_text()))
    base = "nginx-mod-brix-cache"
    return frozenset(names | {f"{base}-{name}" for name in names if name != base})


OUR_PACKAGES = _our_packages()


def _our_package_versions(text: str):
    return [
        (name, version, release)
        for name, version, release, _ in _PACKAGE_FILE.findall(text)
        if name in OUR_PACKAGES
    ]


def test_the_spec_package_set_is_readable():
    """The version pins below filter by this set; an empty set would make them
    vacuously green."""
    assert "nginx-mod-brix-cache" in OUR_PACKAGES
    assert "brix-cache-client" in OUR_PACKAGES
    assert "nginx-mod-brix-cache-selinux" in OUR_PACKAGES
    assert "wlcg-repo" not in OUR_PACKAGES


def test_spec_release_is_still_one():
    """The `-1` in every documented filename comes from the spec, not a guess."""
    assert re.search(r"^Release:\s+1%\{\?dist\}", SPEC.read_text(), re.M), (
        "packaging/rpm/nginx-mod-brix-cache.spec no longer pins Release: 1 — "
        "the documented package filenames below encode it"
    )


def test_no_user_facing_doc_quotes_a_stale_package_version():
    """Every X.Y.Z inside a documented .rpm/.deb filename is the shipped one."""
    stale = [
        f"{_relative(path)}: {name}-{version}-{release}"
        for path in DOCS
        for name, version, release in _our_package_versions(path.read_text())
        if version != CANONICAL_VERSION
    ]
    assert not stale, (
        "user-facing docs quote package filenames at a version other than "
        f"{CANONICAL_VERSION} (src/core/ident.h):\n  " + "\n  ".join(stale)
    )


def test_no_user_facing_doc_quotes_a_stale_package_release():
    stale = [
        f"{_relative(path)}: {name}-{version}-{release}"
        for path in DOCS
        for name, version, release in _our_package_versions(path.read_text())
        if release != "1"
    ]
    assert not stale, (
        "user-facing docs quote a package release other than the spec's "
        "Release: 1:\n  " + "\n  ".join(stale)
    )


# --- post-rebrand client names ----------------------------------------------

# Deliberately anchored: `xrdc_` needs a word boundary so `XRDC_ERESOLVE` (an
# uppercase error code that KEPT its name) is not matched, and `xrdc\.h` needs
# the dot so `xrdcp` (the binary, which KEPT its name) is not matched.
_PRE_REBRAND = re.compile(
    r"\blibxrdc[a-z_]*"          # libxrdc, libxrdcposix, …
    r"|-lxrdc\b"                 # the old link flag, as a doc would print it
    r"|\bxrdc\.h\b"             # the old public header
    r"|\blibxrdposix_preload\b"
    r"|\bxrdc_[a-z][a-z0-9_]*",  # lowercase symbol prefix only
    re.ASCII,
)

SURVIVING_NAMES = ("xrdcp", "xrdfs", ".xrdcap", "XRDC_ERESOLVE", "XRDC_CONNECT_TIMEOUT_MS")


def test_no_user_facing_doc_names_a_pre_rebrand_client_artifact():
    hits = [
        f"{_relative(path)}:{number}: {match}"
        for path in DOCS
        for number, line in enumerate(path.read_text().splitlines(), 1)
        for match in _PRE_REBRAND.findall(line)
    ]
    assert not hits, (
        "user-facing docs still name pre-rebrand client artifacts "
        "(libxrdc* -> libbrix*, xrdc.h -> brix.h, xrdc_* -> brix_*, "
        "libxrdposix_preload.so -> libbrixposix_preload.so):\n  " + "\n  ".join(hits)
    )


@pytest.mark.parametrize("name", SURVIVING_NAMES)
def test_the_rebrand_pattern_spares_names_that_were_never_renamed(name):
    """Security-negative for the sweep itself.

    A broader pattern (`xrdc` unanchored) would flag the `xrdcp` binary, the
    `.xrdcap` capability suffix and the `XRDC_*` error codes — all still real —
    and a well-meaning fix would then rename them in the docs, sending users to
    commands and env vars that do not exist."""
    assert not _PRE_REBRAND.search(f"run {name} now")


def test_the_rebrand_pattern_does_catch_a_real_pre_rebrand_name():
    """Positive control: the pattern is not vacuously green."""
    for stale in ("link with -lxrdc", "#include <xrdc.h>", "call xrdc_send()",
                  "LD_PRELOAD=libxrdposix_preload.so"):
        assert _PRE_REBRAND.search(stale), stale


# --- the rebranded names are the ones actually shipped ----------------------

@pytest.mark.parametrize("artifact", [
    "client/lib/brix.h",
    "client/Makefile",
])
def test_the_successor_artifacts_exist(artifact):
    """If the successor moved again, the pattern above is pinning a dead target."""
    assert (REPO / artifact).exists(), artifact


def test_client_makefile_builds_the_rebranded_library_names():
    text = (REPO / "client" / "Makefile").read_text()
    for name in ("libbrix.a", "libbrixposix_preload.so"):
        assert name in text, f"client/Makefile no longer produces {name}"
