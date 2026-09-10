"""Pins for `tools/ci/check_doc_paths.py` v2 — the guard's REACH and its filters.

The 2.0 documentation sweep found stale paths all over the user-facing tree: a
`tests/run_cvmfs_*.sh` fleet that had been ported to Python, a
`src/protocols/webdav/proxy.c` deleted in the 2026-07-20 legacy-proxy cleanup,
a `tests/test_official_brix_resilience.py` cited as evidence that never existed,
and a `manage_test_servers.sh` runner named in 89 places after the bash fleet
was dissolved. None of it reddened CI, because the guard scanned exactly three
files: CLAUDE.md, README.md and docs/index.md.

v2 widened the scope to docs/01-getting-started … docs/08-metrics-monitoring and
added three filters that widening REQUIRES. Each is pinned here with a positive
case, a negative case, and (for the scope) a security-shaped negative — a doc
that quotes a path outside the repo must not be able to smuggle a green verdict
by being outside the scanned set.

The guard's own verdict on the live tree is asserted by
`tests/_test_ci_guards_helpers.py`; this module pins the mechanism, so a future
"simplification" that narrows the scope or loosens a filter fails here with a
message naming what it broke rather than silently returning to a three-file scan.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GUARD = REPO / "tools" / "ci" / "check_doc_paths.py"

pytestmark = pytest.mark.xdist_group("doc-path-guard")


def _load():
    spec = importlib.util.spec_from_file_location("check_doc_paths_v2", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load()


# --- scope ------------------------------------------------------------------

EXPECTED_TREES = (
    "docs/01-getting-started",
    "docs/02-concepts",
    "docs/03-configuration",
    "docs/04-protocols",
    "docs/05-operations",
    "docs/06-authentication",
    "docs/07-security",
    "docs/08-metrics-monitoring",
)


def test_navigation_docs_are_still_scanned_strictly():
    """The original three-file scope survives the widening, in strict mode."""
    scanned = dict(guard.scanned_documents(REPO))
    for name in ("CLAUDE.md", "README.md", "docs/index.md"):
        assert scanned.get(name) is True, f"{name} lost its strict scan"


def test_every_user_facing_tree_is_in_scope():
    """The eight operator/user trees are scanned; a narrowing fails here."""
    assert tuple(guard.TREE_ROOTS) == EXPECTED_TREES


def test_scope_reaches_the_docs_that_rotted():
    """Named victims of the 2.0 sweep are actually reached, not just their trees.

    A tree can be listed and still contribute nothing if the rglob pattern or
    the suffix filter regresses."""
    scanned = dict(guard.scanned_documents(REPO))
    for relative in (
        "docs/04-protocols/cvmfs.md",
        "docs/04-protocols/native-client-tools.md",
        "docs/05-operations/operation-status.md",
        "docs/05-operations/cluster-management.md",
        "docs/07-security/hardening-evidence.md",
        "docs/07-security/hyper-hardening-plan.md",
    ):
        assert relative in scanned, f"{relative} is not scanned"
        assert scanned[relative] is False, f"{relative} should be non-strict"


def test_developer_history_trees_are_deliberately_out_of_scope():
    """docs/09..11 name deleted paths ON PURPOSE — that IS the record."""
    scanned = dict(guard.scanned_documents(REPO))
    assert not [name for name in scanned if name.startswith("docs/09-")]
    assert not [name for name in scanned if name.startswith("docs/1")
                and name != "docs/index.md"]


# --- brace expansion --------------------------------------------------------

@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("src/auth/gssapi/gsi_mech.{c,h}",
         ["src/auth/gssapi/gsi_mech.c", "src/auth/gssapi/gsi_mech.h"]),
        ("src/net/cms/{connect,recv,send}.c",
         ["src/net/cms/connect.c", "src/net/cms/recv.c", "src/net/cms/send.c"]),
        ("packaging/selinux/brix.{te,fc,if}",
         ["packaging/selinux/brix.te", "packaging/selinux/brix.fc",
          "packaging/selinux/brix.if"]),
    ],
)
def test_brace_lists_expand_with_their_suffix(line, expected):
    """`a/{x,y}.c` must yield BOTH names WITH the extension.

    Dropping the trailing group is the subtle version of this bug: every branch
    then resolves to an extensionless path that exists nowhere, so the guard
    reports three fabricated misses and a reader learns to ignore it."""
    assert guard._expand_braces(line).split() == expected


def test_a_line_without_braces_is_returned_unchanged():
    line = "see src/fs/vfs/vfs_policy.c and tools/ci/check_vfs_seam.py"
    assert guard._expand_braces(line) == line


# --- the prose filter -------------------------------------------------------

@pytest.mark.parametrize("token", [
    "docs/index.md",                     # known extension
    "src/fs/backend/ucred.c",            # three segments
    "src/protocols/webdav/",             # trailing slash
    "packaging/selinux/brix.te",         # extension from the wider set
    "tests/cmdscripts/manage_test_servers.py",
])
def test_real_paths_pass_the_prose_filter(token):
    assert guard._looks_like_path(token)


@pytest.mark.parametrize("token", [
    "client/server",     # "a client/server ecosystem"
    "shared/mounted",    # "shared/mounted state"
    "deploy/doc",        # "a deploy/doc split"
    "client/op",
    "shared/ambiguous",
])
def test_english_prose_does_not_look_like_a_path(token):
    """Widening the scope drags in prose; without this filter the guard cries
    wolf on every page and stops being read."""
    assert not guard._looks_like_path(token)


# --- build products ---------------------------------------------------------

@pytest.mark.parametrize("token", ["client/bin", "client/bin/xrdcp",
                                   "client/lib/libbrix.a", "objs/nginx"])
def test_build_products_are_exempt(token):
    """`client/bin/xrdcp` is the command the docs tell a user to RUN.

    It is gitignored by design and absent until `make -C client`, so both the
    existence and the tracked-ness test would fire on a correct reference."""
    assert guard._is_build_output(token)


@pytest.mark.parametrize("token", ["client/lib/net/resolve.c", "src/core/ident.h",
                                   "tests/settings.py"])
def test_sources_are_not_treated_as_build_products(token):
    """Security-negative: the exemption must not become a blanket escape.

    A prefix written one segment too short (`client/` instead of `client/bin/`)
    would silence every stale reference under the client tree."""
    assert not guard._is_build_output(token)


# --- fencing ----------------------------------------------------------------

def test_doc_paths_off_region_is_skipped(tmp_path):
    doc = tmp_path / "sample.md"
    doc.write_text(
        "live src/core/ident.h\n"
        "<!-- doc-paths:off -->\n"
        "dead src/protocols/webdav/proxy.c\n"
        "<!-- doc-paths:on -->\n"
        "live tools/ci/check_doc_paths.py\n"
    )
    tokens = guard._extract(doc, strict=True)
    assert "src/protocols/webdav/proxy.c" not in tokens
    assert "src/core/ident.h" in tokens
    assert "tools/ci/check_doc_paths.py" in tokens


def test_an_unclosed_fence_swallows_the_rest_of_the_file(tmp_path):
    """Security-negative: an `off` with no `on` blinds everything after it.

    Pinned so the behaviour is a known, deliberate property rather than a
    surprise — a reviewer seeing a bare `doc-paths:off` knows the whole tail of
    that document is unchecked."""
    doc = tmp_path / "sample.md"
    doc.write_text(
        "<!-- doc-paths:off -->\n"
        "src/core/ident.h\n"
        "tools/ci/check_doc_paths.py\n"
    )
    assert guard._extract(doc, strict=True) == []


# --- end-to-end -------------------------------------------------------------

def test_a_stale_reference_in_a_widened_tree_is_reported(tmp_path):
    """The whole point: a dead path in docs/05-operations must now FAIL."""
    root = tmp_path
    (root / "docs" / "05-operations").mkdir(parents=True)
    (root / "docs" / "05-operations" / "guide.md").write_text(
        "Implemented in `src/protocols/webdav/proxy.c`.\n"
    )
    clean, messages = guard.run(root)
    assert not clean
    assert any("src/protocols/webdav/proxy.c" in line for line in messages)


def test_prose_in_a_widened_tree_is_not_reported(tmp_path):
    root = tmp_path
    (root / "docs" / "02-concepts").mkdir(parents=True)
    (root / "docs" / "02-concepts" / "intro.md").write_text(
        "A client/server ecosystem with shared/mounted state.\n"
    )
    clean, messages = guard.run(root)
    assert clean, messages
