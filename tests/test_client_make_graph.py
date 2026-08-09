# tests/test_client_make_graph.py
"""Guards the client build GRAPH against the clean-tree link failure.

`client/Makefile` builds the shared protocol core by recursing into
`shared/xrdproto`.  Most targets only need the archive to EXIST, so they hang
off the order-only `| proto` alias.  Two targets — `libbrixposix_preload.so`
and `libbrix.so` — actually LINK it and therefore name `$(PROTO_LIB)` as a
normal prerequisite.  That is only legal if the archive is a real make target:
when the recursion lived on the phony alone, any tree without a pre-built
`shared/xrdproto/libxrdproto.a` (i.e. every clean CI checkout) died with

    make: *** No rule to make target '../shared/xrdproto/libxrdproto.a',
          needed by 'libbrixposix_preload.so'.  Stop.

which is exactly how the `asan` lane failed.  A local incremental tree hides
the bug because the archive is already on disk, so this has to be checked
against a deliberately absent archive.

The dry runs below point `PROTO_LIB` at a path that cannot exist and neuter the
recursion with `MAKE=true`, so the graph is exercised without building or
touching anything.

    PYTHONPATH=tests pytest tests/test_client_make_graph.py -v
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
CLIENT = REPO / "client"
MAKEFILE = CLIENT / "Makefile"
ABSENT = "/nonexistent/brix-make-graph/libxrdproto.a"

pytestmark = pytest.mark.timeout(120)


def _dry_run(goal: str) -> subprocess.CompletedProcess:
    """Resolve `goal`'s graph with the protocol archive absent.

    `MAKE=true` replaces the recursive sub-make (GNU make executes recipe lines
    containing `$(MAKE)` even under `-n`) with a no-op that ignores its
    arguments, so nothing is built and `shared/xrdproto` is never entered.

    `-B` is load-bearing: the Makefile's blanket `.SECONDARY:` makes every file
    secondary, and make forgives a missing secondary prerequisite when the goal
    is already up to date — which on a developer box it always is.  Forcing the
    goal out of date is what makes make actually ask how to build the archive,
    i.e. what reproduces the clean-checkout question locally.
    """
    if shutil.which("make") is None:
        pytest.skip("no make")
    return subprocess.run(
        ["make", "-n", "-B", "-C", str(CLIENT), "MAKE=true", f"PROTO_LIB={ABSENT}", goal],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("goal", ["libbrixposix_preload.so", "lib"])
def test_shared_object_goals_resolve_with_the_archive_missing(goal: str) -> None:
    """The clean-tree regression: both .so goals must have a rule for the archive."""
    proc = _dry_run(goal)
    combined = proc.stdout + proc.stderr
    assert "No rule to make target" not in combined, (
        f"`make {goal}` cannot build the protocol archive on a clean tree:\n{combined}"
    )
    assert proc.returncode == 0, combined


def test_protocol_archive_is_a_real_target() -> None:
    """The invariant behind both goals: $(PROTO_LIB) carries its own rule.

    An order-only `| proto` dependency does NOT make the archive buildable — it
    only orders the work — so a target that links the archive needs this rule to
    exist.  Losing it reintroduces the clean-tree failure silently, because an
    incremental tree still has the archive lying around.
    """
    body = MAKEFILE.read_text()
    assert re.search(r"^\$\(PROTO_LIB\)\s*:", body, re.M), (
        "$(PROTO_LIB) has no rule of its own — targets that link it will fail "
        "on any tree where shared/xrdproto/libxrdproto.a does not exist yet"
    )


def test_the_protocol_core_has_exactly_one_recursion_point() -> None:
    """Two rules recursing into shared/xrdproto would race under `make -j`.

    A parallel build could then run two sub-makes in the same directory and link
    a half-written archive into a hardened binary, so the recursion must live in
    exactly one recipe with every other path reaching it through `proto`.
    """
    recipes = [
        line
        for line in MAKEFILE.read_text().splitlines()
        if line.startswith("\t") and "$(MAKE) -C $(PROTO_DIR)" in line
    ]
    assert len(recipes) == 1, f"expected one sub-make into $(PROTO_DIR), got {recipes}"
