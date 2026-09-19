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
from brix_suite.client_build import client_make

import pytest

from lib_py.preload_shim import SHIM_NAME

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
    return client_make(str(CLIENT), "-n", "-B", "MAKE=true", f"PROTO_LIB={ABSENT}", goal, capture_output=True, text=True)


@pytest.mark.parametrize("goal", [SHIM_NAME, "lib"])
def test_shared_object_goals_resolve_with_the_archive_missing(goal: str) -> None:
    """The clean-tree regression: both shared-object goals (the preload shim
    under its host's name, libbrix) must have a rule for the archive."""
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


# --- archive ORDER: the protocol core's PAL callers must still resolve --------
#
# shared/xrdproto ships no PAL.  Its storage backends call brix_plat_* entry
# points that each consumer supplies for its own host, so libxrdproto.a reaches
# the linker with brix_plat_pwrite_at, brix_plat_blockdev_size and friends
# undefined and libbrix.a is what defines them.  GNU ld resolves an archive
# once, against the undefined symbols it holds at that moment: a link line
# naming libbrix.a only BEFORE libxrdproto.a is already past it when those
# symbols appear, and xrdcksum/xrddiag died with "undefined reference to
# `brix_plat_pwrite_at'".  Every executable therefore offers libbrix.a on both
# sides, which is also the only cure that survives Mach-O linking.


def _link_lines(output: str, goal: str) -> list[str]:
    """Every line in a dry run that links `goal` against the proto archive."""
    return [
        line
        for line in output.splitlines()
        if f"-o {goal}" in line and "libxrdproto.a" in line
    ]


def _link_line(goal: str) -> str:
    """The compiler command `make` would run to link `goal`.

    `-B` forces the goal out of date (an incremental tree has the binary) and
    `MAKE=true` neuters the sub-make, so this reads the graph without building.
    """
    if shutil.which("make") is None:
        pytest.skip("no make")
    proc = client_make(str(CLIENT), "-n", "-B", "MAKE=true", goal, capture_output=True, text=True)
    links = _link_lines(proc.stdout + proc.stderr, goal)
    assert len(links) == 1, f"expected one link line for {goal}, got {links}"
    return links[0]


@pytest.mark.parametrize("goal", ["bin/xrdcksum", "bin/xrddiag"])
def test_executables_offer_the_pal_after_the_protocol_core(goal: str) -> None:
    """The regression: both binaries that pull the xrdproto storage backends
    must name libbrix.a again after libxrdproto.a, or their PAL calls dangle."""
    line = _link_line(goal)
    order = [tok for tok in re.findall(r"\S*lib(?:brix|xrdproto)\.a", line)]
    assert len(order) >= 3 and order[-1].endswith("libbrix.a"), (
        f"{goal} links the archives as {order} — libbrix.a must follow "
        f"libxrdproto.a so the protocol core's brix_plat_* callers resolve:\n{line}"
    )


def test_every_executable_link_uses_the_shared_archive_pair() -> None:
    """One variable owns the order so a new front-end cannot reintroduce it.

    The bug was per-recipe, and twelve recipes spelt the pair by hand; a
    thirteenth would have copied the broken order. Only the definition of
    $(BRIX_LIBS) and the `install` rule may name the two archives directly.
    """
    offenders = [
        line
        for line in MAKEFILE.read_text().splitlines()
        if line.lstrip().startswith("$(CC)") and "$(CLIENT_LIB) $(PROTO_LIB)" in line
    ]
    assert not offenders, (
        "these link recipes spell the archive pair by hand instead of using "
        f"$(BRIX_LIBS), and so carry the single-pass ordering bug: {offenders}"
    )


def test_the_unit_recipe_closes_the_same_cycle() -> None:
    """`make <name>-unit` links the same two archives and needs the same cure.

    It cannot use $(BRIX_LIBS) verbatim — $$lib selects whole-archive per test
    from $(WHOLEARCH_TESTS) — so it trails $(CLIENT_LIB) by hand. Dropping that
    breaks cred_refresh, relsafe, web_proxy_pem and xrdrc_defaults, whose units
    reach a storage backend and so import brix_plat_* from libxrdproto.a.
    """
    body = MAKEFILE.read_text()
    recipe = re.search(r"^%-unit:.*?(?=\n[^\t\n#])", body, re.M | re.S)
    assert recipe, "the %-unit pattern rule is gone"
    link = recipe.group(0)
    assert re.search(r"\$\(PROTO_LIB\)\s+\$\(CLIENT_LIB\)", link), (
        "the %-unit link no longer offers $(CLIENT_LIB) after $(PROTO_LIB); "
        f"units importing brix_plat_* through the protocol core will dangle:\n{link}"
    )


def test_the_sweep_recipe_closes_the_same_cycle() -> None:
    """`make test` links each unit itself and needs the cure independently.

    The sweep at the `test:` target has its OWN $(CC) line — fixing only the
    %-unit pattern rule left `make test` dying on brix_plat_wait_pid_timeout /
    brix_plat_pipe2 at cred_refresh_unit, because libxrdproto's subprocess.o
    calls back into the PAL that libbrix defines and GNU ld had already walked
    past libbrix.a. The two recipes must stay in step.
    """
    body = MAKEFILE.read_text()
    recipe = re.search(r"^test:.*?(?=\n[^\t\n#])", body, re.M | re.S)
    assert recipe, "the `test` sweep target is gone"
    link = recipe.group(0)
    assert re.search(r"\$\(PROTO_LIB\)\s+\$\(CLIENT_LIB\)", link), (
        "the `make test` sweep no longer offers $(CLIENT_LIB) after "
        f"$(PROTO_LIB); the C unit sweep will fail to link:\n{link}"
    )


def _makefile_code_lines_naming(flag: str) -> list[str]:
    """Makefile lines naming `flag`, comments excluded.

    The rationale comments deliberately say the words this test bans, so a raw
    text search would flag the explanation of the ban.
    """
    return [
        line
        for line in MAKEFILE.read_text().splitlines()
        if flag in line and not line.lstrip().startswith("#")
    ]


def test_the_ordering_cure_stays_portable_to_macos() -> None:
    """Repeating the archive is the fix precisely because ld64 accepts it.

    --start-group/--end-group would resolve the same cycle on GNU ld and break
    every Darwin link, so reaching for them is a regression on the macOS host
    even though this host's build would go green.
    """
    offenders = {
        flag: _makefile_code_lines_naming(flag)
        for flag in ("--start-group", "--end-group")
    }
    assert not any(offenders.values()), (
        "--start-group/--end-group are GNU ld only — Mach-O linking rejects "
        "them; repeat the archive (see $(BRIX_LIBS)) to resolve the "
        f"libbrix/libxrdproto cycle: {offenders}"
    )


def _undefined_pal_symbols(binary) -> list[str]:
    """The `brix_plat_*` imports `binary` still leaves unresolved, sorted."""
    if not binary.exists():
        pytest.skip(f"{binary} not built")
    if shutil.which("nm") is None:
        pytest.skip("no nm")
    proc = subprocess.run(["nm", "-u", str(binary)], capture_output=True, text=True)
    return sorted({s for s in proc.stdout.split() if s.startswith("brix_plat_")})


@pytest.mark.parametrize("goal", ["xrdcksum", "xrddiag"])
def test_built_executables_carry_no_undefined_pal_symbols(goal: str) -> None:
    """The proof the order actually worked, read off the real artifact.

    The dry runs above check the recipe; this checks the binary the recipe
    produced, so a link that silently left a brix_plat_* import unresolved
    (a lazily bound .so would only fail at the first call) is caught here.
    """
    binary = CLIENT / "bin" / goal
    dangling = _undefined_pal_symbols(binary)
    assert not dangling, f"{goal} has unresolved PAL symbols: {dangling}"
