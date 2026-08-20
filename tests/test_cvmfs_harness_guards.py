# tests/test_cvmfs_harness_guards.py — meta-guards for the cvmfs test harness.
#
# Pins the two latent-harness failure modes found (and fixed) during the
# phase-87 CCN burndown, so they cannot regrow silently:
#   * stale private compile lists — fuse suites carried their own copies of
#     the brixcvmfs shared-core source list; when Waves A/B added new .c
#     files the copies drifted, one suite link-failed and another silently
#     SKIPPED 64 tests behind its build guard. Guard: the compile list is
#     single-truth (`BRIXCVMFS_CORE_DEPS`), every entry exists, and the fuse
#     suites consume it instead of literals.
#   * absolute canonical ports in conformance suites — fixtures hardcoding
#     1312x/1330x literals collide with the fleet's fixed-port stubs when a
#     fleet is up (session tiles shift PortBlock.base, literals don't).
#     Guard: AST walk rejects int constants inside the canonical tile range
#     anywhere under tests/test_cvmfs_conformance_*.py.
import ast
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
REPO_ROOT = TESTS.parent
sys.path.insert(0, str(TESTS / "cvmfs"))

from cmdscripts.cvmfs_driver_units import (  # noqa: E402
    BRIXCVMFS_CORE_DEPS,
    CVMFS_CLIENT_DEPS,
    CVMFS_CORE_DEPS,
    CVMFS_WALK_DEPS,
)
from conformance_common import PORT_BLOCKS  # noqa: E402

_FUSE_SUITES = ("test_cvmfs_conformance_fuse_whitelist.py",
                "test_cvmfs_conformance_fuse_trust.py")


def test_compile_list_entries_all_exist():
    """Every source/object named by the single-truth compile lists must exist —
    a renamed or deleted file otherwise surfaces as a link error (or worse, a
    build-guard skip) deep inside a fuse suite."""
    missing = sorted({d for d in (*CVMFS_CORE_DEPS, *CVMFS_CLIENT_DEPS,
                                  *CVMFS_WALK_DEPS, *BRIXCVMFS_CORE_DEPS)
                      if not (REPO_ROOT / d).exists()})
    assert not missing, f"compile-list entries missing on disk: {missing}"


def test_fuse_suites_consume_single_truth_compile_list():
    """The fuse conformance suites must derive their shared-core compile list
    from BRIXCVMFS_CORE_DEPS, never a private literal copy (the stale-copy
    failure mode: 59 link ERRORs in whitelist, 64 silent skips in trust)."""
    for name in _FUSE_SUITES:
        facade = TESTS / name
        # Split suites are intentionally tiny re-export facades. Inspect the
        # continuation helper as well; checking only the facade makes a valid
        # split look like a stale private compile list.
        helper_stem = "_" + facade.stem + "_helpers"
        sources = [facade, *sorted(TESTS.glob(helper_stem + "*.py"))]
        text = "\n".join(path.read_text() for path in sources)
        assert "BRIXCVMFS_CORE_DEPS" in text, \
            f"{name} no longer imports the single-truth compile list"
        literal_lists = [n.lineno for n in ast.walk(ast.parse(text))
                         if isinstance(n, (ast.List, ast.Tuple))
                         and any(isinstance(e, ast.Constant)
                                 and e.value == "shared/cvmfs/client/client.c"
                                 for e in n.elts)]
        assert not literal_lists, \
            f"{name}:{literal_lists} regrew a private literal shared-core list"


def test_conformance_suites_free_of_canonical_port_literals():
    """No int literal inside the canonical PortBlock tile range may appear in
    a conformance suite — ports must come from PortBlock.base so session
    tiling keeps them clear of the fleet's fixed-port stubs. (Docstrings are
    str constants and survive; test_cvmfs_pin_root.py is fixed-port by design
    and outside this glob.)"""
    lo = min(PORT_BLOCKS.values())
    hi = max(PORT_BLOCKS.values()) + 20
    offenders = []
    for path in sorted(TESTS.glob("test_cvmfs_conformance_*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and type(node.value) is int
                    and lo <= node.value < hi):
                offenders.append(f"{path.name}:{node.lineno} = {node.value}")
    assert not offenders, \
        "absolute canonical-port literals in conformance suites " \
        f"(derive from PortBlock.base instead): {offenders}"
