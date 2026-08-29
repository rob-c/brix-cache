"""Pin the cvmfs conformance port-block anchoring in cvmfs/conformance_common.

The mock-Stratum-1 + nginx port blocks are anchored to THIS suite's
TEST_PORT_START (immediately past the fixed-fleet ladder,
port_ladder.CVMFS_CONFORMANCE_OFFSET) so every port stays within
TEST_PORT_START+3000 — part of the main fleet's band, not an absolute 13100+
range disconnected from it.  A second suite on a different TEST_PORT_START then
draws a fully disjoint range automatically (no cross-suite / debug collision),
which replaces the old absolute per-session tile scheme.
"""

import os

import pytest

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_tiles")

from cvmfs import conformance_common as cc
from port_ladder import CVMFS_CONFORMANCE_OFFSET
from settings import TEST_PORT_START

# An explicit CVMFS_CONFORMANCE_PORT_BASE override deliberately unpins the map
# from TEST_PORT_START (CI/debug), so the anchoring invariants only hold without it.
_ANCHORED = os.environ.get("CVMFS_CONFORMANCE_PORT_BASE") is None


def test_all_conformance_ports_within_3000_of_test_port_start():
    """The user-facing invariant: no cvmfs port is more than 3000 above the start
    of the port range, so a second suite on a different TEST_PORT_START cannot
    collide with this one."""
    if not _ANCHORED:
        pytest.skip("CVMFS_CONFORMANCE_PORT_BASE pins the base away from the ladder")
    for name, base in cc.PORT_BLOCKS.items():
        # a block hands out base+0..base+19 (mock 0..9, nginx 10..19)
        assert TEST_PORT_START <= base and base + 19 <= TEST_PORT_START + 3000, (
            f"cvmfs block {name} ({base}..{base + 19}) escapes "
            f"[{TEST_PORT_START}, {TEST_PORT_START + 3000}]")


def test_blocks_are_anchored_to_test_port_start():
    if not _ANCHORED:
        pytest.skip("CVMFS_CONFORMANCE_PORT_BASE pins the base explicitly")
    # +1 matches port_ladder._port(offset, 0): the category starts right where
    # the fixed-fleet ladder ends.
    assert cc._CVMFS_BASE == TEST_PORT_START + CVMFS_CONFORMANCE_OFFSET + 1
    assert min(cc.PORT_BLOCKS.values()) == cc._CVMFS_BASE
    # sits just past the fixed-fleet ladder, never overlapping it
    assert cc._CVMFS_BASE > TEST_PORT_START


def test_blocks_are_distinct_and_20_apart_preserving_relative_layout():
    bases = sorted(cc.PORT_BLOCKS.values())
    assert len(set(bases)) == len(bases), "each corpus file must own a distinct block"
    assert all(b - a == 20 for a, b in zip(bases, bases[1:])), \
        "the per-file 20-port relative layout (mock base+0..9, nginx base+10..19) must hold"


def test_no_per_session_tile_shift_applied():
    """TEST_PORT_START separates concurrent suites now, so no absolute tile offset
    is layered on top of the anchored bases."""
    assert cc._SESSION_OFFSET == 0
