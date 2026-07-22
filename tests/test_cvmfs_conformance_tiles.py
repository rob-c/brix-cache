"""Pin the atomic port-tile claim in cvmfs/conformance_common.

Each process (xdist worker, concurrent session) claims a tile by binding and
HOLDING its lock port, so two workers can never settle on the same tile — the
transient-probe scheme this replaced let 12 workers race the probe window and
collide, which surfaced as ConnectionReset storms across the qos/transcode
conformance suites under -n 12.
"""

import socket

import pytest

from cvmfs import conformance_common as cc
from settings import BIND_HOST


@pytest.fixture
def spare_tile():
    """A tile base whose ports are free right now, with module state restored."""
    saved = cc._TILE_LOCK
    cc._TILE_LOCK = None
    # Find a tile whose lock port is currently bindable, far from the session's.
    for t in reversed(range(cc._N_TILES)):
        lo = cc._CANON_LO + t * cc._TILE
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.bind((BIND_HOST, lo + cc._TILE - 1))
            probe.close()
            break
        except OSError:
            continue
    else:
        pytest.skip("no free tile on this host")
    yield lo
    if cc._TILE_LOCK is not None and cc._TILE_LOCK is not saved:
        cc._TILE_LOCK.close()
    cc._TILE_LOCK = saved


def test_claim_holds_the_lock_port_so_a_rival_loses(spare_tile):
    assert cc._claim_tile(spare_tile) is True
    won = cc._TILE_LOCK
    assert won is not None
    # A rival process's claim is a fresh bind of the same lock port: it must lose
    # while the winner holds it.
    rival = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(OSError):
        rival.bind((BIND_HOST, spare_tile + cc._TILE - 1))
    rival.close()


def test_released_tile_is_claimable_again(spare_tile):
    assert cc._claim_tile(spare_tile) is True
    cc._TILE_LOCK.close()
    cc._TILE_LOCK = None
    assert cc._claim_tile(spare_tile) is True


def test_occupied_sentinel_fails_the_claim_and_releases_the_lock(spare_tile):
    # Squat a sentinel port (not the lock port): the claim must fail AND must
    # not leak the lock bind, or the tile would look taken forever.
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    squatter.bind((BIND_HOST, spare_tile))
    try:
        assert cc._claim_tile(spare_tile) is False
        assert cc._TILE_LOCK is None
        relock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        relock.bind((BIND_HOST, spare_tile + cc._TILE - 1))
        relock.close()
    finally:
        squatter.close()


def test_lock_port_sits_outside_every_block_span():
    """The lock port (tile offset _TILE-1) must never collide with a port a
    PortBlock can hand out (offsets 0.._TILE-2)."""
    lock_offset = cc._TILE - 1
    for base in cc.PORT_BLOCKS.values():
        top_offset = (base + 19) - cc._CANON_LO   # last port the block hands out
        assert top_offset < lock_offset
    assert cc._TILE == (cc._CANON_HI - cc._CANON_LO) + 1
