"""Guard: the TEST_PORT_START lane is ONE contiguous range with zero overlaps.

`port_ladder.py` hands every managed test listener a slot in a packed lane above
`TEST_PORT_START`, carved into ordered category segments (settings, the two
lifecycle ledgers, cmdscripts, the two meshes, placeholders, cvmfs conformance,
interop workers). Two failure modes must never ship:

  * OVERLAP — two segments assigned the same port. Two unrelated test servers
    then bind the same socket and collide, silently and flakily. (The older
    `test_fleet_ports` contiguity check builds a *set* of allocated ports, which
    DEDUPS an overlap, so it catches gaps but is blind to overlaps — this file
    closes that hole by checking each port is assigned exactly ONCE.)
  * GAP / drift — a segment offset or PORT_COUNT that does not match the packed
    widths, wasting ports or mis-reporting the lane.

The lane is meant to stay overlap-free BY CONSTRUCTION (offsets are derived from
widths in port_ladder._build_ladder). These tests lock that invariant so an edit
by a future agent — hand-editing an offset, or adding a server config to a
lifecycle ledger without bumping the matching width — fails HERE, loudly, instead
of surfacing later as a mystery "Address already in use".

Run:
    PYTHONPATH=tests pytest tests/test_port_ladder.py -v
"""

import port_ladder as pl


# The ladder segments in packed order, read from the module's PUBLIC constants so
# this is a genuine external check (not a re-read of the private _LADDER tuple).
# Keep this list in the same order port_ladder declares the segments.
SEGMENTS = [
    ("settings",             pl.SETTINGS_OFFSET,            pl.SETTINGS_WIDTH),
    ("lifecycle-shared",     pl.LIFECYCLE_SHARED_OFFSET,    pl.LIFECYCLE_SHARED_WIDTH),
    ("lifecycle-exclusive",  pl.LIFECYCLE_EXCLUSIVE_OFFSET, pl.LIFECYCLE_EXCLUSIVE_WIDTH),
    ("cmdscripts",           pl.CMDSCRIPTS_OFFSET,          pl.CMDSCRIPTS_WIDTH),
    ("cms-mesh",             pl.CMS_MESH_OFFSET,            pl.CMS_MESH_WIDTH),
    ("hybrid-mesh",          pl.HYBRID_MESH_OFFSET,         pl.HYBRID_MESH_WIDTH),
    ("placeholders",         pl.PLACEHOLDERS_OFFSET,        pl.PLACEHOLDERS_WIDTH),
    ("cvmfs-conformance",    pl.CVMFS_CONFORMANCE_OFFSET,   pl.CVMFS_CONFORMANCE_WIDTH),
    ("interop-worker",       pl.INTEROP_WORKER_OFFSET,      pl.INTEROP_WORKER_WIDTH),
]


def test_segment_offsets_are_contiguous_from_zero():
    """Every segment begins exactly where the previous one ended — the packed
    lane starts at 0, has no gap and no overlap, and PORT_COUNT is the sum."""
    cursor = 0
    for name, offset, width in SEGMENTS:
        assert width > 0, f"{name}: width must be positive, got {width}"
        assert offset == cursor, (
            f"{name}: offset {offset} != expected {cursor} — a preceding width "
            f"changed but the offsets below were not shifted. The ladder is "
            f"packed: derive offsets from widths, never hand-edit an offset.")
        cursor += width
    assert cursor == pl.PORT_COUNT, (
        f"PORT_COUNT {pl.PORT_COUNT} != sum of segment widths {cursor}")
    assert pl.PORT_LAST - pl.PORT_FIRST + 1 == pl.PORT_COUNT


def test_actual_ports_tile_the_lane_exactly_once():
    """The REAL ports (via port_ladder._port) cover [PORT_FIRST, PORT_LAST] with
    each port used exactly once — zero overlaps (the check the set-based lint
    cannot make) and zero gaps."""
    owner: dict[int, str] = {}
    for name, offset, width in SEGMENTS:
        for index in range(width):
            port = pl._port(offset, index)
            assert pl.PORT_FIRST <= port <= pl.PORT_LAST, (
                f"{name}[{index}] port {port} escapes the lane "
                f"{pl.PORT_FIRST}..{pl.PORT_LAST}")
            if port in owner:
                raise AssertionError(
                    f"port {port} is assigned to BOTH {owner[port]} and "
                    f"{name}[{index}] — overlapping ladder segments")
            owner[port] = f"{name}[{index}]"
    # exactly-once over the whole lane => one continuous, gap-free range
    assert set(owner) == set(range(pl.PORT_FIRST, pl.PORT_LAST + 1)), (
        "the assigned ports do not exactly fill the lane (a gap remains)")
    assert len(owner) == pl.PORT_COUNT


def _lifecycle_slot_count(ledger: dict) -> int:
    """Count the port slots a lifecycle ledger consumes: one per entry plus one
    per named `extra` — the same accounting rebase_lifecycle_ledger uses."""
    return sum(1 + len(entry.get("extra", {})) for entry in ledger.values())


def test_lifecycle_widths_match_the_live_ledgers():
    """The declared LIFECYCLE_* widths equal the real ledger sizes.

    This is the guard for the most common accident: an agent adds (or removes) a
    server config in a lifecycle ledger but forgets to bump the matching width.
    The ports are read straight from the raw ledger modules (no rebase side
    effects), and the slot count is compared to the ladder width.
    """
    from fleet_ports_exclusive import LIFECYCLE_EXCLUSIVE_PORTS
    from fleet_ports_shared_phase5 import LIFECYCLE_SHARED_PORTS_PHASE5
    from fleet_ports_shared_waves import LIFECYCLE_SHARED_PORTS_WAVES

    exclusive = _lifecycle_slot_count(LIFECYCLE_EXCLUSIVE_PORTS)
    assert exclusive == pl.LIFECYCLE_EXCLUSIVE_WIDTH, (
        f"the exclusive lifecycle ledger holds {exclusive} port slot(s) but "
        f"port_ladder.LIFECYCLE_EXCLUSIVE_WIDTH is {pl.LIFECYCLE_EXCLUSIVE_WIDTH} "
        f"— bump the width in port_ladder._LADDER to match")

    shared_merged = {**LIFECYCLE_SHARED_PORTS_WAVES, **LIFECYCLE_SHARED_PORTS_PHASE5}
    shared = _lifecycle_slot_count(shared_merged)
    assert shared == pl.LIFECYCLE_SHARED_WIDTH, (
        f"the shared lifecycle ledger holds {shared} port slot(s) but "
        f"port_ladder.LIFECYCLE_SHARED_WIDTH is {pl.LIFECYCLE_SHARED_WIDTH} "
        f"— bump the width in port_ladder._LADDER to match")


def test_lane_stays_inside_the_ephemeral_safe_window():
    """The whole lane fits within TEST_PORT_START+3000 (the documented budget
    each test port must respect) and inside the valid socket range."""
    assert pl.PORT_COUNT <= 3000, (
        f"the ladder is {pl.PORT_COUNT} ports wide; it must stay within the "
        f"TEST_PORT_START+3000 budget so a relocated lane cannot cross into a "
        f"neighbouring suite's band")
    assert 1024 <= pl.PORT_FIRST <= pl.PORT_LAST <= 65535
