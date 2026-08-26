"""Contiguous, relocatable ladder for central Python test infrastructure.

Set ``TEST_PORT_START`` to the number immediately below the first allocated
port.  For example, ``TEST_PORT_START=10000`` allocates 10001..PORT_LAST.

The old values remain beside their owning constants/ledger entries in
``settings.py``, ``fleet_lifecycle_ports.py`` and ``fleet_ports.py``.  They are
the historical ports used while each test was developed; this module only
translates those named allocations onto a compact per-run lane.

## One packed lane, zero overlaps — BY CONSTRUCTION

The lane is carved into ordered category *segments* declared in ``_LADDER`` as
``(name, width)``.  Segment OFFSETS ARE DERIVED cumulatively (``_build_ladder``),
so the lane is always contiguous with zero gaps AND zero overlaps: bump a width
and every later segment shifts automatically — there is no hand-maintained offset
to edit into an overlap, and ``PORT_COUNT`` is simply the sum of the widths.  A
category that adds a test server bumps ONLY its own width.  ``tests/
test_port_ladder.py`` asserts this so a future edit that breaks it fails loudly.

Width history (each bump = a test subject added; the ladder is packed, so a width
change is an intentional compatibility event):
  LIFECYCLE_SHARED  523 -> ... -> 550: CMS parity + HTTP redirect + pmark-s3 +
    parity-fix waves 3-16 (multipath, dirlist, chkpnt, tpc-markers, prepflags,
    cache-evict, ztn-maxsz, oss-maxsize, html-listing, oss-cgroup, fsoverload,
    qspace ×4, cms-wire-minfree, slowop+METRICS_PORT).
  LIFECYCLE_EXCLUSIVE 137 -> 140 -> 141: audit-fix onlyifcached/coldpurge/signing
    (2026-08-09); +cache-uvkeep §4.3 (2026-08-10).
"""

from __future__ import annotations

import os

PORT_START = int(os.environ.get("TEST_PORT_START", "10000"))


from split_continuation import load as _load_port_ladder_ext
_load_port_ladder_ext(globals(), __file__, "port_ladder_offsets.py")

PORT_FIRST = PORT_START + 1
PORT_LAST = PORT_START + PORT_COUNT

# Python mock listeners and differential upstreams are not registry servers,
# but they still must not ask the kernel to choose a port.  They receive slots
# from this session-shared range through ``ephemeral_port.free_port`` (kept as
# a compatibility spelling).  Keeping this pool after the named ledger means
# the full range is still controlled by TEST_PORT_START while static ledger
# checks retain their exact, contiguous PORT_FIRST..PORT_LAST contract.
MOCK_PORT_OFFSET, MOCK_PORT_WIDTH = PORT_COUNT, 16384
MOCK_PORT_FIRST = PORT_START + MOCK_PORT_OFFSET + 1
MOCK_PORT_LAST = PORT_START + MOCK_PORT_OFFSET + MOCK_PORT_WIDTH
TOTAL_PORT_COUNT = MOCK_PORT_OFFSET + MOCK_PORT_WIDTH

if not 1024 <= PORT_FIRST <= MOCK_PORT_LAST <= 65535:
    raise ValueError(
        f"TEST_PORT_START={PORT_START} yields invalid test port range "
        f"{PORT_FIRST}..{MOCK_PORT_LAST}; choose a base whose complete "
        f"{TOTAL_PORT_COUNT}-port lane fits within 1024..65535"
    )


_load_port_ladder_ext(globals(), __file__, "port_ladder_part2.py")
