"""Contiguous, relocatable ladder for central Python test infrastructure.

Set ``TEST_PORT_START`` to the number immediately below the first allocated
port.  For example, ``TEST_PORT_START=10000`` allocates 10001..PORT_LAST.

The old values remain beside their owning constants/ledger entries in
``settings.py``, ``fleet_lifecycle_ports.py`` and ``fleet_ports.py``.  They are
the historical ports used while each test was developed; this module only
translates those named allocations onto a compact per-run lane.

## One packed lane, checked against the actual consumers

The offset shards declare ordered category segments. Historical categories
retain explicit offsets, whose contiguity is checked by test_port_ladder.py.
CVMFS takes its width from the consumer's pure catalogue; interoperability
begins immediately after it and PORT_COUNT follows the final category. Adding
a CVMFS block therefore grows the reservation and shifts later allocations
without a second manual width edit. The tests check actual block/matrix ports,
not just a self-consistent but undersized ledger.

Main-only proof lanes may set TEST_MOCK_PORT_WIDTH=0. Their mock allocator
then refuses every draw; full suites retain the default 16384-slot mock band.

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
import subprocess
import sys

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
def configured_mock_width(value):
    """A partial fleet may disable mocks, never allocate outside its ledger."""
    try:
        width = int(value)
    except (TypeError, ValueError) as error:
        raise RuntimeError("TEST_MOCK_PORT_WIDTH must be an integer in 0..16384") from error
    if not 0 <= width <= 16384:
        raise RuntimeError("TEST_MOCK_PORT_WIDTH must be an integer in 0..16384")
    return width


MOCK_PORT_OFFSET = PORT_COUNT
MOCK_PORT_WIDTH = configured_mock_width(os.environ.get("TEST_MOCK_PORT_WIDTH", "16384"))
MOCK_PORT_FIRST = PORT_START + MOCK_PORT_OFFSET + 1
MOCK_PORT_LAST = PORT_START + MOCK_PORT_OFFSET + MOCK_PORT_WIDTH
TOTAL_PORT_COUNT = MOCK_PORT_OFFSET + MOCK_PORT_WIDTH

if not 1024 <= PORT_FIRST <= MOCK_PORT_LAST <= 65535:
    raise ValueError(
        f"TEST_PORT_START={PORT_START} yields invalid test port range "
        f"{PORT_FIRST}..{MOCK_PORT_LAST}; choose a base whose complete "
        f"{TOTAL_PORT_COUNT}-port lane fits within 1024..65535"
    )



EPHEMERAL_RANGE_PATH = "/proc/sys/net/ipv4/ip_local_port_range"


def _parse_port_pair(parts):
    """Return only a complete ascending pair of legal TCP port numbers."""
    try:
        lo, hi = map(int, parts)
    except ValueError:
        return None
    return (lo, hi) if 0 < lo <= hi <= 65535 else None


def _native_ephemeral_range(host):
    """Read the default BSD range, not its optional high-port-only range."""
    if not (host.startswith('freebsd') or host == 'darwin'):
        return None
    utility = '/sbin/sysctl' if host.startswith('freebsd') else '/usr/sbin/sysctl'
    try:
        result = subprocess.run(
            [utility, '-n', 'net.inet.ip.portrange.first',
             'net.inet.ip.portrange.last'], capture_output=True, text=True,
            check=True, timeout=2)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return _parse_port_pair(result.stdout.split())


def read_ephemeral_range(path=EPHEMERAL_RANGE_PATH):
    """The kernel's outbound source-port range, or None when it cannot be read.

    BSD reads its native default range when Linux procfs is absent. None means
    "do not judge" only when neither native interface can establish the range.
    An explicit fixture path never falls back to this host's kernel settings.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            parts = fh.read().split()[:2]
    except (OSError, ValueError):
        return _native_ephemeral_range(sys.platform) if path == EPHEMERAL_RANGE_PATH else None
    return _parse_port_pair(parts)


def _ephemeral_lane_hint(floor, port_count):
    """Never suggest a lower base when even the lowest lane cannot fit."""
    highest = floor - port_count - 1
    if highest < 1024:
        return (f'No supported TEST_PORT_START fits the complete {port_count}-port '
                f'ledger below {floor}; select a smaller explicit test reservation '
                'or reconfigure the default ephemeral range in an isolated test VM.')
    return (f'Choose a base at or below {highest} so the complete {port_count}-port '
            'ledger clears the floor (10000 is the default).')


def check_lane_clears_ephemeral_range(port_start, port_count, ephemeral_range):
    """Raise RuntimeError if the requested listener span reaches outbound ports.

    Pure and fully parameterised so the pins can judge synthetic lanes: the
    module-body call below is the only place that supplies live values.  An
    import-time refusal cannot be exercised by monkeypatching a module constant
    — the check has already run by the time a test can patch — so the decision
    lives here and the module body is the one-line caller.

    The import-time caller includes the full mock reservation. Leases are
    session-unique, not kernel-reserved: even a single mock lease that reaches
    the outbound range can collide with a client socket. A long suite reaches
    thousands of leases without holding them simultaneously.
    """
    if ephemeral_range is None:
        return
    lo, hi = ephemeral_range
    last = port_start + port_count
    if last < lo:
        return
    raise RuntimeError(
        f"TEST_PORT_START={port_start} puts test listener allocations "
        f"{max(port_start + 1, lo)}..{min(last, hi)} inside this host's "
        f"ephemeral port range {lo}..{hi} (kernel default range); the kernel "
        f"hands those numbers to outbound sockets, so binds fail intermittently "
        f"with EADDRINUSE while a socket inspection shows the port free. "
        + _ephemeral_lane_hint(lo, port_count)
    )


# WHY a refusal and not only a lint: tests/test_fleet_ports.py already checks
# the bands against this floor, but a lint fires only for a lane that collects
# that suite, and at a bad base the fleet boot wedges before its assertion is
# ever reached.  Every lane imports the ladder before any server starts.
EPHEMERAL_RANGE = read_ephemeral_range()
check_lane_clears_ephemeral_range(PORT_START, TOTAL_PORT_COUNT, EPHEMERAL_RANGE)


_load_port_ladder_ext(globals(), __file__, "port_ladder_part2.py")
