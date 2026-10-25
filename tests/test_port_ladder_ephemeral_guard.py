"""PREPARED — tests/test_port_ladder_ephemeral_guard.py, apply with the patch.

WHAT: the ladder refuses, at import, a lane whose FIXED listens fall inside the
      kernel's outbound port range, and stays silent when it cannot know.
WHY:  `tests/test_fleet_ports.py:291-308` lints the same floor and is this
      guard's sibling, not its duplicate — it judges each band, this judges the
      lane. A lint only fires for a lane that collects it, and at a bad base the
      fleet boot wedges before its assertion is reached (measured 2026-09-07: a
      base-42000 run of that suite never reported, and the lane died on
      bind() 43202 instead).
HOW:  the decision is a pure function, so synthetic lanes are judged directly
      with an explicit range and no dependence on this host; one subprocess pin
      proves the module body really calls it at import.  Every port number is
      derived from the live ladder constants — a repack moves PORT_COUNT (2393
      → 2395 on 2026-09-07 alone), so a literal here would red on the next one.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

import port_ladder as pl

# A synthetic floor for the pure-function pins: fixed so the arithmetic is
# host-independent, and deliberately NOT read from this machine's sysctl.
FLOOR, CEILING = 32768, 60999
RANGE = (FLOOR, CEILING)


def _last_legal_base(count=None):
    """Highest base whose complete named and mock reservation clears FLOOR."""
    return FLOOR - (pl.TOTAL_PORT_COUNT if count is None else count) - 1


def test_the_live_lane_clears_the_ephemeral_range():
    """The base this run is using must itself be legal — the guard's own lane."""
    pl.check_lane_clears_ephemeral_range(pl.PORT_START, pl.TOTAL_PORT_COUNT,
                                         pl.EPHEMERAL_RANGE)


@pytest.mark.parametrize("base", [2000, 10000])
def test_the_documented_bases_are_accepted(base):
    """The two bases the peers actually run, judged against a synthetic range."""
    assert base <= _last_legal_base()
    pl.check_lane_clears_ephemeral_range(base, pl.TOTAL_PORT_COUNT, RANGE)


def test_a_lane_inside_the_range_is_refused():
    """Base 42000 is the measured failure: all of its named ledger is inside."""
    with pytest.raises(RuntimeError, match="ephemeral port range"):
        pl.check_lane_clears_ephemeral_range(42000, pl.PORT_COUNT, RANGE)


def test_the_boundary_is_the_floor_not_the_span():
    """A lane ending one port below the floor is legal; touching it is not.

    This is the distinction the guard exists to make, and both sides are
    computed from PORT_COUNT so a repack cannot falsify them.
    """
    legal = _last_legal_base()
    pl.check_lane_clears_ephemeral_range(legal, pl.TOTAL_PORT_COUNT, RANGE)
    assert legal + pl.TOTAL_PORT_COUNT == FLOOR - 1
    with pytest.raises(RuntimeError):
        pl.check_lane_clears_ephemeral_range(legal + 1, pl.TOTAL_PORT_COUNT, RANGE)


def test_the_mock_window_cannot_overlap_outbound_connections():
    """Named listens alone can be safe while later mock leases still collide."""
    base = _last_legal_base(pl.PORT_COUNT)
    assert base + pl.MOCK_PORT_OFFSET + pl.MOCK_PORT_WIDTH > FLOOR, "mock window must cross"
    with pytest.raises(RuntimeError, match="complete"):
        pl.check_lane_clears_ephemeral_range(base, pl.TOTAL_PORT_COUNT, RANGE)


def test_the_message_suggests_a_base_that_is_itself_accepted():
    """A refusal that hands back an illegal base would send the reader in circles."""
    with pytest.raises(RuntimeError) as excinfo:
        pl.check_lane_clears_ephemeral_range(42000, pl.TOTAL_PORT_COUNT, RANGE)
    suggested = int(str(excinfo.value).split("at or below ")[1].split(" ")[0])
    assert suggested == _last_legal_base()
    pl.check_lane_clears_ephemeral_range(suggested, pl.TOTAL_PORT_COUNT, RANGE)


def test_an_unknown_range_never_refuses():
    """No sysctl (container, non-Linux) must still import and collect."""
    pl.check_lane_clears_ephemeral_range(42000, pl.PORT_COUNT, None)


def test_no_legal_lane_never_suggests_another_overlapping_base():
    with pytest.raises(RuntimeError) as error:
        pl.check_lane_clears_ephemeral_range(1024, 16384, (10000, 65535))
    assert 'No supported TEST_PORT_START fits' in str(error.value)
    assert 'at or below 1024' not in str(error.value)


@pytest.mark.parametrize("text", ["not a range", "", "60999 32768", "0 0", "1 99999"])
def test_an_unreadable_sysctl_reads_as_unknown(tmp_path, text):
    """A broken sysctl must never block a lane — same rule as the DNS seam."""
    path = tmp_path / "range"
    path.write_text(text, encoding="utf-8")
    assert pl.read_ephemeral_range(str(path)) is None


def test_the_reader_parses_a_real_pair(tmp_path):
    """Proven against a stub, so the guard is known to read the file."""
    path = tmp_path / "range"
    path.write_text("11000 12000\n", encoding="utf-8")
    assert pl.read_ephemeral_range(str(path)) == (11000, 12000)


def test_a_missing_sysctl_reads_as_unknown(tmp_path):
    assert pl.read_ephemeral_range(str(tmp_path / "absent")) is None


@pytest.mark.parametrize('host,utility', [('freebsd15', '/sbin/sysctl'),
                                       ('darwin', '/usr/sbin/sysctl')])
def test_native_range_uses_default_not_high_port_bounds(monkeypatch, host, utility):
    calls = []

    def native(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout='10000\n65535\n', stderr='')

    monkeypatch.setattr(pl.subprocess, 'run', native)
    assert pl._native_ephemeral_range(host) == (10000, 65535)
    assert calls[0][0] == [utility, '-n', 'net.inet.ip.portrange.first',
                          'net.inet.ip.portrange.last']
    assert calls[0][1]['timeout'] == 2 and calls[0][1]['check'] is True
    with pytest.raises(RuntimeError, match='ephemeral port range'):
        pl.check_lane_clears_ephemeral_range(10000, pl.TOTAL_PORT_COUNT, (10000, 65535))


@pytest.mark.parametrize('output', ['', 'broken', '65535 10000', '0 65535', '32768 65536'])
def test_malformed_native_range_cannot_authorize_a_false_floor(monkeypatch, output):
    monkeypatch.setattr(pl.subprocess, 'run', lambda argv, **kwargs:
                        subprocess.CompletedProcess(argv, 0, stdout=output, stderr=''))
    assert pl._native_ephemeral_range('freebsd15') is None


def test_native_range_permission_failure_is_unknown_not_a_fabricated_default(monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError('injected unreadable kernel settings')

    monkeypatch.setattr(pl.subprocess, 'run', denied)
    assert pl._native_ephemeral_range('freebsd15') is None


def test_the_refusal_fires_at_import_before_any_server_starts():
    """The whole point of promoting the lint: no fleet boot precedes it.

    A bare interpreter importing the ladder with a bad base must fail, which is
    what the fleet-boot wedge prevented the existing band lint from ever doing.
    """
    if pl.EPHEMERAL_RANGE is None:
        pytest.skip("host outbound port range is unknown; synthetic refusal covered above")
    proc = subprocess.run(
        [sys.executable, "-c", "import port_ladder"],
        env={"TEST_PORT_START": str(pl.EPHEMERAL_RANGE[0]), "PATH": "/usr/bin:/bin",
             "TEST_MOCK_PORT_WIDTH": "0",
             "PYTHONPATH": str(pl.__file__).rsplit("/", 1)[0]},
        capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode != 0, proc.stdout
    assert "ephemeral port range" in proc.stderr, proc.stderr
