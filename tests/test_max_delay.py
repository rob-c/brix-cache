"""brix_max_delay — the ofs.maxdelay analog (parity audit §1.10).

Every kXR_wait a client can be told flows through ONE emission choke point
(``response/control.c brix_send_wait``); ``brix_max_delay`` clamps the seconds
there (cached in ctx at accept, like the phase-39 deadlines). Default 60 —
stock ofs.maxdelay's default — so a misconfigured or hostile-length stall can
never park a stock client for minutes; 0 disables the clamp entirely.

The observable wait here is the §2.2 CMS SUPCount floor hold
(``brix_cms_delay_hold``), whose configured value the redirector answers as
kXR_wait seconds — asking for 120 s makes the clamp visible in one probe.
Harness: the CMS parity-wave manager template + helpers (same xdist_group, so
the shared ``lc-cms-parity-mgr`` spec/port stays serialised).

Coverage (the change-class trio):
  * success      — default: a 120 s hold is answered as 60 (stock clamp), and
                   an under-clamp 3 s hold passes through untouched.
  * error        — brix_max_delay 10: the same hold answers 10 — the hold
                   still functions (status stays kXR_wait), only the seconds
                   are clamped.
  * security-neg — brix_max_delay 0 DISABLES the clamp (full 120 answered):
                   0 must never mean "clamp to 0", which would turn every
                   stall into a client busy-loop.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_max_delay.py -v
"""

from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_parity_wave_helpers")


def _held_seconds(port, path):
    """One locate that must be answered kXR_wait; returns the wait seconds."""
    status, body = _locate(port, path)
    assert status == kXR_wait, f"expected kXR_wait below the floor: {status}"
    assert len(body) >= 4, f"kXR_wait body too short: {body!r}"
    return struct.unpack(">i", body[:4])[0]


def test_default_clamps_long_hold_to_stock_60(lifecycle):
    """(success) default brix_max_delay: a 120 s floor hold is clamped to the
    stock 60."""
    root_port, _cms = _mgr(lifecycle, "lc-cms-parity-mgr",
        "brix_cms_delay_servers 2; brix_cms_delay_hold 120;",
        "§1.10 maxdelay: default clamps a 120s hold")
    assert _held_seconds(root_port, "/md.dat") == 60


def test_default_passes_short_hold_untouched(lifecycle):
    """(success) an under-clamp hold (3 s) is not altered by the default."""
    root_port, _cms = _mgr(lifecycle, "lc-cms-parity-mgr",
        "brix_cms_delay_servers 2; brix_cms_delay_hold 3;",
        "§1.10 maxdelay: short hold passes through")
    assert _held_seconds(root_port, "/md.dat") == 3


def test_configured_clamp_applies(lifecycle):
    """(error) brix_max_delay 10: the hold still fires (kXR_wait), only the
    seconds are clamped to the configured cap."""
    root_port, _cms = _mgr(lifecycle, "lc-cms-parity-mgr",
        "brix_cms_delay_servers 2; brix_cms_delay_hold 120; "
        "brix_max_delay 10;",
        "§1.10 maxdelay: explicit 10s clamp")
    assert _held_seconds(root_port, "/md.dat") == 10


def test_zero_disables_clamp(lifecycle):
    """(security-neg) brix_max_delay 0 disables clamping — the full 120 is
    answered. 0 must never mean "clamp to 0" (a zero-second kXR_wait would
    turn every stall into a client busy-loop)."""
    root_port, _cms = _mgr(lifecycle, "lc-cms-parity-mgr",
        "brix_cms_delay_servers 2; brix_cms_delay_hold 120; "
        "brix_max_delay 0;",
        "§1.10 maxdelay: 0 = unclamped")
    assert _held_seconds(root_port, "/md.dat") == 120
