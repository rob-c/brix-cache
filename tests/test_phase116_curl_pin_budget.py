"""
test_phase116_curl_pin_budget.py — the pinned transfer loop is time-bounded.

WHAT: brix_dns_curl_perform_pinned() (phase-116 amendment 14) performs on a
      libcurl handle it did not create, once per redirect hop.  This suite
      pins that the loop owns a TOTAL wall-clock budget: it bounds every hop
      itself, never hands libcurl a 0 (which means "no timeout"), falls back
      to a non-zero default when the caller names none, and stops the chain
      when the budget is spent instead of starting another hop.
WHY:  tests/test_blocking_curl_bounded.py states the invariant for every
      blocking libcurl site — a perform with no timeout is an unbounded stall
      and therefore a denial-of-service.  This wrapper was the one site that
      relied on its callers for the bound, so a new caller (or a caller that
      dropped its timeout) would have reintroduced the stall silently.
HOW:  A C unit drives the real loop against three local endpoints (a black
      hole, a 302 into that black hole, a prompt 200); the rest is source
      reading, so a missing binary or a busy port ladder cannot hide it.  No
      fleet, no nginx binary.

Run:
    PYTHONPATH=tests pytest tests/test_phase116_curl_pin_budget.py -v
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from cmdscripts.c_regression_units import run_checks

pytestmark = pytest.mark.timeout(120)

REPO = Path(__file__).resolve().parent.parent
PIN_C = REPO / "src" / "net" / "dns" / "curl_pin.c"
PIN_H = REPO / "src" / "net" / "dns" / "curl_pin.h"
WRAPPER = "brix_dns_curl_perform_pinned"


def _bare(text: str) -> str:
    """Source with comments removed: a symbol named in prose is not a call."""
    return re.sub(r"/\*.*?\*/|//[^\n]*", " ", text, flags=re.S)


# --------------------------------------------------------------------------- #
# the loop, driven for real                                                    #
# --------------------------------------------------------------------------- #

def test_c_unit_black_hole_redirect_and_success(tmp_path):
    """(success + error) The shipped loop: a black-holed endpoint times out
    fast, a redirect into one spends the same budget rather than a second copy
    of it, and a prompt answer is unaffected."""
    ok, msg = run_checks(tmp_path, ["dns_curl_pin_budget"])[0]
    assert ok, msg


def test_c_unit_caller_that_names_no_budget_is_still_bounded(tmp_path):
    """(security-neg) The arm that matters most: a caller that sets no timeout
    at all must still be bounded by the default.  Built with a 400 ms default
    so the proof costs a second rather than a minute."""
    ok, msg = run_checks(tmp_path, ["dns_curl_pin_budget_default"])[0]
    assert ok, msg


# --------------------------------------------------------------------------- #
# the properties the unit cannot see                                           #
# --------------------------------------------------------------------------- #

def test_shipped_default_is_a_minute_not_zero():
    """The unit overrides the default to keep itself fast, so the value the
    product actually ships has to be pinned here.  0 would mean 'no timeout'
    to libcurl — the exact defect this amendment removed."""
    m = re.search(r"#define\s+BRIX_DNS_CURL_TIMEOUT_MS_DEFAULT\s+(\d+)",
                  PIN_H.read_text())
    assert m, "the default budget macro is gone"
    assert int(m.group(1)) == 60000


def test_every_hop_is_bounded_by_the_loop_itself():
    """The wrapper sets the bound on the caller's handle each hop; relying on
    the caller to have set CURLOPT_TIMEOUT is what the audit flagged."""
    src = _bare(PIN_C.read_text())
    for opt in ("CURLOPT_TIMEOUT_MS", "CURLOPT_CONNECTTIMEOUT_MS"):
        assert opt in src, f"{opt} no longer set by the pinned loop"
    assert "curl_pin_bound(curl" in src, "the per-hop bound is not applied"


def test_an_exhausted_budget_ends_the_transfer():
    """(error) When nothing is left the loop must return, not perform a hop
    with a 0 timeout — libcurl reads 0 as unlimited."""
    src = _bare(PIN_C.read_text())
    assert "CURLE_OPERATION_TIMEDOUT" in src
    assert re.search(r"left\s*==\s*0", src), \
        "the loop no longer checks the remaining budget before a hop"


def test_the_budget_is_spent_by_libcurls_own_clock():
    """ngx_current_msec does not advance on a thread-pool thread, so a loop
    that measured with it would never see time pass and the total budget would
    silently become per-hop again."""
    src = _bare(PIN_C.read_text())
    assert "CURLINFO_TOTAL_TIME_T" in src
    assert "ngx_current_msec" not in src


@pytest.mark.parametrize("caller", ["src/fs/cache/origin/pelican_register.c"])
def test_every_caller_names_its_own_budget(caller):
    """(security-neg, named regression) A caller may rely on the default, but
    these ones have a policy timeout of their own; dropping it would quietly
    widen their ceiling to a minute."""
    src = _bare((REPO / caller).read_text())
    assert WRAPPER in src
    assert "timeout_ms" in src, f"{caller} stopped naming a transfer budget"


def test_the_caller_census_is_complete():
    """The parametrisation above is a snapshot; a new caller must join it
    rather than inherit the default unnoticed."""
    callers = set()
    for path in (REPO / "src").rglob("*.c"):
        if path == PIN_C:
            continue
        if re.search(re.escape(WRAPPER) + r"\s*\(", _bare(path.read_text())):
            callers.add(str(path.relative_to(REPO)))
    assert callers == {"src/fs/cache/origin/pelican_register.c"}, callers
