"""Per-family exposition-structure grid over a live two-scrape window.

For every one of the catalogued metric families, against a board that has
just absorbed a mixed all-plane traffic burst:

  * HELP comes before TYPE comes before the first sample line;
  * no series (name + exact label set) is emitted twice in one scrape;
  * every sample value parses as a finite float (counters/histograms also
    non-negative);
  * every true counter is monotonic across two traffic-separated scrapes.

Structure tests parametrize over the full catalogue; monotonicity over the
counter subset.  Families without live rows (conditional subsystems) pass
the structure checks on their HELP/TYPE header alone.
"""

import math

import pytest

import _cachemx as cx
import _cachemx_grid as gg
from _cachemx import mx  # noqa: F401
from test_cachemx_catalog import CATALOG, TOTAL_SUFFIX_GAUGES

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

FAMILIES = sorted(CATALOG)
COUNTERS = sorted(f for f, t in CATALOG.items()
                  if t == "counter" and f not in TOTAL_SUFFIX_GAUGES)


@pytest.fixture(scope="module")
def scrapes(mx):
    """burst -> scrape S1 -> burst -> scrape S2 (split into lines)."""
    gg.burst(mx)
    s1 = cx.mfetch(mx.metrics).splitlines()
    gg.burst(mx)
    s2 = cx.mfetch(mx.metrics).splitlines()
    return s1, s2


@pytest.mark.parametrize("family", FAMILIES)
def test_help_type_sample_order(scrapes, family):
    lines = scrapes[1]
    h = gg.first_index(lines, f"# HELP {family} ")
    t = gg.first_index(lines, f"# TYPE {family} ")
    assert h >= 0, f"{family}: HELP missing"
    assert t >= 0, f"{family}: TYPE missing"
    assert h < t, f"{family}: TYPE before HELP"
    firsts = [gg.first_index(lines, c + "{") for c in
              gg.components(family, CATALOG[family])]
    firsts += [gg.first_index(lines, c + " ") for c in
               gg.components(family, CATALOG[family])]
    live = [i for i in firsts if i >= 0]
    if live:
        assert t < min(live), f"{family}: sample precedes TYPE"


@pytest.mark.parametrize("family", FAMILIES)
def test_no_duplicate_series(scrapes, family):
    for lines in scrapes:
        for key, vals in gg.series(lines, family, CATALOG[family]).items():
            assert len(vals) == 1, f"duplicate series {key}"


@pytest.mark.parametrize("family", FAMILIES)
def test_sample_values_finite(scrapes, family):
    typ = CATALOG[family]
    nonneg = typ in ("counter", "histogram")
    for lines in scrapes:
        for key, vals in gg.series(lines, family, typ).items():
            for raw in vals:
                v = float(raw)
                assert math.isfinite(v), f"{key} = {raw}"
                if nonneg:
                    assert v >= 0, f"{key} = {raw} (negative {typ})"


@pytest.mark.parametrize("family", COUNTERS)
def test_counter_monotonic_across_scrapes(scrapes, family):
    s1, s2 = scrapes
    before = {k: float(v[0])
              for k, v in gg.series(s1, family, "counter").items()}
    after = {k: float(v[0])
             for k, v in gg.series(s2, family, "counter").items()}
    for key, v1 in before.items():
        assert key in after, f"{key} vanished between scrapes"
        assert after[key] >= v1, \
            f"{key} decreased: {v1} -> {after[key]}"
