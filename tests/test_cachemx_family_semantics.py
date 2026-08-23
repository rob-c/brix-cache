"""Per-family label-value conformance + histogram-structure invariants.

Runs against one scrape taken after a mixed all-plane burst.  Every family
in the catalogue gets a label-value well-formedness check: pinned keys
(port, le, status_class, hash, depth) must match tight grammars, enum-like
keys must be short identifier-shaped tokens, everything else printable
ASCII with no edge whitespace.  Every histogram family gets three
invariant checks over its live rows: cumulative buckets non-decreasing
with le ascending (+Inf last), the +Inf bucket equal to _count for the
same base label set, and _sum finite and non-negative.
"""

import math
import re

import pytest

import _cachemx as cx
import _cachemx_grid as gg
from _cachemx import mx  # noqa: F401
from test_cachemx_catalog import CATALOG

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

FAMILIES = sorted(CATALOG)
HISTOGRAMS = sorted(f for f, t in CATALOG.items() if t == "histogram")

TIGHT = {
    "port": re.compile(r"^[0-9]{2,5}$"),
    "le": re.compile(r"^(\+Inf|[0-9]*\.?[0-9]+(e[+-]?[0-9]+)?)$"),
    "status_class": re.compile(r"^([1-5]xx|other)$"),
    "hash": re.compile(r"^[0-9a-f]{8}$"),
    "depth": re.compile(r"^(0|1|infinity)$"),
}
ENUM_KEYS = {"op", "status", "method", "proto", "auth", "result", "state",
             "source", "class", "signal", "flavor", "reason", "kind"}
ENUM_SHAPE = re.compile(r"^[A-Za-z0-9_+.-]{1,64}$")
PRINTABLE = re.compile(r"^[\x20-\x7e]{1,256}$")
EMPTY_ALLOWED = {("brix_storage_backend_info", "origin")}


@pytest.fixture(scope="module")
def scrape(mx):
    gg.burst(mx)
    return cx.mfetch(mx.metrics).splitlines()


@pytest.mark.parametrize("family", FAMILIES)
def test_label_values_well_formed(scrape, family):
    for key in gg.series(scrape, family, CATALOG[family]):
        _assert_series_labels(key, family)


def _assert_series_labels(series_key, family):
    block = series_key[series_key.index("{"):] if "{" in series_key else ""
    for label, value in gg.label_pairs(block):
        _assert_label_value(series_key, family, label, value)


def _assert_label_value(series_key, family, label, value):
    if not value:
        assert (family, label) in EMPTY_ALLOWED, \
            f"{series_key}: empty value for label {label}"
        return
    if label in TIGHT:
        assert TIGHT[label].match(value), f"{series_key}: {label}={value!r}"
        return
    if label in ENUM_KEYS:
        assert ENUM_SHAPE.match(value), f"{series_key}: {label}={value!r}"
        return
    assert PRINTABLE.match(value), f"{series_key}: {label}={value!r}"
    assert value == value.strip(), \
        f"{series_key}: {label}={value!r} edge whitespace"


def _hist_rows(scrape, family):
    """{base-labelset-tuple: {'buckets': [(le, val)], 'count': v, 'sum': v}}"""
    out = {}
    for key, vals in gg.series(scrape, family, "histogram").items():
        _add_histogram_row(out, key, vals)
    return out


def _histogram_base(pairs):
    return tuple(sorted((key, value) for key, value in pairs if key != "le"))


def _bucket_limit(value):
    return math.inf if value == "+Inf" else float(value)


def _add_histogram_row(rows, series_key, values):
    name = series_key.split("{", 1)[0]
    block = series_key[series_key.index("{"):] if "{" in series_key else ""
    pairs = gg.label_pairs(block)
    slot = rows.setdefault(
        _histogram_base(pairs), {"buckets": [], "count": None, "sum": None})
    value = float(values[0])
    if name.endswith("_bucket"):
        slot["buckets"].append((_bucket_limit(dict(pairs)["le"]), value))
        return
    if name.endswith("_count"):
        slot["count"] = value
        return
    if name.endswith("_sum"):
        slot["sum"] = value


@pytest.mark.parametrize("family", HISTOGRAMS)
def test_histogram_buckets_cumulative(scrape, family):
    for base, slot in _hist_rows(scrape, family).items():
        bks = slot["buckets"]
        assert bks, f"{family}{dict(base)}: no buckets"
        les = [le for le, _ in bks]
        assert les == sorted(les), f"{family}{dict(base)}: le out of order"
        assert les[-1] == math.inf, f"{family}{dict(base)}: no +Inf bucket"
        vals = [v for _, v in bks]
        assert vals == sorted(vals), \
            f"{family}{dict(base)}: buckets not cumulative {vals}"


@pytest.mark.parametrize("family", HISTOGRAMS)
def test_histogram_inf_equals_count(scrape, family):
    for base, slot in _hist_rows(scrape, family).items():
        assert slot["count"] is not None, f"{family}{dict(base)}: no _count"
        inf = [v for le, v in slot["buckets"] if le == math.inf]
        assert inf and inf[0] == slot["count"], \
            f"{family}{dict(base)}: +Inf {inf} != _count {slot['count']}"


@pytest.mark.parametrize("family", HISTOGRAMS)
def test_histogram_sum_sane(scrape, family):
    for base, slot in _hist_rows(scrape, family).items():
        assert slot["sum"] is not None, f"{family}{dict(base)}: no _sum"
        assert math.isfinite(slot["sum"]) and slot["sum"] >= 0, \
            f"{family}{dict(base)}: _sum {slot['sum']}"
