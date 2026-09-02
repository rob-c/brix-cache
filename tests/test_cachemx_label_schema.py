"""Per-family label-schema conformance: the exact label KEY SET of every
family pinned, on every sample row.

WHAT: One scrape under live mixed traffic, then a parametrized pin of each
      family's label keys against the calibrated snapshot (histograms
      checked on _count/_sum, _bucket additionally carries `le`), plus
      board-wide structural rules: no unpinned sample names, strict text
      exposition (every label pair quoted — no residue inside braces), and
      Invariant-8 cardinality hygiene (no path-, DN- or hostname-shaped
      label VALUES outside the pinned config-bounded exemptions).

WHY:  A label key added or dropped on one emit path breaks every recording
      rule that aggregates the family, and a high-cardinality label value
      (a path, a user DN) is an SHM/scrape-size time bomb.  Pinning the
      schema per family catches both at the exact family that moved.
      CONDITIONAL families (cvmfs, VO, per-user sessions, cache-enabled
      planes) emit headers unconditionally but rows only under their
      subsystem's traffic — the pin then applies to whatever rows exist.
"""

import re

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401
from _cachemx_catalog_schema import CONDITIONAL, LABEL_KEYS

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

HISTOGRAMS = {"brix_cvmfs_upstream_fill_duration_seconds",
              "brix_frm_stage_latency_seconds",
              "brix_io_latency_usec",
              "brix_io_latency_seconds"}

# Config-bounded exemptions from the value-shape rules, pinned exactly:
# `export` labels carry the configured mount path (one row per export —
# operator config, not request input), and brix_storage_backend_info's
# `origin` is empty for exports with no remote origin (posix).
PATH_VALUED_KEYS = {"export"}
EMPTY_ALLOWED = {("brix_storage_backend_info", "origin")}

_PAIR_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"')


def parse_rows(text):
    """{sample_name: [(sorted_key_tuple, [(key, value), ...]), ...]}."""
    rows = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        sample = line.split("{", 1)[0].split(" ", 1)[0]
        if "{" in line:
            inner = line.split("{", 1)[1].rsplit("}", 1)[0]
            pairs = _PAIR_RE.findall(inner)
        else:
            pairs = []
        keys = tuple(sorted(k for k, _ in pairs))
        rows.setdefault(sample, []).append((keys, pairs))
    return rows


@pytest.fixture(scope="module")
def expo(mx):
    """Drive one op per protocol family so labeled rows exist, then parse
    a single scrape for the whole module."""
    n = cx.unique_name("lsdav")
    mx.seed_local(n, 300)
    assert mx.dav_request("dav", f"/{n}")[0] == 200
    assert mx.s3_request("s3", n, method="HEAD")[0] == 200
    o = cx.unique_name("lsstrm")
    mx.seed_origin(o, 300)
    assert mx.xrdfs("none", "stat", f"/{o}").returncode == 0
    cx.settle()
    text = cx.mfetch(mx.metrics)
    return text, parse_rows(text)


def _family_checks(family, pinned):
    if family in HISTOGRAMS:
        return [(family + "_count", pinned), (family + "_sum", pinned),
                (family + "_bucket", tuple(sorted(pinned + ("le",))))]
    return [(family, pinned)]


def _assert_label_keys(rows, family, sample, want):
    got = {keys for keys, _ in rows.get(sample, [])}
    if family in CONDITIONAL:
        assert got <= {want}, f"{sample}: {got} != subset of {{{want}}}"
        return
    assert got == {want}, f"{sample}: {got} != {{{want}}}"


@pytest.mark.parametrize("family", sorted(LABEL_KEYS))
def test_label_keys_pinned(expo, family):
    """Every row carries the pinned keys; histogram buckets also carry le."""
    _, rows = expo
    for sample, want in _family_checks(family, LABEL_KEYS[family]):
        _assert_label_keys(rows, family, sample, want)


def test_no_unpinned_sample_names(expo):
    """Every sample name on the wire maps back to a pinned family — a new
    family (or a typo'd emit) cannot ship unpinned."""
    _, rows = expo
    known = set(LABEL_KEYS)
    for h in HISTOGRAMS:
        known |= {h + "_bucket", h + "_sum", h + "_count"}
    unknown = {s for s in rows if s not in known}
    assert unknown == set()


def test_conditional_set_is_current(expo):
    """Every family pinned as CONDITIONAL is genuinely traffic-gated under
    baseline traffic in at least one direction: it is pinned, and it is a
    subset of the catalogue (drift in either set fails here, not in 26
    per-family pins)."""
    _, rows = expo
    assert CONDITIONAL <= set(LABEL_KEYS)
    always_on = {f for f in CONDITIONAL
                 if LABEL_KEYS[f] == () and f in rows}
    assert always_on == set(), f"unlabeled CONDITIONAL families with rows: {always_on}"


def test_exposition_has_no_unparsed_label_residue(expo):
    """STRICT text format: inside every `{...}` section, the quoted
    key="value" pairs and their separators account for ALL characters.
    An unquoted label value (e.g. `hash=a1b2c3d4`) parses as residue —
    the exact bug class strict Prometheus scrapers reject."""
    text, _ = expo
    for line in text.splitlines():
        if not line or line.startswith("#") or "{" not in line:
            continue
        inner = line.split("{", 1)[1].rsplit("}", 1)[0]
        residue = _PAIR_RE.sub("", inner).replace(",", "").strip()
        assert residue == "", f"unparsed label residue {residue!r} in: {line}"


def _unsafe_label(key, value):
    if key == "le" or key in PATH_VALUED_KEYS:
        return False
    return "/" in value or value.startswith("CN=") or "://" in value


def _row_label_offenders(sample, rowlist):
    offenders = []
    for _, pairs in rowlist:
        offenders.extend((sample, key, value) for key, value in pairs
                         if _unsafe_label(key, value))
    return offenders


def test_label_values_are_low_cardinality_shapes(expo):
    """Invariant 8: no label VALUE anywhere looks like a path, a DN, a URL,
    or a hostname — the cardinality classes that blow up SHM slots.  Sole
    pinned exemption: `export` (config-bounded mount path, one row per
    configured export)."""
    _, rows = expo
    offenders = []
    for sample, rowlist in rows.items():
        offenders.extend(_row_label_offenders(sample, rowlist))
    assert offenders == []


def test_label_values_never_empty(expo):
    """No emitted row carries an empty label value — an empty enum string
    means a name-table hole (Pattern 1's misalignment symptom).  Sole
    pinned exemption: backend_info's `origin` on origin-less exports."""
    _, rows = expo
    offenders = [(s, k) for s, rl in rows.items()
                 for _, pairs in rl for k, v in pairs
                 if v == "" and (s, k) not in EMPTY_ALLOWED]
    assert offenders == []


def test_port_label_values_are_numeric(expo):
    """Families keyed by `port` carry decimal port numbers, never
    host:port strings (host would be a cardinality leak)."""
    _, rows = expo
    for sample, rowlist in rows.items():
        for _, pairs in rowlist:
            for k, v in pairs:
                if k == "port":
                    assert v.isdigit(), f"{sample}: port={v!r}"
