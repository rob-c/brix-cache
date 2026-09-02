"""Prometheus exposition-format conformance for the BriX-Cache /metrics
endpoint (cachemx suite).

WHAT: Wire-format and family-catalogue assertions against the multi-plane
      matrix instance: content type, HELP/TYPE presence, label-set schemas,
      histogram internal consistency, counter monotonicity, sample uniqueness
      and the value-grammar of every exported line.

WHY:  The accuracy suites (stream/http/s3) assert COUNTS; this file asserts
      that the exposition itself is well-formed enough for a real Prometheus
      scraper to ingest, and that the family catalogue the dashboards depend
      on cannot silently vanish or change label schema.
"""

import re

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401  (module-scoped origin+matrix stack)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

# Families that must always be exported by a cache matrix instance, with the
# exact label keys every sample of the family must carry ([] = unlabelled).
FAMILY_SCHEMA = {
    "brix_connections_total": ["port", "auth"],
    "brix_bytes_rx_total": ["port", "auth"],
    "brix_bytes_tx_total": ["port", "auth"],
    "brix_bytes_root_rx_total": ["port", "auth"],
    "brix_bytes_root_tx_total": ["port", "auth"],
    "brix_wire_bytes_rx_total": ["port", "auth"],
    "brix_wire_bytes_tx_total": ["port", "auth"],
    "brix_requests_total": ["port", "auth", "op", "status"],
    "brix_io_bytes_read": ["proto"],
    "brix_io_bytes_written": ["proto"],
    "brix_io_ops_total": ["proto", "op", "status"],
    "brix_cache_hits_total": ["proto"],
    "brix_cache_misses_total": ["proto"],
    "brix_cache_requests_total": ["proto", "cache_status"],
    "brix_cache_bytes_evicted_total": ["proto"],
    "brix_cache_watermark_purges_total": [],
    "brix_cache_watermark_evicted_files_total": [],
    "brix_cache_watermark_evicted_bytes_total": [],
    "brix_cache_usage_ratio": [],
    "brix_auth_total": ["proto", "method", "status"],
    "brix_cred_select_user_total": ["proto"],
    "brix_cred_select_fallback_total": ["proto"],
    "brix_cred_select_deny_total": ["proto"],
    "brix_webdav_requests_total": ["method"],
    "brix_webdav_responses_total": ["method", "status_class"],
    "brix_webdav_auth_total": ["result"],
    "brix_webdav_bytes_rx_total": [],
    "brix_webdav_bytes_tx_total": [],
    "brix_webdav_range_requests_total": ["result"],
    "brix_webdav_put_bodies_total": ["mode"],
    "brix_webdav_propfind_depth_total": ["depth"],
    "brix_s3_requests_total": ["method"],
    "brix_s3_responses_total": ["method", "status_class"],
    "brix_s3_auth_total": ["result"],
    "brix_s3_bytes_rx_total": [],
    "brix_s3_bytes_tx_total": [],
    "brix_s3_range_requests_total": ["result"],
    "brix_s3_put_bodies_total": ["mode"],
    "brix_s3_events_total": ["event"],
    "brix_cluster_servers_registered": [],
    "brix_storage_backend_info": ["export", "backend", "origin", "auth",
                                 "staging"],
}

IO_PROTOS = {"stream", "webdav", "s3", "cvmfs", "gridftp", "oci", "rpm"}
IO_OPS = {"read", "write", "stat", "delete", "mkdir", "rename", "dirlist",
          "tpc", "xattr", "copy"}
IO_STATUSES = {"ok", "not_found", "forbidden", "io_error", "other"}
S3_AUTH_RESULTS = {"anonymous", "sigv4_ok", "missing", "malformed",
                   "bad_access_key", "bad_date", "signature_mismatch",
                   "internal_error"}

SAMPLE_RE = re.compile(
    r'^([a-zA-Z_:][a-zA-Z0-9_:]*)'          # metric name
    r'(\{[^{}]*\})?'                          # optional label set
    r' '
    r'(-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?|\+Inf|-Inf|NaN)$')
LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"')


def parse_samples(text):
    """-> list of (name, {label: value}, float) for every sample line."""
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = SAMPLE_RE.match(line)
        assert m, f"malformed exposition line: {line!r}"
        labels = dict(LABEL_RE.findall(m.group(2) or ""))
        out.append((m.group(1), labels, float(m.group(3))))
    return out


@pytest.fixture(scope="module")
def scrape(mx):
    return cx.mfetch(mx.metrics)


# -- endpoint semantics ------------------------------------------------------

def test_metrics_get_ok(mx):
    st, body, hdrs = cx.http_request(mx.metrics)
    assert st == 200
    assert body


def test_cache_requests_carries_the_neghit_series(mx):
    """(phase-110 W10) The unified cache family emits a NEGHIT disposition series
    per protocol — so a fleet-wide negative-hit rate is one query, not cvmfs's
    private negative_hits_total. HIT and MISS series are already present; NEGHIT
    is the W10 addition that completes the shared cache vocabulary on the metric
    surface."""
    st, body, _ = cx.http_request(mx.metrics)
    assert st == 200
    text = body.decode(errors="replace") if isinstance(body, bytes) else body
    assert 'brix_cache_requests_total{' in text, "cache family missing"
    assert 'cache_status="NEGHIT"' in text, (
        "brix_cache_requests_total has no NEGHIT series (phase-110 W10 "
        "unification of the negative-cache disposition)")
    # And the vocabulary is complete: HIT and MISS series coexist.
    for disp in ('HIT', 'MISS', 'NEGHIT'):
        assert f'cache_status="{disp}"' in text, disp


def test_latency_family_is_in_seconds(mx):
    """(phase-110 W11) The canonical latency histogram is brix_io_latency_seconds
    (the uniform latency unit — Prometheus `_seconds`), emitted alongside the
    DEPRECATED brix_io_latency_usec for the removal window. So every latency
    histogram (io + cvmfs + frm) carries the `_seconds` suffix."""
    st, body, _ = cx.http_request(mx.metrics)
    assert st == 200
    text = body.decode(errors="replace") if isinstance(body, bytes) else body
    assert "brix_io_latency_seconds_bucket{" in text, "no seconds histogram"
    assert "brix_io_latency_seconds_count{" in text
    # deprecated µs family still present for the window.
    assert "brix_io_latency_usec_bucket{" in text
    # the seconds `le` values are fractional (µs bounds / 1e6): a bucket <= 1s.
    assert 'le="0.001000"' in text or 'le="0.005000"' in text, (
        "seconds histogram le values are not scaled to seconds")


def test_metrics_content_type(mx):
    _, _, hdrs = cx.http_request(mx.metrics)
    ctype = {k.lower(): v for k, v in hdrs.items()}.get("content-type")
    assert ctype == "text/plain; version=0.0.4; charset=utf-8"


def test_metrics_post_rejected(mx):
    st, _, _ = cx.http_request(mx.metrics, method="POST", data=b"x")
    assert st == 405


def test_metrics_head_ok(mx):
    st, body, _ = cx.http_request(mx.metrics, method="HEAD")
    assert st == 200
    assert body == b""


def test_metrics_scrape_is_complete_families(scrape):
    # A scrape must terminate cleanly: last line is a full sample/comment,
    # not a truncated fragment.
    assert scrape.endswith("\n")


def test_help_and_type_counts_match(scrape):
    """Every family gets exactly one HELP and one TYPE comment."""
    helps = _comment_families(scrape, "# HELP ")
    types = _comment_families(scrape, "# TYPE ")
    assert len(helps) == len(set(helps)), "duplicate HELP lines"
    assert sorted(helps) == sorted(types)
    assert len(helps) >= 190     # full family catalogue compiled in


def _comment_families(scrape, prefix):
    return [line.split()[2] for line in scrape.splitlines()
            if line.startswith(prefix)]


# -- family catalogue --------------------------------------------------------

@pytest.mark.parametrize("family", sorted(FAMILY_SCHEMA))
def test_family_has_help_and_type(scrape, family):
    assert f"# HELP {family} " in scrape, f"{family}: HELP line missing"
    assert f"# TYPE {family} " in scrape, f"{family}: TYPE line missing"


@pytest.mark.parametrize("family,keys",
                         sorted((f, k) for f, k in FAMILY_SCHEMA.items()))
def test_family_label_schema(scrape, family, keys):
    """Every exported sample of the family carries exactly the schema keys."""
    rows = [s for s in parse_samples(scrape) if s[0] == family]
    for _, labels, _ in rows:
        assert set(labels) == set(keys), (
            f"{family}: label keys {sorted(labels)} != schema {sorted(keys)}")


def test_unset_threshold_family_has_no_samples(scrape):
    """brix_cache_eviction_threshold_ratio: HELP/TYPE render, but a matrix
    with no eviction threshold configured exports NO sample row (absent, not
    0.0 — a scraper must be able to distinguish unset from zero)."""
    assert "# TYPE brix_cache_eviction_threshold_ratio gauge" in scrape
    assert not [s for s in parse_samples(scrape)
                if s[0] == "brix_cache_eviction_threshold_ratio"]


# -- value grammar -----------------------------------------------------------

def test_every_sample_line_parses(scrape):
    parse_samples(scrape)   # parse asserts per line


def test_no_duplicate_samples(scrape):
    seen = set()
    for name, labels, _ in parse_samples(scrape):
        key = (name, tuple(sorted(labels.items())))
        assert key not in seen, f"duplicate sample {key}"
        seen.add(key)


def test_counters_are_non_negative(scrape):
    for name, labels, v in parse_samples(scrape):
        if name.endswith("_total"):
            assert v >= 0, f"{name}{labels} negative: {v}"


@pytest.mark.parametrize("ratio", ["brix_cache_usage_ratio",
                                   "brix_storage_occupancy_ratio",
                                   "brix_wt_stage_usage_ratio"])
def test_ratio_gauges_bounded(scrape, ratio):
    for name, labels, v in parse_samples(scrape):
        if name == ratio:
            assert 0.0 <= v <= 1.0, f"{name}{labels} out of [0,1]: {v}"


# -- io_ops label-value conformance (low-cardinality invariant 8) ------------

def test_io_ops_label_values_conform(scrape):
    for name, labels, _ in parse_samples(scrape):
        if name != "brix_io_ops_total":
            continue
        assert labels["proto"] in IO_PROTOS, labels
        assert labels["op"] in IO_OPS, labels
        assert labels["status"] in IO_STATUSES, labels


def test_s3_auth_label_values_conform(scrape):
    results = {labels["result"] for name, labels, _ in parse_samples(scrape)
               if name == "brix_s3_auth_total"}
    assert results == S3_AUTH_RESULTS


# -- histogram internal consistency ------------------------------------------

def _histogram(scrape, family, sub):
    rows = {}
    for name, labels, v in parse_samples(scrape):
        if name.startswith(family) and all(
                labels.get(k) == sv for k, sv in sub.items()):
            rows.setdefault(name[len(family):], []).append((labels, v))
    return rows


@pytest.mark.parametrize("proto,op", [("stream", "stat"), ("stream", "read"),
                                      ("webdav", "read"), ("s3", "read"),
                                      ("webdav", "write"), ("s3", "write")])
def test_latency_histogram_consistent(scrape, proto, op):
    """Buckets are cumulative (non-decreasing in le) and +Inf == _count."""
    sub = {"proto": proto, "op": op}
    rows = _histogram(scrape, "brix_io_latency_usec", sub)
    buckets = rows.get("_bucket", [])
    counts = rows.get("_count", [])
    assert buckets and counts, f"histogram series missing for {sub}"

    def le_key(labels):
        le = labels["le"]
        return float("inf") if le == "+Inf" else float(le)

    ordered = sorted(buckets, key=lambda r: le_key(r[0]))
    values = [v for _, v in ordered]
    assert values == sorted(values), f"buckets not cumulative for {sub}"
    assert ordered[-1][0]["le"] == "+Inf"
    assert ordered[-1][1] == counts[0][1], f"+Inf != _count for {sub}"


# -- monotonicity across traffic ---------------------------------------------

MONOTONIC = ["brix_io_ops_total", "brix_requests_total", "brix_bytes_tx_total",
             "brix_cache_hits_total", "brix_cache_misses_total",
             "brix_cache_requests_total",
             "brix_webdav_requests_total", "brix_s3_requests_total",
             "brix_auth_total", "brix_connections_total",
             "brix_cache_bytes_evicted_total"]


def test_counters_monotonic_under_traffic(mx):
    """Drive one op on every protocol plane; no counter may decrease."""
    before = _monotonic_values(mx)
    name = cx.unique_name("mono")
    mx.seed_origin(name, 1024)
    mx.seed_local(name, 1024)
    out = mx.cache_root.parent / f"dl_{name}"
    r = mx.xrdcp_get("none", name, str(out))
    assert r.returncode == 0, r.stderr
    out.unlink()
    mx.dav_request("dav", f"/{name}")
    mx.s3_request("s3", name)
    cx.settle()
    after = _monotonic_values(mx)
    for key, vb in before.items():
        assert after.get(key, vb) >= vb, f"counter went backwards: {key}"


def _monotonic_values(mx):
    return {(name, tuple(sorted(labels.items()))): value
            for name, labels, value in parse_samples(cx.mfetch(mx.metrics))
            if name in MONOTONIC}


def test_scrape_is_side_effect_free(mx):
    """Scraping /metrics twice with no traffic in between must not move any
    op/auth/cache counter (the scrape-time ledger fold is idempotent)."""
    a = _monotonic_values(mx)
    b = _monotonic_values(mx)
    assert a == b


# -- per-server plane rows ---------------------------------------------------

def test_stream_plane_ledger_rows_exported(mx):
    """A stream plane exports its per-server ledger rows keyed by
    (port, auth) once the listener has seen traffic — the "none" plane
    definitely has in this module (monotonicity test drove an xrdcp)."""
    samples = parse_samples(cx.mfetch(mx.metrics))
    ports = {(l.get("port"), l.get("auth"))
             for n, l, _ in samples if n == "brix_connections_total"}
    assert (str(mx.port("PORT")), "anon") in ports


def test_storage_backend_info_rows(scrape):
    backends = _storage_backends(scrape)
    assert "xroot" in backends     # stream planes' remote origin
    assert "posix" in backends     # HTTP/S3 planes' local tier


def _storage_backends(scrape):
    infos = [labels for name, labels, value in parse_samples(scrape)
             if name == "brix_storage_backend_info" and value == 1]
    return {labels["backend"] for labels in infos}
