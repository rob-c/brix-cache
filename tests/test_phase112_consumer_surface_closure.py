"""phase-112 third wave — the two surfaces a *consumer* touches.

The first wave pinned the tree that produces the names (sources, configs, the
exposition) and the second pinned the deprecation-window contract and the three
self-deleting pins themselves.  Neither looked outward, and phase-112's damage
lands outward, in two places with opposite failure modes:

  * **The HTTP config plane.**  The phase's own acceptance list asks that "an
    nginx config using each removed variable is rejected".  That is pinned for
    the seven ``$brix_session_*`` stream aliases
    (``test_brix_stream_variables.py::test_phase_112_removed_variable_is_now_unknown``)
    and for nothing else.  The six removed *cache* variables live on the HTTP
    plane, where the failure is loudest — nginx does not log a ``-`` for an
    unknown variable, it refuses to start — and no test has ever asserted it.
    These probes are pure ``nginx -t`` (no fleet, no registry) via the shared
    ``config_parse.nginx_t`` helper and the reviewable template beside it.

  * **The shipped operator artifacts** under ``contrib/``.  ``grafana-dashboard.json``
    and ``prometheus-alerts.yml`` are the reason the canonical families exist,
    and they fail in the opposite direction: PromQL naming a family nobody
    exports is not an error.  It returns an empty vector, forever, silently.  A
    stale rule therefore does not break — it stops being able to fire, which is
    an alert that reports "healthy" precisely because it is blind.  That is the
    security-negative of this wave: ``XrootdCacheMissSurge`` still asking for
    ``brix_cache_hits_total`` would be a permanently-quiet detector, and every
    green build would agree with it.

Both artifacts were verified migrated by hand during the phase; nothing held
them there.  A unit hazard rides along: the latency family changed base unit
(``_usec`` → ``_seconds``), so a threshold or panel unit carried across
unchanged is off by a factor of a million while remaining perfectly valid
PromQL.
"""
import json
import os
import re

import pytest

from config_parse import nginx_t
from settings import NGINX_BIN

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTRIB = os.path.join(ROOT, "contrib")
TEMPLATE = "nginx_phase112_http_var.conf"

# The six HTTP cache variables phase-112 removed, in both spellings the tree
# carried (bare and brix-prefixed), and the one variable they collapsed into.
REMOVED_HTTP_VARS = ("cvmfs_cache", "brix_cvmfs_cache",
                     "oci_cache", "brix_oci_cache",
                     "rpm_cache", "brix_rpm_cache")
CANONICAL_HTTP_VAR = "brix_cache_status"

# The eleven removed families, as a consumer would spell them in PromQL.
REMOVED_FAMILIES = (
    "brix_io_latency_usec",
    "brix_webdav_bytes_tx_total", "brix_s3_bytes_tx_total",
    "brix_bytes_tx_total", "brix_bytes_root_tx_total",
    "brix_webdav_bytes_rx_total", "brix_s3_bytes_rx_total",
    "brix_bytes_rx_total", "brix_bytes_root_rx_total",
    "brix_cache_hits_total", "brix_cache_misses_total",
)
CANONICAL_FAMILIES = ("brix_io_latency_seconds", "brix_io_bytes_read",
                      "brix_io_bytes_written", "brix_cache_requests_total")

# Families that legitimately keep the removed per-plane *shape* because they
# carry a label dimension instead of baking the plane into the name.
SHAPED_SURVIVORS = ("brix_vo_bytes_rx_total", "brix_vo_bytes_tx_total",
                    "brix_wire_bytes_rx_total", "brix_wire_bytes_tx_total")
_SHAPE_RE = re.compile(r"brix_[a-z0-9_]*bytes_(?:rx|tx)_total")

needs_nginx = pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                                 reason="nginx binary (set NGINX_BIN) not available")


def _probe(tmp_path, reference):
    """`nginx -t` an http{} whose log_format holds exactly `reference`."""
    for sub in ("logs", "tmp"):
        os.makedirs(os.path.join(str(tmp_path), sub), exist_ok=True)
    return nginx_t(TEMPLATE, tmp_path, ROOT=str(tmp_path), VAR=reference)


def _read(name):
    with open(os.path.join(CONTRIB, name), encoding="utf-8") as fh:
        return fh.read()


def _dashboard():
    return json.loads(_read("grafana-dashboard.json"))


def _panels(node):
    """Every panel in a dashboard, including panels nested inside rows."""
    out = []
    for panel in node.get("panels", ()):
        out.append(panel)
        out.extend(_panels(panel))
    return out


def _panel_exprs(panel):
    return [t.get("expr", "") for t in panel.get("targets", ())]


def _dashboard_exprs():
    return [e for panel in _panels(_dashboard()) for e in _panel_exprs(panel)]


def _latency_panels():
    """(title, declared unit, exprs) for every panel plotting the latency family."""
    out = []
    for panel in _panels(_dashboard()):
        exprs = _panel_exprs(panel)
        if any("brix_io_latency_seconds" in e for e in exprs):
            defaults = panel.get("fieldConfig", {}).get("defaults", {})
            out.append((panel.get("title"), defaults.get("unit"), exprs))
    return out


def _wrong_unit(panels):
    return [(title, unit) for title, unit, _ in panels if unit != "s"]


def _scale_hazards(exprs):
    """µs-era multipliers/divisors that stay valid PromQL after the rename."""
    hazards = ("1e6", "1e+06", "1000000", "usec", "microsecond")
    return sorted({h for expr in exprs for h in hazards if h in expr})


def _scaled_panels(panels):
    return [(title, _scale_hazards(exprs)) for title, _, exprs in panels
            if _scale_hazards(exprs)]


def _source_files():
    out = []
    for base in ("src", "client", "shared"):
        for dirpath, _, names in os.walk(os.path.join(ROOT, base)):
            out.extend(os.path.join(dirpath, n) for n in names
                       if n.endswith((".c", ".h")))
    return out


def _shape_census():
    """Every family name in the removed per-plane byte-counter shape."""
    seen = set()
    for path in _source_files():
        with open(path, encoding="utf-8", errors="replace") as fh:
            seen.update(_SHAPE_RE.findall(fh.read()))
    return seen


def _alert_rules():
    """(alert-name, expr) for every rule in the shipped rules file, parsed
    textually so the test needs no YAML dependency beyond the stdlib."""
    rules, name = [], None
    for block in re.split(r"\n\s+- alert: ", "\n" + _read("prometheus-alerts.yml")):
        head, _, rest = block.partition("\n")
        if not head.strip() or head.startswith("#"):
            continue
        name = head.strip()
        expr = re.search(r"expr:\s*\|?\s*\n?((?:.|\n)*?)\n\s+(?:for|labels|annotations):",
                         rest)
        rules.append((name, expr.group(1) if expr else ""))
    return rules


# --- the HTTP config plane: the acceptance criterion the phase never pinned ---

@needs_nginx
@pytest.mark.parametrize("removed", REMOVED_HTTP_VARS)
def test_every_removed_http_cache_variable_is_refused_by_the_config_parser(
        tmp_path, removed):
    """Error case, and the loud half of phase-112's blast radius.

    An unknown variable is not a runtime degradation on the HTTP plane — nginx
    refuses the whole configuration at parse time.  An operator whose
    ``log_format`` still names ``$cvmfs_cache`` after upgrading does not get a
    dash in a log field; the server does not come up.  The phase's acceptance
    list asks for exactly this assertion and it existed only for the stream
    aliases.
    """
    r = _probe(tmp_path, f"${removed}")
    assert r.returncode != 0, (
        f"${removed} was removed by phase-112 but still parses; a compatibility "
        f"variable survived the removal")
    assert f'unknown "{removed}" variable' in r.stderr, (
        f"${removed} is rejected, but not with nginx's unknown-variable "
        f"diagnostic — the operator gets no name to grep for:\n{r.stderr}")


@needs_nginx
def test_the_canonical_cache_variable_the_six_collapsed_into_still_parses(tmp_path):
    """Success case: the migration target resolves, so the rejection above is a
    removal and not a broken variable registration taking the plane down with
    it."""
    r = _probe(tmp_path, f"${CANONICAL_HTTP_VAR}")
    assert r.returncode == 0, (
        f"${CANONICAL_HTTP_VAR} is the documented replacement for all six "
        f"removed cache variables and must parse:\n{r.stderr}")


# --- the shipped operator artifacts: the silent half ---

def test_the_shipped_alert_rules_name_no_removed_metric_family():
    """Security-negative.  A rule querying a family nobody exports never errors
    and never fires: it is a detector that reports healthy because it is blind.
    """
    text = _read("prometheus-alerts.yml")
    stale = [f for f in REMOVED_FAMILIES if f in text]
    assert not stale, (
        f"contrib/prometheus-alerts.yml queries removed families {stale}; those "
        f"rules cannot fire and will report healthy forever")


def test_the_shipped_dashboard_names_no_removed_metric_family():
    """The same silent failure, rendered as an empty panel rather than a
    missing alert."""
    text = _read("grafana-dashboard.json")
    stale = [f for f in REMOVED_FAMILIES if f in text]
    assert not stale, (
        f"contrib/grafana-dashboard.json queries removed families {stale}; those "
        f"panels draw nothing and say nothing about why")


def test_the_shipped_dashboard_queries_every_canonical_replacement():
    """Removal is not migration.  Deleting the stale queries would satisfy the
    two tests above while leaving the operator with no panel at all — this pins
    that each of the four replacements actually took over."""
    joined = "\n".join(_dashboard_exprs())
    missing = [f for f in CANONICAL_FAMILIES if f not in joined]
    assert not missing, (
        f"the shipped dashboard never queries {missing}; phase-112 removed the "
        f"predecessors of those families without the dashboard adopting them")


def test_the_cache_alert_asks_by_label_not_by_the_removed_counter_pair():
    """``brix_cache_hits_total`` / ``_misses_total`` did not become two new
    families — they became one family split by a ``cache_status`` label.  A
    consumer that "migrated" by renaming would produce a rule that parses and
    is wrong."""
    rules = dict(_alert_rules())
    expr = rules.get("XrootdCacheMissSurge", "")
    assert "brix_cache_requests_total" in expr, (
        "the cache-hit-ratio alert no longer names brix_cache_requests_total; "
        f"the shipped rule reads:\n{expr}")
    assert "cache_status" in expr, (
        "the cache-hit-ratio alert names the canonical family but never selects "
        f"on cache_status, so it sums hits and misses together:\n{expr}")


def test_the_latency_panel_is_declared_in_seconds_and_scales_by_nothing():
    """The unit hazard.  ``brix_io_latency_usec`` → ``brix_io_latency_seconds``
    is a base-unit change, so a panel unit or a µs-era multiplier carried across
    unchanged stays valid PromQL and is wrong by 1e6."""
    panels = _latency_panels()
    assert panels, (
        "no shipped panel plots brix_io_latency_seconds; the unit change has "
        "no consumer and this pin has nothing to hold")
    assert not _wrong_unit(panels), (
        f"panels {_wrong_unit(panels)} plot brix_io_latency_seconds under a "
        f"unit that is not 's'; the µs-era unit survived the rename")
    assert not _scaled_panels(panels), (
        f"panels {_scaled_panels(panels)} scale a seconds-based latency query "
        f"by a leftover µs conversion")


def test_the_per_plane_counter_shape_stays_gone_and_its_labelled_lookalikes_stay():
    """Both directions of the census escape.

    ``brix_cache_hits_total`` reached phase-112 without ever entering the
    deprecation registry, so the phase learned to distrust name-by-name
    inventories.  The generalisation is the *shape*: a byte counter that bakes
    its plane into the family name.  It cannot be banned outright — four live
    families share the shape legitimately because they carry the dimension as a
    label — so this pins the shape census exactly: the four survivors stay, and
    nothing else in that shape may appear.
    """
    seen = _shape_census()
    assert seen == set(SHAPED_SURVIVORS), (
        f"the per-plane byte-counter shape census changed: unexpected "
        f"{sorted(seen - set(SHAPED_SURVIVORS))}, missing "
        f"{sorted(set(SHAPED_SURVIVORS) - seen)}. A new family in the shape "
        f"phase-112 removed must justify itself here, and the labelled "
        f"survivors must not be swept out with it")
