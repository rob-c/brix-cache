"""2.0 readiness F10 — the health-check ``/metrics`` family is real, aggregate,
and named correctly in the register.

The 2026-09-05 register said health checks had "no /metrics family".  They have
one: ``brix_cluster_hc_probes_total`` / ``_pass_total`` / ``_fail_total`` /
``_blacklist_total`` (src/observability/metrics/cluster.c, phase 22), and it is
deliberately aggregate-only — a per-server ``server=`` label would let every
node a hostile fleet member registers grow the series (INVARIANT 8).  Three
legs pin that: the family is emitted and moves on a live probe loop (success),
the register names all four (the documentation-error leg), and no hc row ever
carries a per-server label (security negative).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from _test_release20_metrics_helpers import scrape, type_lines, value, wait_for, wait_port
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-r20-hc")]

REPO = Path(__file__).resolve().parents[1]
REGISTER = REPO / "docs" / "10-reference" / "release-2.0-readiness.md"
CLUSTER_C = REPO / "src" / "observability" / "metrics" / "cluster.c"

HC_FAMILY = ("brix_cluster_hc_probes_total", "brix_cluster_hc_pass_total",
             "brix_cluster_hc_fail_total", "brix_cluster_hc_blacklist_total")


@pytest.fixture
def hc_metrics_port(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("x\n")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-r20-hc-metrics",
        template="nginx_hc_cluster.conf",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST},
        reason="2.0 readiness F10: manager probing one data server",
    ))
    if not (wait_port(ep.extra_ports["DS_PORT"]) and wait_port(ep.extra_ports["METRICS_PORT"])):
        pytest.skip("health-check cluster did not become ready")
    return ep.extra_ports["METRICS_PORT"]


def _passed_scrape(port):
    """The scrape once at least one probe has run AND passed, else None."""
    body = scrape(port)
    if value(body, "brix_cluster_hc_probes_total") and value(body, "brix_cluster_hc_pass_total"):
        return body
    return None


def test_health_family_is_emitted_as_counters_and_moves(hc_metrics_port):
    """Success: all four families are declared counters and the probe loop
    (interval 2s) drives probes_total and pass_total above zero."""
    body = scrape(hc_metrics_port)
    types = type_lines(body)
    for fam in HC_FAMILY:
        assert types.get(fam) == "counter", (fam, types.get(fam))
    moved = wait_for(lambda: _passed_scrape(hc_metrics_port), timeout=25)
    assert moved is not None, "no probe passed within 25s"
    assert value(moved, "brix_cluster_hc_fail_total") == 0.0
    assert value(moved, "brix_cluster_hc_blacklist_total") == 0.0


def test_register_health_row_names_all_four_families():
    """Documentation leg: the (c.2) health row cites every family by name, so
    the 2026-09-05 'no /metrics family' claim cannot come back unnoticed."""
    row = _health_row()
    missing = [fam for fam in HC_FAMILY if _needle(fam) not in row]
    assert not missing, f"health row lacks {missing}"
    assert "no /metrics family" not in row


def _health_row():
    text = REGISTER.read_text(encoding="utf-8")
    rows = [l for l in text.splitlines() if l.startswith("| Health checks |")]
    assert len(rows) == 1, rows
    return rows[0]


def _needle(fam):
    """The row spells the first family in full and the rest as suffixes."""
    return fam if fam == HC_FAMILY[0] else fam.replace("brix_cluster_hc", "")


def test_hc_family_is_emitted_before_the_first_member_registers():
    """Error leg (source pin): the hc block runs BEFORE the empty-registry
    early return, so a manager with no member yet still exposes all four
    counters — a family that appeared only after the first registration read
    as a counter reset to every scraper (found and fixed 2026-09-07)."""
    src = CLUSTER_C.read_text(encoding="utf-8")
    exporter = src[src.index("brix_export_cluster_metrics(metrics_writer_t *mw)"):]
    call = exporter.index("cluster_export_health_counters(mw);")
    empty_return = exporter.index("if (n == 0) {")
    assert call < empty_return, "hc counters must be emitted before the n == 0 return"


def test_hc_rows_carry_no_per_server_label(hc_metrics_port):
    """Security negative (INVARIANT 8): the hc family is aggregate-only — in
    the live scrape and in the emitter's format strings."""
    body = scrape(hc_metrics_port)
    for line in body.splitlines():
        if line.startswith("brix_cluster_hc_"):
            assert "{" not in line and "server=" not in line, line
    src = CLUSTER_C.read_text(encoding="utf-8")
    block = src[src.index("brix_cluster_hc_probes_total"):]
    block = block[:block.index("brix_cluster_hc_blacklist_total") + 400]
    assert "server=" not in block
    assert re.search(r'brix_cluster_hc_[a-z_]+_total\{', block) is None
