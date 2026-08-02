"""
Export-presence test for the outbound native-TPC GSI proxy-delegation counter
family — brix_tpc_gsi_delegated_total{result="ok|expired|absent"} (phase-58
§5.8 sub-task 3).

The counter is incremented only from the pull launcher (tpc_pull_attach_creds,
src/tpc/engine/launch.c) on a live delegated native-TPC transfer, which needs a
full GSI source/dest pair — exercised end-to-end by test_tpc_delegation.py. This
test instead verifies the SHM → exporter wiring that the launcher depends on:
the unified metrics writer must emit the HELP/TYPE header plus one series per
result label (unconditionally, at zero) so the counters are scrape-visible from
the first tick. That covers the metrics.h SHM field, the unified.c names table,
and the unified_export.c emitter added for the sub-task.

Stands up a stream-only xrootd (so the module maps its shared-memory metrics
table) plus an HTTP /metrics endpoint, scrapes it, and asserts:

  * the ``# HELP``/``# TYPE ... counter`` lines for the family are present;
  * exactly the three documented result labels appear, each a valid counter;
  * no stray/unknown result label leaks (INVARIANT #8 — low cardinality).

Self-skips when the nginx binary is absent (a checkout without a build).
"""
import os
import re

import pytest

from server_registry import NginxInstanceSpec

try:
    from settings import NGINX_BIN, BIND_HOST
except Exception:  # noqa: BLE001 — settings import optional outside the harness
    NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
    BIND_HOST = "127.0.0.1"  # net-literal-allow: fallback BIND_HOST when settings module unavailable outside harness

_METRIC = "brix_tpc_gsi_delegated_total"
_EXPECTED_LABELS = {"ok", "expired", "absent"}

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason="nginx binary not built"),
]


def _scrape(port):
    import urllib.request
    with urllib.request.urlopen("http://%s:%d/metrics" % (BIND_HOST, port),
                                timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def test_tpc_gsi_deleg_metric_exported(lifecycle, tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-tpc-gsi-deleg-metrics",
        template="nginx_lc_tpc_gsi_deleg_metrics.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "ROOT_DIR": str(root)},
        reason="outbound TPC GSI proxy-delegation counter export"))
    mport = ep.extra_ports["METRICS_PORT"]

    text = _scrape(mport)

    # HELP/TYPE exposition headers for the family.
    assert ("# HELP %s " % _METRIC) in text, "missing HELP line for " + _METRIC
    assert ("# TYPE %s counter" % _METRIC) in text, \
        "missing TYPE counter line for " + _METRIC

    # Every documented result label must export as a valid counter value, and no
    # other label may appear (low-cardinality, closed enum — INVARIANT #8).
    rows = re.findall(
        r'^%s\{result="([^"]+)"\}\s+(\d+(?:\.\d+)?(?:e[+-]?\d+)?)\s*$'
        % re.escape(_METRIC), text, re.MULTILINE)
    seen = {label for label, _ in rows}
    assert seen == _EXPECTED_LABELS, \
        "result labels %r != expected %r" % (seen, _EXPECTED_LABELS)
    # Each series parses as a number and, absent any transfer, sits at zero.
    for label, value in rows:
        assert float(value) == 0.0, \
            "expected %s{result=%r} == 0 on a fresh server, got %s" % (
                _METRIC, label, value)
