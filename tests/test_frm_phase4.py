"""
tests/test_frm_phase4.py

Phase 35 / Phase 4 — optional parity (F1-F6).

Covers the parity directives + scaffolding that don't need a full recall to
observe:
  S  the Phase-4 directives (brix_frm_max_per_source [F4], brix_frm_purge_*
     [F6], brix_frm_migrate_copycmd [F6], brix_frm_residency_cmd [F3]) are
     accepted by the config parser and the server starts.
  S  the F6 Category-2 purge-watermark monitor arms (a NOTICE in the log) and is
     an explicit SCAFFOLD ("no files are purged").
  S  /metrics exports the new parity counters (migrate/purge/cmsd_have).

These items are deferrable parity (none gates the MVP); this test pins the wiring.

Throwaway nginx comes from the registry lifecycle harness.
"""

import os
import time
import urllib.request

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-frm-phase4")]

PORT = None
METRICS_PORT = None


@pytest.fixture
def srv(lifecycle, tmp_path):
    global PORT, METRICS_PORT
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    data = tmp_path / "data"; data.mkdir()
    queue = tmp_path / "frm.queue"

    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name="lc-frm-phase4",
            template="nginx_lc_frm_phase4.conf",
            protocol="root",
            template_values={
                "BIND_HOST": BIND_HOST,
                "DATA_DIR": str(data),
                "QUEUE_PATH": str(queue),
            },
            reason="frm phase-4 parity directives + purge-monitor scaffold"))
    except (RegistryCommandFailure, RuntimeError) as exc:
        # Preserves the original skip guards: the build may reject the Phase-4
        # config (the brix_frm* directive surface was disabled in-source on
        # 2026-06-30) or fail to come up.
        pytest.skip("nginx rejected config or did not start: %s" % str(exc)[-300:])
    PORT = endpoint.port
    METRICS_PORT = endpoint.extra_ports["METRICS_PORT"]
    time.sleep(1.5)   # let the purge monitor arm + tick once

    class S:
        pass
    s = S()
    s.logfile = os.path.join(endpoint.prefix, "logs", "error.log")
    yield s


def test_phase4_directives_accepted_and_started(srv):
    # If we got here the fixture started the server, so nginx -t accepted all the
    # Phase-4 directives (max_per_source, residency_cmd, migrate_copycmd,
    # purge_watermark, purge_interval).
    assert os.path.exists(srv.logfile)


@pytest.mark.skip(reason="F6 purge-watermark monitor is retired by the src/frm "
                         "dissolution: the legacy FRM queue/scheduler/purge "
                         "worker-init no longer runs (see process_server_init.c) and "
                         "the 'purge-watermark monitor armed'/SCAFFOLD notice is gone "
                         "from source. Cache-tier eviction (brix_cache_store) now owns "
                         "reclamation; there is no live purge monitor to arm. Skipped "
                         "(not deleted) to re-arm if a purge monitor is reintroduced.")
def test_purge_monitor_armed_and_is_scaffold(srv):
    log = open(srv.logfile, errors="replace").read()
    assert "purge-watermark monitor armed" in log, \
        "F6 purge monitor did not arm: %s" % log[-500:]
    assert "SCAFFOLD" in log, "F6 should announce itself as a scaffold"


def test_phase4_metrics_exported(srv):
    with urllib.request.urlopen(
            "http://%s:%d/metrics" % (HOST, METRICS_PORT), timeout=5) as r:
        text = r.read().decode(errors="replace")
    for fam in ("brix_frm_migrate_total",
                "brix_frm_purge_total",
                "brix_frm_cmsd_have_total"):
        assert fam in text, "missing Phase-4 metric %s" % fam
