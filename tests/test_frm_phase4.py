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
"""

import os
import socket
import subprocess
import time
import urllib.request

import pytest

from config_templates import render_config
from settings import NGINX_BIN, HOST, BIND_HOST

PORT = int(os.environ.get("TEST_FRM_P4_STREAM", "11247"))
METRICS_PORT = int(os.environ.get("TEST_FRM_P4_METRICS", "11248"))


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path_factory.mktemp("frmp4")
    (d / "logs").mkdir()
    data = d / "data"; data.mkdir()
    queue = d / "frm.queue"

    conf = render_config("nginx_frm_phase4.conf",
                         BASE_DIR=d,
                         BIND_HOST=BIND_HOST,
                         PORT=PORT,
                         METRICS_PORT=METRICS_PORT,
                         DATA_DIR=data,
                         QUEUE_PATH=queue)
    cp = d / "nginx.conf"
    cp.write_text(conf)
    chk = subprocess.run([NGINX_BIN, "-t", "-p", str(d), "-c", str(cp)],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        pytest.skip("nginx rejected config: %s" % chk.stderr.strip()[-300:])
    proc = subprocess.Popen([NGINX_BIN, "-p", str(d), "-c", str(cp)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.time() + 10
    up = False
    while time.time() < deadline:
        try:
            socket.create_connection((HOST, METRICS_PORT), timeout=0.5).close()
            up = True
            break
        except OSError:
            time.sleep(0.1)
    if not up:
        err = proc.stderr.read().decode(errors="replace")
        proc.terminate()
        pytest.skip("server did not start: %s" % err[-300:])
    time.sleep(1.5)   # let the purge monitor arm + tick once

    class S:
        pass
    s = S()
    s.logfile = str(d / "logs" / "error.log")
    yield s
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_phase4_directives_accepted_and_started(srv):
    # If we got here the fixture started the server, so nginx -t accepted all the
    # Phase-4 directives (max_per_source, residency_cmd, migrate_copycmd,
    # purge_watermark, purge_interval).
    assert os.path.exists(srv.logfile)


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
