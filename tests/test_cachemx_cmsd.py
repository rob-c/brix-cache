"""cmsd:// clustering metric-accuracy conformance.

WHAT: A manager (redirector) + one cache data-server are booted as a real
      cms pair; assertions cover the registration gauge, the per-server
      utilization/last-seen gauges, redirected-read payload exactness, the
      data-server's cache miss/hit accounting through a redirect, and the
      zero-data-server refusal path.

WHY:  The cluster plane is the only place a manager's view of its fleet is
      exported; a wrong registration count or a redirect that silently
      serves from the wrong node breaks fleet capacity dashboards.
"""

import os
import time
from pathlib import Path

import pytest

import _cachemx as cx
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

PAYLOAD_SIZE = 6000


class CmsPair:
    def __init__(self, work, redir, ds, redir_metrics, ds_metrics,
                 zero_ds_rc, zero_ds_stderr, payload):
        self.work = work
        self.redir = redir
        self.ds = ds
        self.redir_metrics = redir_metrics
        self.ds_metrics = ds_metrics
        self.zero_ds_rc = zero_ds_rc
        self.zero_ds_stderr = zero_ds_stderr
        self.payload = payload

    def read_via_redirector(self, name, out):
        return cx.run_client(cx.XRDCP, "-f",
                             f"root://{HOST}:{self.redir.port}/{name}",
                             str(out), env=cx.env_none(), timeout=40)


@pytest.fixture(scope="module")
def cms(tmp_path_factory):
    """Boot the manager alone (capturing the zero-DS refusal), then attach
    one data-server and wait for it to register."""
    work = tmp_path_factory.mktemp("cachemx-cms")
    harness = LifecycleHarness()
    try:
        redir = harness.start(NginxInstanceSpec(
            name="lc-cachemx-redir",
            template="nginx_lc_cachemx_redir.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST},
            reason="cachemx conformance: cms manager"))
        rm = f"http://{HOST}:{redir.extra_ports['METRICS_PORT']}/metrics"

        # Zero-DS refusal, captured before any data-server exists.
        r = cx.run_client(cx.XRDCP, "-f",
                          f"root://{HOST}:{redir.port}/nofile.bin",
                          str(work / "z.bin"), env=cx.env_none(), timeout=25)

        dscache = work / "dscache"
        dscache.mkdir()
        ds = harness.start(NginxInstanceSpec(
            name="lc-cachemx-cmsds",
            template="nginx_lc_cachemx_cmsds.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST,
                             "CMS_PORT": redir.extra_ports["CMS_PORT"],
                             "CACHE_DIR": str(dscache)},
            reason="cachemx conformance: cms cache data-server"))
        dsm = f"http://{HOST}:{ds.extra_ports['METRICS_PORT']}/metrics"
        payload = os.urandom(PAYLOAD_SIZE)
        p = Path(ds.data_root) / "cms1.bin"
        p.write_bytes(payload)

        deadline = time.time() + 15
        while time.time() < deadline:
            if cx.gauge(rm, "brix_cluster_servers_registered"):
                break
            time.sleep(1)

        yield CmsPair(work, redir, ds, rm, dsm, r.returncode,
                      r.stderr or "", payload)
    finally:
        harness.close()


def test_zero_ds_read_refused(cms):
    """With no data-server registered, a read through the manager fails with
    a client error, not a hang and not a silent empty file."""
    assert cms.zero_ds_rc != 0
    assert not (cms.work / "z.bin").exists() or \
        (cms.work / "z.bin").stat().st_size == 0


def test_data_server_registers(cms):
    """Exactly one data-server registered with the manager."""
    assert cx.gauge(cms.redir_metrics,
                    "brix_cluster_servers_registered") == 1


def test_per_server_gauges_exported(cms):
    """The manager exports utilization and last-seen gauges keyed by the
    data-server's address; last-seen stays fresh (heartbeats flowing)."""
    text = cx.mfetch(cms.redir_metrics)
    util = [l for l in text.splitlines()
            if l.startswith("brix_cluster_server_utilization_percent{")]
    seen = [l for l in text.splitlines()
            if l.startswith("brix_cluster_server_last_seen_seconds{")]
    assert len(util) == 1 and len(seen) == 1
    assert 0 <= float(util[0].rsplit(" ", 1)[1]) <= 100
    assert float(seen[0].rsplit(" ", 1)[1]) < 60


def test_redirected_read_exact_payload(cms):
    """A read via the manager is redirected to the data-server and delivers
    the exact seeded bytes."""
    out = cms.work / "cmsout.bin"
    r = cms.read_via_redirector("cms1.bin", out)
    assert r.returncode == 0, r.stderr
    assert out.read_bytes() == cms.payload


def test_redirect_counts_miss_on_data_server(cms):
    """The cold redirected read was the DATA-SERVER's cache miss (the
    manager holds no cache) — exactly one miss booked there."""
    s = cx.Snap(cms.ds_metrics)
    out = cms.work / "cmsmiss.bin"
    name = "cms2.bin"
    (Path(cms.ds.data_root) / name).write_bytes(os.urandom(3000))
    r = cms.read_via_redirector(name, out)
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(cms.ds_metrics)
    assert s.delta("brix_cache_misses_total", {"proto": "stream"},
                   after) == 1
    assert s.delta("brix_cache_hits_total", {"proto": "stream"}, after) == 0


def test_redirect_warm_read_is_hit(cms):
    """Re-reading the same name through the manager is one data-server cache
    hit and zero further misses."""
    out = cms.work / "cmshit.bin"
    r = cms.read_via_redirector("cms1.bin", out)      # ensure cached
    assert r.returncode == 0, r.stderr
    cx.settle()
    s = cx.Snap(cms.ds_metrics)
    r = cms.read_via_redirector("cms1.bin", out)
    assert r.returncode == 0, r.stderr
    cx.settle()
    after = cx.mfetch(cms.ds_metrics)
    assert s.delta("brix_cache_hits_total", {"proto": "stream"}, after) == 1
    assert s.delta("brix_cache_misses_total", {"proto": "stream"},
                   after) == 0


def test_manager_books_login_ledger(cms):
    """The manager's own (port,auth) ledger books the client sessions it
    redirected — at least the logins and stats seen so far."""
    text = cx.mfetch(cms.redir_metrics)
    lbl = f'port="{cms.redir.port}",auth="anon"'
    logins = [l for l in text.splitlines()
              if l.startswith("brix_requests_total{")
              and lbl in l and 'op="login"' in l and 'status="ok"' in l]
    assert logins, "manager exported no login ledger row"
    assert int(logins[0].rsplit(" ", 1)[1]) >= 3


def test_manager_holds_no_cache_counters(cms):
    """The manager plane never serves data itself: its own cache hit/miss
    counters stay untouched by redirected traffic."""
    text = cx.mfetch(cms.redir_metrics)
    for fam in ("brix_cache_hits_total", "brix_cache_misses_total"):
        rows = [l for l in text.splitlines()
                if l.startswith(fam + "{") or l.startswith(fam + " ")]
        for row in rows:
            assert float(row.rsplit(" ", 1)[1]) == 0, row
