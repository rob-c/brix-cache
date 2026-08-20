"""
test_audit15b_srr_cache.py — the SRR × cache pair (audit §B3.15,
testsuite-combinatorial-coverage-audit 2026-08-15: "SRR appears only in 3
standalone units.  What the report claims about a cache instance's capacity is
untested").

One nginx process runs a read-through cache plane (root:// front, posix origin,
fills landing in CACHE_DIR) AND the SRR endpoint whose single share IS the
cache store — the shape a WLCG cache site actually reports.  The three cases:

  * the cache plane works (a read through the front returns origin bytes and
    the fill lands under CACHE_DIR) — the co-residence is live, not idle config
  * the SRR document is coherent for the cache share: schema-valid, the share
    path is the cache store, statvfs numbers sane, capacity sums match
  * the report survives cache activity: after the fill, a re-fetch still
    parses and usedsize has not regressed below zero/total (builder.c statvfs
    runs per request against the live cache filesystem)
"""

import json
import os

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from test_phase25_ratelimit import (_xrd_login, _xrd_open, _xrd_read, KXR_OK)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15b-srr-cache")]

SEED = b"cache-member-report-bytes\n" * 8

SRR_PATH = "/.well-known/wlcg-storage-resource-reporting"


@pytest.fixture()
def srr_cache(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path / "origin-data"
    data.mkdir()
    (data / "hot.bin").write_bytes(SEED)
    cache_dir = tmp_path / "cache-store"
    cache_dir.mkdir()
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15b-srr-cache",
        template="nginx_srr_cache.conf",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "CACHE_DIR": str(cache_dir)},
        reason="audit-15b SRR x cache-tier pair"))
    srr_port = ep.extra_ports["SRR_PORT"]
    return ep.port, srr_port, cache_dir


def _read_through(port):
    s = _xrd_login(HOST, port)
    try:
        status, body = _xrd_open(s, "/hot.bin")
        assert status == KXR_OK, (status, body)
        status, data = _xrd_read(s, body[:4], 0, len(SEED))
        assert status == KXR_OK, status
        return data
    finally:
        s.close()


def _fetch_doc(srr_port):
    r = requests.get(f"http://{HOST}:{srr_port}{SRR_PATH}", timeout=10)
    assert r.status_code == 200, (r.status_code, r.text[:200])
    return json.loads(r.text)


def test_cache_plane_fills_while_srr_coresident(srr_cache):
    port, _, cache_dir = srr_cache
    assert _read_through(port) == SEED
    fills = [p for p in cache_dir.rglob("*") if p.is_file()]
    assert fills, "read-through returned bytes but nothing landed in the cache store"


def test_srr_reports_the_cache_share(srr_cache):
    port, srr_port, cache_dir = srr_cache
    doc = _fetch_doc(srr_port)
    svc = doc["storageservice"]
    assert svc["implementation"] == "BriX-Cache"

    shares = svc["storageshares"]
    assert len(shares) == 1
    sh = shares[0]
    assert sh["name"] == "cachedata"
    assert sh["path"] == [str(cache_dir)], sh["path"]
    assert sh["vos"] == ["atlas"]
    assert isinstance(sh["totalsize"], int) and sh["totalsize"] > 0
    assert isinstance(sh["usedsize"], int) and 0 <= sh["usedsize"] <= sh["totalsize"]

    online = svc["storagecapacity"]["online"]
    assert online["totalsize"] == sh["totalsize"]
    assert online["usedsize"] == sh["usedsize"]

    eps = svc["storageendpoints"]
    assert len(eps) == 1 and eps[0]["interfacetype"] == "xroot"
    assert "cachedata" in eps[0]["assignedshares"]


def test_srr_stays_coherent_after_cache_activity(srr_cache):
    port, srr_port, _ = srr_cache
    before = _fetch_doc(srr_port)["storageservice"]["storageshares"][0]
    assert _read_through(port) == SEED
    after = _fetch_doc(srr_port)["storageservice"]["storageshares"][0]
    # statvfs is filesystem-wide, so exact deltas are not assertable — but the
    # numbers must stay sane and the endpoint must not wedge under stream load.
    assert after["totalsize"] == before["totalsize"]
    assert 0 <= after["usedsize"] <= after["totalsize"]
    assert after["timestamp"] >= before["timestamp"]
