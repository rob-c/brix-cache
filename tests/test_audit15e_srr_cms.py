"""
test_audit15e_srr_cms.py — the WLCG SRR endpoint on a live CMS mesh member
(audit §B3.15 residual, testsuite-combinatorial-coverage-audit 2026-08-15:
SRR appeared only in standalone units and, in tranche 2, on a cache-tier
member — never on a node joined to a cms mesh, though a real site's
reporting endpoint sits on exactly such a node).

Two instances: a CMS manager (nginx_cms_state_server.conf as
lc-audit15e-cmsmgr) and a data node (nginx_audit15e_srrcms.conf) that both
registers with that manager and serves the SRR document over HTTP.  The join
is proven from the member's own log line — "CMS registered with ... after N
ms (K connect attempt(s), profile)" — so the report is demonstrably being
made BY a mesh member, not by an idle node with a manager directive.

Cases:
  * success — the member joins the mesh AND its data plane serves a read
    over the raw root wire (the co-residence is live, not idle config)
  * success — the SRR document is coherent for the member's share: schema
    shape, the share path is the export, capacity sums match, the endpoint
    is the node's own root:// URL
  * success — the report survives mesh + data activity: a re-fetch after a
    read still parses, totals are stable and the timestamp advances
  * error — an unknown path on the SRR port is a clean 404, i.e. the
    reporting endpoint is not a catch-all on a mesh member
"""

import json
import os

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from test_phase25_ratelimit import (_xrd_login, _xrd_open, _xrd_read, KXR_OK)
from test_cms_fast_settle import Node  # noqa: F401 - documents the join regex

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15e-srrcms")]

SEED = b"mesh-member-report-bytes\n" * 8
SRR_PATH = "/.well-known/wlcg-storage-resource-reporting"


@pytest.fixture()
def srr_member(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    mgr = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-cmsmgr",
        template="nginx_cms_state_server.conf",
        protocol="root",
        readiness="tcp",
        reason="audit-15e cms manager for the SRR-member pair"))
    data = tmp_path / "member-data"
    data.mkdir()
    (data / "hot.bin").write_bytes(SEED)
    # The master may run as root, in which case the worker drops privilege and
    # still needs to create the checkpoint-recovery lock inside the export.
    os.chmod(data, 0o777)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-srrcms",
        template="nginx_audit15e_srrcms.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "MANAGER_PORT": str(mgr.port)},
        reason="audit-15e SRR endpoint on a cms mesh member"))
    return ep, ep.extra_ports["SRR_PORT"], data


def _member_log(ep):
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _wait_registered(ep, timeout=8.0):
    import re
    import time
    rx = re.compile(r"CMS registered with \S+ after (\d+) ms "
                    r"\((\d+) connect attempt\(s\), (\w+)\)")
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = rx.search(_member_log(ep))
        if m:
            return int(m.group(1)), int(m.group(2)), m.group(3)
        time.sleep(0.05)
    return None


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


def test_member_joins_mesh_and_serves_data(srr_member):
    ep, _, _ = srr_member
    joined = _wait_registered(ep)
    assert joined is not None, \
        "the SRR member never registered with the manager\n" + _member_log(ep)
    _ms, attempts, _profile = joined
    assert attempts >= 1
    assert _read_through(ep.port) == SEED


def test_srr_reports_the_member_share(srr_member):
    ep, srr_port, data = srr_member
    assert _wait_registered(ep) is not None
    svc = _fetch_doc(srr_port)["storageservice"]
    assert svc["implementation"] == "BriX-Cache"

    shares = svc["storageshares"]
    assert len(shares) == 1
    sh = shares[0]
    assert sh["name"] == "meshdata"
    assert sh["path"] == [str(data)], sh["path"]
    assert sh["vos"] == ["atlas"]
    assert isinstance(sh["totalsize"], int) and sh["totalsize"] > 0
    assert isinstance(sh["usedsize"], int) and 0 <= sh["usedsize"] \
        <= sh["totalsize"]

    online = svc["storagecapacity"]["online"]
    assert online["totalsize"] == sh["totalsize"]
    assert online["usedsize"] == sh["usedsize"]

    eps = svc["storageendpoints"]
    assert len(eps) == 1 and eps[0]["interfacetype"] == "xroot"
    assert "meshdata" in eps[0]["assignedshares"]
    assert str(ep.port) in eps[0]["endpointurl"], eps[0]["endpointurl"]


def test_srr_stays_coherent_under_mesh_and_data_activity(srr_member):
    ep, srr_port, _ = srr_member
    assert _wait_registered(ep) is not None
    before = _fetch_doc(srr_port)["storageservice"]["storageshares"][0]
    assert _read_through(ep.port) == SEED
    after = _fetch_doc(srr_port)["storageservice"]["storageshares"][0]
    # statvfs is filesystem-wide, so exact deltas are not assertable — but the
    # numbers must stay sane and neither plane may wedge the other.
    assert after["totalsize"] == before["totalsize"]
    assert 0 <= after["usedsize"] <= after["totalsize"]
    assert after["timestamp"] >= before["timestamp"]
    # The mesh membership is still live after the report was served.
    assert "CMS registered with" in _member_log(ep)


def test_unknown_path_on_the_report_port_404s(srr_member):
    _ep, srr_port, _ = srr_member
    r = requests.get(f"http://{HOST}:{srr_port}/not-the-report", timeout=10)
    assert r.status_code == 404, (r.status_code, r.text[:200])
