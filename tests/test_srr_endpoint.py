"""
tests/test_srr_endpoint.py

WLCG Storage Resource Reporting (SRR) endpoint — src/protocols/srr/.

The module serves the WLCG "storageservice" JSON document (schema v4.x) that
CRIC / WLCG storage accounting harvests over HTTP, deliberately in place of the
XRootD UDP f/g-stream monitoring stack.  These tests assert:

  * success           — GET returns a schema-valid storageservice document with
                        live statvfs-derived space per share + aggregate capacity
  * required fields   — every REQUIRED v4.x field is present (service, shares,
                        endpoints, capacity)
  * error             — a write method (POST) is rejected 405
  * security/negative — request input (query string / headers) cannot influence
                        which path is stat'd or leak into the document; HEAD
                        returns headers with no body

Throwaway nginx comes from the registry lifecycle harness, no fleet dependency.
"""

import json
import os
from collections import namedtuple
from pathlib import Path

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import NGINX_BIN, HOST, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

SRR_PATH = "/.well-known/wlcg-storage-resource-reporting"
_Srr = namedtuple("_Srr", "url base data")


@pytest.fixture
def srr_server(lifecycle):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-srr",
        template="nginx_srr_endpoint.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST},
        reason="WLCG SRR storageservice document coverage"))
    Path(endpoint.data_root, "f.bin").write_bytes(b"x" * 4096)
    base = f"http://{HOST}:{endpoint.port}"
    return _Srr(url=base + SRR_PATH, base=base, data=endpoint.data_root)


def test_srr_document_is_schema_valid(srr_server):
    data_dir = srr_server.data
    r = requests.get(srr_server.url, timeout=10)
    assert r.status_code == 200, f"{r.status_code} {r.text[:200]}"
    assert r.headers.get("Content-Type", "").startswith("application/json"), \
        r.headers.get("Content-Type")

    doc = json.loads(r.text)
    svc = doc["storageservice"]

    # identity
    assert svc["implementation"] == "BriX-Cache"
    assert svc["implementationversion"] == "3.5"
    assert svc["name"] == "TEST-SE"
    assert svc["qualitylevel"] == "production"
    assert isinstance(svc["latestupdate"], int) and svc["latestupdate"] > 0

    # shares — one share, live statvfs space
    shares = svc["storageshares"]
    assert isinstance(shares, list) and len(shares) == 1
    sh = shares[0]
    assert sh["name"] == "atlasdata"
    assert isinstance(sh["timestamp"], int) and sh["timestamp"] > 0
    assert isinstance(sh["totalsize"], int) and sh["totalsize"] > 0
    assert isinstance(sh["usedsize"], int) and sh["usedsize"] >= 0
    assert sh["usedsize"] <= sh["totalsize"]
    assert sh["vos"] == ["atlas", "cms"]
    assert sh["path"] == [data_dir]

    # capacity — site-wide online sum
    online = svc["storagecapacity"]["online"]
    assert online["totalsize"] == sh["totalsize"]
    assert online["usedsize"] == sh["usedsize"]

    # endpoints — two configured doors
    eps = svc["storageendpoints"]
    assert isinstance(eps, list) and len(eps) == 2
    iftypes = {e["interfacetype"] for e in eps}
    assert iftypes == {"davs", "xroot"}
    for e in eps:
        assert "atlasdata" in e["assignedshares"]


def test_srr_required_v4_fields_present(srr_server):
    doc = json.loads(requests.get(srr_server.url, timeout=10).text)
    svc = doc["storageservice"]
    # storageservice REQUIRED
    for k in ("implementation", "implementationversion",
              "storageendpoints", "storageshares"):
        assert k in svc, f"missing required storageservice.{k}"
    # storagecapacity.online REQUIRED
    online = svc["storagecapacity"]["online"]
    for k in ("totalsize", "usedsize"):
        assert k in online
    # each endpoint REQUIRED
    for e in svc["storageendpoints"]:
        for k in ("name", "endpointurl", "interfacetype", "assignedshares"):
            assert k in e, f"missing required endpoint.{k}"
    # each share REQUIRED
    for s in svc["storageshares"]:
        for k in ("timestamp", "totalsize", "usedsize", "vos"):
            assert k in s, f"missing required share.{k}"


def test_srr_rejects_write_method(srr_server):
    r = requests.post(srr_server.url, data=b"x", timeout=10)
    assert r.status_code == 405, f"POST must be 405, got {r.status_code}"
    r = requests.put(srr_server.url, data=b"x", timeout=10)
    assert r.status_code == 405, f"PUT must be 405, got {r.status_code}"


def test_srr_ignores_request_input(srr_server):
    # The document is a pure function of config + filesystem; query strings and
    # headers must not change which path is stat'd or leak into the output.
    base = json.loads(requests.get(srr_server.url, timeout=10).text)
    crafted = requests.get(
        srr_server.url + "?path=/etc/passwd&share=../../etc",
        headers={"X-Forwarded-Host": "/etc/passwd", "X-Share-Path": "/etc"},
        timeout=10,
    )
    assert crafted.status_code == 200
    assert "/etc/passwd" not in crafted.text
    assert "/etc" not in [p for s in json.loads(crafted.text)
                          ["storageservice"]["storageshares"] for p in s["path"]]
    # totalsize must be identical regardless of the injected request input
    inj = json.loads(crafted.text)
    assert inj["storageservice"]["storageshares"][0]["totalsize"] == \
        base["storageservice"]["storageshares"][0]["totalsize"]

    # HEAD: headers (incl. Content-Length) but no body
    h = requests.head(srr_server.url, timeout=10)
    assert h.status_code == 200
    assert int(h.headers.get("Content-Length", "0")) > 0
    assert h.content == b""


def test_srr_only_served_where_enabled(srr_server):
    # A location without brix_srr must not emit the document.
    r = requests.get(f"{srr_server.base}/not-srr", timeout=10)
    assert r.status_code == 204
    assert "storageservice" not in r.text
