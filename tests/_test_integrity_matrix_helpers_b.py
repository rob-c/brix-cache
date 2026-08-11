"""
tests/test_integrity_matrix.py — cross-topology data-integrity matrix.

For every way the harness can present a file server to a client, this proves
that bytes survive the round trip EXACTLY and that the server's CHECKSUM agrees
with an independent local computation — for READ (scalar), READ (vector /
scatter-gather), and WRITE, over root://, https/davs, and s3.

The test is data-driven from a TOPOLOGY REGISTRY (see ENDPOINTS).  Each entry is
a (topology, protocol, locator) triple covering the categories the request
named: a storage endpoint reached DIRECTLY, and the same storage reached behind
a PROXY, a MIRROR, a HEAD NODE / MANAGER, a REDIRECTOR, and other MESH
combinations (pure nginx→nginx proxy chain, 3-tier proxy→cache→storage,
read-through and write-through caches, CMS cluster).

Per protocol the integrity primitives are:

  root://  (XRootD client)   write = open(NEW)+write ; read_scalar = read() ;
                             read_vector = vector_read() ; checksum =
                             FileSystem.query(CHECKSUM) == zlib.adler32.
  https/davs (requests)      write = PUT ; read_scalar = GET ; read_vector =
                             multi-Range GET (multipart/byteranges) ; checksum =
                             Want-Digest -> Digest header.
  s3   (requests)            write = PUT ; read_scalar = GET ; read_vector =
                             multi-Range GET ; checksum = ETag == md5 / Content-MD5.

Endpoints that are not reachable when the test runs are SKIPPED (so the matrix
runs against whatever subset of the fleet is up), except the `mirror` row, which
is provisioned by a self-contained fixture because the standard fleet has no
mirror server.

Run:
    tests/manage_test_servers.sh start          # bring up the fleet subset
    PYTHONPATH=tests pytest tests/test_integrity_matrix.py -v
"""

import hashlib
import os
import socket
import time
import zlib
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_default

import pytest
from _xrdcl_proxy import real_bindings_available

from settings import (
    CACHE_ONLY_PORT,
    CHAOS_TIER1_PORT,
    CLUSTER_REDIR_PORT,
    DATA_ROOT,
    HOST,
    MANAGER_PORT,
    NGINX_ANON_PORT,
    NGINX_BIN,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    NGINX_WEBDAV_PORT,
    PROXY_NGINX_PORT,
    PROXY_PURE_NGINX_PROXY_PORT,
    S3_BUCKET,
    SERVER_HOST,
    VIRTUAL_REDIR_PORT,
    WT_SYNC_PORT,
)
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# This matrix drives stateful mesh/cluster/proxy/mirror topologies (cluster-cms
# redirector, 3-tier chaos mesh, mirror front/sink, proxy chains). Under the
# parallel bulk lane those shared backends are contended by co-executing suites,
# which flaked TestMirrorTopology and the cluster-cms endpoint (both pass in
# isolation). Mark the module `serial` so conftest pins it to the isolated serial
# lane — the same pattern test_conformance_topologies / test_cms_mesh_interop use.
pytestmark = [pytest.mark.serial, pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-im")]

# Deterministic-but-distinct payloads.  Sizes chosen to span multiple read
# chunks and a non-page-aligned tail.
@pytest.fixture(scope="session")
def mirror_endpoint():
    """Stand up a transparent stream-mirror server; yield its root Endpoint.

    The sink (shadow-traffic destination) and the mirror front are throwaway
    registry instances (LifecycleHarness): the harness renders the committed
    nginx_integrity_mirror_{sink,front}.conf templates, runs `nginx -t`, waits
    for each to be TCP-ready, and reaps both on close().  The front's
    brix_mirror_url is wired to the sink's assigned port via
    template_values."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    harness = LifecycleHarness()
    try:
        sink = harness.start(NginxInstanceSpec(
            name="im-mirror-sink",
            template="nginx_integrity_mirror_sink.conf",
            protocol="root",
            port=_pinned_port("TEST_MIRROR_SINK_PORT"),
            readiness="tcp",
            reason="integrity-matrix mirror shadow-traffic sink"))
        front = harness.start(NginxInstanceSpec(
            name="im-mirror-front",
            template="nginx_integrity_mirror_front.conf",
            protocol="root",
            port=_pinned_port("TEST_MIRROR_FRONT_PORT"),
            readiness="tcp",
            template_values={"MIRROR_SINK": f"{H}:{sink.port}"},
            reason="integrity-matrix mirror front (client-facing)"))
    except Exception as exc:
        harness.close()
        pytest.skip(f"mirror servers did not start: {str(exc)[-300:]}")

    ep = Endpoint("mirror", "root", _root(front.port), H, front.port)
    try:
        yield ep
    finally:
        harness.close()


# ===========================================================================
# Shared assertions
# ===========================================================================

def _unique(prefix):
    return f"/{prefix}_{os.getpid()}_{int(time.time() * 1000) & 0xFFFFFF}.bin"


def _ensure(ep):
    if not _reachable(ep.host, ep.port):
        pytest.skip(f"{ep.topo}/{ep.proto} endpoint {ep.host}:{ep.port} unreachable")
    return _driver(ep.proto)


def _guard(ep, fn):
    """Run fn(); for best-effort endpoints turn an EndpointError (topology not
    fully wired in this fleet) into a skip.  Byte/checksum asserts are not
    EndpointErrors, so they always surface as real failures."""
    try:
        return fn()
    except EndpointError as exc:
        if ep.best_effort:
            pytest.skip(f"{ep.topo}/{ep.proto} backing not available: {exc}")
        raise


def _seed(ep, drv, path, data):
    """Place `data` at `path` so it is readable through `ep`."""
    if ep.can_write:
        _guard(ep, lambda: drv.write(ep.locator, path, data))
    elif ep.seed_locator:
        # Seeding goes to the writable origin; a dead origin is a hard error
        # for non-best-effort endpoints (the test could not run as designed).
        _guard(ep, lambda: drv.write(ep.seed_locator, path, data))
    else:
        pytest.skip(f"{ep.topo}/{ep.proto} is read-only with no seed origin")


def _assert_vector(result_segs, want_data):
    result, segs = result_segs
    assert len(result) == len(segs), "vector read returned wrong segment count"
    for (off, got), (req_off, req_len) in zip(result, segs):
        assert got == want_data[req_off:req_off + req_len], \
            f"vector segment at {req_off} mismatch"


# ===========================================================================
# Parametrization
# ===========================================================================

def _ids(eps):
    return [f"{e.topo}-{e.proto}" for e in eps]


ALL_FIXED = ROOT_ENDPOINTS + HTTP_ENDPOINTS

@pytest.fixture(scope="session")
def proxy_chain():
    """storage(nginx) <- proxy(nginx) <- mesh(nginx); yield locator URLs.

    All three hops are throwaway registry instances (LifecycleHarness): the
    harness renders the committed nginx_integrity_proxy_{storage,hop}.conf
    templates, runs `nginx -t`, waits for each to be TCP-ready, and reaps them
    on close().  Each proxy hop's brix_tap_proxy_upstream is wired to the previous
    hop's assigned port via template_values."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    harness = LifecycleHarness()
    try:
        storage = harness.start(NginxInstanceSpec(
            name="im-proxy-storage",
            template="nginx_integrity_proxy_storage.conf",
            protocol="root",
            port=_pinned_port("TEST_IM_PROXY_STORAGE_PORT"),
            readiness="tcp",
            reason="integrity-matrix pure-nginx proxy chain storage origin"))
        hop1 = harness.start(NginxInstanceSpec(
            name="im-proxy-hop1",
            template="nginx_integrity_proxy_hop.conf",
            protocol="root",
            port=_pinned_port("TEST_IM_PROXY_HOP1_PORT"),
            readiness="tcp",
            template_values={"UPSTREAM": f"{HOST}:{storage.port}"},
            reason="integrity-matrix proxy chain hop 1 (one-hop proxy)"))
        hop2 = harness.start(NginxInstanceSpec(
            name="im-proxy-hop2",
            template="nginx_integrity_proxy_hop.conf",
            protocol="root",
            port=_pinned_port("TEST_IM_PROXY_HOP2_PORT"),
            readiness="tcp",
            template_values={"UPSTREAM": f"{HOST}:{hop1.port}"},
            reason="integrity-matrix proxy chain hop 2 (two-hop mesh)"))
    except Exception as exc:
        harness.close()
        pytest.skip(f"proxy-chain servers did not start: {str(exc)[-300:]}")

    info = {
        "storage": _root(storage.port),
        "proxy":   _root(hop1.port),
        "mesh":    _root(hop2.port),
    }
    try:
        yield info
    finally:
        harness.close()


# All user-facing kXR_query infotypes the client can issue.  Path-bearing ones
# get the seeded path; the rest a server-level argument.
from XRootD.client.flags import QueryCode  # noqa: E402

_QUERY_CASES = [
    ("CHECKSUM", QueryCode.CHECKSUM, "path"),
    ("XATTR",    QueryCode.XATTR,    "path"),
    ("CONFIG",   QueryCode.CONFIG,   "bind_max"),
    ("SPACE",    QueryCode.SPACE,    "path"),
    ("STATS",    QueryCode.STATS,    "a"),
    ("OPAQUE",   QueryCode.OPAQUE,   "path"),
    ("VISA",     QueryCode.VISA,     "path"),
    ("PREPARE",  QueryCode.PREPARE,  "path"),
]
