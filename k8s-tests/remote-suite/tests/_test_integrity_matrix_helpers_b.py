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
import subprocess
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
    free_port,
)

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# This matrix drives stateful mesh/cluster/proxy/mirror topologies (cluster-cms
# redirector, 3-tier chaos mesh, mirror front/sink, proxy chains). Under the
# parallel bulk lane those shared backends are contended by co-executing suites,
# which flaked TestMirrorTopology and the cluster-cms endpoint (both pass in
# isolation). Mark the module `serial` so conftest pins it to the isolated serial
# lane — the same pattern test_conformance_topologies / test_cms_mesh_interop use.
pytestmark = [pytest.mark.serial]

# Deterministic-but-distinct payloads.  Sizes chosen to span multiple read
# chunks and a non-page-aligned tail.
def _selected_port(environment_name):
    value = os.environ.get(environment_name)
    return int(value) if value else free_port()


class _StandaloneNginxGroup:
    def __init__(self, name):
        temp_root = os.environ.get("TMPDIR", "/tmp")
        self.root = os.path.join(temp_root, name)
        self.configs = []

    def _config_path(self, name, port, body):
        run = os.path.join(self.root, f"{name}-run")
        os.makedirs(os.path.join(run, "logs"), exist_ok=True)
        config = os.path.join(self.root, f"{name}.conf")
        text = (
            f"error_log {run}/logs/error.log info;\n"
            f"pid {run}/nginx.pid;\nevents {{}}\nstream {{\n"
            f"    server {{\n        listen 0.0.0.0:{port};\n"
            f"{body}\n    }}\n}}\n")
        with open(config, "w") as stream:
            stream.write(text)
        return config

    @staticmethod
    def _validate(config):
        result = subprocess.run(
            [NGINX_BIN, "-t", "-c", config], capture_output=True, text=True)
        if result.returncode != 0:
            pytest.skip(f"nginx config rejected: {result.stderr[-300:]}")

    def _wait_ready(self, port):
        for _attempt in range(50):
            if _reachable(H, port, 0.5):
                return
            time.sleep(0.1)
        self.close()
        pytest.skip(f"nginx port {port} did not come up")

    def start(self, name, port, body):
        config = self._config_path(name, port, body)
        self._validate(config)
        subprocess.run([NGINX_BIN, "-c", config], capture_output=True)
        self.configs.append(config)
        self._wait_ready(port)

    def close(self):
        for config in self.configs:
            subprocess.run(
                [NGINX_BIN, "-c", config, "-s", "stop"], capture_output=True)


def _start_mirror_group(group):
    sink_port = _selected_port("TEST_MIRROR_SINK_PORT")
    front_port = _selected_port("TEST_MIRROR_FRONT_PORT")
    sink_data = os.path.join(group.root, "sink_data")
    front_data = os.path.join(group.root, "data")
    os.makedirs(sink_data, exist_ok=True)
    os.makedirs(front_data, exist_ok=True)
    sink_body = (
        f"        brix_root on; brix_storage_backend posix:{sink_data};\n"
        "        brix_auth none; brix_allow_write on;")
    front_body = (
        f"        brix_root on; brix_storage_backend posix:{front_data};\n"
        "        brix_auth none; brix_allow_write on;\n"
        f"        brix_stream_mirror_url {H}:{sink_port};\n"
        "        brix_mirror_opcodes open read readv stat;")
    group.start("sink", sink_port, sink_body)
    group.start("front", front_port, front_body)
    return front_port


@pytest.fixture(scope="session")
def mirror_endpoint():
    """Stand up a transparent stream-mirror server."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    group = _StandaloneNginxGroup("xrd_mirror_rt")
    try:
        front_port = _start_mirror_group(group)
        yield Endpoint("mirror", "root", _root(front_port), H, front_port)
    finally:
        group.close()


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

def _start_proxy_group(group):
    ports = {
        "storage": _selected_port("TEST_IM_PROXY_STORAGE_PORT"),
        "proxy": _selected_port("TEST_IM_PROXY_HOP1_PORT"),
        "mesh": _selected_port("TEST_IM_PROXY_HOP2_PORT"),
    }
    data = os.path.join(group.root, "data")
    os.makedirs(data, exist_ok=True)
    storage_body = (
        f"        brix_root on; brix_storage_backend posix:{data};\n"
        "        brix_auth none; brix_allow_write on;")
    proxy_body = (
        "        brix_root on; brix_auth none; brix_proxy on;\n"
        f"        brix_proxy_upstream {HOST}:{ports['storage']};")
    mesh_body = (
        "        brix_root on; brix_auth none; brix_proxy on;\n"
        f"        brix_proxy_upstream {HOST}:{ports['proxy']};")
    group.start("storage", ports["storage"], storage_body)
    group.start("proxy", ports["proxy"], proxy_body)
    group.start("mesh", ports["mesh"], mesh_body)
    return {name: _root(port) for name, port in ports.items()}


@pytest.fixture(scope="session")
def proxy_chain():
    """Stand up a storage/proxy/mesh chain and return its locators."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    group = _StandaloneNginxGroup("xrd_proxychain_rt")
    try:
        endpoints = _start_proxy_group(group)
        yield endpoints
    finally:
        group.close()


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
