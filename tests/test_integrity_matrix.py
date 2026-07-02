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

from settings import (
    CACHE_ONLY_PORT,
    CHAOS_TIER1_PORT,
    CLUSTER_REDIR_PORT,
    DATA_ROOT,
    HOST,
    MANAGER_PORT,
    NGINX_ANON_PORT,
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

NGINX_BIN = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")

# Deterministic-but-distinct payloads.  Sizes chosen to span multiple read
# chunks and a non-page-aligned tail.
def _payload(seed, size):
    return bytes((i * (seed | 1) + seed) & 0xFF for i in range(size))


SMALL = _payload(0x11, 4096)
BIG   = _payload(0x57, 5 * 1024 * 1024 + 777)   # > 4 MiB read cap, unaligned


def _reachable(host, port, timeout=2.0):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


class EndpointError(Exception):
    """A protocol-level failure reaching/serving an endpoint (NOT a byte
    mismatch).  Best-effort endpoints turn this into a skip; the byte-exact and
    checksum assertions stay hard failures."""


# ===========================================================================
# Protocol drivers — each implements write / read_scalar / read_vector /
# checksum against an endpoint locator, returning (algo, server_hex, want_hex)
# from checksum() or None when the endpoint offers no checksum.
# ===========================================================================

class RootDriver:
    """root:// via the XRootD python client."""

    proto = "root"
    supports_vector = True

    def __init__(self):
        from XRootD import client  # noqa: F401  (import-time availability check)

    def _file(self):
        from XRootD import client
        return client.File()

    def write(self, locator, path, data):
        from XRootD.client.flags import OpenFlags
        f = self._file()
        st, _ = f.open(f"{locator}//{path.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
        if not st.ok:
            raise EndpointError(f"open(NEW) failed: {st.message}")
        if data:
            st, _ = f.write(data)
            if not st.ok:
                raise EndpointError(f"write failed: {st.message}")
        st, _ = f.close()
        if not st.ok:
            raise EndpointError(f"close failed: {st.message}")

    def read_scalar(self, locator, path, size):
        from XRootD.client.flags import OpenFlags
        f = self._file()
        st, _ = f.open(f"{locator}//{path.lstrip('/')}", OpenFlags.READ)
        if not st.ok:
            raise EndpointError(f"open(READ) failed: {st.message}")
        out = bytearray()
        off = 0
        while off < size:
            st, chunk = f.read(offset=off, size=min(1 << 20, size - off))
            if not st.ok:
                raise EndpointError(f"read failed at {off}: {st.message}")
            if not chunk:
                break
            out.extend(chunk)
            off += len(chunk)
        f.close()
        return bytes(out)

    def read_vector(self, locator, path, size):
        from XRootD.client.flags import OpenFlags
        # Scatter the read into non-contiguous segments and reassemble in order.
        segs = [(0, 100), (1000, 512), (size // 2, 4096),
                (size - 200, 200)]
        segs = [(o, n) for (o, n) in segs if o + n <= size]
        f = self._file()
        st, _ = f.open(f"{locator}//{path.lstrip('/')}", OpenFlags.READ)
        if not st.ok:
            raise EndpointError(f"open(READ) failed: {st.message}")
        st, result = f.vector_read(segs)
        f.close()
        if not st.ok:
            raise EndpointError(f"vector_read failed: {st.message}")
        return [(c.offset, bytes(c.buffer)) for c in result], segs

    def checksum(self, locator, path, data):
        from XRootD import client
        from XRootD.client.flags import QueryCode
        fs = client.FileSystem(locator)
        st, resp = fs.query(QueryCode.CHECKSUM, path.lstrip("/"))
        if not st.ok or not resp:
            return None  # topology/endpoint offers no checksum query
        text = resp.decode(errors="replace").strip().split("\x00")[0]
        parts = text.split()
        if len(parts) < 2:
            return None
        algo, hexval = parts[0], parts[1]
        if algo == "adler32":
            return algo, hexval.lower(), f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
        if algo == "crc32c":
            return None  # accepted, but we don't recompute crc32c here
        try:
            want = {"md5": hashlib.md5, "sha1": hashlib.sha1,
                    "sha256": hashlib.sha256}[algo](data).hexdigest()
        except KeyError:
            return None
        return algo, hexval.lower(), want


class _HTTPDriver:
    """Shared GET/PUT/Range/Digest logic for WebDAV and S3."""

    supports_vector = True
    verify = False

    def _url(self, locator, path):
        raise NotImplementedError

    def write(self, locator, path, data):
        r = requests.put(self._url(locator, path), data=data,
                         verify=self.verify, timeout=30)
        if r.status_code not in (200, 201, 204):
            raise EndpointError(f"PUT {r.status_code}: {r.text[:200]}")

    def read_scalar(self, locator, path, size):
        r = requests.get(self._url(locator, path), verify=self.verify,
                         timeout=30)
        if r.status_code != 200:
            raise EndpointError(f"GET {r.status_code}")
        return r.content

    def read_vector(self, locator, path, size):
        segs = [(0, 100), (1000, 512), (size - 200, 200)]
        segs = [(o, n) for (o, n) in segs if o + n <= size]
        rng = ", ".join(f"{o}-{o + n - 1}" for o, n in segs)
        r = requests.get(self._url(locator, path),
                         headers={"Range": f"bytes={rng}"},
                         verify=self.verify, timeout=30)
        if r.status_code == 200:
            pytest.skip("server returned full body — no multi-range support")
        assert r.status_code == 206, f"ranged GET {r.status_code}"
        ctype = r.headers.get("Content-Type", "")
        out = []
        if "multipart/byteranges" in ctype:
            boundary = ctype.split("boundary=")[1].strip()
            msg = BytesParser(policy=email_default).parsebytes(
                b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + r.content)
            parts = [p for p in msg.iter_parts()]
            assert len(parts) == len(segs), \
                f"expected {len(segs)} ranges, got {len(parts)}"
            for (o, n), part in zip(segs, parts):
                out.append((o, part.get_payload(decode=True)))
        else:
            # Single 206 covering one range only — not a true vector read.
            pytest.skip("server collapsed multi-range to a single range")
        return out, segs

    def checksum(self, locator, path, data):
        raise NotImplementedError


class WebDAVDriver(_HTTPDriver):
    proto = "webdav"

    def _url(self, locator, path):
        return f"{locator}/{path.lstrip('/')}"

    def checksum(self, locator, path, data):
        r = requests.get(self._url(locator, path),
                         headers={"Want-Digest": "adler32, md5, sha-256"},
                         verify=self.verify, timeout=30)
        dig = r.headers.get("Digest") or r.headers.get("Want-Digest")
        if not dig:
            return None  # server advertises no RFC-3230 digest
        # Digest: adler32=...,md5=base64,sha-256=base64
        import base64
        for token in dig.split(","):
            if "=" not in token:
                continue
            algo, val = token.split("=", 1)
            algo = algo.strip().lower()
            val = val.strip()
            if algo == "md5":
                want = base64.b64encode(hashlib.md5(data).digest()).decode()
                return "md5", val, want
            if algo in ("sha-256", "sha256"):
                want = base64.b64encode(hashlib.sha256(data).digest()).decode()
                return "sha-256", val, want
            if algo == "adler32":
                return "adler32", val.lower(), \
                    f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
        return None


class S3Driver(_HTTPDriver):
    proto = "s3"

    def _url(self, locator, path):
        # locator is the S3 base URL; objects live under the bucket.
        return f"{locator}/{S3_BUCKET}/{path.lstrip('/')}"

    def checksum(self, locator, path, data):
        r = requests.head(self._url(locator, path), verify=self.verify,
                          timeout=30)
        etag = r.headers.get("ETag")
        if not etag:
            return None
        etag = etag.strip('"')
        # Non-multipart S3 ETag is the hex MD5 of the object.
        if "-" in etag:
            return None  # multipart upload ETag — not a plain md5
        return "md5(etag)", etag.lower(), hashlib.md5(data).hexdigest()


# ===========================================================================
# Topology registry
# ===========================================================================

H = SERVER_HOST


@dataclass
class Endpoint:
    topo: str            # topology category
    proto: str           # root | webdav | s3
    locator: str         # client-facing base (root url / http base / s3 base)
    host: str
    port: int
    can_write: bool = True
    # For read-only endpoints (caches/redirectors that don't accept writes),
    # seed the file through this writable sibling locator first.
    seed_locator: str = ""
    # Best-effort endpoints whose full backing mesh may not be wired in the
    # running fleet subset: seed/read failures become a skip, not a failure.
    # (Byte-exact and checksum mismatches always remain hard failures.)
    best_effort: bool = False


def _root(port):
    return f"root://{H}:{port}"


def _https(port):
    return f"https://{H}:{port}"


def _http(port):
    return f"http://{H}:{port}"


# root:// topologies — storage reached directly and behind every mesh variant.
ROOT_ENDPOINTS = [
    Endpoint("direct",            "root", _root(NGINX_ANON_PORT), H, NGINX_ANON_PORT),
    Endpoint("proxy",             "root", _root(PROXY_NGINX_PORT), H, PROXY_NGINX_PORT),
    Endpoint("pure-nginx-mesh",   "root", _root(PROXY_PURE_NGINX_PROXY_PORT), H, PROXY_PURE_NGINX_PROXY_PORT),
    Endpoint("cluster-cms",       "root", _root(CLUSTER_REDIR_PORT), H, CLUSTER_REDIR_PORT),
    Endpoint("wt-cache",          "root", _root(WT_SYNC_PORT), H, WT_SYNC_PORT),
    Endpoint("rt-cache",          "root", _root(CACHE_ONLY_PORT), H, CACHE_ONLY_PORT,
             can_write=False, seed_locator=_root(NGINX_ANON_PORT)),
    # Static virtual-redirector: maps every path to the anon origin but performs
    # a local existence lookup before redirecting and has no data root of its
    # own, so arbitrary seeded files are not surfaced in this harness — best
    # effort.  (CMS-redirector integrity is covered concretely by cluster-cms.)
    Endpoint("redirector",        "root", _root(VIRTUAL_REDIR_PORT), H, VIRTUAL_REDIR_PORT,
             can_write=False, seed_locator=_root(NGINX_ANON_PORT), best_effort=True),
    # Head-node (static-map manager -> reference daemons) and the 3-tier
    # proxy->cache->storage mesh need their full backing up (ref daemon / tier3),
    # which the minimal `start` fleet does not provide — best-effort.
    Endpoint("head-node-manager", "root", _root(MANAGER_PORT), H, MANAGER_PORT,
             can_write=False, seed_locator=_root(NGINX_ANON_PORT), best_effort=True),
    Endpoint("3tier-mesh",        "root", _root(CHAOS_TIER1_PORT), H, CHAOS_TIER1_PORT,
             can_write=False, seed_locator=_root(NGINX_ANON_PORT), best_effort=True),
]

# https/davs + s3 topologies (the protocols only their fronts expose).
HTTP_ENDPOINTS = [
    Endpoint("direct",     "webdav", _https(NGINX_WEBDAV_PORT), H, NGINX_WEBDAV_PORT),
    Endpoint("http-proxy", "webdav", _http(NGINX_HTTP_WEBDAV_PORT), H, NGINX_HTTP_WEBDAV_PORT),
    Endpoint("direct",     "s3",     _http(NGINX_S3_PORT), H, NGINX_S3_PORT),
]

DRIVERS = {"root": None, "webdav": None, "s3": None}  # lazy-instantiated


def _driver(proto):
    if DRIVERS[proto] is None:
        try:
            DRIVERS[proto] = {"root": RootDriver, "webdav": WebDAVDriver,
                              "s3": S3Driver}[proto]()
        except Exception as exc:  # e.g. XRootD client not installed
            pytest.skip(f"{proto} driver unavailable: {exc}")
    return DRIVERS[proto]


# ===========================================================================
# Mirror fixture — the fleet has no mirror server, so provision one:
#   origin-sink (storage)  <- mirrored shadow traffic
#   mirror-front (storage + xrootd_stream_mirror_url -> sink)  <- client I/O
# The client reads/writes the front; integrity must be unaffected by mirroring.
# ===========================================================================

MIRROR_FRONT_PORT = int(os.environ.get("TEST_MIRROR_FRONT_PORT") or free_port())
MIRROR_SINK_PORT  = int(os.environ.get("TEST_MIRROR_SINK_PORT") or free_port())
_MIRROR_DIR = os.path.join(os.environ["TMPDIR"], "xrd_mirror_rt")


@pytest.fixture(scope="session")
def mirror_endpoint():
    """Stand up a transparent stream-mirror server; yield its root Endpoint."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    data = os.path.join(_MIRROR_DIR, "data")
    sink_data = os.path.join(_MIRROR_DIR, "sink_data")
    for d in (data, sink_data,
              os.path.join(_MIRROR_DIR, "front-run", "logs"),
              os.path.join(_MIRROR_DIR, "sink-run", "logs")):
        os.makedirs(d, exist_ok=True)

    sink_conf = os.path.join(_MIRROR_DIR, "sink.conf")
    front_conf = os.path.join(_MIRROR_DIR, "front.conf")
    with open(sink_conf, "w") as f:
        f.write(f"""\
error_log {_MIRROR_DIR}/sink-run/logs/error.log info;
pid {_MIRROR_DIR}/sink-run/nginx.pid;
events {{}}
stream {{
    server {{
        listen 0.0.0.0:{MIRROR_SINK_PORT};
        xrootd on; xrootd_storage_backend posix:{sink_data}; xrootd_auth none;
        xrootd_allow_write on;
    }}
}}
""")
    with open(front_conf, "w") as f:
        f.write(f"""\
error_log {_MIRROR_DIR}/front-run/logs/error.log info;
pid {_MIRROR_DIR}/front-run/nginx.pid;
events {{}}
stream {{
    server {{
        listen 0.0.0.0:{MIRROR_FRONT_PORT};
        xrootd on; xrootd_storage_backend posix:{data}; xrootd_auth none;
        xrootd_allow_write on;
        xrootd_stream_mirror_url {H}:{MIRROR_SINK_PORT};
        xrootd_mirror_opcodes open read readv stat;
    }}
}}
""")

    procs = []
    for conf in (sink_conf, front_conf):
        chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                             capture_output=True, text=True)
        if chk.returncode != 0:
            pytest.skip(f"mirror config rejected: {chk.stderr[-300:]}")
        subprocess.run([NGINX_BIN, "-c", conf], capture_output=True, text=True)
        procs.append(conf)

    # Wait for the front to accept connections.
    for _ in range(50):
        if _reachable(H, MIRROR_FRONT_PORT, 0.5):
            break
        time.sleep(0.1)
    else:
        for conf in procs:
            subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"],
                           capture_output=True)
        pytest.skip("mirror front did not come up")

    ep = Endpoint("mirror", "root", _root(MIRROR_FRONT_PORT), H, MIRROR_FRONT_PORT)
    yield ep

    for conf in procs:
        subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)


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


@pytest.mark.parametrize("ep", ALL_FIXED, ids=_ids(ALL_FIXED))
class TestFixedTopologies:
    """Direct + every fleet mesh variant (proxy, redirector, manager, cluster,
    caches, 3-tier) for the protocols each front exposes."""

    def test_write_read_scalar_byte_exact(self, ep):
        drv = _ensure(ep)
        path = _unique(f"int_{ep.topo}_{ep.proto}_scalar")
        data = BIG
        _seed(ep, drv, path, data)
        got = _guard(ep, lambda: drv.read_scalar(ep.locator, path, len(data)))
        assert got == data, \
            f"{ep.topo}/{ep.proto}: {len(got)}B read != {len(data)}B written"

    def test_read_vector_byte_exact(self, ep):
        drv = _ensure(ep)
        if not getattr(drv, "supports_vector", False):
            pytest.skip("protocol has no vector read")
        path = _unique(f"int_{ep.topo}_{ep.proto}_vec")
        data = BIG
        _seed(ep, drv, path, data)
        res = _guard(ep, lambda: drv.read_vector(ep.locator, path, len(data)))
        _assert_vector(res, data)

    def test_checksum_matches(self, ep):
        drv = _ensure(ep)
        path = _unique(f"int_{ep.topo}_{ep.proto}_cks")
        data = SMALL
        _seed(ep, drv, path, data)
        result = _guard(ep, lambda: drv.checksum(ep.locator, path, data))
        if result is None:
            pytest.skip(f"{ep.topo}/{ep.proto} exposes no verifiable checksum")
        algo, server_hex, want_hex = result
        assert server_hex == want_hex, \
            f"{ep.topo}/{ep.proto} {algo}: server={server_hex} expected={want_hex}"


# ===========================================================================
# Mirror topology (self-provisioned)
# ===========================================================================

class TestMirrorTopology:
    """A transparent stream-mirror server: client integrity must be unaffected
    by the shadow traffic, for scalar read, vector read, write, and checksum."""

    def test_write_read_scalar_byte_exact(self, mirror_endpoint):
        ep = mirror_endpoint
        drv = _ensure(ep)
        path = _unique("int_mirror_scalar")
        drv.write(ep.locator, path, BIG)
        assert drv.read_scalar(ep.locator, path, len(BIG)) == BIG

    def test_read_vector_byte_exact(self, mirror_endpoint):
        ep = mirror_endpoint
        drv = _ensure(ep)
        path = _unique("int_mirror_vec")
        drv.write(ep.locator, path, BIG)
        _assert_vector(drv.read_vector(ep.locator, path, len(BIG)), BIG)

    def test_checksum_matches(self, mirror_endpoint):
        ep = mirror_endpoint
        drv = _ensure(ep)
        path = _unique("int_mirror_cks")
        drv.write(ep.locator, path, SMALL)
        result = drv.checksum(ep.locator, path, SMALL)
        if result is None:
            pytest.skip("mirror front exposes no checksum query")
        algo, server_hex, want_hex = result
        assert server_hex == want_hex, \
            f"mirror {algo}: server={server_hex} expected={want_hex}"


# ===========================================================================
# Pure-nginx proxy chain (self-provisioned) — storage -> proxy -> mesh
# ===========================================================================
#
# The fleet's proxy/mesh terminate at a checksum-less reference xrootd, so their
# checksum cells skip above.  Here every hop is nginx (which DOES compute
# checksums), proving that the transparent proxy forwards byte-exact data AND
# every user query — checksum included — through one and two proxy hops.

PROXY_STORAGE_PORT = int(os.environ.get("TEST_IM_PROXY_STORAGE_PORT") or free_port())
PROXY_HOP1_PORT    = int(os.environ.get("TEST_IM_PROXY_HOP1_PORT") or free_port())
PROXY_HOP2_PORT    = int(os.environ.get("TEST_IM_PROXY_HOP2_PORT") or free_port())
_PROXY_DIR = os.path.join(os.environ["TMPDIR"], "xrd_proxychain_rt")


@pytest.fixture(scope="session")
def proxy_chain():
    """storage(nginx) <- proxy(nginx) <- mesh(nginx); yield locator URLs."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    data = os.path.join(_PROXY_DIR, "data")
    confs = {
        "storage": (PROXY_STORAGE_PORT, f"""\
        xrootd on; xrootd_storage_backend posix:{data}; xrootd_auth none;
        xrootd_allow_write on;"""),
        "hop1": (PROXY_HOP1_PORT, f"""\
        xrootd on; xrootd_auth none;
        xrootd_proxy on; xrootd_proxy_upstream {HOST}:{PROXY_STORAGE_PORT};"""),
        "hop2": (PROXY_HOP2_PORT, f"""\
        xrootd on; xrootd_auth none;
        xrootd_proxy on; xrootd_proxy_upstream {HOST}:{PROXY_HOP1_PORT};"""),
    }
    os.makedirs(data, exist_ok=True)
    started = []
    for name, (port, body) in confs.items():
        run = os.path.join(_PROXY_DIR, f"{name}-run", "logs")
        os.makedirs(run, exist_ok=True)
        conf = os.path.join(_PROXY_DIR, f"{name}.conf")
        with open(conf, "w") as f:
            f.write(f"error_log {os.path.dirname(run)}/logs/error.log info;\n"
                    f"pid {os.path.dirname(run)}/nginx.pid;\nevents {{}}\n"
                    f"stream {{\n    server {{\n        listen 0.0.0.0:{port};\n"
                    f"{body}\n    }}\n}}\n")
        chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                             capture_output=True, text=True)
        if chk.returncode != 0:
            for c2 in started:
                subprocess.run([NGINX_BIN, "-c", c2, "-s", "stop"],
                               capture_output=True)
            pytest.skip(f"proxy-chain config rejected: {chk.stderr[-300:]}")
        subprocess.run([NGINX_BIN, "-c", conf], capture_output=True)
        started.append(conf)

    for port in (PROXY_STORAGE_PORT, PROXY_HOP1_PORT, PROXY_HOP2_PORT):
        for _ in range(50):
            if _reachable(H, port, 0.5):
                break
            time.sleep(0.1)
        else:
            for c2 in started:
                subprocess.run([NGINX_BIN, "-c", c2, "-s", "stop"],
                               capture_output=True)
            pytest.skip(f"proxy-chain port {port} did not come up")

    info = {
        "storage": _root(PROXY_STORAGE_PORT),
        "proxy":   _root(PROXY_HOP1_PORT),
        "mesh":    _root(PROXY_HOP2_PORT),
    }
    yield info

    for c2 in started:
        subprocess.run([NGINX_BIN, "-c", c2, "-s", "stop"], capture_output=True)


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


class TestProxyChainQueries:
    """Byte-exact + checksum integrity AND full query forwarding through a
    one-hop proxy and a two-hop pure-nginx mesh."""

    def _query(self, url, code, arg):
        from XRootD import client
        fs = client.FileSystem(url)
        st, resp = fs.query(code, arg)
        return st.ok, (bytes(resp) if resp else b"")

    @pytest.fixture(autouse=True)
    def _seed(self, proxy_chain):
        self.urls = proxy_chain
        self.drv = _driver("root")
        self.path = _unique("int_proxychain")
        self.drv.write(proxy_chain["storage"], self.path, BIG)

    # --- integrity through proxy / mesh ---

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    def test_scalar_byte_exact(self, hop):
        got = self.drv.read_scalar(self.urls[hop], self.path, len(BIG))
        assert got == BIG

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    def test_vector_byte_exact(self, hop):
        _assert_vector(self.drv.read_vector(self.urls[hop], self.path, len(BIG)),
                       BIG)

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    def test_checksum_matches(self, hop):
        result = self.drv.checksum(self.urls[hop], self.path, BIG)
        assert result is not None, f"checksum not forwarded through {hop}"
        algo, server_hex, want_hex = result
        assert server_hex == want_hex, \
            f"{hop} {algo}: server={server_hex} expected={want_hex}"

    # --- ALL user queries forward identically through proxy / mesh ---

    @pytest.mark.parametrize("hop", ["proxy", "mesh"])
    @pytest.mark.parametrize("name,code,argkind", _QUERY_CASES,
                             ids=[q[0] for q in _QUERY_CASES])
    def test_query_forwarded(self, hop, name, code, argkind):
        """Every query must reach the backend: the result through the proxy/mesh
        must equal the result of the same query issued directly to storage —
        proving the proxy forwards it rather than answering or rejecting locally."""
        arg = self.path.lstrip("/") if argkind == "path" else argkind
        direct_ok, direct_resp = self._query(self.urls["storage"], code, arg)
        hop_ok, hop_resp = self._query(self.urls[hop], code, arg)
        assert hop_ok == direct_ok, (
            f"{name} status differs through {hop}: "
            f"direct_ok={direct_ok} {hop}_ok={hop_ok} "
            f"(proxy rejected/handled locally instead of forwarding)")
        if direct_ok and name in ("CHECKSUM", "XATTR", "CONFIG"):
            # Deterministic responses must match byte-for-byte through the proxy.
            assert hop_resp == direct_resp, \
                f"{name} response differs through {hop}"
