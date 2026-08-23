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

import base64
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
        if not real_bindings_available():
            raise RuntimeError("real libXrdCl bindings unavailable")

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

    @staticmethod
    def _vector_segments(size):
        candidates = [(0, 100), (1000, 512), (size - 200, 200)]
        return [(offset, length) for offset, length in candidates
                if offset + length <= size]

    @staticmethod
    def _require_partial_response(response):
        if response.status_code == 200:
            pytest.skip("server returned full body — no multi-range support")
        assert response.status_code == 206, f"ranged GET {response.status_code}"

    @staticmethod
    def _multipart_parts(response, content_type, segments):
        if "multipart/byteranges" not in content_type:
            pytest.skip("server collapsed multi-range to a single range")
        message = BytesParser(policy=email_default).parsebytes(
            b"Content-Type: " + content_type.encode() + b"\r\n\r\n"
            + response.content)
        parts = list(message.iter_parts())
        assert len(parts) == len(segments), (
            f"expected {len(segments)} ranges, got {len(parts)}")
        return parts

    @staticmethod
    def _decoded_ranges(segments, parts):
        return [(offset, part.get_payload(decode=True))
                for (offset, _length), part in zip(segments, parts)]

    def read_vector(self, locator, path, size):
        segments = self._vector_segments(size)
        ranges = ", ".join(
            f"{offset}-{offset + length - 1}" for offset, length in segments)
        response = requests.get(
            self._url(locator, path), headers={"Range": f"bytes={ranges}"},
            verify=self.verify, timeout=30)
        self._require_partial_response(response)
        content_type = response.headers.get("Content-Type", "")
        parts = self._multipart_parts(response, content_type, segments)
        return self._decoded_ranges(segments, parts), segments

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
        for token in dig.split(","):
            result = self._digest_result(token, data)
            if result is not None:
                return result
        return None

    @staticmethod
    def _digest_result(token, data):
        if "=" not in token:
            return None
        algorithm, value = token.split("=", 1)
        name = algorithm.strip().lower()
        handlers = {
            "md5": WebDAVDriver._md5_digest,
            "sha-256": WebDAVDriver._sha256_digest,
            "sha256": WebDAVDriver._sha256_digest,
            "adler32": WebDAVDriver._adler32_digest,
        }
        handler = handlers.get(name)
        if handler is None:
            return None
        return handler(value.strip(), data)

    @staticmethod
    def _md5_digest(value, data):
        expected = base64.b64encode(hashlib.md5(data).digest()).decode()
        return "md5", value, expected

    @staticmethod
    def _sha256_digest(value, data):
        expected = base64.b64encode(hashlib.sha256(data).digest()).decode()
        return "sha-256", value, expected

    @staticmethod
    def _adler32_digest(value, data):
        expected = f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
        return "adler32", value.lower(), expected


# CRC-64/NVME (AWS x-amz-checksum-crc64nvme): reflected in/out, init/xorout
# all-FF, reflected polynomial 0x9A6C9329AC4BC9B5 (normal form 0xAD93D23594C93659)
# — the exact variant src/core/compat/crc64.c serves to the S3 front.
_CRC64NVME_POLY_REFL = 0x9A6C9329AC4BC9B5
_CRC64NVME_TABLE = []
for _b in range(256):
    _c = _b
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC64NVME_POLY_REFL if _c & 1 else _c >> 1
    _CRC64NVME_TABLE.append(_c)
del _b, _c


def _crc64nvme(data):
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc = _CRC64NVME_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFFFFFFFFFF


class S3Driver(_HTTPDriver):
    proto = "s3"

    def _url(self, locator, path):
        # locator is the S3 base URL; objects live under the bucket.
        return f"{locator}/{S3_BUCKET}/{path.lstrip('/')}"

    def checksum(self, locator, path, data):
        import base64
        r = requests.head(self._url(locator, path), verify=self.verify,
                          timeout=30)
        # Primary: the full-object CRC-64/NVME the S3 front echoes verbatim
        # (base64 of the 8-byte big-endian CRC) on PUT/HEAD/GET.
        server = r.headers.get("x-amz-checksum-crc64nvme")
        if server:
            want = base64.b64encode(_crc64nvme(data).to_bytes(8, "big")).decode()
            return "crc64nvme", server, want
        # Fallback: a non-multipart ETag is the hex MD5 of the object.
        etag = r.headers.get("ETag")
        if etag:
            etag = etag.strip('"')
            if "-" not in etag:
                return "md5(etag)", etag.lower(), hashlib.md5(data).hexdigest()
        return None


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
#   mirror-front (storage + brix_stream_mirror_url -> sink)  <- client I/O
# The client reads/writes the front; integrity must be unaffected by mirroring.
# ===========================================================================

def _pinned_port(env_var):
    """Honor an explicit port pin (env), else let the registry assign one."""
    value = os.environ.get(env_var)
    return int(value) if value else None


# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_integrity_matrix_helpers_b")
