"""_cachemx.py — shared plumbing for the BriX-Cache Prometheus conformance
suite (test_cachemx_*.py).

WHAT: One module-scoped stack of private lifecycle nginx instances (an anon
      posix origin + a multi-plane cache matrix) plus per-instance /metrics
      snapshot helpers and protocol drivers for every plane the suite covers:
      root:// {none,gsi,token,sss}, WebDAV {plain,TLS+token,TLS+cert-required},
      and S3 {anonymous,SigV4}.

WHY:  Metric-accuracy assertions (exact query counts, exact byte tallies) need
      a serialized private server whose counters only this suite moves — the
      shared fleet would race.  All test files pin
      pytest.mark.xdist_group("lc-cachemx") so the fixed shared-band ports in
      fleet_lifecycle_ports never have two concurrent drivers.

HOW:  start_stack() boots the origin then the matrix (caches fill from the
      origin over root://), mints a throwaway SSS keytab, and hands back a
      MatrixStack with url/env builders per plane.  Snap binds the
      metrics_helpers parser to one instance's /metrics URL; byte counters
      flush at TCP disconnect, so drivers run as subprocesses and byte
      assertions call settle() before re-scraping.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

import pytest

from metrics_helpers import scalar, value
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from brix_suite.settings import TESTS_DIR
from settings import (
    BIND_HOST,
    CA_CERT,
    CA_DIR,
    HOST,
    NGINX_BIN,
    PKI_DIR,
    PROXY_STD,
    TOKENS_DIR,
)

# Anchored on the suite root ``brix_suite.settings`` *searches* for, not on
# this file's parents.  Two parents from ``tests/`` was the repo; two parents
# from ``tests/brix_suite/cachemx/`` is ``tests/brix_suite`` — a directory
# that exists, so the hop would have kept resolving and simply named the
# wrong tree.  ``_require_binaries()`` below would then have looked for the
# native clients under ``tests/brix_suite/client/bin/`` and skipped every
# cachemx test with "native client binary missing", which reads as a host
# without a built client rather than as a broken path.
REPO = os.path.dirname(TESTS_DIR)
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
XRDSSSADMIN = os.path.join(REPO, "client", "bin", "xrdsssadmin-brix")

TOKEN_FILE = os.path.join(TOKENS_DIR, "upstream.jwt")
CLIENT_CERT = os.path.join(PKI_DIR, "user", "usercert.pem")
CLIENT_KEY = os.path.join(PKI_DIR, "user", "userkey.pem")

S3_BUCKET = "testbucket"
S3_REGION = "us-east-1"
S3_ACCESS_KEY = "cachemx-access"
S3_SECRET_KEY = "cachemx-secret-key"

# root:// byte/op counters flush when the client's TCP session closes; give the
# worker a beat to fold the session tallies into SHM before re-scraping.
FLUSH_WAIT = 1.0

# Stream planes: ledger port key, expected per-server `auth` label, cache
# subdirectory under CACHE_ROOT, and the client-environment builder name.
STREAM_PLANES = {
    "none": {"port_key": "PORT", "auth": "anon", "cache": "none"},
    "gsi": {"port_key": "GSI_PORT", "auth": "gsi", "cache": "gsi"},
    "token": {"port_key": "TOK_PORT", "auth": "token", "cache": "tok"},
    "sss": {"port_key": "SSS_PORT", "auth": "sss", "cache": "sss"},
}

HTTP_PLANES = {
    "dav": {"port_key": "HTTP_PORT", "scheme": "http", "cache": "dav"},
    "davs": {"port_key": "DAVS_PORT", "scheme": "https", "cache": "davs"},
    "davsg": {"port_key": "DAVS_GSI_PORT", "scheme": "https", "cache": "davsg"},
    # The only HTTP plane backed by a REMOTE origin (root://) instead of the
    # local posix tree — seed it with seed_origin(), not seed_local().
    "davo": {"port_key": "DAV_ORIGIN_PORT", "scheme": "http", "cache": "davo",
             "remote_origin": True},
    # The only plane with brix_webdav_tpc on: COPY + Source: is a third-party
    # pull here, a plain local copy everywhere else.
    "davtpc": {"port_key": "DAV_TPC_PORT", "scheme": "http", "cache": "davtpc",
               "tpc": True},
}

# HTTP planes whose objects can be planted straight into the local posix tree.
# The generic per-plane grids (GET/HEAD/Range/DELETE/PROPFIND accounting) are
# written against seed_local() and are meaningless on a remote-origin plane,
# where the same object has to be planted on the origin and pulled over root://
# — a different ledger with a fill leg in it.  Those cells live in
# test_cachemx_ops_grid.py instead, which addresses "davo" by name.
LOCAL_HTTP_PLANES = {name: meta for name, meta in HTTP_PLANES.items()
                     if not meta.get("remote_origin")}

S3_PLANES = {
    "s3": {"port_key": "S3_PORT", "cache": "s3", "signed": False,
           "scheme": "http"},
    "s3sig": {"port_key": "S3_SIG_PORT", "cache": "s3sig", "signed": True,
              "scheme": "http"},
    "s3tls": {"port_key": "S3_TLS_PORT", "cache": "s3tls", "signed": True,
              "scheme": "https"},
}


def settle():
    time.sleep(FLUSH_WAIT)


# --------------------------------------------------------------------------
# Per-instance /metrics access
# --------------------------------------------------------------------------

def mfetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode()


class Snap:
    """Before/after counter deltas against one instance's /metrics URL."""

    def __init__(self, url: str):
        self.url = url
        self.before = mfetch(url)

    def _pair(self, name, labels, after):
        if labels:
            return value(self.before, name, labels), value(after, name, labels)
        return scalar(self.before, name), scalar(after, name)

    def delta(self, name: str, labels: dict | None = None,
              after: str | None = None) -> int:
        """Increment since the snapshot; the series must exist afterwards."""
        after = after if after is not None else mfetch(self.url)
        vb, va = self._pair(name, labels or {}, after)
        assert va != -1, f"metric {name}{labels or ''} not exported"
        return va - (vb if vb != -1 else 0)

    def delta_or_absent(self, name: str, labels: dict | None = None,
                        after: str | None = None) -> int:
        """Like delta(), but an absent series counts as 0 (families that only
        appear once their listener has seen traffic)."""
        after = after if after is not None else mfetch(self.url)
        vb, va = self._pair(name, labels or {}, after)
        if va == -1:
            return 0
        return va - (vb if vb != -1 else 0)

    def cache_delta(self, proto: str, status: str,
                    after: str | None = None) -> int:
        """Cache lookups of one disposition on one protocol.

        phase-110 W1 made the disposition a LABEL VALUE on a single family
        instead of a family per outcome, and phase 112 removed the
        brix_cache_{hits,misses}_total pair it replaced.  `status` is a word
        from the one cache vocabulary ("HIT", "MISS", "NEGHIT") — the same
        string $brix_cache_status logs and the JSON "cache_status" prints.
        """
        return self.delta("brix_cache_requests_total",
                          {"proto": proto, "cache_status": status}, after)

    def cache_delta_or_absent(self, proto: str, status: str,
                              after: str | None = None) -> int:
        """cache_delta() for a disposition whose series may not exist yet."""
        return self.delta_or_absent("brix_cache_requests_total",
                                    {"proto": proto,
                                     "cache_status": status}, after)


def gauge(url: str, name: str, labels: dict | None = None) -> int:
    text = mfetch(url)
    v = value(text, name, labels) if labels else scalar(text, name)
    assert v != -1, f"gauge {name}{labels or ''} not exported"
    return v


def mark_in_use(port: int) -> None:
    """Open one raw kXR handshake so the per-server SHM slot exports rows."""
    with socket.create_connection((HOST, port), timeout=5) as s:
        s.sendall(struct.pack(">5i", 0, 0, 0, 4, 2012))
        s.settimeout(2)
        try:
            s.recv(64)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Client environments + subprocess drivers
# --------------------------------------------------------------------------

def _base_env() -> dict:
    env = dict(os.environ)
    for k in ("LD_LIBRARY_PATH", "X509_USER_PROXY", "X509_CERT_DIR",
              "XrdSecPROTOCOL", "BEARER_TOKEN_FILE", "XrdSecSSSKT"):
        env.pop(k, None)
    # xrdcp otherwise falls back to /tmp/x509up_<uid> even when the caller
    # requested an anonymous/token/SSS plane.  Keep those planes independent
    # of the shared proxy's lifetime; env_gsi() replaces this with PROXY_STD.
    env["X509_USER_PROXY"] = "/nonexistent/brix-cachemx-proxy.pem"
    return env


def env_none() -> dict:
    return _base_env()


def env_gsi() -> dict:
    env = _base_env()
    env["X509_USER_PROXY"] = PROXY_STD
    env["X509_CERT_DIR"] = CA_DIR
    env["XrdSecPROTOCOL"] = "gsi"
    return env


def env_token(token_file: str = TOKEN_FILE) -> dict:
    env = _base_env()
    env["BEARER_TOKEN_FILE"] = token_file
    return env


def env_sss(keytab: str) -> dict:
    env = _base_env()
    env["XrdSecSSSKT"] = keytab
    env["XrdSecPROTOCOL"] = "sss"
    return env


def run_client(binary: str, *args, env: dict, timeout: int = 90):
    return subprocess.run([binary, *args], capture_output=True, text=True,
                          env=env, timeout=timeout)


# --------------------------------------------------------------------------
# HTTP / S3 drivers (urllib only — no extra deps)
# --------------------------------------------------------------------------

def tls_context(client_cert: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA_CERT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # test CA; server identity not under test
    if client_cert:
        ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    return ctx


def http_request(url: str, method: str = "GET", data: bytes | None = None,
                 headers: dict | None = None, ctx: ssl.SSLContext | None = None,
                 timeout: int = 15):
    """One-shot HTTP request; returns (status, body_bytes, response_headers).

    Never raises on HTTP error statuses — the suite asserts on 4xx/5xx classes
    as first-class outcomes.
    """
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def sigv4_headers(method: str, host: str, port: int, path: str) -> dict:
    """SigV4 header-auth for the matrix S3 SigV4 plane (mirrors the server's
    canonicalization: SignedHeaders=host;x-amz-date, UNSIGNED-PAYLOAD)."""
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    canonical = (
        f"{method}\n"
        f"{quote(path, safe='/-_.~')}\n"
        "\n"
        f"host:{host}:{port}\n"
        f"x-amz-date:{amz_date}\n"
        "\n"
        "host;x-amz-date\n"
        "UNSIGNED-PAYLOAD"
    )
    sts = ("AWS4-HMAC-SHA256\n"
           f"{amz_date}\n"
           f"{date}/{S3_REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    k = hmac.new(f"AWS4{S3_SECRET_KEY}".encode(), date.encode(),
                 hashlib.sha256).digest()
    for part in (S3_REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    cred = f"{S3_ACCESS_KEY}/{date}/{S3_REGION}/s3/aws4_request"
    return {
        "x-amz-date": amz_date,
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={cred}, "
                          f"SignedHeaders=host;x-amz-date, Signature={sig}"),
    }


# --------------------------------------------------------------------------
# The stack
# --------------------------------------------------------------------------

def _s3_request_headers(meta, headers, signed, method, port, key):
    result = dict(headers or {})
    should_sign = meta["signed"] if signed is None else signed
    if should_sign:
        result.update(sigv4_headers(
            method, HOST, port, f"/{S3_BUCKET}/{key.lstrip('/')}"))
    return result


def _s3_tls_context(meta):
    if meta.get("scheme") == "https":
        return tls_context()
    return None


class MatrixStack:
    """Handles + drivers for the origin/matrix instance pair."""

    def __init__(self, harness, origin_ep, mx_ep, cache_root, sss_keytab):
        self.harness = harness
        self.origin_ep = origin_ep
        self.mx_ep = mx_ep
        self.cache_root = Path(cache_root)
        self.sss_keytab = sss_keytab
        self.origin_data = Path(origin_ep.data_root)
        self.local_data = Path(mx_ep.data_root)
        self.origin_metrics = (f"http://{HOST}:"
                               f"{origin_ep.extra_ports['METRICS_PORT']}/metrics")
        self.metrics = (f"http://{HOST}:"
                        f"{mx_ep.extra_ports['METRICS_PORT']}/metrics")

    # -- ports / urls ------------------------------------------------------

    def port(self, key: str) -> int:
        if key == "PORT":
            return self.mx_ep.port
        return self.mx_ep.extra_ports[key]

    def root_url(self, plane: str, path: str = "") -> str:
        p = self.port(STREAM_PLANES[plane]["port_key"])
        return f"root://{HOST}:{p}/{path.lstrip('/')}"

    def http_url(self, plane: str, path: str) -> str:
        meta = HTTP_PLANES[plane]
        p = self.port(meta["port_key"])
        return f"{meta['scheme']}://{HOST}:{p}/{path.lstrip('/')}"

    def s3_url(self, plane: str, key: str) -> str:
        meta = S3_PLANES[plane]
        p = self.port(meta["port_key"])
        return (f"{meta.get('scheme', 'http')}://{HOST}:{p}"
                f"/{S3_BUCKET}/{key.lstrip('/')}")

    def plane_env(self, plane: str) -> dict:
        if plane == "none":
            return env_none()
        if plane == "gsi":
            return env_gsi()
        if plane == "token":
            return env_token()
        if plane == "sss":
            return env_sss(self.sss_keytab)
        raise KeyError(plane)

    def cache_dir(self, plane: str) -> Path:
        table = {**STREAM_PLANES, **HTTP_PLANES, **S3_PLANES}
        return self.cache_root / table[plane]["cache"]

    # -- seeding -----------------------------------------------------------

    @staticmethod
    def _seed(path: Path, size: int) -> bytes:
        """Write `size` random bytes at `path`, dropping any stale integrity
        sidecar.  A server-side write stamps block CRCs in the data file's
        user.xrd.cinfo xattr; rewriting the bytes out-of-band (as seeding a
        pre-used name does) would leave a contradictory checksum record and
        the server then — correctly — refuses to serve the file (IOError on
        cache fill).  Seeding IS an out-of-band modification, so it must also
        retire the sidecar, exactly as a storage admin restoring a file would."""
        payload = os.urandom(size)
        path.write_bytes(payload)
        try:
            os.removexattr(path, "user.xrd.cinfo")
        except OSError:
            pass
        return payload

    def seed_origin(self, name: str, size: int) -> bytes:
        """Plant a file on the anon posix origin (stream planes fill from it)."""
        return self._seed(self.origin_data / name, size)

    def seed_local(self, name: str, size: int) -> bytes:
        """Plant a file on the matrix instance's own posix backend (the HTTP
        and S3 planes' storage tier)."""
        return self._seed(self.local_data / name, size)

    # -- stream drivers ----------------------------------------------------

    def xrdcp_get(self, plane: str, remote: str, local: str, timeout=90):
        return run_client(XRDCP, "-f", self.root_url(plane, remote), local,
                          env=self.plane_env(plane), timeout=timeout)

    def xrdcp_put(self, plane: str, local: str, remote: str, timeout=90):
        return run_client(XRDCP, "-f", local, self.root_url(plane, remote),
                          env=self.plane_env(plane), timeout=timeout)

    def xrdfs(self, plane: str, *args, timeout=30):
        p = self.port(STREAM_PLANES[plane]["port_key"])
        return run_client(XRDFS, f"root://{HOST}:{p}", *args,
                          env=self.plane_env(plane), timeout=timeout)

    # -- HTTP plane drivers ------------------------------------------------

    def dav_request(self, plane: str, path: str, method="GET", data=None,
                    headers=None, cert=None):
        """cert: None = plane default (davsg presents the user cert), True /
        False force presenting / withholding the client certificate."""
        meta = HTTP_PLANES[plane]
        ctx = None
        if meta["scheme"] == "https":
            present = cert if cert is not None else (plane == "davsg")
            ctx = tls_context(client_cert=present)
        return http_request(self.http_url(plane, path), method=method,
                            data=data, headers=headers, ctx=ctx)

    def s3_request(self, plane: str, key: str, method="GET", data=None,
                   headers=None, signed=None):
        meta = S3_PLANES[plane]
        headers = _s3_request_headers(
            meta, headers, signed, method, self.port(meta["port_key"]), key)
        # SigV4 signs host:port, never the scheme — the TLS plane's headers are
        # byte-identical to the cleartext one's, only the transport differs.
        ctx = _s3_tls_context(meta)
        return http_request(self.s3_url(plane, key), method=method, data=data,
                            headers=headers, ctx=ctx)


def _require_binaries():
    if not os.path.exists(NGINX_BIN) or not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not available at {NGINX_BIN}")
    for b in (XRDCP, XRDFS, XRDSSSADMIN):
        if not os.path.exists(b):
            pytest.skip(f"native client binary missing: {b}")


def start_stack(harness: LifecycleHarness, workdir: Path) -> MatrixStack:
    """Boot origin + matrix; workdir holds the SSS keytab and cache stores."""
    _require_binaries()

    keytab = str(workdir / "server.keytab")
    r = subprocess.run(
        [XRDSSSADMIN, "-k", keytab, "add", "--id", "1", "--user", "anybody",
         "--group", "anygroup", "--name", "cachemx"],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"xrdsssadmin keytab mint failed: {r.stdout}{r.stderr}")

    cache_root = workdir / "cache"
    planes = {**STREAM_PLANES, **HTTP_PLANES, **S3_PLANES}
    for meta in planes.values():
        (cache_root / meta["cache"]).mkdir(parents=True, exist_ok=True)

    origin_ep = harness.start(NginxInstanceSpec(
        name="lc-cachemx-origin",
        template="nginx_lc_cachemx_origin.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST},
        reason="cachemx conformance: anon posix origin"))

    mx_ep = harness.start(NginxInstanceSpec(
        name="lc-cachemx",
        template="nginx_lc_cachemx.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST,
                         "ORIGIN_PORT": origin_ep.port,
                         "CACHE_ROOT": str(cache_root),
                         "SSS_KEYTAB": keytab},
        reason="cachemx conformance: multi-plane cache matrix"))

    return MatrixStack(harness, origin_ep, mx_ep, cache_root, keytab)


@pytest.fixture(scope="module")
def mx(tmp_path_factory):
    """Module-scoped origin+matrix pair (fresh SHM counters per test module)."""
    harness = LifecycleHarness()
    try:
        yield start_stack(harness, tmp_path_factory.mktemp("cachemx"))
    finally:
        harness.close()


def unique_name(tag: str) -> str:
    return f"cachemx_{tag}_{os.getpid()}_{time.monotonic_ns()}.bin"
