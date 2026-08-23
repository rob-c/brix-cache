#!/usr/bin/env python3
"""
load_test.py — Concurrent transfer load test for nginx-xrootd vs xrootd.

Measures peak throughput and latency distribution under 200+ simultaneous
connections across three auth modes:
  • XRootD root:// + GSI
  • WebDAV davs:// + GSI
  • WebDAV davs:// + Bearer token

Runs against nginx-xrootd and optionally an official xrootd server,
then prints a side-by-side comparison table.

Usage
-----
    # Start servers first (see docs/load-testing.md or run_load_test.sh)

    # Test nginx-xrootd only
    python3 tests/load_test.py --target nginx

    # Test official xrootd only
    python3 tests/load_test.py --target xrootd

    # Full comparison (requires both servers running)
    python3 tests/load_test.py --target both

    # Custom concurrency and file size
    python3 tests/load_test.py --target nginx --concurrency 50,100,200 --file load_1g.bin

    # Save JSON results
    python3 tests/load_test.py --target both --json results.json

    # Direct nginx-xrootd vs xrootd-native root:// comparison
    python3 tests/load_test.py --target both --suite root-gsi --concurrency 128

    # High-concurrency read test without 500+ GiB of client temp files
    python3 tests/load_test.py --target both --suite root-gsi --concurrency 500 --read-sink devnull

    # Read-only tests (no writes)
    python3 tests/load_test.py --target nginx --mode read

    # Write tests only
    python3 tests/load_test.py --target nginx --mode write

File sizes
----------
    load_100m.bin  100 MiB — fast sweep, tests connection handling
    load_1g.bin    1 GiB   — stress test, tests sustained throughput (default)
    large200.bin   200 MiB — existing file from test suite

Servers
-------
    nginx-xrootd:
        XRootD+GSI    root://localhost:12795
        WebDAV+GSI    davs://localhost:12794
        WebDAV+token  davs://localhost:12792  (Bearer token in env)

    xrootd native:
        XRootD+GSI    root://localhost:12094
        (HTTP plugin is optional; token auth requires xrootd-http)
"""

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from settings import HOST, url_host

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_LOAD_ROOT = os.path.join(
    os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "artifacts", "load", "fixtures"
)
DATA_DIR   = os.path.join(_LOAD_ROOT, "data")
CA_DIR     = os.path.join(_LOAD_ROOT, "pki", "ca")
PROXY_PEM  = os.path.join(_LOAD_ROOT, "pki", "user", "proxy_std.pem")
TOKEN_DIR  = os.path.join(_LOAD_ROOT, "tokens")
SERVER_CERT = os.path.join(_LOAD_ROOT, "pki", "server", "hostcert.pem")

_H = url_host(HOST)   # client connect host (bracketed if IPv6)

NGINX_XRD_GSI_URL       = f"root://{_H}:12795"
NGINX_XRD_TLS_URL       = f"roots://{_H}:12796"  # stream-level TLS, auth none
NGINX_XRD_GSI_TLS_URL   = f"roots://{_H}:12797"  # stream-level TLS, auth gsi
NGINX_XRD_ANON_URL      = f"root://{_H}:12793"   # perf config anon port
NGINX_DAV_GSI_URL       = f"davs://{_H}:12792"
NGINX_DAV_GSI_HTTP_URL  = f"https://{_H}:12792"   # for curl (perf WebDAV port)
NGINX_DAV_TOKEN_URL     = f"davs://{_H}:12792"
NGINX_DAV_TOKEN_HTTP_URL = f"https://{_H}:12792"  # for curl

# S3 REST — anonymous, cleartext HTTP (no native-xrootd S3 counterpart).
NGINX_S3_HTTP_URL = f"http://{_H}:12798"
S3_BUCKET         = "perfbucket"

BRIX_GSI_URL      = f"root://{_H}:12094"   # official xrootd GSI instance
BRIX_ANON_URL     = f"root://{_H}:12093"   # official xrootd anon instance
BRIX_DAV_HTTP_URL = f"https://{_H}:12443"  # not available in this config

DEFAULT_FILE    = "load_1g.bin"
DEFAULT_WORKERS = [1, 8, 32, 64, 128, 200]


def _apply_brix_gsi_env(env: dict, proxy: Optional[str],
                          ca_dir: str) -> None:
    """Configure xrdcp for the local test GSI proxy.

    Also sets X509_CERT_DIR unconditionally so that roots:// (stream-level TLS)
    connections can verify the server certificate against the test CA.
    """
    # Always needed: server-cert verification for roots:// TLS connections.
    env["X509_CERT_DIR"] = ca_dir

    if not proxy:
        return

    env["X509_USER_PROXY"] = proxy
    env["XrdSecPROTOCOL"]  = "gsi"
    env["XRD_SECPROTOCOL"] = "gsi"
    env["XrdSecGSISRVNAMES"] = "*"
    env.pop("X509_USER_CERT", None)
    env.pop("X509_USER_KEY", None)

    # A 128-way 1 GiB localhost benchmark can queue briefly behind disk and
    # thread-pool work. Keep xrdcp's own request timer above the subprocess
    # wall timeout so slower workers report transfer time, not client timeout.
    env.setdefault("XRD_REQUESTTIMEOUT", "600")
    env.setdefault("XRD_STREAMTIMEOUT", "120")

# ---------------------------------------------------------------------------
# Worker functions (must be module-level for multiprocessing pickling)
# ---------------------------------------------------------------------------

def _safe_run(*args, **kwargs):
    """subprocess.run that converts a TimeoutExpired (one hung transfer) into a
    sentinel None instead of raising.  pool.map() re-raises any worker exception
    and aborts the WHOLE sweep, so an uncaught timeout on a single curl/xrdcp
    would lose every remaining concurrency level.  Returning None lets the
    worker record a failed sample and the sweep continues."""
    try:
        return subprocess.run(*args, **kwargs)
    except subprocess.TimeoutExpired:
        return None


def _brix_read_worker(args: dict) -> dict:
    """Single-process xrdcp read. One file download."""
    worker_id  = args["id"]
    url        = args["url"]         # full URL incl. path
    proxy      = args["proxy"]
    ca_dir     = args["ca_dir"]
    sink       = args.get("sink", "tempfile")
    expected_bytes = args.get("expected_bytes", 0)
    tls_nosecureverify = args.get("tls_nosecureverify", False)
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    env = os.environ.copy()
    _apply_brix_gsi_env(env, proxy, ca_dir)
    if tls_nosecureverify:
        # Skip hostname verification for roots:// with the test PKI whose cert
        # CN may not match "localhost".  CA trust is still enforced via X509_CERT_DIR.
        env["XRD_NOSECUREVERIFY"] = "1"

    if sink == "devnull":
        t0 = time.perf_counter()
        proc = _safe_run(
            ["xrdcp", "-f", url, "/dev/null"],
            env=env, capture_output=True, timeout=600,
        )
        if proc is None:
            result["error"] = "timeout"
            return result
        elapsed = time.perf_counter() - t0

        if proc.returncode != 0:
            result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
            return result

        result.update(ok=True, bytes=expected_bytes, elapsed=elapsed)
        return result

    with tempfile.NamedTemporaryFile(delete=True) as dst:
        t0 = time.perf_counter()
        proc = _safe_run(
            ["xrdcp", "-f", url, dst.name],
            env=env, capture_output=True, timeout=600,
        )
        if proc is None:
            result["error"] = "timeout"
            return result
        elapsed = time.perf_counter() - t0

        if proc.returncode != 0:
            result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
            return result

        nbytes = os.path.getsize(dst.name)
        result.update(ok=True, bytes=nbytes, elapsed=elapsed)
    return result


def _brix_write_worker(args: dict) -> dict:
    """Single-process xrdcp write. Uploads a local file to the server."""
    worker_id  = args["id"]
    src        = args["src"]         # local file path
    url        = args["url"]         # destination URL incl. path
    proxy      = args["proxy"]
    ca_dir     = args["ca_dir"]
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    env = os.environ.copy()
    _apply_brix_gsi_env(env, proxy, ca_dir)

    t0 = time.perf_counter()
    proc = _safe_run(
        ["xrdcp", "-f", src, url],
        env=env, capture_output=True, timeout=600,
    )
    if proc is None:
        result["error"] = "timeout"
        return result
    elapsed = time.perf_counter() - t0

    if proc.returncode != 0:
        result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
        return result

    result.update(ok=True, bytes=os.path.getsize(src), elapsed=elapsed)
    return result


def _webdav_read_worker(args: dict) -> dict:
    """curl-based WebDAV GET. Supports GSI (client cert) and bearer token.
    Uses HTTP/2 when the server advertises it via ALPN (--http2).
    """
    worker_id  = args["id"]
    url        = args["url"]
    proxy      = args.get("proxy")
    ca_dir     = args.get("ca_dir")
    token      = args.get("token")
    server_cert = args.get("server_cert")
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    cmd = ["curl", "-s", "-S", "-o", "/dev/null", "-w", "%{size_download}",
           "--insecure",   # test PKI; remove for production
           "--http2"]      # negotiate HTTP/2 via ALPN when server supports it
    _add_webdav_auth(cmd, proxy, token)
    cmd.append(url)

    t0 = time.perf_counter()
    proc = _safe_run(cmd, capture_output=True, timeout=300)
    if proc is None:
        result["error"] = "timeout"
        return result
    elapsed = time.perf_counter() - t0

    if proc.returncode != 0:
        result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
        return result

    try:
        nbytes = int(proc.stdout.decode().strip())
    except ValueError:
        result["error"] = "could not parse curl output"
        return result

    result.update(ok=True, bytes=nbytes, elapsed=elapsed)
    return result


def _add_webdav_auth(command, proxy, token):
    if proxy:
        command.extend(["--cert", proxy, "--key", proxy])
    if token:
        command.extend(["-H", f"Authorization: Bearer {token}"])


def _webdav_write_worker(args: dict) -> dict:
    """curl-based WebDAV PUT."""
    worker_id   = args["id"]
    src         = args["src"]
    url         = args["url"]
    proxy       = args.get("proxy")
    token       = args.get("token")
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    file_size = os.path.getsize(src)
    cmd = ["curl", "-s", "-S", "-X", "PUT",
           "--insecure",
           "--upload-file", src,
           "-w", "%{http_code}",
           "-o", "/dev/null"]
    _add_webdav_auth(cmd, proxy, token)
    cmd.append(url)

    t0 = time.perf_counter()
    proc = _safe_run(cmd, capture_output=True, timeout=300)
    if proc is None:
        result["error"] = "timeout"
        return result
    elapsed = time.perf_counter() - t0

    if proc.returncode != 0:
        result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
        return result

    code = proc.stdout.decode().strip()
    if code not in ("200", "201", "204"):
        result["error"] = f"HTTP {code}"
        return result

    result.update(ok=True, bytes=file_size, elapsed=elapsed)
    return result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class RunStats:
    label:       str = ""
    n_workers:   int = 0
    n_ok:        int = 0
    n_err:       int = 0
    total_bytes: int = 0
    wall_s:      float = 0.0
    elapsed_list: list = field(default_factory=list)
    errors:      list = field(default_factory=list)

    @property
    def ok_rate(self) -> float:
        return self.n_ok / self.n_workers if self.n_workers else 0.0

    @property
    def agg_mib_s(self) -> float:
        return (self.total_bytes / (1024**2)) / self.wall_s if self.wall_s else 0.0

    @property
    def agg_gib_s(self) -> float:
        return self.agg_mib_s / 1024.0

    @property
    def p50(self) -> float:
        return self._percentile(50)

    @property
    def p95(self) -> float:
        return self._percentile(95)

    @property
    def p99(self) -> float:
        return self._percentile(99)

    @property
    def mean_mib_s(self) -> float:
        if not self.elapsed_list or self.n_ok == 0:
            return 0.0
        per = [self.total_bytes / self.n_ok / (1024**2) / e
               for e in self.elapsed_list if e > 0]
        return sum(per) / len(per) if per else 0.0

    def _percentile(self, pct: int) -> float:
        s = sorted(self.elapsed_list)
        if not s:
            return 0.0
        idx = max(0, int(math.ceil(len(s) * pct / 100)) - 1)
        return s[idx]

    def summary_line(self) -> str:
        return (
            f"  n={self.n_workers:<4}  ok={self.n_ok}/{self.n_workers}"
            f"  agg={self.agg_mib_s:>7.0f} MiB/s"
            f"  ({self.agg_gib_s:.2f} GiB/s)"
            f"  p50={self.p50:.1f}s  p95={self.p95:.1f}s  p99={self.p99:.1f}s"
            f"  per-conn={self.mean_mib_s:.0f} MiB/s"
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_concurrent(worker_fn, arg_list: list[dict], n_workers: int,
                   label: str) -> RunStats:
    """
    Launch n_workers parallel processes using the given worker function.
    Returns a RunStats with aggregate metrics.
    """
    stats = RunStats(label=label, n_workers=n_workers)

    t_wall_start = time.perf_counter()
    with multiprocessing.Pool(processes=n_workers) as pool:
        results = pool.map(worker_fn, arg_list)
    stats.wall_s = time.perf_counter() - t_wall_start

    for r in results:
        if r["ok"]:
            stats.n_ok        += 1
            stats.total_bytes += r["bytes"]
            stats.elapsed_list.append(r["elapsed"])
        else:
            stats.n_err += 1
            if r.get("error"):
                stats.errors.append(r["error"])

    return stats


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

def _make_bearer_token() -> Optional[str]:
    """Generate a short-lived read token using make_token.py."""
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "utils", "make_token.py"
    )
    if not os.path.exists(script):
        return None
    # Default is a read-only token (negative-test friendly); override the scope
    # via env for a read+write token when profiling the token WRITE path.
    scope = os.environ.get("BRIX_LOAD_TOKEN_SCOPE", "storage.read:/")
    proc = subprocess.run(
        [sys.executable, script, "gen",
         "--scope", scope,
         TOKEN_DIR],
        capture_output=True, timeout=10,
    )
    if proc.returncode != 0:
        return None
    # make_token.py prints the JWT on stdout
    return proc.stdout.decode().strip()


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

def _read_args_xrd(base_url: str, filename: str, n: int,
                   proxy: Optional[str] = None,
                   sink: str = "tempfile",
                   expected_bytes: int = 0,
                   tls_nosecureverify: bool = False) -> list[dict]:
    return [{"id": i, "url": f"{base_url}//{filename}",
             "proxy": proxy, "ca_dir": CA_DIR, "sink": sink,
             "expected_bytes": expected_bytes,
             "tls_nosecureverify": tls_nosecureverify} for i in range(n)]


def _read_args_dav(base_url: str, filename: str, n: int,
                   proxy: Optional[str] = None,
                   token: Optional[str] = None) -> list[dict]:
    return [{"id": i, "url": f"{base_url}/{filename}",
             "proxy": proxy, "ca_dir": CA_DIR, "token": token,
             "server_cert": SERVER_CERT} for i in range(n)]


def _write_args_xrd(base_url: str, src: str, n: int,
                    proxy: Optional[str] = None) -> list[dict]:
    basename = os.path.basename(src)
    return [{"id": i, "url": f"{base_url}//load_write_{i}_{basename}",
             "src": src, "proxy": proxy, "ca_dir": CA_DIR} for i in range(n)]


def _write_args_dav(base_url: str, src: str, n: int,
                    proxy: Optional[str] = None,
                    token: Optional[str] = None) -> list[dict]:
    basename = os.path.basename(src)
    return [{"id": i, "url": f"{base_url}/load_write_{i}_{basename}",
             "src": src, "proxy": proxy, "ca_dir": CA_DIR, "token": token} for i in range(n)]

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "load_test_part2.py", "load_test_part3.py")
