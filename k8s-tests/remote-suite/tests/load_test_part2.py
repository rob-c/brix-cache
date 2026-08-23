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

# TS-5, declared deviation from verbatim — one line, and it buys the cluster its
# uniformity back.  ``Suite.run_one`` is annotated ``-> RunStats``, a name shard
# 1 defines; without this the annotation is evaluated when the class body runs,
# so importing this shard on its own raises ``NameError`` — as the archived
# pre-move body still does.  That cost the shard its §10.2 shim (guard #3 and
# ``dump_suite_surface`` both import a shim's target), which would have meant
# the flat and package spellings were two objects for this file alone.  Under
# exec-composition nothing changes: ``RunStats`` is bound in the namespace this
# shard is loaded into either way, and no caller reads these annotations.
from __future__ import annotations

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

DATA_DIR   = "/tmp/xrd-load/data"
CA_DIR     = "/tmp/xrd-load/pki/ca"
PROXY_PEM  = "/tmp/xrd-load/pki/user/proxy_std.pem"
TOKEN_DIR  = "/tmp/xrd-load/tokens"
SERVER_CERT = "/tmp/xrd-load/pki/server/hostcert.pem"

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


class Suite:
    """One named collection of runs at various concurrency levels."""

    def __init__(self, label: str, worker_fn, arg_fn, concurrency: list[int],
                 cleanup_fn=None):
        self.label      = label
        self.worker_fn  = worker_fn
        self.arg_fn     = arg_fn        # callable(n) → list[dict]
        self.concurrency = concurrency
        self.cleanup_fn = cleanup_fn    # called after each level (write suites)
        self.runs: list[RunStats] = []

    def run_one(self, n: int) -> RunStats:
        """Run a single concurrency level and append the result to self.runs."""
        args = self.arg_fn(n)
        stats = run_concurrent(self.worker_fn, args, n,
                               label=f"{self.label} n={n}")
        self.runs.append(stats)
        print(stats.summary_line())
        if stats.errors:
            sample = stats.errors[:3]
            print(f"    errors (sample): {sample}")
        # Write suites leave large upload targets on the server FS — reclaim
        # them after every level so peak disk use stays at one level's worth
        # (concurrency × file size) rather than the whole sweep's.
        if self.cleanup_fn is not None:
            self.cleanup_fn()
        return stats

    def run(self) -> list[RunStats]:
        print(f"\n{'='*60}")
        print(f"  {self.label}")
        print(f"{'='*60}")
        for n in self.concurrency:
            print(f"  launching {n} workers ...", flush=True)
            self.run_one(n)
        return self.runs


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_comparison(nginx_suites: list[Suite], xrd_suites: list[Suite]):
    print("\n" + "="*80)
    print("  COMPARISON REPORT: nginx-xrootd  vs  xrootd native")
    print("="*80)

    headers = ["Protocol/Auth", "n", "nginx agg MiB/s", "xrootd agg MiB/s",
               "nginx p95 s", "xrootd p95 s", "nginx ok%", "xrootd ok%"]
    row_fmt = "  {:<28} {:>4}  {:>14}  {:>16}  {:>10}  {:>11}  {:>8}  {:>9}"

    print(row_fmt.format(*headers))
    print("  " + "-"*78)

    # Pair up suites by index
    for ns, xs in zip(nginx_suites, xrd_suites):
        assert len(ns.runs) == len(xs.runs)
        for nr, xr in zip(ns.runs, xs.runs):
            label = ns.label[:28]
            print(row_fmt.format(
                label, nr.n_workers,
                f"{nr.agg_mib_s:.0f}",
                f"{xr.agg_mib_s:.0f}",
                f"{nr.p95:.1f}",
                f"{xr.p95:.1f}",
                f"{nr.ok_rate*100:.0f}%",
                f"{xr.ok_rate*100:.0f}%",
            ))


def save_json(suites: list[Suite], path: str, target: str):
    data = {"target": target, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "suites": []}
    for s in suites:
        suite_data = {"label": s.label, "runs": []}
        for r in s.runs:
            d = asdict(r)
            d["agg_mib_s"]  = r.agg_mib_s
            d["agg_gib_s"]  = r.agg_gib_s
            d["mean_mib_s"] = r.mean_mib_s
            d["p50"]        = r.p50
            d["p95"]        = r.p95
            d["p99"]        = r.p99
            d["ok_rate"]    = r.ok_rate
            d.pop("elapsed_list", None)   # can be very long
            suite_data["runs"].append(d)
        data["suites"].append(suite_data)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  Results saved to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _cleanup_write_files() -> None:
    """Delete load_write_* upload targets from the server data dir.

    Both nginx (brix_export) and native xrootd (oss.localroot) write into
    DATA_DIR, so the uploaded large files accumulate there.  Called after each
    write concurrency level to bound peak disk use to one level's worth
    (concurrency × file size) instead of the whole sweep's."""
    import glob
    for p in glob.glob(os.path.join(DATA_DIR, "load_write_*")):
        try:
            os.remove(p)
        except OSError:
            pass


def _target_urls(target):
    if target == "nginx":
        return {
            "xrd_gsi": NGINX_XRD_GSI_URL,
            "xrd_tls": NGINX_XRD_TLS_URL,
            "xrd_gsi_tls": NGINX_XRD_GSI_TLS_URL,
            "xrd_anon": NGINX_XRD_ANON_URL,
            "dav_gsi": NGINX_DAV_GSI_HTTP_URL,
            "dav_token": NGINX_DAV_TOKEN_HTTP_URL,
        }
    return {
        "xrd_gsi": BRIX_GSI_URL,
        "xrd_tls": None,
        "xrd_gsi_tls": None,
        "xrd_anon": BRIX_ANON_URL,
        "dav_gsi": BRIX_DAV_HTTP_URL,
        "dav_token": BRIX_DAV_HTTP_URL,
    }


def _suite_wanted(context, name):
    wanted = context["wanted"]
    if "all" in wanted:
        return name != "s3"
    return name in wanted


def _s3_enabled(context):
    return all((_suite_wanted(context, "s3"), context["target"] == "nginx"))


def _url_enabled(context, name, url_key):
    return all((_suite_wanted(context, name), context["urls"][url_key] is not None))


def _token_enabled(context):
    return all((_suite_wanted(context, "webdav-token"), bool(context["token"])))


def _add_suite(suites, enabled, label, worker, arguments, concurrency, cleanup=None):
    if enabled:
        suites.append(Suite(label=label, worker_fn=worker, arg_fn=arguments,
                            concurrency=concurrency, cleanup_fn=cleanup))


def _read_args_s3(base_url, bucket, filename, n):
    return [{"id": index, "url": f"{base_url}/{bucket}/{filename}"}
            for index in range(n)]


def _write_args_s3(base_url, bucket, source, n):
    basename = os.path.basename(source)
    return [{"id": index, "src": source,
             "url": f"{base_url}/{bucket}/load_write_{index}_{basename}"}
            for index in range(n)]


def _read_suites(context):
    from functools import partial

    suites, urls = [], context["urls"]
    common = (context["filename"], context["concurrency"])
    filename, concurrency = common
    _add_suite(suites, _s3_enabled(context), "S3 GET (read, nginx only)",
               _webdav_read_worker,
               partial(_read_args_s3, NGINX_S3_HTTP_URL, S3_BUCKET, filename),
               concurrency)
    _add_suite(suites, _suite_wanted(context, "root-anon"),
               "XRootD root:// anon (read)", _brix_read_worker,
               partial(_read_args_xrd, urls["xrd_anon"], filename,
                       sink=context["read_sink"], expected_bytes=context["src_size"]),
               concurrency)
    _add_suite(suites, _suite_wanted(context, "root-gsi"),
               "XRootD root:// + GSI (read)", _brix_read_worker,
               partial(_read_args_xrd, urls["xrd_gsi"], filename, proxy=PROXY_PEM,
                       sink=context["read_sink"], expected_bytes=context["src_size"]),
               concurrency)
    _add_suite(suites, _url_enabled(context, "root-tls", "xrd_tls"),
               "XRootD roots:// + TLS (read)", _brix_read_worker,
               partial(_read_args_xrd, urls["xrd_tls"], filename,
                       sink=context["read_sink"], expected_bytes=context["src_size"],
                       tls_nosecureverify=True), concurrency)
    _add_suite(suites, _url_enabled(context, "root-gsi-tls", "xrd_gsi_tls"),
               "XRootD roots:// + GSI + TLS (read)", _brix_read_worker,
               partial(_read_args_xrd, urls["xrd_gsi_tls"], filename, proxy=PROXY_PEM,
                       sink=context["read_sink"], expected_bytes=context["src_size"],
                       tls_nosecureverify=True), concurrency)
    _add_suite(suites, _suite_wanted(context, "webdav-gsi"),
               "WebDAV davs:// + GSI (read)", _webdav_read_worker,
               partial(_read_args_dav, urls["dav_gsi"], filename, proxy=PROXY_PEM),
               concurrency)
    _add_suite(suites, _token_enabled(context),
               "WebDAV davs:// + token (read)", _webdav_read_worker,
               partial(_read_args_dav, urls["dav_token"], filename,
                       token=context["token"]), concurrency)
    return suites


def _write_suites(context):
    from functools import partial

    suites, urls = [], context["urls"]
    source, concurrency = context["src_file"], context["concurrency"]
    cleanup = _cleanup_write_files
    _add_suite(suites, _s3_enabled(context), "S3 PUT (write, nginx only)",
               _webdav_write_worker,
               partial(_write_args_s3, NGINX_S3_HTTP_URL, S3_BUCKET, source),
               concurrency, cleanup)
    _add_suite(suites, _suite_wanted(context, "root-anon"),
               "XRootD root:// anon (write)", _brix_write_worker,
               partial(_write_args_xrd, urls["xrd_anon"], source),
               concurrency, cleanup)
    _add_suite(suites, _suite_wanted(context, "root-gsi"),
               "XRootD root:// + GSI (write)", _brix_write_worker,
               partial(_write_args_xrd, urls["xrd_gsi"], source, proxy=PROXY_PEM),
               concurrency, cleanup)
    _add_suite(suites, _suite_wanted(context, "webdav-gsi"),
               "WebDAV davs:// + GSI (write)", _webdav_write_worker,
               partial(_write_args_dav, urls["dav_gsi"], source, proxy=PROXY_PEM),
               concurrency, cleanup)
    _add_suite(suites, _token_enabled(context),
               "WebDAV davs:// + token (write)", _webdav_write_worker,
               partial(_write_args_dav, urls["dav_token"], source,
                       token=context["token"]), concurrency, cleanup)
    return suites


def _suite_context(target, filename, concurrency, suite_filter, read_sink):
    source = os.path.join(DATA_DIR, filename)
    if not os.path.exists(source):
        sys.exit(f"Source file not found: {source}")
    token = _make_bearer_token()
    if token is None:
        print("  WARNING: could not generate bearer token — WebDAV+token tests skipped")
    return {"target": target, "filename": filename, "concurrency": concurrency,
            "wanted": set(suite_filter.split(",")), "read_sink": read_sink,
            "src_file": source, "src_size": os.path.getsize(source),
            "token": token, "urls": _target_urls(target)}


def build_suites(target: str, filename: str, concurrency: list[int],
                 mode: str, suite_filter: str, read_sink: str) -> list[Suite]:
    context = _suite_context(target, filename, concurrency, suite_filter, read_sink)
    suites = []
    if mode in ("read", "both"):
        suites.extend(_read_suites(context))
    if mode in ("write", "both"):
        suites.extend(_write_suites(context))
    if not suites:
        sys.exit(f"No suites selected for mode={mode!r}, suite={suite_filter!r}")

    return suites
