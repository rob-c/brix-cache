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


def main():
    ap = argparse.ArgumentParser(
        description="Load test nginx-xrootd vs xrootd native",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--target", choices=["nginx", "xrootd", "both"],
                    default="nginx")
    ap.add_argument("--file", default=DEFAULT_FILE,
                    help=f"filename under {DATA_DIR} (default: {DEFAULT_FILE})")
    ap.add_argument("--concurrency",
                    default=",".join(str(c) for c in DEFAULT_WORKERS),
                    help="comma-separated list of worker counts")
    ap.add_argument("--mode", choices=["read", "write", "both"], default="read")
    ap.add_argument("--suite",
                    default="all",
                    help="comma-separated protocol/auth suites, or 'all'. "
                         "Valid: root-anon, root-gsi, root-tls, root-gsi-tls, "
                         "webdav-gsi, webdav-token, s3 (s3 is nginx-only and "
                         "must be named explicitly).")
    ap.add_argument("--read-sink", choices=["tempfile", "devnull"],
                    default="tempfile",
                    help="where root:// read workers write downloaded bytes")
    ap.add_argument("--json", metavar="FILE",
                    help="save results to JSON file")
    ap.add_argument("--cooldown", type=int, default=0, metavar="SECS",
                    help="sleep this many seconds between concurrency levels "
                         "when --target both; reduces CPU thermal noise "
                         "(default: 0)")
    args = ap.parse_args()

    concurrency = [int(c) for c in args.concurrency.split(",")]

    print(f"\n  nginx-xrootd / xrootd load test")
    print(f"  target={args.target}  file={args.file}"
          f"  concurrency={concurrency}  mode={args.mode}"
          f"  suite={args.suite}  read_sink={args.read_sink}")

    all_results: dict[str, list[Suite]] = {}

    if args.target == "both":
        # Build both suite lists up front so we can interleave at each
        # concurrency level.  This ensures nginx and xrootd are benchmarked
        # under the same thermal conditions (both start cool at n=1,
        # both are warm at n=32) instead of nginx always getting the
        # cool CPU and xrootd always getting the throttled one.
        nginx_suites = build_suites("nginx",   args.file, concurrency,
                                    args.mode, args.suite, args.read_sink)
        xrd_suites   = build_suites("xrootd",  args.file, concurrency,
                                    args.mode, args.suite, args.read_sink)

        for n in concurrency:
            for ns in nginx_suites:
                print(f"\n  nginx   {ns.label}", flush=True)
                ns.run_one(n)
            for xs in xrd_suites:
                print(f"\n  xrootd  {xs.label}", flush=True)
                xs.run_one(n)
            if args.cooldown > 0 and n != concurrency[-1]:
                print(f"\n  [cooldown {args.cooldown}s between concurrency levels...]",
                      flush=True)
                time.sleep(args.cooldown)

        all_results["nginx"]  = nginx_suites
        all_results["xrootd"] = xrd_suites

        if args.json:
            save_json(nginx_suites,
                      args.json.replace(".json", "_nginx.json"), "nginx")
            save_json(xrd_suites,
                      args.json.replace(".json", "_xrootd.json"), "xrootd")

    else:
        target_name = args.target
        suites = build_suites(target_name, args.file, concurrency, args.mode,
                              args.suite, args.read_sink)
        for s in suites:
            s.run()
        all_results[target_name] = suites
        if args.json:
            save_json(suites, args.json, target_name)

    if args.target == "both":
        # Pair up by position — assumes same suite ordering
        print_comparison(all_results["nginx"], all_results["xrootd"])

    print("\n  Done.\n")


def run_cli():
    """The entry point the ``__main__`` guard used to be.

    This shard is exec-composed into ``load_test``'s globals, so the guard fired
    on the *parent's* ``__name__`` — which was ``"__main__"`` while the parent
    was a script at ``tests/load_test.py`` and is ``"brix_suite.perf.load_test"``
    now that it is a module.  Left as a guard the driver would have imported
    cleanly, run nothing and exited 0: the tokenforge failure mode
    (``tools/ci/check_shard_entrypoints.py``), and worse here than there, because
    a load test that measures nothing still prints its table headings.

    ``set_start_method`` stays with the entry point rather than moving to import
    time: the workers are forked per run and forcing the method on any import of
    ``load_test`` would reach into processes that never asked for it.
    """
    # Required for multiprocessing on Linux (fork is default, but be explicit)
    multiprocessing.set_start_method("fork", force=True)
    main()
    return 0
