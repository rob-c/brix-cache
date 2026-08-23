"""Direct Python ports of the remaining CVMFS live shell scenarios.

Continues tests/cmdscripts/cvmfs_live.py: one function per legacy shell
script, a SCENARIOS dict keyed by the script stem, and a main() dispatcher.

  bench            <- tests/run_cvmfs_bench.sh
  reverse          <- tests/run_cvmfs_reverse.sh
  holdopen         <- tests/run_cvmfs_holdopen.sh
  proxy            <- tests/run_cvmfs_proxy.sh
  resilience       <- tests/run_cvmfs_resilience.sh
  stock            <- tests/run_cvmfs_stock.sh
  unified-origin   <- tests/run_cvmfs_unified_origin.sh
  upstream-metrics <- tests/run_cvmfs_upstream_metrics.sh
  logging          <- tests/run_cvmfs_logging.sh
  select           <- tests/run_cvmfs_select.sh
  selectlog        <- tests/run_cvmfs_selectlog.sh
  evict            <- tests/run_cvmfs_evict.sh
  brix-all         <- tests/run_cvmfs_brix_all.sh
  faultproxy-bench <- tests/run_cvmfs_faultproxy_bench.sh
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

from cmdscripts.cvmfs_live import _checks, _count_log, _ctl
from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, sha256
from lib_py.util import wait_tcp
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST

MOCK_STRATUM1 = REPO_ROOT / "tests/cvmfs/mock_stratum1.py"

_PORTS = cmdscript_ports("cvmfs_live_ext")


def _resilience_sink(run, sink_dir):
    if not _geo_port_available():
        print("  SKIP geo ranking asserts: port 8000 already in use")
        return None
    sink = run.spawn([sys.executable, REPO_ROOT / "tests/cvmfs/probe_sink.py",
                      sink_dir, "8000", "2222"])
    for _ in range(50):
        if (sink_dir / "ready").exists():
            break
        time.sleep(0.1)
    return sink


def _geo_port_available():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", 8000))  # net-literal-allow: semantic geo-probe port
        return True
    except OSError:
        return False


def _resilience_stall_checks(run, origin_port, client_port):
    obj = _objects(run, origin_port)[0]
    original = run.curl_bytes(f"http://{HOST}:{origin_port}{obj}")
    _fault(run, origin_port, "stall", 1)
    received = run.root / "got.bin"
    started = time.monotonic()
    code = _curl_code_to(
        run, f"http://{HOST}:{client_port}{obj}", received, timeout=15
    )
    elapsed = time.monotonic() - started
    _fault(run, origin_port, "none", 0)
    return [
        (_successful_stall_read(code, received, original),
         f"stalled origin forced through (code={code} in {elapsed:.1f}s, no 504/hang)"),
        (elapsed < 12,
         f"stall detected fast ({elapsed:.1f}s << 60s default ceiling)"),
    ]


def _successful_stall_read(code, received, original):
    if code != 200:
        return False
    return received.read_bytes() == original


def _compact_geo_answer(run, client_port, servers):
    url = (f"http://{HOST}:{client_port}/cvmfs/test.cern.ch/"
           f"api/v1.0/geo/x/{servers}")
    return "".join(run.call(["curl", "-s", url]).stdout.split())


def _hit_count(path):
    return path.stat().st_size if path.exists() else 0


def _resilience_geo_checks(run, sink, sink_dir, client_port):
    if sink is None:
        return []
    first = "192.0.2.2:8000,127.0.0.1:8000,127.0.0.1:2222"  # net-literal-allow: geo-order payload
    answer = _compact_geo_answer(run, client_port, first)
    hits_8000 = _hit_count(sink_dir / "8000.hits")
    hits_2222 = _hit_count(sink_dir / "2222.hits")
    second = "127.0.0.1:2222,127.0.0.1:8000,192.0.2.2:8000,127.0.0.1:22,127.0.0.1:8000"  # net-literal-allow: geo-order payload
    answer2 = _compact_geo_answer(run, client_port, second)
    ordered = ",".join(sorted(answer2.split(","), key=_numeric_geo_item))
    return [
        (answer == "2,1,3",
         f"geo RTT rank: reachable<unreachable<disallowed ({answer!r})"),
        (hits_8000 >= 1,
         f"guard: allowed port 8000 was probed ({hits_8000})"),
        (hits_2222 == 0,
         f"guard: disallowed port 2222 never connected ({hits_2222} connects)"),
        (ordered == "1,2,3,4,5",
         f"geo answer is a complete permutation of 1..5 ({answer2!r})"),
    ]


def _numeric_geo_item(item):
    return int(item) if item else 0


def resilience(nginx: Path | None = None) -> int:
    mport, cport = _PORTS[11:13]  # was free_ports(2)
    # Ports 8000/2222 are semantic: the geo probe guard allows the standard
    # CVMFS port (8000) and must never touch a disallowed one (2222).
    with LiveRun("cvmfs_res", nginx) as run:
        cache, logs, sink_dir = run.mkdir("cache"), run.mkdir("logs"), run.mkdir("sink")
        sink = _resilience_sink(run, sink_dir)

        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{
    server {{
        listen {BIND_HOST}:{cport};
        location /cvmfs/ {{
            brix_storage_backend http://{HOST}:{mport};
            brix_cache_store posix:{cache};
            brix_cvmfs on;
            brix_cvmfs_manifest_ttl 1;
            brix_cvmfs_origin_connect_timeout 1;
            brix_cvmfs_origin_stall_timeout   2;
            brix_cvmfs_origin_stall_bytes     1;
            brix_cvmfs_fill_retry_policy       force-primary;
            brix_cvmfs_client_hold             20;
            brix_cvmfs_geo_answer      rtt;
            brix_cvmfs_geo_cache_ttl   60;
            brix_cvmfs_geo_max_servers 8;
        }}
        location / {{ return 403; }}
    }}
}}
""")
        parses = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode == 0
        _mock(run, mport, 8, 7)
        run.start_nginx(run.root, config, cport)

        checks: list[tuple[bool, str]] = [(parses, "new resilience+geo directives parse")]

        checks.extend(_resilience_stall_checks(run, mport, cport))
        checks.extend(_resilience_geo_checks(run, sink, sink_dir, cport))

        # robustness: unresolvable-hostname list still yields a well-formed answer
        fallback = _compact_geo_answer(run, cport, "a,b")
        checks.append((len(fallback) > 0,
                       f"geo answer/fallback returns non-empty for name list ({fallback!r})"))
        return _checks(checks)


# ---------------------------------------------------------------------------
# stock — Phase-1 stock-nginx CVMFS cache e2e (deploy/cvmfs template)
# ---------------------------------------------------------------------------

def stock(nginx: Path | None = None) -> int:
    mport, rport, pport = _PORTS[13:16]  # was free_ports(3)
    with LiveRun("cvmfs_stock", nginx) as run:
        run.mkdir("store")
        run.mkdir("logs")
        _mock(run, mport, 8, 7)
        template = (REPO_ROOT / "deploy/cvmfs/nginx-proxy-cache.conf").read_text()
        rendered = (template
                    .replace("@PORT@", str(rport))
                    .replace("@PPORT@", str(pport))
                    .replace("@CACHEDIR@", str(run.root))
                    .replace("@ORIGIN@", f"{HOST}:{mport}")
                    .replace("@ORIGINHOST@", HOST)
                    .replace("@ORIGINPORT@", str(mport)))
        config = run.write(run.root / "nginx.conf", rendered)
        run.start_nginx(run.root, config, rport)

        objects = _objects(run, mport)
        obj = objects[0]

        # 1: cold + warm byte-exact
        cold = run.curl_bytes(f"http://{HOST}:{rport}{obj}")
        warm = run.curl_bytes(f"http://{HOST}:{rport}{obj}")
        orig = run.curl_bytes(f"http://{HOST}:{mport}{obj}")

        # 2: stampede coalescing on a fresh object
        obj2 = objects[3]
        n0 = _count_log(run, mport, obj2)
        _concurrent_gets(f"http://{HOST}:{rport}{obj2}", 40)
        n1 = _count_log(run, mport, obj2)

        # 3: security-neg
        c1 = run.curl_status(f"http://{HOST}:{rport}/etc/passwd")
        c2 = run.curl_status("http://evil.example.org/cvmfs/x/data/aa/bb",
                             "-x", f"http://{HOST}:{pport}")

        return _checks([
            (cold == orig and warm == orig, "cold+warm byte-exact"),
            (n1 - n0 <= 2, f"stampede coalesced ({n1 - n0} origin fetches)"),
            (c1 == 403, f"non-cvmfs path rejected ({c1})"),
            (c2 == 403, f"disallowed upstream rejected ({c2})"),
        ])


# ---------------------------------------------------------------------------
# unified-origin — brix_cvmfs_unified_origin forward-proxy semantics
# ---------------------------------------------------------------------------

def unified_origin(nginx: Path | None = None) -> int:
    m1, m2, cport = _PORTS[16:19]  # was free_ports(3)
    with LiveRun("cvmfs_unified", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        mock1 = _mock(run, m1, 4, 55)
        _mock(run, m2, 4, 55)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
worker_processes 1; thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{cport};
    location / {{
        brix_storage_backend "http://{HOST}:{m1}|http://{HOST}:{m2}";
        brix_cache_store posix:{cache};
        brix_cvmfs on;
        brix_cvmfs_upstream_allow {HOST};
        brix_cvmfs_unified_origin on;
        brix_cvmfs_origin_connect_timeout 1;
        brix_cvmfs_origin_attempt_timeout 2;
        brix_cvmfs_client_hold 4;
    }}
}} }}
""")
        parses = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode == 0

        obj = _objects(run, m1)[0]
        ref = run.curl_bytes(f"http://{HOST}:{m1}{obj}")

        # B: two client-named authorities -> ONE origin fetch (unified backend)
        run.start_nginx(run.root, config, cport)
        proxy_url = f"http://{HOST}:{cport}"
        b1 = _count_log(run, m1, obj)
        b2 = _count_log(run, m2, obj)
        g1 = run.curl_bytes(f"http://{HOST}:{m1}{obj}", "-x", proxy_url)
        g2 = run.curl_bytes(f"http://{HOST}:{m2}{obj}", "-x", proxy_url)
        f1 = _count_log(run, m1, obj)
        f2 = _count_log(run, m2, obj)
        delta = (f1 - b1) + (f2 - b2)
        run.stop_nginx(run.root)

        # A: primary origin DOWN -> request naming it still 200 (failover hidden)
        shutil.rmtree(cache, ignore_errors=True)
        cache.mkdir(parents=True, exist_ok=True)
        _mock_stop(run, mock1, m1)
        run.start_nginx(run.root, config, cport)
        ha = run.root / "ha.bin"
        code = _curl_code_to(run, f"http://{HOST}:{m1}{obj}", ha, "-x", proxy_url, timeout=8)
        failover_ok = code == 200 and ha.read_bytes() == ref

        # config guard: unified_origin without an http storage_backend rejected
        bad = run.write(run.root / "bad.conf", f"""daemon off; events {{ worker_connections 32; }}
http {{ server {{ listen {BIND_HOST}:{cport}; location / {{
    brix_cache_store posix:{cache};
    brix_cvmfs on; brix_cvmfs_upstream_allow {HOST};
    brix_cvmfs_unified_origin on;
}} }} }}
""")
        guard = run.call([run.nginx, "-t", "-c", bad, "-p", run.root], check=False).returncode != 0

        return _checks([
            (parses, "unified_origin + multi-endpoint storage_backend parse"),
            (g1 == ref and g2 == ref, "both client-named authorities serve byte-exact 200"),
            (delta == 1, f"unified: M1-named + M2-named = ONE origin fetch total (delta={delta})"),
            (failover_ok, f"primary origin DOWN: request naming it still returns 200 (code={code})"),
            (guard, "config guard: unified_origin without http storage_backend rejected"),
        ])


# ---------------------------------------------------------------------------
# upstream-metrics — per-upstream Prometheus attribution + trace logging
# ---------------------------------------------------------------------------

def upstream_metrics(nginx: Path | None = None) -> int:
    mral, malt, cport, xport, dead = _PORTS[19:24]  # was free_ports(5)
    with LiveRun("cvmfs_upm", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        error_log = logs / "e.log"
        _mock(run, mral, 8, 41)
        _mock(run, malt, 8, 41)
        objects = _objects(run, mral)
        obj0, obj1 = objects[0], objects[1]

        def mkconf(backends: str, extra: str = "", level: str = "info") -> Path:
            return run.write(run.root / "nginx.conf", f"""daemon on; error_log {error_log} {level}; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off;
    server {{ listen {BIND_HOST}:{cport};
        location /cvmfs/ {{
            brix_storage_backend "{backends}";
            brix_cache_store posix:{cache};
            brix_cvmfs on;
{extra}
        }} }}
    server {{ listen {BIND_HOST}:{xport}; location = /metrics {{ brix_metrics on; }} }}
}}
""")

        checks: list[tuple[bool, str]] = []

        # 1: attribution to the RAL upstream
        config = mkconf(f"http://{HOST}:{mral}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj0}")
        ral = f"{HOST}:{mral}"
        metrics = _metrics(run, xport)
        requests = _mval(metrics, f'brix_cvmfs_upstream_requests_total{{upstream="{ral}"}}')
        fills = _mval(metrics, f'brix_cvmfs_upstream_fills_total{{upstream="{ral}"}}')
        origin_bytes = _mval(metrics, f'brix_cvmfs_upstream_origin_bytes_total{{upstream="{ral}"}}')
        checks.append((min(requests, fills, origin_bytes) >= 1,
                       f"fill attributed to upstream RAL (req={requests:g} fills={fills:g} bytes={origin_bytes:g})"))
        hist_count = _mval(metrics, f'brix_cvmfs_upstream_fill_duration_seconds_count{{upstream="{ral}"}}')
        hist_inf = _mval(metrics, f'brix_cvmfs_upstream_fill_duration_seconds_bucket{{upstream="{ral}",le="+Inf"}}')
        hist_sum = f'brix_cvmfs_upstream_fill_duration_seconds_sum{{upstream="{ral}"}}' in metrics
        checks.append((_histogram_present(hist_sum, hist_count, hist_inf),
                       f"fill-duration histogram present (count={hist_count:g} +Inf={hist_inf:g})"))

        # 3: cardinality — the upstream label is host:port only, no path/repo
        leaked = re.search(r'brix_cvmfs_upstream_.*upstream="[^"]*(/|data/|\.cvmfs)', metrics)
        checks.append((leaked is None, "upstream label is bounded host:port (no path/repo leak)"))

        # 2: failover attribution — dead primary, fills served by the fallback
        config = mkconf(f"http://{HOST}:{dead}|http://{HOST}:{malt}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj1}")
        alt = f"{HOST}:{malt}"
        metrics = _metrics(run, xport)
        failovers = _mval(metrics, f'brix_cvmfs_upstream_failovers_total{{upstream="{alt}"}}')
        alt_fills = _mval(metrics, f'brix_cvmfs_upstream_fills_total{{upstream="{alt}"}}')
        checks.append((min(failovers, alt_fills) >= 1,
                       f"failover fill attributed to the fallback upstream (failovers={failovers:g})"))

        # 4: trace ON -> client + upstream lines at INFO
        config = mkconf(f"http://{HOST}:{mral}", "            brix_cvmfs_trace on;", "info")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj0}")
        time.sleep(0.3)
        checks.append((_grep(error_log, r"cvmfs-trace: client .*class=cas .*cache=fill", regex=True),
                       "trace on: client-op line at INFO"))
        checks.append((_grep(error_log,
                             rf"cvmfs-trace: upstream (GET|HEAD) http://{HOST}:{mral}.*status=2[0-9][0-9]",
                             regex=True),
                       "trace on: upstream-request line at INFO"))

        # 5: trace OFF + info level -> neither line
        config = mkconf(f"http://{HOST}:{mral}", "", "info")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj1}")
        time.sleep(0.3)
        checks.append((not _grep(error_log, "cvmfs-trace:"),
                       "trace off + error_log info: no trace lines"))

        # 6: trace OFF + debug level -> both lines (debug path)
        config = mkconf(f"http://{HOST}:{mral}", "", "debug")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj0}")
        time.sleep(0.3)
        checks.append((_both_trace_lines(error_log),
                       "trace off + error_log debug: both lines at DEBUG"))

        return _checks(checks)


def _histogram_present(has_sum, count, infinite_bucket):
    if not has_sum:
        return False
    return min(count, infinite_bucket) >= 1


def _both_trace_lines(error_log):
    if not _grep(error_log, "cvmfs-trace: client "):
        return False
    return _grep(error_log, "cvmfs-trace: upstream GET")


# ---------------------------------------------------------------------------
# logging — the cvmfs operational-logging contract
# ---------------------------------------------------------------------------
