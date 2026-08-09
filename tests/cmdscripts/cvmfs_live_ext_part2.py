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


def reverse(nginx: Path | None = None) -> int:
    mport, cport, xport, dport = _PORTS[1:5]  # was free_ports(4)
    with LiveRun("cvmfs_rev", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        access_log = logs / "cvmfs_access.log"
        error_log = logs / "e.log"
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{
    log_format cvmfs '$remote_addr [$time_local] "$request" $status '
                     '$body_bytes_sent $request_time '
                     'class=$cvmfs_class cache=$cvmfs_cache origin=$cvmfs_origin';
    access_log {access_log} cvmfs;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {{
        listen {BIND_HOST}:{cport} so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {{
            brix_storage_backend http://{HOST}:{mport};
            brix_cache_store posix:{cache};
            brix_cvmfs on;
            brix_cvmfs_manifest_ttl 1;
        }}
        location / {{ return 403; }}
    }}
    server {{
        listen {BIND_HOST}:{xport};
        access_log off;
        location /metrics {{ brix_metrics on; }}
        location /healthz {{ brix_health on; }}
    }}
    server {{
        listen {BIND_HOST}:{dport};
        access_log off;
        location /brix/ {{ brix_dashboard on; brix_dashboard_password "t16"; }}
    }}
}}
""")
        parses = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode == 0

        _mock(run, mport, 8, 9)
        run.start_nginx(run.root, config, cport)
        objects = _objects(run, mport)
        obj = objects[0]

        # success: cold fill + warm hit, byte-exact, warm served without origin
        cold = run.curl_bytes(f"http://{HOST}:{cport}{obj}")
        after_cold = _count_log(run, mport, obj)
        warm = run.curl_bytes(f"http://{HOST}:{cport}{obj}")
        after_warm = _count_log(run, mport, obj)
        origin = run.curl_bytes(f"http://{HOST}:{mport}{obj}")

        # stampede: exactly 1 origin fetch (module fill-lock)
        obj2 = objects[4]
        _concurrent_gets(f"http://{HOST}:{cport}{obj2}", 40)
        stampede_fetches = _count_log(run, mport, obj2)

        # manifest: 1s TTL — a bump becomes visible after expiry (poll windows)
        manifest_url = f"http://{HOST}:{cport}/cvmfs/test.cern.ch/.cvmfspublished"
        m1 = run.curl_bytes(manifest_url)
        run.call(["curl", "-s", "-o", os.devnull, f"http://{HOST}:{mport}/ctl/manifest/bump"])
        revalidated = False
        for _ in range(3):
            time.sleep(2)
            if run.curl_bytes(manifest_url) != m1:
                revalidated = True
                break

        # geo passthrough
        geo = run.curl_bytes(f"http://{HOST}:{cport}/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b")

        # security-neg: rejects for non-CVMFS shapes; 405 for writes
        c1 = run.curl_status(f"http://{HOST}:{cport}/cvmfs/../etc/passwd")
        c2 = run.curl_status(f"http://{HOST}:{cport}/cvmfs/repo/random.txt")
        c3 = run.curl_status(f"http://{HOST}:{cport}/cvmfs/test.cern.ch/.cvmfspublished",
                             "-X", "PUT", "--data", "x")

        # negative cache: 2 misses for the same bogus CAS name -> 1 origin probe
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "ab" * 19
        cn1 = run.curl_status(f"http://{HOST}:{cport}{bogus}")
        nb1 = _count_log(run, mport, bogus, endpoint="heads")
        cn2 = run.curl_status(f"http://{HOST}:{cport}{bogus}")
        nb2 = _count_log(run, mport, bogus, endpoint="heads")

        # T16: dashboard sees an IN-FLIGHT cvmfs fill (stalled origin)
        obj6 = objects[6]
        _fault(run, mport, "stall", 1)
        stalled = run.spawn(["curl", "-s", "--max-time", "6",
                             f"http://{HOST}:{cport}{obj6}", "-o", os.devnull])
        dashboard_json = ""
        slot_visible = False
        for _ in range(25):
            ts = str(int(time.time()))
            digest = hmac.new(b"t16", ts.encode(), hashlib.sha256).hexdigest()
            dashboard_json = run.call(
                ["curl", "-s", "-H", f"Cookie: xrd_dashboard={digest}.{ts}",
                 f"http://{HOST}:{dport}/brix/api/v1/transfers"], check=False).stdout
            if '"protocol":"cvmfs"' in dashboard_json and f'"path":"{obj6}"' in dashboard_json:
                slot_visible = True
                break
            time.sleep(0.3)
        totals_present = '"cvmfs_bytes_tx":' in dashboard_json
        stalled.wait(10)
        _fault(run, mport, "none", 0)

        # T17: reject lines are guard-parsable
        reject_logged = _grep(error_log, r"cvmfs-reject: method=GET uri=.*client=.*class=reject", regex=True)

        # T16: the three visibility surfaces
        metrics = _metrics(run, xport)
        cas_count = _mval(metrics, 'brix_cvmfs_requests_total{class="cas"} ')
        proto_label = 'proto="cvmfs"' in metrics
        fill_bytes = _mval(metrics, 'brix_cvmfs_bytes_served_total{source="fill"} ')
        fill_line = _grep(access_log, "class=cas cache=fill")
        hit_line = _grep(access_log, "class=cas cache=hit")
        healthz = run.call(["curl", "-s", f"http://{HOST}:{xport}/healthz?verbose"]).stdout
        origins_present = '"cvmfs_origins":[{"host"' in healthz

        # per-repository families (bounded fqrn label set)
        repo_req = _mval(metrics, 'brix_cvmfs_repo_requests_total{repo="test.cern.ch",class="cas"} ')
        repo_files = _mval(metrics, 'brix_cvmfs_repo_files_accessed_total{repo="test.cern.ch"} ')
        repo_hits = _mval(metrics, 'brix_cvmfs_repo_cache_hits_total{repo="test.cern.ch"} ')
        repo_fill = _mval(metrics, 'brix_cvmfs_repo_bytes_served_total{repo="test.cern.ch",source="fill"} ')
        repo_origin = _mval(metrics, 'brix_cvmfs_repo_origin_bytes_total{repo="test.cern.ch"} ')

        # cardinality bound: 40 bogus fqrns fold into repo="_other"
        flood_bogus = "ab" * 19
        for i in range(1, 41):
            run.curl_status(f"http://{HOST}:{cport}/cvmfs/flood{i}.example.org/data/aa/{flood_bogus}")
        metrics2 = _metrics(run, xport)
        nrepo = sum(1 for line in metrics2.splitlines()
                    if line.startswith("brix_cvmfs_repo_files_accessed_total{"))
        bounded = 'repo="_other"' in metrics2 and nrepo <= 32

        return _checks([
            (parses, "cvmfs directives parse"),
            (cold == origin and warm == origin, "cold+warm byte-exact"),
            (after_warm == after_cold, "warm hit served from cache"),
            (stampede_fetches == 1, f"stampede: exactly 1 origin fetch ({stampede_fetches})"),
            (revalidated, "expired manifest revalidated (TTL)"),
            (len(geo) > 0, "geo passthrough"),
            (c1 == 403, f"traversal rejected ({c1})"),
            (c2 == 403, f"non-class path rejected ({c2})"),
            (c3 == 405, f"write method rejected ({c3})"),
            (cn1 == 404 and cn2 == 404 and nb1 >= 1 and nb1 == nb2,
             f"negative cache absorbed repeat 404 (codes={cn1}/{cn2} probes={nb1}->{nb2})"),
            (slot_visible, "dashboard: in-flight cvmfs fill visible (proto+path)"),
            (totals_present, "dashboard: totals carry the cvmfs bucket"),
            (reject_logged, "reject line guard-parsable"),
            (cas_count >= 1, f"metrics: cas requests counted ({cas_count:g})"),
            (proto_label, "metrics: proto=cvmfs on module-wide families"),
            (fill_bytes >= 1, "metrics: fill bytes counted"),
            (fill_line, "access log: cold read logged as class=cas cache=fill"),
            (hit_line, "access log: warm read logged as cache=hit"),
            (origins_present, "healthz: cvmfs_origins present"),
            (repo_req >= 1, f"repo metrics: per-fqrn cas requests ({repo_req:g})"),
            (repo_files >= 1, f"repo metrics: files_accessed counted ({repo_files:g})"),
            (repo_hits >= 1 and repo_fill >= 1 and repo_origin >= 1,
             "repo metrics: hits/bytes-served/origin-bytes all counted"),
            (bounded, f"repo metrics: label set bounded ({nrepo} repos, overflow -> _other)"),
        ])


# ---------------------------------------------------------------------------
# holdopen — never-drop client semantics
# ---------------------------------------------------------------------------

def holdopen(nginx: Path | None = None) -> int:
    mport, cport = _PORTS[5:7]  # was free_ports(2)
    with LiveRun("cvmfs_hold", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")

        def mkconf(client_hold: int) -> Path:
            return run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{cport};
    location /cvmfs/ {{
        brix_storage_backend http://{HOST}:{mport};
        brix_cache_store posix:{cache};
        brix_cvmfs on;
        brix_cvmfs_client_hold {client_hold};
        brix_cvmfs_fill_max_life 60;
        brix_cvmfs_negative_ttl 10;
    }}
}} }}
""")

        # discover object names with a throwaway mock (same seed each start)
        probe_mock = _mock(run, mport, 6, 20)
        objs = _objects(run, mport)
        _mock_stop(run, probe_mock, mport)

        checks: list[tuple[bool, str]] = []

        # --- 1: retry-until-origin-returns -----------------------------------
        config = mkconf(20)
        run.start_nginx(run.root, config, cport)
        late_mock: dict[str, subprocess.Popen[str]] = {}
        timer = threading.Timer(3.0, lambda: late_mock.setdefault("proc", run.spawn(
            [sys.executable, MOCK_STRATUM1, "--port", str(mport), "--objects", "6", "--seed", "20"])))
        timer.start()
        a_bin = run.root / "a.bin"
        code = _curl_code_to(run, f"http://{HOST}:{cport}{objs[0]}", a_bin, timeout=30)
        timer.join()
        time.sleep(0.5)
        ref = run.curl_bytes(f"http://{HOST}:{mport}{objs[0]}")
        checks.append((code == 200 and a_bin.read_bytes() == ref,
                       f"held through outage, served on recovery ({code})"))

        # --- 2: hold expiry -> 504 keep-alive, retry on the SAME socket -------
        _mock_stop(run, late_mock.get("proc"), mport)
        run.stop_nginx(run.root)
        config = mkconf(2)
        shutil.rmtree(cache, ignore_errors=True)
        cache.mkdir(parents=True, exist_ok=True)
        run.start_nginx(run.root, config, cport)
        same_socket_ok = False
        recovery_mock: subprocess.Popen[str] | None = None
        conn = http.client.HTTPConnection(HOST, cport, timeout=30)
        try:
            conn.request("GET", objs[1])
            r1 = conn.getresponse()
            r1.read()
            if (r1.status == 504 and r1.getheader("Retry-After") is not None
                    and (r1.getheader("Connection") or "keep-alive").lower() != "close"):
                recovery_mock = _mock(run, mport, 6, 20)
                time.sleep(1.0)
                conn.request("GET", objs[1])
                r2 = conn.getresponse()
                body = r2.read()
                same_socket_ok = r2.status == 200 and len(body) > 0
        except (OSError, http.client.HTTPException):
            same_socket_ok = False
        finally:
            conn.close()
        checks.append((same_socket_ok, "504-keepalive + same-socket retry"))

        # --- 3: detached fill completes after client abort --------------------
        _mock_stop(run, recovery_mock, mport)
        run.stop_nginx(run.root)
        config = mkconf(20)
        shutil.rmtree(cache, ignore_errors=True)
        cache.mkdir(parents=True, exist_ok=True)
        run.start_nginx(run.root, config, cport)
        run.call(["curl", "-s", "--max-time", "1",
                  f"http://{HOST}:{cport}{objs[2]}", "-o", os.devnull], check=False)  # aborts
        _mock(run, mport, 6, 20)
        time.sleep(6)  # detached fill (max_life 60) retries and lands
        n1 = _count_log(run, mport, objs[2])
        code = run.curl_status(f"http://{HOST}:{cport}{objs[2]}")
        n2 = _count_log(run, mport, objs[2])
        checks.append((code == 200 and n1 >= 1 and n1 == n2,
                       f"detached fill populated cache (code={code} origin={n1}->{n2})"))

        # --- 4: 404 definitive, immediate -------------------------------------
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "ef" * 19
        t0 = time.monotonic()
        code = run.curl_status(f"http://{HOST}:{cport}{bogus}")
        elapsed = time.monotonic() - t0
        checks.append((code == 404 and elapsed <= 2,
                       f"404 immediate (no hold): code={code} took {elapsed:.1f}s"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# proxy — forward-proxy (CVMFS_HTTP_PROXY) mode
# ---------------------------------------------------------------------------

def proxy(nginx: Path | None = None) -> int:
    m1, m2, cport, cport2 = _PORTS[7:11]  # was free_ports(4)
    with LiveRun("cvmfs_proxy", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        _mock(run, m1, 4, 11)
        _mock(run, m2, 4, 22)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{cport};
    location / {{
        brix_cache_store posix:{cache};
        brix_cvmfs on;
        brix_cvmfs_upstream_allow {HOST};
        brix_cvmfs_upstream_max 4;
    }}
}} }}
""")
        run.start_nginx(run.root, config, cport)
        proxy_url = f"http://{HOST}:{cport}"

        o1 = _objects(run, m1)[0]
        o2 = _objects(run, m2)[0]

        # 1: proxy-style fetch, byte-exact, warm hit stays local
        p1 = run.curl_bytes(f"http://{HOST}:{m1}{o1}", "-x", proxy_url)
        r1 = run.curl_bytes(f"http://{HOST}:{m1}{o1}")
        na = _count_log(run, m1, o1)
        run.curl_bytes(f"http://{HOST}:{m1}{o1}", "-x", proxy_url)
        nb = _count_log(run, m1, o1)

        # 2: second upstream is independent (different seed -> different objects)
        p2 = run.curl_bytes(f"http://{HOST}:{m2}{o2}", "-x", proxy_url)
        r2 = run.curl_bytes(f"http://{HOST}:{m2}{o2}")

        # 3: disallowed authority -> 403
        evil = run.curl_status("http://evil.example.org/cvmfs/x/data/aa/" + "cd" * 19,
                               "-x", proxy_url)

        # 4: regression — MULTI-host single-line allowlist keeps every host
        prefix2 = run.mkdir("p2")
        cache2, logs2 = run.mkdir("p2", "cache"), run.mkdir("p2", "logs")
        config2 = run.write(prefix2 / "nginx.conf", f"""daemon on; error_log {logs2}/e.log info; pid {prefix2}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{
    log_format cvt '$status class=$cvmfs_class uri=$request_uri';
    server {{
    listen {BIND_HOST}:{cport2};
    access_log {logs2}/a.log cvt;
    location / {{
        brix_cache_store posix:{cache2};
        brix_cvmfs on;
        brix_cvmfs_upstream_allow bogus.example.org {HOST} also-bogus.example.org;
        brix_cvmfs_upstream_max 4;
    }}
}} }}
""")
        run.start_nginx(prefix2, config2, cport2)
        proxy2 = f"http://{HOST}:{cport2}"
        multi_ok = run.curl_status(f"http://{HOST}:{m1}{o1}", "-x", proxy2)
        multi_reject = run.curl_status("http://evil.example.org/cvmfs/x/.cvmfspublished", "-x", proxy2)

        # 5: regression — a REJECTED request logs its TRUE URL class
        run.curl_status("http://evil.example.org/cvmfs/x/api/v1.0/geo/localhost/a,b", "-x", proxy2)  # net-literal-allow: geo request client-name path segment under test
        time.sleep(0.2)
        alog = logs2 / "a.log"
        manifest_class = _grep(alog, "403 class=manifest uri=/cvmfs/x/.cvmfspublished")
        geo_class = _grep(alog, "403 class=geo")

        return _checks([
            (p1 == r1, "proxy-mode byte-exact"),
            (na == nb, "proxy-mode warm hit cached"),
            (p2 == r2, "second upstream independent"),
            (evil == 403, f"disallowed upstream rejected ({evil})"),
            (multi_ok == 200, f"one-line multi-host allowlist: 2nd host allowed ({multi_ok})"),
            (multi_reject == 403, f"multi-host allowlist still rejects others ({multi_reject})"),
            (manifest_class, "rejected manifest logs class=manifest"),
            (geo_class, "rejected geo logs class=geo"),
        ])


# ---------------------------------------------------------------------------
# resilience — fast stall detection + RTT-ranked geo answer with probe guard
# ---------------------------------------------------------------------------

