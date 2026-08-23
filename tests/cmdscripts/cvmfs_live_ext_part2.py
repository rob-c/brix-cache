"""Reverse-cache, hold-open, and proxy CVMFS live scenarios."""

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


def _reverse_config(run, cache, access_log, error_log, ports):
    mock_port, cache_port, metrics_port, dashboard_port = ports
    text = f"""daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
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
        listen {BIND_HOST}:{cache_port} so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {{
            brix_storage_backend http://{HOST}:{mock_port};
            brix_cache_store posix:{cache};
            brix_cvmfs on;
            brix_cvmfs_manifest_ttl 1;
        }}
        location / {{ return 403; }}
    }}
    server {{
        listen {BIND_HOST}:{metrics_port};
        access_log off;
        location /metrics {{ brix_metrics on; }}
        location /healthz {{ brix_health on; }}
    }}
    server {{
        listen {BIND_HOST}:{dashboard_port};
        access_log off;
        location /brix/ {{ brix_dashboard on; brix_dashboard_password "t16"; }}
    }}
}}
"""
    return run.write(run.root / "nginx.conf", text)


def _start_reverse(run, cache, access_log, error_log, ports):
    mock_port, cache_port, _metrics_port, _dashboard_port = ports
    config = _reverse_config(run, cache, access_log, error_log, ports)
    parsed = run.call(
        [run.nginx, "-t", "-c", config, "-p", run.root], check=False
    ).returncode == 0
    _mock(run, mock_port, 8, 9)
    run.start_nginx(run.root, config, cache_port)
    return _objects(run, mock_port), [(parsed, "cvmfs directives parse")]


def _reverse_cache_checks(run, mock_port, cache_port, objects):
    first = objects[0]
    cold = run.curl_bytes(f"http://{HOST}:{cache_port}{first}")
    after_cold = _count_log(run, mock_port, first)
    warm = run.curl_bytes(f"http://{HOST}:{cache_port}{first}")
    after_warm = _count_log(run, mock_port, first)
    origin = run.curl_bytes(f"http://{HOST}:{mock_port}{first}")
    stampede_object = objects[4]
    _concurrent_gets(f"http://{HOST}:{cache_port}{stampede_object}", 40)
    fetches = _count_log(run, mock_port, stampede_object)
    return [
        (cold == origin and warm == origin, "cold+warm byte-exact"),
        (after_warm == after_cold, "warm hit served from cache"),
        (fetches == 1, f"stampede: exactly 1 origin fetch ({fetches})"),
    ]


def _reverse_manifest_checks(run, mock_port, cache_port):
    url = f"http://{HOST}:{cache_port}/cvmfs/test.cern.ch/.cvmfspublished"
    initial = run.curl_bytes(url)
    run.call([
        "curl", "-s", "-o", os.devnull,
        f"http://{HOST}:{mock_port}/ctl/manifest/bump",
    ])
    revalidated = False
    for _attempt in range(3):
        time.sleep(2)
        if run.curl_bytes(url) != initial:
            revalidated = True
            break
    geo = run.curl_bytes(
        f"http://{HOST}:{cache_port}/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b")
    return [
        (revalidated, "expired manifest revalidated (TTL)"),
        (len(geo) > 0, "geo passthrough"),
    ]


def _reverse_security_checks(run, mock_port, cache_port):
    traversal = run.curl_status(
        f"http://{HOST}:{cache_port}/cvmfs/../etc/passwd")
    random_path = run.curl_status(
        f"http://{HOST}:{cache_port}/cvmfs/repo/random.txt")
    write = run.curl_status(
        f"http://{HOST}:{cache_port}/cvmfs/test.cern.ch/.cvmfspublished",
        "-X", "PUT", "--data", "x")
    bogus = "/cvmfs/test.cern.ch/data/aa/" + "ab" * 19
    first = run.curl_status(f"http://{HOST}:{cache_port}{bogus}")
    probes_before = _count_log(run, mock_port, bogus, endpoint="heads")
    second = run.curl_status(f"http://{HOST}:{cache_port}{bogus}")
    probes_after = _count_log(run, mock_port, bogus, endpoint="heads")
    absorbed = all((
        first == 404,
        second == 404,
        probes_before >= 1,
        probes_before == probes_after,
    ))
    return [
        (traversal == 403, f"traversal rejected ({traversal})"),
        (random_path == 403, f"non-class path rejected ({random_path})"),
        (write == 405, f"write method rejected ({write})"),
        (absorbed, "negative cache absorbed repeat 404 "
         f"(codes={first}/{second} probes={probes_before}->{probes_after})"),
    ]


def _reverse_dashboard_checks(run, mock_port, cache_port, dashboard_port, obj):
    _fault(run, mock_port, "stall", 1)
    stalled = run.spawn([
        "curl", "-s", "--max-time", "6",
        f"http://{HOST}:{cache_port}{obj}", "-o", os.devnull,
    ])
    dashboard = ""
    visible = False
    for _attempt in range(25):
        timestamp = str(int(time.time()))
        digest = hmac.new(
            b"t16", timestamp.encode(), hashlib.sha256).hexdigest()
        dashboard = run.call([
            "curl", "-s",
            "-H", f"Cookie: xrd_dashboard={digest}.{timestamp}",
            f"http://{HOST}:{dashboard_port}/brix/api/v1/transfers",
        ], check=False).stdout
        if '"protocol":"cvmfs"' in dashboard and f'"path":"{obj}"' in dashboard:
            visible = True
            break
        time.sleep(0.3)
    stalled.wait(10)
    _fault(run, mock_port, "none", 0)
    return [
        (visible, "dashboard: in-flight cvmfs fill visible (proto+path)"),
        ('"cvmfs_bytes_tx":' in dashboard,
         "dashboard: totals carry the cvmfs bucket"),
    ]


def _reverse_observability_checks(run, metrics_port, access_log, error_log):
    reject_logged = _grep(
        error_log,
        r"cvmfs-reject: method=GET uri=.*client=.*class=reject",
        regex=True)
    metrics = _metrics(run, metrics_port)
    request_count = _mval(metrics, 'brix_cvmfs_requests_total{class="cas"} ')
    fill_bytes = _mval(
        metrics, 'brix_cvmfs_bytes_served_total{source="fill"} ')
    health = run.call([
        "curl", "-s", f"http://{HOST}:{metrics_port}/healthz?verbose"
    ]).stdout
    checks = [
        (reject_logged, "reject line guard-parsable"),
        (request_count >= 1, f"metrics: cas requests counted ({request_count:g})"),
        ('proto="cvmfs"' in metrics, "metrics: proto=cvmfs on module-wide families"),
        (fill_bytes >= 1, "metrics: fill bytes counted"),
        (_grep(access_log, "class=cas cache=fill"),
         "access log: cold read logged as class=cas cache=fill"),
        (_grep(access_log, "class=cas cache=hit"),
         "access log: warm read logged as cache=hit"),
        ('"cvmfs_origins":[{"host"' in health,
         "healthz: cvmfs_origins present"),
    ]
    return checks, metrics


def _reverse_repo_metric_checks(metrics):
    requests = _mval(
        metrics,
        'brix_cvmfs_repo_requests_total{repo="test.cern.ch",class="cas"} ')
    files = _mval(
        metrics,
        'brix_cvmfs_repo_files_accessed_total{repo="test.cern.ch"} ')
    hits = _mval(
        metrics,
        'brix_cvmfs_repo_cache_hits_total{repo="test.cern.ch"} ')
    fill = _mval(
        metrics,
        'brix_cvmfs_repo_bytes_served_total{repo="test.cern.ch",source="fill"} ')
    origin = _mval(
        metrics,
        'brix_cvmfs_repo_origin_bytes_total{repo="test.cern.ch"} ')
    byte_metrics = all((hits >= 1, fill >= 1, origin >= 1))
    return [
        (requests >= 1, f"repo metrics: per-fqrn cas requests ({requests:g})"),
        (files >= 1, f"repo metrics: files_accessed counted ({files:g})"),
        (byte_metrics, "repo metrics: hits/bytes-served/origin-bytes all counted"),
    ]


def _reverse_cardinality_check(run, cache_port, metrics_port):
    bogus = "ab" * 19
    for index in range(1, 41):
        run.curl_status(
            f"http://{HOST}:{cache_port}/cvmfs/flood{index}.example.org/"
            f"data/aa/{bogus}")
    metrics = _metrics(run, metrics_port)
    repositories = sum(
        1 for line in metrics.splitlines()
        if line.startswith("brix_cvmfs_repo_files_accessed_total{"))
    bounded = 'repo="_other"' in metrics and repositories <= 32
    return [(bounded, "repo metrics: label set bounded "
             f"({repositories} repos, overflow -> _other)")]


def reverse(nginx: Path | None = None) -> int:
    ports = tuple(_PORTS[1:5])
    mock_port, cache_port, metrics_port, dashboard_port = ports
    with LiveRun("cvmfs_rev", nginx) as run:
        cache = run.mkdir("cache")
        logs = run.mkdir("logs")
        access_log = logs / "cvmfs_access.log"
        error_log = logs / "e.log"
        objects, checks = _start_reverse(
            run, cache, access_log, error_log, ports)
        checks += _reverse_cache_checks(run, mock_port, cache_port, objects)
        checks += _reverse_manifest_checks(run, mock_port, cache_port)
        checks += _reverse_security_checks(run, mock_port, cache_port)
        checks += _reverse_dashboard_checks(
            run, mock_port, cache_port, dashboard_port, objects[6])
        observable, metrics = _reverse_observability_checks(
            run, metrics_port, access_log, error_log)
        checks += observable
        checks += _reverse_repo_metric_checks(metrics)
        checks += _reverse_cardinality_check(run, cache_port, metrics_port)
        return _checks(checks)
def _hold_config(run, cache, logs, mock_port, cache_port, client_hold):
    text = f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{cache_port};
    location /cvmfs/ {{
        brix_storage_backend http://{HOST}:{mock_port};
        brix_cache_store posix:{cache};
        brix_cvmfs on;
        brix_cvmfs_client_hold {client_hold};
        brix_cvmfs_fill_max_life 60;
        brix_cvmfs_negative_ttl 10;
    }}
}} }}
"""
    return run.write(run.root / "nginx.conf", text)


def _hold_objects(run, mock_port):
    process = _mock(run, mock_port, 6, 20)
    objects = _objects(run, mock_port)
    _mock_stop(run, process, mock_port)
    return objects


def _start_delayed_mock(run, mock_port, target):
    target["proc"] = run.spawn([
        sys.executable, MOCK_STRATUM1,
        "--port", str(mock_port), "--objects", "6", "--seed", "20",
    ])


def _hold_outage_check(run, cache, logs, mock_port, cache_port, obj):
    config = _hold_config(run, cache, logs, mock_port, cache_port, 20)
    run.start_nginx(run.root, config, cache_port)
    late_mock = {}
    timer = threading.Timer(
        3.0, _start_delayed_mock, args=(run, mock_port, late_mock))
    timer.start()
    destination = run.root / "a.bin"
    code = _curl_code_to(
        run, f"http://{HOST}:{cache_port}{obj}", destination, timeout=30)
    timer.join()
    time.sleep(0.5)
    reference = run.curl_bytes(f"http://{HOST}:{mock_port}{obj}")
    passed = code == 200 and destination.read_bytes() == reference
    return (passed, f"held through outage, served on recovery ({code})"), late_mock


def _retry_same_connection(run, mock_port, cache_port, obj):
    connection = http.client.HTTPConnection(HOST, cache_port, timeout=30)
    recovery_mock = None
    try:
        connection.request("GET", obj)
        first = connection.getresponse()
        first.read()
        retryable = all((
            first.status == 504,
            first.getheader("Retry-After") is not None,
            (first.getheader("Connection") or "keep-alive").lower() != "close",
        ))
        if not retryable:
            return False, recovery_mock
        recovery_mock = _mock(run, mock_port, 6, 20)
        time.sleep(1.0)
        connection.request("GET", obj)
        second = connection.getresponse()
        body = second.read()
        return second.status == 200 and len(body) > 0, recovery_mock
    except (OSError, http.client.HTTPException):
        return False, recovery_mock
    finally:
        connection.close()


def _hold_same_socket_check(
        run, cache, logs, mock_port, cache_port, obj, late_mock):
    _mock_stop(run, late_mock.get("proc"), mock_port)
    run.stop_nginx(run.root)
    config = _hold_config(run, cache, logs, mock_port, cache_port, 2)
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    run.start_nginx(run.root, config, cache_port)
    passed, recovery_mock = _retry_same_connection(
        run, mock_port, cache_port, obj)
    return (passed, "504-keepalive + same-socket retry"), recovery_mock


def _hold_detached_check(
        run, cache, logs, mock_port, cache_port, obj, recovery_mock):
    _mock_stop(run, recovery_mock, mock_port)
    run.stop_nginx(run.root)
    config = _hold_config(run, cache, logs, mock_port, cache_port, 20)
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    run.start_nginx(run.root, config, cache_port)
    run.call([
        "curl", "-s", "--max-time", "1",
        f"http://{HOST}:{cache_port}{obj}", "-o", os.devnull,
    ], check=False)
    _mock(run, mock_port, 6, 20)
    time.sleep(6)
    fetches_before = _count_log(run, mock_port, obj)
    code = run.curl_status(f"http://{HOST}:{cache_port}{obj}")
    fetches_after = _count_log(run, mock_port, obj)
    passed = all((
        code == 200,
        fetches_before >= 1,
        fetches_before == fetches_after,
    ))
    return (
        passed,
        f"detached fill populated cache "
        f"(code={code} origin={fetches_before}->{fetches_after})",
    )


def _hold_404_check(run, cache_port):
    bogus = "/cvmfs/test.cern.ch/data/aa/" + "ef" * 19
    started = time.monotonic()
    code = run.curl_status(f"http://{HOST}:{cache_port}{bogus}")
    elapsed = time.monotonic() - started
    return (
        code == 404 and elapsed <= 2,
        f"404 immediate (no hold): code={code} took {elapsed:.1f}s",
    )


def holdopen(nginx: Path | None = None) -> int:
    mock_port, cache_port = _PORTS[5:7]
    with LiveRun("cvmfs_hold", nginx) as run:
        cache = run.mkdir("cache")
        logs = run.mkdir("logs")
        objects = _hold_objects(run, mock_port)
        outage, late_mock = _hold_outage_check(
            run, cache, logs, mock_port, cache_port, objects[0])
        same_socket, recovery_mock = _hold_same_socket_check(
            run, cache, logs, mock_port, cache_port, objects[1], late_mock)
        detached = _hold_detached_check(
            run, cache, logs, mock_port, cache_port, objects[2], recovery_mock)
        immediate = _hold_404_check(run, cache_port)
        return _checks([outage, same_socket, detached, immediate])
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
