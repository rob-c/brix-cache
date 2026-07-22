"""Direct Python ports of self-contained CVMFS live shell scenarios."""

from __future__ import annotations

import argparse
import http.client
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from settings import BIND_HOST, HOST


def _mock(run: LiveRun, port: int, objects: int, seed: int, *, keepalive: bool = False) -> subprocess.Popen[str]:
    argv = [sys.executable, REPO_ROOT / "tests/cvmfs/mock_stratum1.py", "--port", str(port), "--objects", str(objects), "--seed", str(seed)]
    if keepalive:
        argv.append("--keepalive")
    proc = run.spawn(argv)
    time.sleep(0.25)
    if proc.poll() is not None:
        raise LiveFailure(f"mock Stratum-1 on port {port} did not start")
    return proc


def _ctl(run: LiveRun, port: int, endpoint: str) -> object:
    return json.loads(run.call(["curl", "-sS", f"http://{HOST}:{port}/ctl/{endpoint}"]).stdout)


def _count_log(run: LiveRun, port: int, value: str, *, endpoint: str = "log") -> int:
    return str(_ctl(run, port, endpoint)).count(value)


def _config(run: LiveRun, port: int, body: str, *, worker_threads: int = 2, extra_http: str = "") -> Path:
    return run.write(
        run.root / "nginx.conf",
        f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
worker_processes 1; thread_pool default threads={worker_threads};
events {{ worker_connections 256; }}
http {{ access_log off; {extra_http} server {{ listen {BIND_HOST}:{port};
{body}
}} }}
""",
    )


def _checks(checks: list[tuple[bool, str]]) -> int:
    for passed, message in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {message}")
    return 0 if all(item[0] for item in checks) else 1


def minimal(nginx: Path | None = None) -> int:
    mock_port, cache_port = 12871, 12872
    with LiveRun("cvmfs_min", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        _mock(run, mock_port, 6, 7)
        body = f"""    location /cvmfs/ {{
        brix_cvmfs on;
        brix_cache_store posix:{cache};
        brix_storage_backend http://{HOST}:{mock_port};
    }}"""
        config = _config(run, cache_port, body)
        parses = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode == 0
        run.start_nginx(run.root, config, cache_port)
        objects = _ctl(run, mock_port, "objects")
        assert isinstance(objects, list)
        obj, corrupt_obj = objects[1], objects[3]
        store_before = len(list(cache.rglob("*")))
        got = run.curl_bytes(f"http://{HOST}:{cache_port}{obj}")
        origin = run.curl_bytes(f"http://{HOST}:{mock_port}{obj}")
        store_after = len(list(cache.rglob("*")))
        cold_count = _count_log(run, mock_port, obj)
        run.curl_bytes(f"http://{HOST}:{cache_port}{obj}")
        warm_count = _count_log(run, mock_port, obj)
        run.call(["curl", "-sS", "-o", "/dev/null", "-X", "POST", "-d", '{"mode":"corrupt","count":8}', f"http://{HOST}:{mock_port}/ctl/fault"])
        corrupt_status = run.curl_status(f"http://{HOST}:{cache_port}{corrupt_obj}")
        run.call(["curl", "-sS", "-o", "/dev/null", "-X", "POST", "-d", '{"mode":"none","count":0}', f"http://{HOST}:{mock_port}/ctl/fault"])
        clean = run.curl_bytes(f"http://{HOST}:{cache_port}{corrupt_obj}")
        clean_origin = run.curl_bytes(f"http://{HOST}:{mock_port}{corrupt_obj}")
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "cd" * 19
        first_miss = run.curl_status(f"http://{HOST}:{cache_port}{bogus}")
        heads_before = _count_log(run, mock_port, bogus, endpoint="heads")
        second_miss = run.curl_status(f"http://{HOST}:{cache_port}{bogus}")
        heads_after = _count_log(run, mock_port, bogus, endpoint="heads")
        return _checks([
            (parses, "three-directive CVMFS configuration parses"),
            (got == origin, "cold fill byte-exact"),
            (store_after > store_before, "object landed in posix cache store"),
            (cold_count == warm_count, "warm read served from store"),
            (corrupt_status == 502, "default verify rejects corrupt fill"),
            (clean == clean_origin, "clean retry byte-exact after rejected corruption"),
            (first_miss == 404 and second_miss == 404, "unknown CAS name returns 404"),
            (heads_before >= 1 and heads_before == heads_after, "negative result cached"),
        ])


def manifest(nginx: Path | None = None) -> int:
    mock_port, cache_port, ttl = 12861, 12862, 4
    with LiveRun("cvmfs_man", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        mock = _mock(run, mock_port, 2, 1)
        config = _config(run, cache_port, f"""    location /cvmfs/ {{
        brix_storage_backend http://{HOST}:{mock_port}; brix_cache_store posix:{cache};
        brix_cvmfs on; brix_cvmfs_manifest_ttl {ttl};
    }}""")
        run.start_nginx(run.root, config, cache_port)
        path = "/cvmfs/test.cern.ch/.cvmfspublished"
        first = run.curl_bytes(f"http://{HOST}:{cache_port}{path}")
        count_one = _count_log(run, mock_port, "cvmfspublished")
        second = run.curl_bytes(f"http://{HOST}:{cache_port}{path}")
        count_two = _count_log(run, mock_port, "cvmfspublished")
        run.call(["curl", "-sS", f"http://{HOST}:{mock_port}/ctl/manifest/bump"])
        time.sleep(ttl + 1)
        third = run.curl_bytes(f"http://{HOST}:{cache_port}{path}")
        mock.terminate()
        mock.wait(2)
        time.sleep(ttl + 1)
        stale_status = run.curl_status(f"http://{HOST}:{cache_port}{path}")
        stale = run.curl_bytes(f"http://{HOST}:{cache_port}{path}") if stale_status == 200 else b""
        return _checks([
            (first == second and count_one == count_two, "manifest cached within TTL"),
            (third != first, "expired manifest revalidated"),
            (stale_status == 200 and stale == third, "stale-if-error serves last manifest"),
        ])


def connection_reuse(nginx: Path | None = None) -> int:
    mock_port, cache_port = 12895, 12896
    with LiveRun("cvmfs_reuse", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        _mock(run, mock_port, 8, 31, keepalive=True)
        config = _config(run, cache_port, f"""    location /cvmfs/ {{
        brix_storage_backend http://{HOST}:{mock_port}; brix_cache_store posix:{cache}; brix_cvmfs on;
    }}""", worker_threads=1)
        parses = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode == 0
        run.start_nginx(run.root, config, cache_port)
        objects = _ctl(run, mock_port, "objects")
        assert isinstance(objects, list)
        reference = run.curl_bytes(f"http://{HOST}:{mock_port}{objects[0]}")
        before_connections = int(_ctl(run, mock_port, "connections")["connections"])
        before_gets = _count_log(run, mock_port, "/cvmfs/")
        for obj in objects:
            run.curl_bytes(f"http://{HOST}:{cache_port}{obj}")
        delta_connections = int(_ctl(run, mock_port, "connections")["connections"]) - before_connections
        delta_gets = _count_log(run, mock_port, "/cvmfs/") - before_gets
        hit = run.curl_bytes(f"http://{HOST}:{cache_port}{objects[0]}")
        return _checks([
            (parses, "configuration parses"),
            (hit == reference, "cache serves byte-exact object"),
            (delta_gets >= 8 and delta_connections <= 6, f"origin connection reused: {delta_gets} fills over {delta_connections} connections"),
        ])


def failover(nginx: Path | None = None) -> int:
    first_port, second_port, cache_port = 12851, 12852, 12853
    with LiveRun("cvmfs_fo", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        first = _mock(run, first_port, 6, 5)
        second = _mock(run, second_port, 6, 5)
        config = _config(run, cache_port, f"""    location /cvmfs/ {{
        brix_storage_backend "http://{HOST}:{first_port}|http://{HOST}:{second_port}";
        brix_cache_store posix:{cache}; brix_cvmfs on; brix_cvmfs_client_hold 3;
        brix_cvmfs_origin_select static;
    }}""")
        run.start_nginx(run.root, config, cache_port)
        objects = _ctl(run, first_port, "objects")
        assert isinstance(objects, list)
        first.terminate()
        first.wait(2)
        time.sleep(0.1)
        filled = run.curl_bytes(f"http://{HOST}:{cache_port}{objects[0]}")
        reference = run.curl_bytes(f"http://{HOST}:{second_port}{objects[0]}")
        served_secondary = _count_log(run, second_port, objects[0]) >= 1
        recovered = _mock(run, first_port, 6, 5)
        for obj in objects[1:4]:
            run.curl_bytes(f"http://{HOST}:{cache_port}{obj}")
        primary_returned = _count_log(run, first_port, "/data/") >= 1
        for proc in (recovered, second):
            proc.terminate()
        time.sleep(0.1)
        both_down = run.curl_status(f"http://{HOST}:{cache_port}{objects[5]}", timeout=30)
        return _checks([
            (filled == reference and served_secondary, "primary-down fill served by secondary"),
            (primary_returned, "primary reused after recovery"),
            (both_down == 504, "both origins down returns bounded 504"),
        ])


def shared_cache(nginx: Path | None = None) -> int:
    first_port, second_port, proxy_port = 12881, 12882, 12883
    with LiveRun("cvmfs_shared", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        _mock(run, first_port, 4, 77)
        _mock(run, second_port, 4, 77)
        objects = _ctl(run, first_port, "objects")
        assert isinstance(objects, list)
        obj = objects[0]
        source_one = run.curl_bytes(f"http://{HOST}:{first_port}{obj}")
        source_two = run.curl_bytes(f"http://{HOST}:{second_port}{obj}")

        def configure(shared: str) -> Path:
            return _config(run, proxy_port, f"""    location / {{
        brix_cache_store posix:{cache}; brix_cvmfs on; brix_cvmfs_upstream_allow {HOST};
        brix_cvmfs_shared_cache {shared};
    }}""")

        on = configure("on")
        parses = run.call([run.nginx, "-t", "-c", on, "-p", run.root], check=False).returncode == 0
        run.start_nginx(run.root, on, proxy_port)
        one = run.curl_bytes(f"http://{HOST}:{first_port}{obj}", "-x", f"http://{HOST}:{proxy_port}")
        before = _count_log(run, second_port, obj)
        two = run.curl_bytes(f"http://{HOST}:{second_port}{obj}", "-x", f"http://{HOST}:{proxy_port}")
        after = _count_log(run, second_port, obj)
        run.stop_nginx(run.root)
        for child in cache.iterdir():
            if child.is_dir():
                import shutil
                shutil.rmtree(child)
            else:
                child.unlink()
        off = configure("off")
        run.start_nginx(run.root, off, proxy_port)
        run.curl_bytes(f"http://{HOST}:{first_port}{obj}", "-x", f"http://{HOST}:{proxy_port}")
        isolated_before = _count_log(run, second_port, obj)
        run.curl_bytes(f"http://{HOST}:{second_port}{obj}", "-x", f"http://{HOST}:{proxy_port}")
        isolated_after = _count_log(run, second_port, obj)
        return _checks([
            (source_one == source_two, "same-seed origins are byte-identical"),
            (parses, "shared-cache directive parses"),
            (one == two == source_one and before == after, "shared cache hits across upstream names"),
            (isolated_after > isolated_before, "shared-cache off preserves upstream isolation"),
        ])


def keepalive(nginx: Path | None = None) -> int:
    mock_port, keepalive_port, control_port = 12896, 12897, 12898
    with LiveRun("cvmfs_ka", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        _mock(run, mock_port, 4, 44)
        config = run.write(
            run.root / "nginx.conf",
            f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 256; }}
http {{
    access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s; reset_timedout_connection off;
    server {{
        listen {BIND_HOST}:{keepalive_port} so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {{ brix_storage_backend http://{HOST}:{mock_port}; brix_cache_store posix:{cache}; brix_cvmfs on; }}
        location / {{ return 403; }}
    }}
    server {{
        listen {BIND_HOST}:{control_port};
        location /cvmfs/ {{ brix_storage_backend http://{HOST}:{mock_port}; brix_cache_store posix:{cache}; brix_cvmfs on; }}
    }}
}}
""",
        )
        run.start_nginx(run.root, config, keepalive_port)
        objects = _ctl(run, mock_port, "objects")
        assert isinstance(objects, list)
        obj = objects[0]
        connections = []
        for port in (keepalive_port, control_port):
            connection = http.client.HTTPConnection(HOST, port, timeout=10)
            connection.request("GET", obj)
            connection.getresponse().read()
            connections.append(connection)
        time.sleep(0.2)
        ss_keepalive = run.call(["ss", "-tno", "state", "established", f"( sport = :{keepalive_port} )"], check=False).stdout
        ss_control = run.call(["ss", "-tno", "state", "established", f"( sport = :{control_port} )"], check=False).stdout
        client = http.client.HTTPConnection(HOST, keepalive_port, timeout=30)
        durable = True
        try:
            for _ in range(200):
                client.request("GET", obj)
                if client.getresponse().status != 200:
                    durable = False
                    break
            client.request("GET", "/etc/passwd")
            durable = durable and client.getresponse().status in (403, 405)
            client.request("GET", obj)
            durable = durable and client.getresponse().status == 200
        except (OSError, http.client.HTTPException):
            durable = False
        finally:
            client.close()
            for connection in connections:
                connection.close()
        return _checks([
            ("timer:(keepalive" in ss_keepalive, "keepalive timer armed on configured listener"),
            ("timer:(keepalive" not in ss_control, "negative-control listener has no keepalive timer"),
            (durable, "200 requests plus reject reuse one socket"),
        ])


SCENARIOS = {"minimal": minimal, "manifest": manifest, "connection-reuse": connection_reuse, "failover": failover, "shared-cache": shared_cache, "keepalive": keepalive}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"CVMFS scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
