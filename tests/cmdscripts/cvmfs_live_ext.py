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
from settings import free_ports

MOCK_STRATUM1 = REPO_ROOT / "tests/cvmfs/mock_stratum1.py"


class LiveSkip(RuntimeError):
    """Missing binary/feature: the scenario cannot run in this environment."""


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise LiveSkip(reason)


def _mock(run: LiveRun, port: int, objects: int, seed: int, *, keepalive: bool = False) -> subprocess.Popen[str]:
    argv = [sys.executable, MOCK_STRATUM1, "--port", str(port), "--objects", str(objects), "--seed", str(seed)]
    if keepalive:
        argv.append("--keepalive")
    proc = run.spawn(argv)
    for _ in range(50):
        if proc.poll() is not None:
            raise LiveFailure(f"mock Stratum-1 on port {port} did not start")
        ready = run.call(["curl", "-sf", "-m", "1", "-o", os.devnull, f"http://127.0.0.1:{port}/ctl/objects"], check=False)
        if ready.returncode == 0:
            return proc
        time.sleep(0.1)
    raise LiveFailure(f"mock Stratum-1 on port {port} never became ready")


def _mock_stop(run: LiveRun, proc: subprocess.Popen[str] | None, port: int) -> None:
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()
    for _ in range(50):
        gone = run.call(["curl", "-sf", "-m", "1", "-o", os.devnull, f"http://127.0.0.1:{port}/ctl/objects"], check=False)
        if gone.returncode != 0:
            return
        time.sleep(0.1)


def _objects(run: LiveRun, port: int) -> list[str]:
    objects = _ctl(run, port, "objects")
    assert isinstance(objects, list)
    return objects


def _fault(run: LiveRun, port: int, mode: str, count: int) -> None:
    run.call(["curl", "-sS", "-o", os.devnull, "-X", "POST", "-d",
              f'{{"mode":"{mode}","count":{count}}}', f"http://127.0.0.1:{port}/ctl/fault"])


def _curl_code_to(run: LiveRun, url: str, out: Path, *extra: str, timeout: int = 25) -> int:
    result = run.call(
        ["curl", "-s", "--max-time", str(timeout), "-o", out, "-w", "%{http_code}", *extra, url],
        check=False,
    )
    text = result.stdout.strip()
    return int(text) if text.isdigit() else 0


def _concurrent_gets(url: str, count: int) -> None:
    procs = [
        subprocess.Popen(["curl", "-s", url, "-o", os.devnull],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(count)
    ]
    for proc in procs:
        proc.wait(60)


def _metrics(run: LiveRun, port: int) -> str:
    return run.call(["curl", "-sS", f"http://127.0.0.1:{port}/metrics"]).stdout


def _mval(text: str, prefix: str) -> float:
    """First metrics line starting with prefix -> its value (0 when absent)."""
    for line in text.splitlines():
        if line.startswith(prefix):
            try:
                return float(line.split()[-1])
            except ValueError:
                return 0.0
    return 0.0


def _grep(path: Path, pattern: str, *, regex: bool = False) -> bool:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return False
    return bool(re.search(pattern, text)) if regex else pattern in text


def _restart_nginx(run: LiveRun, config: Path, port: int, cache: Path) -> None:
    """stop + wipe cache + truncate error log + start (the shell restart())."""
    run.stop_nginx(run.root)
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    log = run.root / "logs/e.log"
    if log.exists():
        log.write_text("")
    run.start_nginx(run.root, config, port)
    time.sleep(0.3)


# ---------------------------------------------------------------------------
# FUSE-bench primitives (bench + faultproxy-bench)
# ---------------------------------------------------------------------------

BRIX_CORE_SOURCES = [
    "shared/cvmfs/client/client.c", "shared/cvmfs/fetch/fetch.c", "shared/cvmfs/object/object.c",
    "shared/cvmfs/failover/failover.c", "shared/cvmfs/catalog/catalog.c", "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c", "shared/cvmfs/signature/manifest.c", "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c", "shared/cvmfs/config/repo.c", "shared/cvmfs/config/cvmfs_conf.c",
    "shared/cvmfs/walk/walk.c", "shared/cache/cas_store.c", "shared/net/proxy_env.c",
]


def _ensure_brixcvmfs(run: LiveRun) -> Path:
    prebuilt = Path("/tmp/brixcvmfs")
    if os.access(prebuilt, os.X_OK):
        return prebuilt
    _require(shutil.which("gcc"), "no gcc to build brixcvmfs")
    _require(shutil.which("pkg-config"), "no pkg-config for fuse3 flags")
    flags = run.call(["pkg-config", "--cflags", "fuse3"], check=False)
    libs = run.call(["pkg-config", "--libs", "fuse3"], check=False)
    _require(flags.returncode == 0 and libs.returncode == 0, "fuse3 development files unavailable")
    binary = run.root / "brixcvmfs"
    built = run.call(
        ["gcc", "-Wall", "-Wextra", "-Werror", "-I", "shared", *flags.stdout.split(),
         "-o", binary, "client/apps/fs/brixcvmfs.c", *BRIX_CORE_SOURCES,
         *libs.stdout.split(), "-lcurl", "-lsqlite3", "-lcrypto", "-lz"],
        cwd=REPO_ROOT, check=False,
    )
    if built.returncode != 0:
        raise LiveFailure(f"brixcvmfs build failed: {(built.stderr or built.stdout)[-2000:]}")
    return binary


def _brix_mount(run: LiveRun, brix: Path, repo: str, server: str, keys: str,
                cache: Path, tmp: Path, mnt: Path, *, retries: int = 5,
                extra_env: dict[str, str] | None = None) -> subprocess.Popen[str]:
    env = {
        "BRIXCVMFS_SERVER": server, "BRIXCVMFS_PUBKEY": keys,
        "BRIXCVMFS_CACHE": str(cache), "BRIXCVMFS_TMP": str(tmp),
        **(extra_env or {}),
    }
    return run.spawn(
        [brix, repo, mnt, "-o", f"noclever,fresh,retries={retries},auto_unmount", "-f"],
        env=env,
    )


def _wait_mount_ready(mnt: Path, tries: int = 80) -> bool:
    for _ in range(tries):
        try:
            if os.listdir(mnt):
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def _umount_wait(run: LiveRun, mnt: Path) -> None:
    if run.call(["fusermount3", "-u", mnt], check=False).returncode != 0:
        run.call(["fusermount", "-u", mnt], check=False)
    time.sleep(1)


def _enumerate_files(run: LiveRun, mnt: Path, nfiles: int) -> list[str]:
    found = run.call(["find", mnt, "-maxdepth", "6", "-type", "f", "-size", "-64k"], check=False)
    files = []
    prefix = f"{mnt}/"
    for line in found.stdout.splitlines():
        if line.startswith(prefix):
            files.append(line[len(prefix):])
        if len(files) >= nfiles:
            break
    return files


def _read_files(mnt: Path, files: list[str], per_file_timeout: int) -> tuple[int, int, float]:
    ok = 0
    start = time.monotonic()
    for rel in files:
        try:
            proc = subprocess.run(["cat", str(mnt / rel)], stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=per_file_timeout)
            if proc.returncode == 0:
                ok += 1
        except subprocess.TimeoutExpired:
            pass
    return ok, len(files), time.monotonic() - start


def _stock_cvmfs2_conf(path: Path, server_url: str, proxy: str, keys: str, cache: Path, retries: int) -> Path:
    path.write_text(
        f"""CVMFS_SERVER_URL={server_url}
CVMFS_HTTP_PROXY={proxy}
CVMFS_KEYS_DIR={keys}
CVMFS_CACHE_BASE={cache}
CVMFS_RELOAD_SOCKETS={cache}
CVMFS_SHARED_CACHE=no
CVMFS_MAX_RETRIES={retries}
""")
    return path


def _bench_cell(mnt_ok: bool, res: tuple[int, int, float] | None, total: int) -> str:
    if not mnt_ok or res is None:
        return f"0/{total}  mount-fail"
    ok, tot, secs = res
    return f"{ok}/{tot}  {secs:.1f}s"


# ---------------------------------------------------------------------------
# bench — cvmfs-brix vs stock cvmfs2 through failproxy.py, real Stratum-1
# ---------------------------------------------------------------------------

def bench(nginx: Path | None = None) -> int:
    repo = os.environ.get("REPO", "cms.cern.ch")
    s1 = os.environ.get("ATLAS_S1", f"http://s1cern-cvmfs.openhtc.io/cvmfs/{repo}")
    keys = "/etc/cvmfs/keys/cern.ch"
    nfiles = int(os.environ.get("NFILES", "25"))
    mode = os.environ.get("MODE", "loss")
    rates = os.environ.get("RATES", "0 15 30").split()
    with LiveRun("cvmfs_bench", nginx) as run:
        reachable = run.call(["curl", "-fsS", "-o", os.devnull, "--max-time", "8",
                              f"{s1}/.cvmfspublished"], check=False)
        _require(reachable.returncode == 0, f"Stratum-1 unreachable: {s1}")
        _require(shutil.which("cvmfs2"), "no stock cvmfs2")
        _require(shutil.which("fusermount3") or shutil.which("fusermount"), "no fusermount")
        _require(Path(keys).exists(), f"CVMFS keys missing: {keys}")
        brix = _ensure_brixcvmfs(run)
        (pport,) = free_ports(1)

        print(f"== enumerate {nfiles} {repo} files (clean brix mount) ==")
        e_mnt, e_cache, e_tmp = run.mkdir("emnt"), run.mkdir("ecache"), run.mkdir("etmp")
        enum_proc = _brix_mount(run, brix, repo, s1, keys, e_cache, e_tmp, e_mnt)
        if not _wait_mount_ready(e_mnt):
            print("   (enumerate mount slow)")
        files = _enumerate_files(run, e_mnt, nfiles)
        ngot = len(files)
        print(f"   enumerated {ngot} files")
        _umount_wait(run, e_mnt)
        if enum_proc.poll() is None:
            enum_proc.terminate()

        rows: list[tuple[str, tuple[int, int, float] | None, tuple[int, int, float] | None, int, int]] = []
        if ngot >= 1:
            print(f"\n{mode + '%':<6} | {'CVMFS-brix (ok/N, secs)':<28} | {'stock cvmfs2 (ok/N, secs)':<28}")
            print("-------+------------------------------+------------------------------")
            for rate in rates:
                plog = run.root / f"failproxy.{rate}.log"
                fp = run.spawn([sys.executable, REPO_ROOT / "tests/cvmfs/failproxy.py", str(pport),
                                "--mode", mode, "--rate", str(int(rate) / 100.0), "--log", plog])
                time.sleep(1)

                bc, bt, bm = run.mkdir(f"bc{rate}"), run.mkdir(f"bt{rate}"), run.mkdir(f"bm{rate}")
                bp = _brix_mount(run, brix, repo, s1, keys, bc, bt, bm,
                                 extra_env={"http_proxy": f"http://127.0.0.1:{pport}"})
                brix_ok = _wait_mount_ready(bm)
                brix_res = _read_files(bm, files, 25) if brix_ok else None
                _umount_wait(run, bm)
                if bp.poll() is None:
                    bp.terminate()

                sc, sm = run.mkdir(f"sc{rate}"), run.mkdir(f"sm{rate}")
                conf = _stock_cvmfs2_conf(run.root / f"bench_stock.{rate}.conf", s1,
                                          f"http://127.0.0.1:{pport}", keys, sc, 5)
                sp = run.spawn(["timeout", "60", "cvmfs2", "-o", f"config={conf}", repo, sm])
                stock_ok = _wait_mount_ready(sm)
                stock_res = _read_files(sm, files, 25) if stock_ok else None
                _umount_wait(run, sm)
                if sp.poll() is None:
                    sp.terminate()

                fp.terminate()
                try:
                    fp.wait(3)
                except subprocess.TimeoutExpired:
                    fp.kill()
                req = faults = 0
                if plog.exists():
                    stats = re.findall(r"STATS req=(\d+) fault=(\d+)", plog.read_text(errors="replace"))
                    if stats:
                        req, faults = int(stats[-1][0]), int(stats[-1][1])
                rows.append((rate, brix_res, stock_res, req, faults))
                print(f"{rate:<6} | {_bench_cell(brix_ok, brix_res, ngot):<28} | "
                      f"{_bench_cell(stock_ok, stock_res, ngot):<28} | proxyreq={req} faults={faults}")
            print(f"\n(mode={mode}, N={ngot} files, {repo} via {s1}; both clients COLD cache)")

        # Bench lane: sanity/correctness only — completed, non-zero throughput.
        rate0 = next((row for row in rows if row[0] == "0"), None)
        return _checks([
            (ngot >= 1, f"enumerated at least one repository file ({ngot})"),
            (len(rows) == len(rates), f"fault-rate sweep completed ({len(rows)}/{len(rates)} rates)"),
            (rate0 is not None and rate0[1] is not None and rate0[1][0] >= 1,
             "fault-free brix run read at least one file"),
            (rate0 is not None and rate0[1] is not None and rate0[1][2] > 0
             and rate0[1][0] / rate0[1][2] > 0, "fault-free brix run has non-zero throughput"),
            (rate0 is not None and rate0[3] >= 1, "reads demonstrably traversed the failproxy (proxyreq>0)"),
        ])


# ---------------------------------------------------------------------------
# reverse — module CVMFS personality e2e (parse, cache, stampede, visibility)
# ---------------------------------------------------------------------------

def reverse(nginx: Path | None = None) -> int:
    mport, cport, xport, dport = free_ports(4)
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
        listen 127.0.0.1:{cport} so_keepalive=60s:10s:6 backlog=2048;
        location /cvmfs/ {{
            brix_storage_backend http://127.0.0.1:{mport};
            brix_cache_store posix:{cache};
            brix_cvmfs on;
            brix_cvmfs_manifest_ttl 1;
        }}
        location / {{ return 403; }}
    }}
    server {{
        listen 127.0.0.1:{xport};
        access_log off;
        location /metrics {{ brix_metrics on; }}
        location /healthz {{ brix_health on; }}
    }}
    server {{
        listen 127.0.0.1:{dport};
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
        cold = run.curl_bytes(f"http://127.0.0.1:{cport}{obj}")
        after_cold = _count_log(run, mport, obj)
        warm = run.curl_bytes(f"http://127.0.0.1:{cport}{obj}")
        after_warm = _count_log(run, mport, obj)
        origin = run.curl_bytes(f"http://127.0.0.1:{mport}{obj}")

        # stampede: exactly 1 origin fetch (module fill-lock)
        obj2 = objects[4]
        _concurrent_gets(f"http://127.0.0.1:{cport}{obj2}", 40)
        stampede_fetches = _count_log(run, mport, obj2)

        # manifest: 1s TTL — a bump becomes visible after expiry (poll windows)
        manifest_url = f"http://127.0.0.1:{cport}/cvmfs/test.cern.ch/.cvmfspublished"
        m1 = run.curl_bytes(manifest_url)
        run.call(["curl", "-s", "-o", os.devnull, f"http://127.0.0.1:{mport}/ctl/manifest/bump"])
        revalidated = False
        for _ in range(3):
            time.sleep(2)
            if run.curl_bytes(manifest_url) != m1:
                revalidated = True
                break

        # geo passthrough
        geo = run.curl_bytes(f"http://127.0.0.1:{cport}/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b")

        # security-neg: rejects for non-CVMFS shapes; 405 for writes
        c1 = run.curl_status(f"http://127.0.0.1:{cport}/cvmfs/../etc/passwd")
        c2 = run.curl_status(f"http://127.0.0.1:{cport}/cvmfs/repo/random.txt")
        c3 = run.curl_status(f"http://127.0.0.1:{cport}/cvmfs/test.cern.ch/.cvmfspublished",
                             "-X", "PUT", "--data", "x")

        # negative cache: 2 misses for the same bogus CAS name -> 1 origin probe
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "ab" * 19
        cn1 = run.curl_status(f"http://127.0.0.1:{cport}{bogus}")
        nb1 = _count_log(run, mport, bogus, endpoint="heads")
        cn2 = run.curl_status(f"http://127.0.0.1:{cport}{bogus}")
        nb2 = _count_log(run, mport, bogus, endpoint="heads")

        # T16: dashboard sees an IN-FLIGHT cvmfs fill (stalled origin)
        obj6 = objects[6]
        _fault(run, mport, "stall", 1)
        stalled = run.spawn(["curl", "-s", "--max-time", "6",
                             f"http://127.0.0.1:{cport}{obj6}", "-o", os.devnull])
        dashboard_json = ""
        slot_visible = False
        for _ in range(25):
            ts = str(int(time.time()))
            digest = hmac.new(b"t16", ts.encode(), hashlib.sha256).hexdigest()
            dashboard_json = run.call(
                ["curl", "-s", "-H", f"Cookie: xrd_dashboard={digest}.{ts}",
                 f"http://127.0.0.1:{dport}/brix/api/v1/transfers"], check=False).stdout
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
        healthz = run.call(["curl", "-s", f"http://127.0.0.1:{xport}/healthz?verbose"]).stdout
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
            run.curl_status(f"http://127.0.0.1:{cport}/cvmfs/flood{i}.example.org/data/aa/{flood_bogus}")
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
    mport, cport = free_ports(2)
    with LiveRun("cvmfs_hold", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")

        def mkconf(client_hold: int) -> Path:
            return run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen 127.0.0.1:{cport};
    location /cvmfs/ {{
        brix_storage_backend http://127.0.0.1:{mport};
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
        code = _curl_code_to(run, f"http://127.0.0.1:{cport}{objs[0]}", a_bin, timeout=30)
        timer.join()
        time.sleep(0.5)
        ref = run.curl_bytes(f"http://127.0.0.1:{mport}{objs[0]}")
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
        conn = http.client.HTTPConnection("127.0.0.1", cport, timeout=30)
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
                  f"http://127.0.0.1:{cport}{objs[2]}", "-o", os.devnull], check=False)  # aborts
        _mock(run, mport, 6, 20)
        time.sleep(6)  # detached fill (max_life 60) retries and lands
        n1 = _count_log(run, mport, objs[2])
        code = run.curl_status(f"http://127.0.0.1:{cport}{objs[2]}")
        n2 = _count_log(run, mport, objs[2])
        checks.append((code == 200 and n1 >= 1 and n1 == n2,
                       f"detached fill populated cache (code={code} origin={n1}->{n2})"))

        # --- 4: 404 definitive, immediate -------------------------------------
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "ef" * 19
        t0 = time.monotonic()
        code = run.curl_status(f"http://127.0.0.1:{cport}{bogus}")
        elapsed = time.monotonic() - t0
        checks.append((code == 404 and elapsed <= 2,
                       f"404 immediate (no hold): code={code} took {elapsed:.1f}s"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# proxy — forward-proxy (CVMFS_HTTP_PROXY) mode
# ---------------------------------------------------------------------------

def proxy(nginx: Path | None = None) -> int:
    m1, m2, cport, cport2 = free_ports(4)
    with LiveRun("cvmfs_proxy", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        _mock(run, m1, 4, 11)
        _mock(run, m2, 4, 22)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen 127.0.0.1:{cport};
    location / {{
        brix_cache_store posix:{cache};
        brix_cvmfs on;
        brix_cvmfs_upstream_allow 127.0.0.1;
        brix_cvmfs_upstream_max 4;
    }}
}} }}
""")
        run.start_nginx(run.root, config, cport)
        proxy_url = f"http://127.0.0.1:{cport}"

        o1 = _objects(run, m1)[0]
        o2 = _objects(run, m2)[0]

        # 1: proxy-style fetch, byte-exact, warm hit stays local
        p1 = run.curl_bytes(f"http://127.0.0.1:{m1}{o1}", "-x", proxy_url)
        r1 = run.curl_bytes(f"http://127.0.0.1:{m1}{o1}")
        na = _count_log(run, m1, o1)
        run.curl_bytes(f"http://127.0.0.1:{m1}{o1}", "-x", proxy_url)
        nb = _count_log(run, m1, o1)

        # 2: second upstream is independent (different seed -> different objects)
        p2 = run.curl_bytes(f"http://127.0.0.1:{m2}{o2}", "-x", proxy_url)
        r2 = run.curl_bytes(f"http://127.0.0.1:{m2}{o2}")

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
    listen 127.0.0.1:{cport2};
    access_log {logs2}/a.log cvt;
    location / {{
        brix_cache_store posix:{cache2};
        brix_cvmfs on;
        brix_cvmfs_upstream_allow bogus.example.org 127.0.0.1 also-bogus.example.org;
        brix_cvmfs_upstream_max 4;
    }}
}} }}
""")
        run.start_nginx(prefix2, config2, cport2)
        proxy2 = f"http://127.0.0.1:{cport2}"
        multi_ok = run.curl_status(f"http://127.0.0.1:{m1}{o1}", "-x", proxy2)
        multi_reject = run.curl_status("http://evil.example.org/cvmfs/x/.cvmfspublished", "-x", proxy2)

        # 5: regression — a REJECTED request logs its TRUE URL class
        run.curl_status("http://evil.example.org/cvmfs/x/api/v1.0/geo/localhost/a,b", "-x", proxy2)
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

def resilience(nginx: Path | None = None) -> int:
    mport, cport = free_ports(2)
    # Ports 8000/2222 are semantic: the geo probe guard allows the standard
    # CVMFS port (8000) and must never touch a disallowed one (2222).
    with LiveRun("cvmfs_res", nginx) as run:
        cache, logs, sink_dir = run.mkdir("cache"), run.mkdir("logs"), run.mkdir("sink")
        sink = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", 8000))
            port_free = True
        except OSError:
            port_free = False
        if port_free:
            sink = run.spawn([sys.executable, REPO_ROOT / "tests/cvmfs/probe_sink.py",
                              sink_dir, "8000", "2222"])
            for _ in range(50):
                if (sink_dir / "ready").exists():
                    break
                time.sleep(0.1)
        else:
            print("  SKIP geo ranking asserts: port 8000 already in use")

        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{
    server {{
        listen 127.0.0.1:{cport};
        location /cvmfs/ {{
            brix_storage_backend http://127.0.0.1:{mport};
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

        # Part A: stuck-before-data origin -> force-through, not a stall
        obj = _objects(run, mport)[0]
        orig = run.curl_bytes(f"http://127.0.0.1:{mport}{obj}")
        _fault(run, mport, "stall", 1)
        got = run.root / "got.bin"
        t0 = time.monotonic()
        code = _curl_code_to(run, f"http://127.0.0.1:{cport}{obj}", got, timeout=15)
        dt = time.monotonic() - t0
        checks.append((code == 200 and got.read_bytes() == orig,
                       f"stalled origin forced through (code={code} in {dt:.1f}s, no 504/hang)"))
        checks.append((dt < 12, f"stall detected fast ({dt:.1f}s << 60s default ceiling)"))
        _fault(run, mport, "none", 0)

        # Part B: RTT-ranked geo answer + probe guard
        if sink is not None:
            geo_list = "192.0.2.2:8000,127.0.0.1:8000,127.0.0.1:2222"
            answer = run.call(["curl", "-s",
                               f"http://127.0.0.1:{cport}/cvmfs/test.cern.ch/api/v1.0/geo/x/{geo_list}"]).stdout
            answer = "".join(answer.split())
            checks.append((answer == "2,1,3",
                           f"geo RTT rank: reachable<unreachable<disallowed ({answer!r})"))
            hits_8000 = (sink_dir / "8000.hits").stat().st_size if (sink_dir / "8000.hits").exists() else 0
            hits_2222 = (sink_dir / "2222.hits").stat().st_size if (sink_dir / "2222.hits").exists() else 0
            checks.append((hits_8000 >= 1, f"guard: allowed port 8000 was probed ({hits_8000})"))
            checks.append((hits_2222 == 0,
                           f"guard: disallowed port 2222 never connected ({hits_2222} connects)"))
            geo_list2 = "127.0.0.1:2222,127.0.0.1:8000,192.0.2.2:8000,127.0.0.1:22,127.0.0.1:8000"
            answer2 = run.call(["curl", "-s",
                                f"http://127.0.0.1:{cport}/cvmfs/test.cern.ch/api/v1.0/geo/x/{geo_list2}"]).stdout
            answer2 = "".join(answer2.split())
            ordered = ",".join(sorted(answer2.split(","), key=lambda item: int(item or "0")))
            checks.append((ordered == "1,2,3,4,5",
                           f"geo answer is a complete permutation of 1..5 ({answer2!r})"))

        # robustness: unresolvable-hostname list still yields a well-formed answer
        fallback = run.call(["curl", "-s",
                             f"http://127.0.0.1:{cport}/cvmfs/test.cern.ch/api/v1.0/geo/x/a,b"]).stdout
        fallback = "".join(fallback.split())
        checks.append((len(fallback) > 0,
                       f"geo answer/fallback returns non-empty for name list ({fallback!r})"))
        return _checks(checks)


# ---------------------------------------------------------------------------
# stock — Phase-1 stock-nginx CVMFS cache e2e (deploy/cvmfs template)
# ---------------------------------------------------------------------------

def stock(nginx: Path | None = None) -> int:
    mport, rport, pport = free_ports(3)
    with LiveRun("cvmfs_stock", nginx) as run:
        run.mkdir("store")
        run.mkdir("logs")
        _mock(run, mport, 8, 7)
        template = (REPO_ROOT / "deploy/cvmfs/nginx-proxy-cache.conf").read_text()
        rendered = (template
                    .replace("@PORT@", str(rport))
                    .replace("@PPORT@", str(pport))
                    .replace("@CACHEDIR@", str(run.root))
                    .replace("@ORIGIN@", f"127.0.0.1:{mport}")
                    .replace("@ORIGINHOST@", "127.0.0.1")
                    .replace("@ORIGINPORT@", str(mport)))
        config = run.write(run.root / "nginx.conf", rendered)
        run.start_nginx(run.root, config, rport)

        objects = _objects(run, mport)
        obj = objects[0]

        # 1: cold + warm byte-exact
        cold = run.curl_bytes(f"http://127.0.0.1:{rport}{obj}")
        warm = run.curl_bytes(f"http://127.0.0.1:{rport}{obj}")
        orig = run.curl_bytes(f"http://127.0.0.1:{mport}{obj}")

        # 2: stampede coalescing on a fresh object
        obj2 = objects[3]
        n0 = _count_log(run, mport, obj2)
        _concurrent_gets(f"http://127.0.0.1:{rport}{obj2}", 40)
        n1 = _count_log(run, mport, obj2)

        # 3: security-neg
        c1 = run.curl_status(f"http://127.0.0.1:{rport}/etc/passwd")
        c2 = run.curl_status("http://evil.example.org/cvmfs/x/data/aa/bb",
                             "-x", f"http://127.0.0.1:{pport}")

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
    m1, m2, cport = free_ports(3)
    with LiveRun("cvmfs_unified", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        mock1 = _mock(run, m1, 4, 55)
        _mock(run, m2, 4, 55)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
worker_processes 1; thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen 127.0.0.1:{cport};
    location / {{
        brix_storage_backend "http://127.0.0.1:{m1}|http://127.0.0.1:{m2}";
        brix_cache_store posix:{cache};
        brix_cvmfs on;
        brix_cvmfs_upstream_allow 127.0.0.1;
        brix_cvmfs_unified_origin on;
        brix_cvmfs_origin_connect_timeout 1;
        brix_cvmfs_origin_attempt_timeout 2;
        brix_cvmfs_client_hold 4;
    }}
}} }}
""")
        parses = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode == 0

        obj = _objects(run, m1)[0]
        ref = run.curl_bytes(f"http://127.0.0.1:{m1}{obj}")

        # B: two client-named authorities -> ONE origin fetch (unified backend)
        run.start_nginx(run.root, config, cport)
        proxy_url = f"http://127.0.0.1:{cport}"
        b1 = _count_log(run, m1, obj)
        b2 = _count_log(run, m2, obj)
        g1 = run.curl_bytes(f"http://127.0.0.1:{m1}{obj}", "-x", proxy_url)
        g2 = run.curl_bytes(f"http://127.0.0.1:{m2}{obj}", "-x", proxy_url)
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
        code = _curl_code_to(run, f"http://127.0.0.1:{m1}{obj}", ha, "-x", proxy_url, timeout=8)
        failover_ok = code == 200 and ha.read_bytes() == ref

        # config guard: unified_origin without an http storage_backend rejected
        bad = run.write(run.root / "bad.conf", f"""daemon off; events {{ worker_connections 32; }}
http {{ server {{ listen 127.0.0.1:{cport}; location / {{
    brix_cache_store posix:{cache};
    brix_cvmfs on; brix_cvmfs_upstream_allow 127.0.0.1;
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
    mral, malt, cport, xport, dead = free_ports(5)
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
    server {{ listen 127.0.0.1:{cport};
        location /cvmfs/ {{
            brix_storage_backend "{backends}";
            brix_cache_store posix:{cache};
            brix_cvmfs on;
{extra}
        }} }}
    server {{ listen 127.0.0.1:{xport}; location = /metrics {{ brix_metrics on; }} }}
}}
""")

        checks: list[tuple[bool, str]] = []

        # 1: attribution to the RAL upstream
        config = mkconf(f"http://127.0.0.1:{mral}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj0}")
        ral = f"127.0.0.1:{mral}"
        metrics = _metrics(run, xport)
        requests = _mval(metrics, f'brix_cvmfs_upstream_requests_total{{upstream="{ral}"}}')
        fills = _mval(metrics, f'brix_cvmfs_upstream_fills_total{{upstream="{ral}"}}')
        origin_bytes = _mval(metrics, f'brix_cvmfs_upstream_origin_bytes_total{{upstream="{ral}"}}')
        checks.append((requests >= 1 and fills >= 1 and origin_bytes >= 1,
                       f"fill attributed to upstream RAL (req={requests:g} fills={fills:g} bytes={origin_bytes:g})"))
        hist_count = _mval(metrics, f'brix_cvmfs_upstream_fill_duration_seconds_count{{upstream="{ral}"}}')
        hist_inf = _mval(metrics, f'brix_cvmfs_upstream_fill_duration_seconds_bucket{{upstream="{ral}",le="+Inf"}}')
        hist_sum = f'brix_cvmfs_upstream_fill_duration_seconds_sum{{upstream="{ral}"}}' in metrics
        checks.append((hist_sum and hist_count >= 1 and hist_inf >= 1,
                       f"fill-duration histogram present (count={hist_count:g} +Inf={hist_inf:g})"))

        # 3: cardinality — the upstream label is host:port only, no path/repo
        leaked = re.search(r'brix_cvmfs_upstream_.*upstream="[^"]*(/|data/|\.cvmfs)', metrics)
        checks.append((leaked is None, "upstream label is bounded host:port (no path/repo leak)"))

        # 2: failover attribution — dead primary, fills served by the fallback
        config = mkconf(f"http://127.0.0.1:{dead}|http://127.0.0.1:{malt}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj1}")
        alt = f"127.0.0.1:{malt}"
        metrics = _metrics(run, xport)
        failovers = _mval(metrics, f'brix_cvmfs_upstream_failovers_total{{upstream="{alt}"}}')
        alt_fills = _mval(metrics, f'brix_cvmfs_upstream_fills_total{{upstream="{alt}"}}')
        checks.append((failovers >= 1 and alt_fills >= 1,
                       f"failover fill attributed to the fallback upstream (failovers={failovers:g})"))

        # 4: trace ON -> client + upstream lines at INFO
        config = mkconf(f"http://127.0.0.1:{mral}", "            brix_cvmfs_trace on;", "info")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj0}")
        time.sleep(0.3)
        checks.append((_grep(error_log, r"cvmfs-trace: client .*class=cas .*cache=fill", regex=True),
                       "trace on: client-op line at INFO"))
        checks.append((_grep(error_log,
                             rf"cvmfs-trace: upstream (GET|HEAD) http://127.0.0.1:{mral}.*status=2[0-9][0-9]",
                             regex=True),
                       "trace on: upstream-request line at INFO"))

        # 5: trace OFF + info level -> neither line
        config = mkconf(f"http://127.0.0.1:{mral}", "", "info")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj1}")
        time.sleep(0.3)
        checks.append((not _grep(error_log, "cvmfs-trace:"),
                       "trace off + error_log info: no trace lines"))

        # 6: trace OFF + debug level -> both lines (debug path)
        config = mkconf(f"http://127.0.0.1:{mral}", "", "debug")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj0}")
        time.sleep(0.3)
        checks.append((_grep(error_log, "cvmfs-trace: client ") and _grep(error_log, "cvmfs-trace: upstream GET"),
                       "trace off + error_log debug: both lines at DEBUG"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# logging — the cvmfs operational-logging contract
# ---------------------------------------------------------------------------

def logging(nginx: Path | None = None) -> int:
    mport, cport = free_ports(2)
    with LiveRun("cvmfs_log", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        log = logs / "e.log"
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {log} info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{cport};
        location /cvmfs/ {{
            brix_storage_backend http://127.0.0.1:{mport};
            brix_cache_store posix:{cache};
            brix_cvmfs on;
            brix_cvmfs_negative_ttl 30;
            brix_cvmfs_client_hold 2;
            brix_cvmfs_fill_max_life 20;
        }}
    }}
}}
""")
        run.start_nginx(run.root, config, cport)
        _mock(run, mport, 8, 5)
        objects = _objects(run, mport)
        checks: list[tuple[bool, str]] = []

        # 1: healthy cold fill logs a clean done
        run.curl_status(f"http://127.0.0.1:{cport}{objects[0]}")
        time.sleep(0.3)
        checks.append((_grep(log, "xrootd-fill: event=done") and _grep(log, "attempts=1"),
                       "clean fill logs event=done attempts=1"))

        # 2: reset the origin repeatedly -> retry + recovered
        _fault(run, mport, "reset", 3)
        run.curl_status(f"http://127.0.0.1:{cport}{objects[2]}", timeout=15)
        time.sleep(0.3)
        checks.append((_grep(log, "xrootd-fill: event=retry"),
                       "transient origin failure logs event=retry (attempt/backoff)"))
        checks.append((_grep(log, "xrootd-fill: event=recovered"),
                       "fill after retries logs event=recovered"))

        # 3: origin health TRANSITION -> degraded
        checks.append((_grep(log, "xrootd-origin: event=degraded"),
                       "origin flap logs event=degraded (host/port)"))

        # 4: stalled origin past the hold -> hold-expired + 504
        _fault(run, mport, "stall", 9)
        code = run.curl_status(f"http://127.0.0.1:{cport}{objects[4]}", timeout=10)
        time.sleep(0.3)
        checks.append((code == 504, f"stalled origin -> client gets 504 (kept-alive) ({code})"))
        checks.append((_grep(log, "xrootd-fill: event=hold-expired") and _grep(log, "held_ms="),
                       "hold expiry logs event=hold-expired with held_ms"))
        _fault(run, mport, "none", 0)

        # 5: client abandons mid-fill -> client-gone
        _fault(run, mport, "stall", 9)
        run.call(["curl", "-s", "--max-time", "1",
                  f"http://127.0.0.1:{cport}{objects[6]}", "-o", os.devnull], check=False)
        time.sleep(1)
        checks.append((_grep(log, "xrootd-fill: event=client-gone") and _grep(log, "parked_ms="),
                       "client abort mid-fill logs event=client-gone with parked_ms"))
        _fault(run, mport, "none", 0)

        # 6: 404 hammering -> absorbed-404
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "bc" * 19
        for _ in range(3):
            run.curl_status(f"http://127.0.0.1:{cport}{bogus}")
        time.sleep(0.2)
        neg_lines = log.read_text(errors="replace").count("cvmfs-neg: event=absorbed-404")
        checks.append((neg_lines >= 1, f"repeated 404s log cvmfs-neg absorbed-404 ({neg_lines})"))

        # 7: every emitted line carries a client= or key= locator
        bad_line = ""
        for line in log.read_text(errors="replace").splitlines():
            if re.search(r"xrootd-fill:|cvmfs-neg:|cvmfs-client:", line) \
                    and not re.search(r"client=|key=", line):
                bad_line = line
                break
        checks.append((not bad_line, f"every cvmfs event line has a client= or key= locator {bad_line!r}"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# select — origin selection policies (static / geo / rtt / default)
# ---------------------------------------------------------------------------

SELECT_UNIT_C = """#include "protocols/cvmfs/origin_geo.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    /* Edinburgh <-> CERN is ~1180 km great-circle */
    double d = brix_cvmfs_haversine_km(55.95, -3.19, 46.23, 6.05);
    assert(d > 1000.0 && d < 1300.0);
    /* argsort with a tie: ties keep input order (stability) */
    double m[4] = { 9.0, 1.0, 9.0, 4.0 };
    int r[4];
    brix_cvmfs_rank_by_metric(m, 4, r);
    assert(r[1] == 0 && r[3] == 1 && r[0] == 2 && r[2] == 3);
    printf("origin_geo unit OK\\n");
    return 0;
}
"""


def select(nginx: Path | None = None) -> int:
    ma, mb, cport = free_ports(3)
    with LiveRun("cvmfs_sel", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        checks: list[tuple[bool, str]] = []

        # 0: pure-C unit (no nginx)
        _require(shutil.which("gcc"), "no gcc for the origin_geo unit test")
        unit_c = run.write(run.root / "u.c", SELECT_UNIT_C)
        unit_bin = run.root / "u"
        built = run.call(["gcc", "-Wall", "-Werror", "-I", REPO_ROOT / "src", "-o", unit_bin,
                          unit_c, REPO_ROOT / "src/protocols/cvmfs/origin_geo.c", "-lm"], check=False)
        unit_ok = built.returncode == 0 and run.call([unit_bin], check=False).returncode == 0
        checks.append((unit_ok, "unit: haversine+argsort"))

        _mock(run, ma, 4, 31)
        _mock(run, mb, 4, 31)
        obj = _objects(run, ma)[0]
        rtt_log = r"cvmfs rtt (ranks|initial ranking|ranking CHANGED)"
        error_log = logs / "e.log"

        def mkconf(directives: str, backends: str) -> Path:
            return run.write(run.root / "nginx.conf", f"""daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen 127.0.0.1:{cport};
    location /cvmfs/ {{
        brix_storage_backend "{backends}";
        brix_cache_store posix:{cache};
        brix_cvmfs on;
{directives}
    }}
}} }}
""")

        # 1: static — first-listed (A) serves
        config = mkconf("        brix_cvmfs_origin_select static;",
                        f"http://127.0.0.1:{ma}|http://127.0.0.1:{mb}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj}")
        na = _count_log(run, ma, obj)
        nb = _count_log(run, mb, obj)
        checks.append((na == 1 and nb == 0, f"static: first-listed served (A={na} B={nb})"))

        # 2: geo — nearer origin (B=Edinburgh) wins although listed second
        config = mkconf(f"""        brix_cvmfs_origin_select geo;
        brix_cvmfs_here 55.95:-3.19;
        brix_cvmfs_origin_coords 127.0.0.1:{ma} 46.23:6.05;
        brix_cvmfs_origin_coords 127.0.0.1:{mb} 55.95:-3.19;""",
                        f"http://127.0.0.1:{ma}|http://127.0.0.1:{mb}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://127.0.0.1:{cport}{obj}")
        nb = _count_log(run, mb, obj)
        checks.append((nb == 1, f"geo: nearer origin served (B={nb})"))

        # 3: rtt — refused endpoint pre-ranked out (not failed-over-from)
        config = mkconf("        brix_cvmfs_origin_select rtt;\n        brix_cvmfs_rtt_interval 1;",
                        f"http://127.0.0.1:1|http://127.0.0.1:{mb}")
        _restart_nginx(run, config, cport, cache)
        time.sleep(1.5)  # let the first probe run and rank
        nb0 = _count_log(run, mb, obj)
        run.curl_status(f"http://127.0.0.1:{cport}{obj}")
        nb1 = _count_log(run, mb, obj)
        checks.append((_grep(error_log, rtt_log, regex=True) and nb1 - nb0 == 1,
                       f"rtt: probe pre-ranked live origin first (fills={nb1 - nb0})"))

        # 4: config-error negatives
        config = mkconf("        brix_cvmfs_origin_select geo;",
                        f"http://127.0.0.1:{ma}|http://127.0.0.1:{mb}")
        rejected = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode != 0
        checks.append((rejected, "geo misconfig (no here/coords) rejected"))

        # 5: default (no brix_cvmfs_origin_select) -> rtt pre-ranks live origin
        config = mkconf("        brix_cvmfs_rtt_interval 1;",
                        f"http://127.0.0.1:1|http://127.0.0.1:{mb}")
        _restart_nginx(run, config, cport, cache)
        time.sleep(1.5)
        nb0 = _count_log(run, mb, obj)
        run.curl_status(f"http://127.0.0.1:{cport}{obj}")
        nb1 = _count_log(run, mb, obj)
        checks.append((_grep(error_log, rtt_log, regex=True) and nb1 - nb0 == 1,
                       f"default: rtt active — probe pre-ranked live origin first (fills={nb1 - nb0})"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# selectlog — the origin-SELECTION diagnostic trail
# ---------------------------------------------------------------------------

def selectlog(nginx: Path | None = None) -> int:
    ral, cern, cport = free_ports(3)
    with LiveRun("cvmfs_sl", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        error_log = logs / "e.log"
        mock_ral = _mock(run, ral, 6, 9)
        mock_cern = _mock(run, cern, 6, 9)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen 127.0.0.1:{cport};
    location /cvmfs/ {{
        brix_storage_backend "http://127.0.0.1:{ral}|http://127.0.0.1:{cern}";
        brix_cache_store posix:{cache};
        brix_cvmfs_origin_select geo;
        brix_cvmfs_here 51.57:-1.31;
        brix_cvmfs_origin_coords 127.0.0.1:{ral}  51.57:-1.31;
        brix_cvmfs_origin_coords 127.0.0.1:{cern} 46.23:6.05;
        brix_cvmfs on;
        brix_cvmfs_client_hold 3;
    }}
}} }}
""")
        # config-time geo selection report goes to the launch stderr — capture it
        # with a direct launch (not start_nginx). As root that means we must add
        # the `user root;` that start_nginx would inject, else workers drop to
        # `nobody` and cannot write the 0700 mkdtemp cache store (fill -> EACCES).
        launch = [run.nginx, "-c", config, "-p", run.root]
        if os.geteuid() == 0:
            launch += ["-g", "user root;"]
        started = run.call(launch, check=False)
        start_err = run.write(logs / "start.err", started.stderr or "")
        if started.returncode:
            raise LiveFailure(started.stderr or started.stdout or "nginx failed to start")
        run.pidfiles.append(run.root / "nginx.pid")
        if not wait_tcp("127.0.0.1", cport, 10):
            raise LiveFailure(f"nginx was not ready on {cport}")

        objs = _objects(run, ral)
        checks: list[tuple[bool, str]] = []

        # 1a: geo ranking table logged at config time, RAL preferred
        checks.append((_grep(start_err, rf"selection report.*127.0.0.1:{ral} .*rank 0 \(preferred", regex=True),
                       "config-time geo table: RAL ranked preferred"))
        checks.append((_grep(start_err, rf"selection report.*127.0.0.1:{cern} .*rank 1", regex=True),
                       "config-time geo table: CERN ranked behind"))

        # warm the cache from the preferred origin (RAL)
        run.curl_status(f"http://127.0.0.1:{cport}{objs[0]}", timeout=20)

        # 1b: kill RAL, request an UNCACHED object -> failover to CERN, logged
        _mock_stop(run, mock_ral, ral)
        got = run.root / "a.bin"
        _curl_code_to(run, f"http://127.0.0.1:{cport}{objs[1]}", got, timeout=25)
        ref = run.curl_bytes(f"http://127.0.0.1:{cern}{objs[1]}")
        checks.append((got.read_bytes() == ref, "served via failover to CERN"))
        checks.append((_grep(error_log, f"http origin 127.0.0.1:{ral} failed"),
                       "driver logged RAL transport failure (per-attempt WARN)"))
        checks.append((_grep(error_log, rf"http origin (failover for|switched to 127.0.0.1:{cern})", regex=True),
                       "driver logged the origin switch to CERN"))
        checks.append((_grep(error_log, "SKIPPED"),
                       "switch line explains preferred RAL was SKIPPED"))

        # 2: both down -> attempt trail + give-up, clean 504
        _mock_stop(run, mock_cern, cern)
        code = run.curl_status(f"http://127.0.0.1:{cport}{objs[4]}", timeout=30)
        checks.append((code == 504, f"both-down -> clean keep-alive 504 ({code})"))
        checks.append((_grep(error_log, "http origin request exhausted all endpoints"),
                       "driver logged endpoint exhaustion"))
        checks.append((_grep(error_log, "xrootd-fill: event=retry"),
                       "fill layer logged the per-attempt retry trail"))

        # 3: sec-neg — encoded CRLF in the path cannot inject a log line
        run.curl_status(f"http://127.0.0.1:{cport}/cvmfs/data/%0d%0aFORGED-ORIGIN-SWITCH", timeout=10)
        log_text = error_log.read_text(errors="replace")
        forged_at_bol = any(line.startswith("FORGED-ORIGIN-SWITCH") for line in log_text.splitlines())
        checks.append((not forged_at_bol, "CRLF in path did not forge a log record (key sanitised)"))
        if "FORGED-ORIGIN-SWITCH" in log_text:
            checks.append((bool(re.search(r"\\x0[dD]\\x0[aA].*FORGED-ORIGIN-SWITCH", log_text)),
                           "wire path logged with CRLF hex-escaped"))
        else:
            checks.append((True, "wire path never logged (rejected before any origin log line)"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# evict — eviction on the unified cache-store surface
# ---------------------------------------------------------------------------

def evict(nginx: Path | None = None) -> int:
    oport, sport, bport, tport = free_ports(4)
    with LiveRun("cvmfs_evict", nginx) as run:
        base_url = f"http://127.0.0.1:{bport}"
        o_root, s_root = run.mkdir("o", "root"), run.mkdir("s", "root")
        run.mkdir("o", "logs"), run.mkdir("s", "logs")
        b_export, b_tmp = run.mkdir("b", "export"), run.mkdir("b", "tmp")
        run.mkdir("b", "logs")
        t_dir = run.mkdir("t")
        run.mkdir("t", "logs")
        checks: list[tuple[bool, str]] = []

        # A. PLUMBING — unified eviction directives on a cvmfs location
        def tcfg(body: str) -> Path:
            return run.write(t_dir / "nginx.conf", f"""daemon off; pid {t_dir}/nginx.pid; error_log {t_dir}/logs.err warn;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ server {{ listen 127.0.0.1:{tport};
  location /cvmfs/ {{
    brix_cvmfs on;
    brix_export {t_dir};
    brix_storage_backend http://127.0.0.1:1;
    brix_cache_store posix:{t_dir};
    {body}
  }} }} }}
""")

        good = tcfg("brix_cache_evict_at 50; brix_cache_evict_to 20;")
        checks.append((run.call([run.nginx, "-t", "-c", good, "-p", t_dir], check=False).returncode == 0,
                       "evict_at/evict_to parse+merge under cvmfs"))
        bad = tcfg("brix_cache_evict_at lots;")
        checks.append((run.call([run.nginx, "-t", "-c", bad, "-p", t_dir], check=False).returncode != 0,
                       "malformed brix_cache_evict_at rejected under cvmfs"))

        # B. BEHAVIOUR — real eviction on the shared cache store (O/S/B mesh)
        o_conf = run.write(run.root / "o/nginx.conf", f"""daemon on; error_log {run.root}/o/logs/e.log error; pid {run.root}/o/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{oport}; brix_root on; brix_export {o_root}; brix_auth none; brix_allow_write on; }} }}
""")
        s_conf = run.write(run.root / "s/nginx.conf", f"""daemon on; error_log {run.root}/s/logs/e.log error; pid {run.root}/s/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{sport}; brix_root on; brix_export {s_root}; brix_auth none; brix_allow_write on; }} }}
""")
        b_conf = run.write(run.root / "b/nginx.conf", f"""daemon on; error_log {run.root}/b/logs/e.log info; pid {run.root}/b/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {b_tmp};
    server {{
        listen 127.0.0.1:{bport};
        location / {{
            dav_methods PUT DELETE;
            brix_webdav on;
            brix_export {b_export};
            brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend root://127.0.0.1:{oport};
            brix_cache_store root://127.0.0.1:{sport};
            brix_cache_evict_at 50;
            brix_cache_evict_to 20;
        }}
    }}
}}
""")
        (o_root / "e.bin").write_bytes(os.urandom(300000))
        run.start_nginx(run.root / "o", o_conf, oport)
        run.start_nginx(run.root / "s", s_conf, sport)
        run.start_nginx(run.root / "b", b_conf, bport)
        time.sleep(1)

        # cold GET caches the object into the remote store S
        got_a = run.root / "cev_a.got"
        code = _curl_code_to(run, f"{base_url}/e.bin", got_a)
        checks.append((code == 200 and got_a.read_bytes() == (o_root / "e.bin").read_bytes(),
                       f"cold GET byte-exact (fills the cache store) ({code})"))
        checks.append(((s_root / "e.bin").is_file(), "object cached on the store S"))
        if shutil.which("getfattr"):
            attrs = run.call(["getfattr", "-d", "-m", ".", s_root / "e.bin"], check=False)
            checks.append(("cinfo" in attrs.stdout.lower(), "cinfo present on cached object"))

        # cache a manifest-analogue — it must survive eviction of e.bin
        (o_root / ".cvmfspublished").write_text("D 0001\nN atlas.cern.ch\nC abc123\n")
        code = _curl_code_to(run, f"{base_url}/.cvmfspublished", run.root / "cev_man.got")
        checks.append((code == 200, f"manifest cold GET (fills cache store) ({code})"))
        checks.append(((s_root / ".cvmfspublished").is_file(), "manifest cached on store S"))

        # DELETE evicts the object + cinfo from the cache store
        code = run.curl_status(f"{base_url}/e.bin", "-X", "DELETE")
        checks.append((code in (200, 204), f"DELETE accepted ({code})"))
        time.sleep(0.3)
        checks.append((not (s_root / "e.bin").exists(),
                       "object EVICTED from the cache store (bytes + cinfo gone)"))
        checks.append(((s_root / ".cvmfspublished").is_file(),
                       "manifest survives eviction of unrelated object (store-file-presence)"))

        # a fresh GET after eviction is a clean MISS that re-fills
        (o_root / "e.bin").write_bytes(os.urandom(300000))
        got_b = run.root / "cev_b.got"
        code = _curl_code_to(run, f"{base_url}/e.bin", got_b)
        checks.append((code == 200 and got_b.read_bytes() == (o_root / "e.bin").read_bytes(),
                       f"post-eviction GET re-fills byte-exact (no stale object served) ({code})"))

        # overwrite is a second eviction trigger
        run.curl_status(f"{base_url}/e.bin")  # re-cache on S
        checks.append(((s_root / "e.bin").is_file(), "object re-cached on S before overwrite"))
        new_file = t_dir / "new"
        new_file.write_bytes(os.urandom(250000))
        new_sha = sha256(new_file)
        code = run.curl_status(f"{base_url}/e.bin", "-T", str(new_file))
        checks.append((code in (200, 201, 204), f"overwrite PUT accepted ({code})"))
        time.sleep(0.3)
        got_c = run.root / "cev_c.got"
        code = _curl_code_to(run, f"{base_url}/e.bin", got_c)
        checks.append((code == 200 and sha256(got_c) == new_sha,
                       f"post-overwrite GET serves NEW bytes (cached copy invalidated) ({code})"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# brix-all — the whole CVMFS-brix / brixMount gate in one shot
# ---------------------------------------------------------------------------

def brix_all(nginx: Path | None = None) -> int:
    from cmdscripts import (brixmount_unit, cache_unit, cvmfs_catalog_unit, cvmfs_classify,
                            cvmfs_conf_unit, cvmfs_driver_units, cvmfs_fetch_unit, proxy_env_unit)

    suites: list[tuple[str, object]] = [
        ("grammar/classify (server)", cvmfs_classify.run_checks),
        ("shared core", lambda base: cvmfs_driver_units.run_checks(base, ["core"])),
        ("cas store", cache_unit.run_checks),
        ("object+fetch", cvmfs_fetch_unit.run_checks),
        ("catalog (sqlite)", cvmfs_catalog_unit.run_checks),
        ("client assembler", lambda base: cvmfs_driver_units.run_checks(base, ["client"])),
        ("CVMFS_* config parse", cvmfs_conf_unit.run_checks),
        ("brixMount dispatch", brixmount_unit.run_checks),
        ("env-proxy resolver", proxy_env_unit.run_checks),
    ]

    fuse_live = (shutil.which("pkg-config") is not None
                 and subprocess.run(["pkg-config", "--exists", "fuse3"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
                 and os.access("/dev/fuse", os.W_OK))

    with LiveRun("cvmfs_brixall", nginx) as run:
        print("== unit suites (pure C, no fleet) ==")
        summary: list[tuple[bool, str]] = []
        for index, (label, runner) in enumerate(suites):
            base = run.mkdir(f"suite{index}")
            results = runner(base)
            passed = all(ok for ok, _ in results)
            print(f"  {'PASS' if passed else 'FAIL'}  {label:<26} {results[-1][1] if results else ''}")
            if not passed:
                for ok, message in results:
                    if not ok:
                        print(f"        {message}")
            summary.append((passed, label))

        if fuse_live:
            print("== live FUSE lane ==")
            base = run.mkdir("fuse")
            results = cvmfs_driver_units.run_checks(base, ["build", "check"])
            passed = all(ok for ok, _ in results)
            for ok, message in results:
                print(f"  {'ok  ' if ok else 'FAIL'} {message}")
            summary.append((passed, "brixcvmfs build + --check (live lane)"))
            print("  NOTE: brixcvmfs/brixMount/mount.cvmfs/clever/env-proxy live-mount"
                  " suites remain shell-only (tests/run_brix*_live.sh) — not yet ported")
        else:
            print("== live FUSE lane: SKIPPED (need fuse3 + writable /dev/fuse) ==")

        passes = sum(1 for ok, _ in summary if ok)
        fails = len(summary) - passes
        print(f"\nbrix cvmfs gate: {passes} passed, {fails} failed")
        return _checks(summary)


# ---------------------------------------------------------------------------
# faultproxy-bench — cvmfs-brix vs stock cvmfs2 through client/bin/brix-fault-proxy
# ---------------------------------------------------------------------------

def _fault_proxy_ctl(port: int, command: str) -> None:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
            conn.sendall(f"{command}\n".encode())
            conn.settimeout(2)
            try:
                conn.recv(120)
            except OSError:
                pass
    except OSError:
        pass


def faultproxy_bench(nginx: Path | None = None) -> int:
    repo = os.environ.get("REPO", "atlas.cern.ch")
    s1host = os.environ.get("S1HOST", "cernvmfs.gridpp.rl.ac.uk")
    keys = "/etc/cvmfs/keys/cern.ch"
    mode = os.environ.get("MODE", "lossy")
    rates = os.environ.get("RATES", "0 1 5 15").split()
    nfiles = int(os.environ.get("NFILES", "15"))
    fault_proxy = REPO_ROOT / "client/bin/brix-fault-proxy"
    brix = Path("/tmp/brixcvmfs")

    _require(os.access(fault_proxy, os.X_OK), f"brix-fault-proxy not built ({fault_proxy})")
    _require(shutil.which("cvmfs2"), "no stock cvmfs2")
    _require(shutil.which("fusermount3") or shutil.which("fusermount"), "no fusermount")
    _require(os.access(brix, os.X_OK), "build /tmp/brixcvmfs first")

    with LiveRun("cvmfs_fpbench", nginx) as run:
        reachable = run.call(["curl", "-fsS", "-o", os.devnull, "--max-time", "8",
                              "-H", "Host: 127.0.0.1",
                              f"http://{s1host}/cvmfs/{repo}/.cvmfspublished"], check=False)
        _require(reachable.returncode == 0, f"{s1host} does not serve {repo} by path")

        lport, ctl_port = free_ports(2)
        run.spawn([fault_proxy, str(lport), s1host, "80", str(ctl_port)])
        time.sleep(1)
        surl = f"http://127.0.0.1:{lport}/cvmfs/{repo}"

        print(f"== enumerate {nfiles} {repo} files (fault-free) ==")
        _fault_proxy_ctl(ctl_port, "clear")
        e_mnt, e_cache, e_tmp = run.mkdir("emnt"), run.mkdir("ecache"), run.mkdir("etmp")
        enum_proc = _brix_mount(run, brix, repo, surl, keys, e_cache, e_tmp, e_mnt, retries=6)
        if not _wait_mount_ready(e_mnt, tries=100):
            print("  (enumerate slow)")
        files = _enumerate_files(run, e_mnt, nfiles)
        ngot = len(files)
        print(f"  enumerated {ngot} files")
        _umount_wait(run, e_mnt)
        if enum_proc.poll() is None:
            enum_proc.terminate()

        rows: list[tuple[str, tuple[int, int, float] | None, tuple[int, int, float] | None]] = []
        if ngot >= 1:
            print(f"\n{mode + '%':<7} | {'CVMFS-brix (ok/N, secs)':<26} | {'stock cvmfs2 (ok/N, secs)':<26}")
            print("--------+----------------------------+----------------------------")
            for rate in rates:
                if rate == "0":
                    _fault_proxy_ctl(ctl_port, "clear")
                elif mode == "reorder":
                    _fault_proxy_ctl(ctl_port, f"reorder {rate} 60")
                else:
                    _fault_proxy_ctl(ctl_port, f"lossy {rate}")

                bc, bt, bm = run.mkdir(f"bc{rate}"), run.mkdir(f"bt{rate}"), run.mkdir(f"bm{rate}")
                bp = _brix_mount(run, brix, repo, surl, keys, bc, bt, bm, retries=6)
                brix_ok = _wait_mount_ready(bm, tries=100)
                brix_res = _read_files(bm, files, 30) if brix_ok else None
                _umount_wait(run, bm)
                if bp.poll() is None:
                    bp.terminate()

                sc, sm = run.mkdir(f"sc{rate}"), run.mkdir(f"sm{rate}")
                conf = _stock_cvmfs2_conf(run.root / f"fpbench_stock.{rate}.conf", surl,
                                          "DIRECT", keys, sc, 6)
                sp = run.spawn(["timeout", "90", "cvmfs2", "-o", f"config={conf}", repo, sm])
                stock_ok = _wait_mount_ready(sm, tries=100)
                stock_res = _read_files(sm, files, 30) if stock_ok else None
                _umount_wait(run, sm)
                if sp.poll() is None:
                    sp.terminate()

                rows.append((rate, brix_res, stock_res))
                print(f"{rate:<7} | {_bench_cell(brix_ok, brix_res, ngot):<26} | "
                      f"{_bench_cell(stock_ok, stock_res, ngot):<26}")
            print(f"\n(REAL brix-fault-proxy {mode} via {s1host} -> {repo}; {ngot} files; both COLD cache)")
        _fault_proxy_ctl(ctl_port, "clear")

        rate0 = next((row for row in rows if row[0] == "0"), None)
        return _checks([
            (ngot >= 1, f"enumerated at least one repository file ({ngot})"),
            (len(rows) == len(rates), f"fault-rate sweep completed ({len(rows)}/{len(rates)} rates)"),
            (rate0 is not None and rate0[1] is not None and rate0[1][0] >= 1,
             "fault-free brix run read at least one file"),
            (rate0 is not None and rate0[1] is not None and rate0[1][2] > 0
             and rate0[1][0] / rate0[1][2] > 0, "fault-free brix run has non-zero throughput"),
        ])


SCENARIOS = {
    "bench": bench,
    "reverse": reverse,
    "holdopen": holdopen,
    "proxy": proxy,
    "resilience": resilience,
    "stock": stock,
    "unified-origin": unified_origin,
    "upstream-metrics": upstream_metrics,
    "logging": logging,
    "select": select,
    "selectlog": selectlog,
    "evict": evict,
    "brix-all": brix_all,
    "faultproxy-bench": faultproxy_bench,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveSkip as exc:
        print(f"SKIP: {exc}")
        return 0
    except LiveFailure as exc:
        print(f"CVMFS scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
