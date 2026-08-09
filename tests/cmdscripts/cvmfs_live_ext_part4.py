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


def logging(nginx: Path | None = None) -> int:
    mport, cport = _PORTS[24:26]  # was free_ports(2)
    with LiveRun("cvmfs_log", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        log = logs / "e.log"
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {log} info; pid {run.root}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server {{
        listen {BIND_HOST}:{cport};
        location /cvmfs/ {{
            brix_storage_backend http://{HOST}:{mport};
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
        run.curl_status(f"http://{HOST}:{cport}{objects[0]}")
        time.sleep(0.3)
        checks.append((_grep(log, "xrootd-fill: event=done") and _grep(log, "attempts=1"),
                       "clean fill logs event=done attempts=1"))

        # 2: reset the origin repeatedly -> retry + recovered
        _fault(run, mport, "reset", 3)
        run.curl_status(f"http://{HOST}:{cport}{objects[2]}", timeout=15)
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
        code = run.curl_status(f"http://{HOST}:{cport}{objects[4]}", timeout=10)
        time.sleep(0.3)
        checks.append((code == 504, f"stalled origin -> client gets 504 (kept-alive) ({code})"))
        checks.append((_grep(log, "xrootd-fill: event=hold-expired") and _grep(log, "held_ms="),
                       "hold expiry logs event=hold-expired with held_ms"))
        _fault(run, mport, "none", 0)

        # 5: client abandons mid-fill -> client-gone
        _fault(run, mport, "stall", 9)
        run.call(["curl", "-s", "--max-time", "1",
                  f"http://{HOST}:{cport}{objects[6]}", "-o", os.devnull], check=False)
        time.sleep(1)
        checks.append((_grep(log, "xrootd-fill: event=client-gone") and _grep(log, "parked_ms="),
                       "client abort mid-fill logs event=client-gone with parked_ms"))
        _fault(run, mport, "none", 0)

        # 6: 404 hammering -> absorbed-404
        bogus = "/cvmfs/test.cern.ch/data/aa/" + "bc" * 19
        for _ in range(3):
            run.curl_status(f"http://{HOST}:{cport}{bogus}")
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
    ma, mb, cport = _PORTS[26:29]  # was free_ports(3)
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
    listen {BIND_HOST}:{cport};
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
                        f"http://{HOST}:{ma}|http://{HOST}:{mb}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj}")
        na = _count_log(run, ma, obj)
        nb = _count_log(run, mb, obj)
        checks.append((na == 1 and nb == 0, f"static: first-listed served (A={na} B={nb})"))

        # 2: geo — nearer origin (B=Edinburgh) wins although listed second
        config = mkconf(f"""        brix_cvmfs_origin_select geo;
        brix_cvmfs_here 55.95:-3.19;
        brix_cvmfs_origin_coords {HOST}:{ma} 46.23:6.05;
        brix_cvmfs_origin_coords {HOST}:{mb} 55.95:-3.19;""",
                        f"http://{HOST}:{ma}|http://{HOST}:{mb}")
        _restart_nginx(run, config, cport, cache)
        run.curl_status(f"http://{HOST}:{cport}{obj}")
        nb = _count_log(run, mb, obj)
        checks.append((nb == 1, f"geo: nearer origin served (B={nb})"))

        # 3: rtt — refused endpoint pre-ranked out (not failed-over-from)
        config = mkconf("        brix_cvmfs_origin_select rtt;\n        brix_cvmfs_rtt_interval 1;",
                        f"http://{HOST}:1|http://{HOST}:{mb}")
        _restart_nginx(run, config, cport, cache)
        time.sleep(1.5)  # let the first probe run and rank
        nb0 = _count_log(run, mb, obj)
        run.curl_status(f"http://{HOST}:{cport}{obj}")
        nb1 = _count_log(run, mb, obj)
        checks.append((_grep(error_log, rtt_log, regex=True) and nb1 - nb0 == 1,
                       f"rtt: probe pre-ranked live origin first (fills={nb1 - nb0})"))

        # 4: config-error negatives
        config = mkconf("        brix_cvmfs_origin_select geo;",
                        f"http://{HOST}:{ma}|http://{HOST}:{mb}")
        rejected = run.call([run.nginx, "-t", "-c", config, "-p", run.root], check=False).returncode != 0
        checks.append((rejected, "geo misconfig (no here/coords) rejected"))

        # 5: default (no brix_cvmfs_origin_select) -> rtt pre-ranks live origin
        config = mkconf("        brix_cvmfs_rtt_interval 1;",
                        f"http://{HOST}:1|http://{HOST}:{mb}")
        _restart_nginx(run, config, cport, cache)
        time.sleep(1.5)
        nb0 = _count_log(run, mb, obj)
        run.curl_status(f"http://{HOST}:{cport}{obj}")
        nb1 = _count_log(run, mb, obj)
        checks.append((_grep(error_log, rtt_log, regex=True) and nb1 - nb0 == 1,
                       f"default: rtt active — probe pre-ranked live origin first (fills={nb1 - nb0})"))

        return _checks(checks)


# ---------------------------------------------------------------------------
# selectlog — the origin-SELECTION diagnostic trail
# ---------------------------------------------------------------------------

def selectlog(nginx: Path | None = None) -> int:
    ral, cern, cport = _PORTS[29:32]  # was free_ports(3)
    with LiveRun("cvmfs_sl", nginx) as run:
        cache, logs = run.mkdir("cache"), run.mkdir("logs")
        error_log = logs / "e.log"
        mock_ral = _mock(run, ral, 6, 9)
        mock_cern = _mock(run, cern, 6, 9)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {error_log} info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{cport};
    location /cvmfs/ {{
        brix_storage_backend "http://{HOST}:{ral}|http://{HOST}:{cern}";
        brix_cache_store posix:{cache};
        brix_cvmfs_origin_select geo;
        brix_cvmfs_here 51.57:-1.31;
        brix_cvmfs_origin_coords {HOST}:{ral}  51.57:-1.31;
        brix_cvmfs_origin_coords {HOST}:{cern} 46.23:6.05;
        brix_cvmfs on;
        brix_cvmfs_client_hold 3;
    }}
}} }}
""")
        # config-time geo selection report goes to the launch stderr — capture it
        # with a direct launch (not start_nginx). As root that bypasses
        # start_nginx's tree-opening, so repeat it here: the de-escalated
        # `nobody` worker cannot write the 0700 mkdtemp cache store otherwise
        # (fill -> EACCES).
        from cmdscripts import open_tree_for_worker  # noqa: PLC0415
        open_tree_for_worker(run.root, config)
        launch = [run.nginx, "-c", config, "-p", run.root]
        started = run.call(launch, check=False)
        start_err = run.write(logs / "start.err", started.stderr or "")
        if started.returncode:
            raise LiveFailure(started.stderr or started.stdout or "nginx failed to start")
        run.pidfiles.append(run.root / "nginx.pid")
        if not wait_tcp(HOST, cport, 10):
            raise LiveFailure(f"nginx was not ready on {cport}")

        objs = _objects(run, ral)
        checks: list[tuple[bool, str]] = []

        # 1a: geo ranking table logged at config time, RAL preferred
        checks.append((_grep(start_err, rf"selection report.*{HOST}:{ral} .*rank 0 \(preferred", regex=True),
                       "config-time geo table: RAL ranked preferred"))
        checks.append((_grep(start_err, rf"selection report.*{HOST}:{cern} .*rank 1", regex=True),
                       "config-time geo table: CERN ranked behind"))

        # warm the cache from the preferred origin (RAL)
        run.curl_status(f"http://{HOST}:{cport}{objs[0]}", timeout=20)

        # 1b: kill RAL, request an UNCACHED object -> failover to CERN, logged
        _mock_stop(run, mock_ral, ral)
        got = run.root / "a.bin"
        _curl_code_to(run, f"http://{HOST}:{cport}{objs[1]}", got, timeout=25)
        ref = run.curl_bytes(f"http://{HOST}:{cern}{objs[1]}")
        checks.append((got.read_bytes() == ref, "served via failover to CERN"))
        checks.append((_grep(error_log, f"http origin {HOST}:{ral} failed"),
                       "driver logged RAL transport failure (per-attempt WARN)"))
        checks.append((_grep(error_log, rf"http origin (failover for|switched to {HOST}:{cern})", regex=True),
                       "driver logged the origin switch to CERN"))
        checks.append((_grep(error_log, "SKIPPED"),
                       "switch line explains preferred RAL was SKIPPED"))

        # 2: both down -> attempt trail + give-up, clean 504
        _mock_stop(run, mock_cern, cern)
        code = run.curl_status(f"http://{HOST}:{cport}{objs[4]}", timeout=30)
        checks.append((code == 504, f"both-down -> clean keep-alive 504 ({code})"))
        checks.append((_grep(error_log, "http origin request exhausted all endpoints"),
                       "driver logged endpoint exhaustion"))
        checks.append((_grep(error_log, "xrootd-fill: event=retry"),
                       "fill layer logged the per-attempt retry trail"))

        # 3: sec-neg — encoded CRLF in the path cannot inject a log line
        run.curl_status(f"http://{HOST}:{cport}/cvmfs/data/%0d%0aFORGED-ORIGIN-SWITCH", timeout=10)
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

