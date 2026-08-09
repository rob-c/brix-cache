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


def evict(nginx: Path | None = None) -> int:
    oport, sport, bport, tport = _PORTS[32:36]  # was free_ports(4)
    with LiveRun("cvmfs_evict", nginx) as run:
        base_url = f"http://{HOST}:{bport}"
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
http {{ server {{ listen {BIND_HOST}:{tport};
  location /cvmfs/ {{
    brix_cvmfs on;
    brix_export {t_dir};
    brix_storage_backend http://{HOST}:1;
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
stream {{ server {{ listen {BIND_HOST}:{oport}; brix_root on; brix_export {o_root}; brix_auth none; brix_allow_write on; }} }}
""")
        s_conf = run.write(run.root / "s/nginx.conf", f"""daemon on; error_log {run.root}/s/logs/e.log error; pid {run.root}/s/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{sport}; brix_root on; brix_export {s_root}; brix_auth none; brix_allow_write on; }} }}
""")
        b_conf = run.write(run.root / "b/nginx.conf", f"""daemon on; error_log {run.root}/b/logs/e.log info; pid {run.root}/b/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {b_tmp};
    server {{
        listen {BIND_HOST}:{bport};
        location / {{
            dav_methods PUT DELETE;
            brix_webdav on;
            brix_export {b_export};
            brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend root://{HOST}:{oport};
            brix_cache_store root://{HOST}:{sport};
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
        with socket.create_connection((HOST, port), timeout=2) as conn:
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
                              "-H", "Host: 127.0.0.1",  # net-literal-allow: literal Host header sent to the external Stratum-1
                              f"http://{s1host}/cvmfs/{repo}/.cvmfspublished"], check=False)
        _require(reachable.returncode == 0, f"{s1host} does not serve {repo} by path")

        lport, ctl_port = _PORTS[36:38]  # was free_ports(2)
        run.spawn([fault_proxy, str(lport), s1host, "80", str(ctl_port)])
        time.sleep(1)
        surl = f"http://{HOST}:{lport}/cvmfs/{repo}"

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
