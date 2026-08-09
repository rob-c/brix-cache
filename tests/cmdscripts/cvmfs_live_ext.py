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
        ready = run.call(["curl", "-sf", "-m", "1", "-o", os.devnull, f"http://{HOST}:{port}/ctl/objects"], check=False)
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
        gone = run.call(["curl", "-sf", "-m", "1", "-o", os.devnull, f"http://{HOST}:{port}/ctl/objects"], check=False)
        if gone.returncode != 0:
            return
        time.sleep(0.1)


def _objects(run: LiveRun, port: int) -> list[str]:
    objects = _ctl(run, port, "objects")
    assert isinstance(objects, list)
    return objects


def _fault(run: LiveRun, port: int, mode: str, count: int) -> None:
    run.call(["curl", "-sS", "-o", os.devnull, "-X", "POST", "-d",
              f'{{"mode":"{mode}","count":{count}}}', f"http://{HOST}:{port}/ctl/fault"])


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
    return run.call(["curl", "-sS", f"http://{HOST}:{port}/metrics"]).stdout


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
    "shared/cvmfs/client/client.c", "shared/cvmfs/client/client_negfilter.c",
    "shared/cvmfs/client/client_pathidx.c", "shared/cvmfs/index/pathidx.c",
    "shared/cvmfs/filter/xorf.c", "shared/cvmfs/fetch/fetch.c", "shared/cvmfs/object/object.c",
    "shared/cvmfs/fetch/fetch_bundle.c", "shared/cvmfs/bundle/bundle.c",
    "shared/cvmfs/dict/dict.c",
    "shared/cvmfs/failover/failover.c", "shared/cvmfs/catalog/catalog.c", "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c", "shared/cvmfs/signature/manifest.c", "shared/cvmfs/signature/whitelist.c",
    "shared/cvmfs/signature/verify.c", "shared/cvmfs/config/repo.c", "shared/cvmfs/config/cvmfs_conf.c",
    "shared/cvmfs/walk/walk.c", "shared/cache/cas_store.c", "shared/cache/cas_pack.c",
    "shared/cvmfs/platform/platform.c", "shared/net/proxy_env.c",
    "client/lib/net/cpool.c", "client/lib/core/types/status.c",
    "src/core/compat/kxr_names.c", "src/core/compat/error_mapping.c",
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
        ["gcc", "-Wall", "-Wextra", "-Werror", "-I", "shared", "-I", "client/lib",
         "-I", "src", "-DXRDPROTO_NO_NGX", *flags.stdout.split(),
         "-o", binary,
         # phase-38: brixcvmfs is split by concern (front-end + transport/
         # prefetch/ops/mount siblings) — none are archived, list all five.
         "client/apps/fs/brixcvmfs.c",
         "client/apps/fs/brixcvmfs_transport.c",
         "client/apps/fs/brixcvmfs_prefetch.c",
         "client/apps/fs/brixcvmfs_ops.c",
         "client/apps/fs/brixcvmfs_mount.c",
         *BRIX_CORE_SOURCES,
         *libs.stdout.split(), "-lcurl", "-lsqlite3", "-lcrypto", "-lz", "-lzstd"],
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


def _enumerate_files(run: LiveRun, mnt: Path, nfiles: int,
                     deadline_s: float = 300.0) -> list[str]:
    # Stream find and kill it once nfiles are collected: a COMPLETE depth-6
    # walk of a big live repo (cms.cern.ch) over the CDN takes far longer than
    # the test timeout, while the first nfiles small files arrive in seconds.
    proc = subprocess.Popen(
        ["find", str(mnt), "-maxdepth", "6", "-type", "f", "-size", "-64k"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    files: list[str] = []
    prefix = f"{mnt}/"
    deadline = time.monotonic() + deadline_s
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line.startswith(prefix):
                files.append(line[len(prefix):])
            if len(files) >= nfiles or time.monotonic() > deadline:
                break
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
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
        (pport,) = _PORTS[0:1]  # was free_ports(1)

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
                                 extra_env={"http_proxy": f"http://{HOST}:{pport}"})
                brix_ok = _wait_mount_ready(bm)
                brix_res = _read_files(bm, files, 25) if brix_ok else None
                _umount_wait(run, bm)
                if bp.poll() is None:
                    bp.terminate()

                sc, sm = run.mkdir(f"sc{rate}"), run.mkdir(f"sm{rate}")
                conf = _stock_cvmfs2_conf(run.root / f"bench_stock.{rate}.conf", s1,
                                          f"http://{HOST}:{pport}", keys, sc, 5)
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

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "cvmfs_live_ext_part2.py",
                    "cvmfs_live_ext_part3.py", "cvmfs_live_ext_part4.py",
                    "cvmfs_live_ext_part5.py")
