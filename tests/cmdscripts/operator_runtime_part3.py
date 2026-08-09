"""Python ports for top-level operator/runtime shell entrypoints."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cmdscripts.compile_run import REPO_ROOT, result, run
from settings import BIND_HOST, HOST, TEST_PORT_START
from port_ladder import PORT_COUNT


TESTS = REPO_ROOT / "tests"


class LifecycleProfiler:
    def __init__(self) -> None:
        self.nginx = Path(os.environ.get("NGINX", "/tmp/nginx-1.28.3/objs/nginx"))
        self.prefix = Path(os.environ.get("PREFIX", "/tmp/xrd-lifecycle-prof"))
        self.port_anon = int(os.environ.get("PORT_ANON", "21094"))
        self.port_gsi = int(os.environ.get("PORT_GSI", "21095"))
        self.workers = int(os.environ.get("WORKERS", "2"))
        self.timeout = float(os.environ.get("TIMEOUT_S", "15"))
        self.conf = self.prefix / "conf/nginx.conf"
        self.error_log = self.prefix / "logs/error.log"
        self.pidfile = self.prefix / "logs/nginx.pid"

    def provision(self) -> None:
        shutil.rmtree(self.prefix, ignore_errors=True)
        for path in (self.prefix / "conf", self.prefix / "logs", self.prefix / "data", self.prefix / "tmp"):
            path.mkdir(parents=True, exist_ok=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(self.prefix / "conf/host.key"), "-out", str(self.prefix / "conf/host.crt"), "-subj", "/CN=lifecycle-prof"], cwd=REPO_ROOT)
        self.conf.write_text(f"""worker_processes {self.workers};
daemon on;
master_process on;
pid {self.pidfile};
error_log {self.error_log} notice;
thread_pool default threads=4 max_queue=512;
events {{ worker_connections 1024; }}
stream {{
    server {{ listen {self.port_anon}; brix_root on; brix_storage_backend posix:{self.prefix}/data; brix_auth none; }}
    server {{ listen {self.port_gsi}; brix_root on; brix_storage_backend posix:{self.prefix}/data; brix_auth gsi; brix_certificate {self.prefix}/conf/host.crt; brix_certificate_key {self.prefix}/conf/host.key; brix_trusted_ca {self.prefix}/conf/host.crt; }}
}}
""")

    def init_count(self) -> int:
        if not self.error_log.exists():
            return 0
        return len(re.findall(r"init_process\[", self.error_log.read_text(errors="ignore")))

    def master_pid(self) -> int | None:
        try:
            return int(self.pidfile.read_text().strip())
        except (OSError, ValueError):
            return None

    def worker_pids(self) -> list[int]:
        master = self.master_pid()
        if master is None:
            return []
        proc = run(["pgrep", "-P", str(master)], cwd=REPO_ROOT)
        return [int(p) for p in proc.stdout.split() if p.isdigit()]

    def wait_new_worker(self, base: int) -> None:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self.init_count() > base:
                return
            time.sleep(0.01)

    def settle(self) -> None:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            before = self.init_count()
            if len(self.worker_pids()) == self.workers:
                time.sleep(0.15)
                if self.init_count() == before:
                    return
            time.sleep(0.05)

    def profile(self) -> int:
        if not self.nginx.exists():
            print(f"FATAL: nginx binary not found/executable: {self.nginx}", file=sys.stderr)
            return 1
        self.provision()
        self.error_log.write_text("")
        start = time.time()
        if run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf)], cwd=REPO_ROOT).returncode != 0:
            return 1
        if not _wait_tcp(BIND_HOST, self.port_anon, self.timeout):
            return 1
        cold_ms = int((time.time() - start) * 1000)
        self.settle()
        base = self.init_count()
        start = time.time()
        run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf), "-s", "reload"], cwd=REPO_ROOT)
        self.wait_new_worker(base)
        _wait_tcp(BIND_HOST, self.port_anon, self.timeout)
        reload_ms = int((time.time() - start) * 1000)
        self.settle()
        workers = self.worker_pids()
        base = self.init_count()
        start = time.time()
        if workers:
            _safe_kill(workers[0], signal.SIGKILL)
        self.wait_new_worker(base)
        respawn_ms = int((time.time() - start) * 1000)
        self.settle()
        master = self.master_pid()
        start = time.time()
        run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf), "-s", "quit"], cwd=REPO_ROOT)
        if master:
            while time.time() - start < self.timeout:
                try:
                    os.kill(master, 0)
                    time.sleep(0.01)
                except OSError:
                    break
        shutdown_ms = int((time.time() - start) * 1000)
        print("============================================================")
        print(f" nginx-xrootd lifecycle profile  (workers={self.workers})")
        print("============================================================")
        print(f"  cold start (boot -> first accept) : {cold_ms:6d} ms")
        print(f"  reload     (HUP  -> serving again): {reload_ms:6d} ms")
        print(f"  respawn    (kill -> worker back)  : {respawn_ms:6d} ms")
        print(f"  shutdown   (quit -> master gone)  : {shutdown_ms:6d} ms")
        print("------------------------------------------------------------")
        for line in sorted(set(re.findall(r".*(?:postconfig:|init_process\[).*", self.error_log.read_text(errors="ignore")))):
            print(re.sub(r"^.*: xrootd ", "    xrootd ", line))
        print(f" (scratch prefix: {self.prefix})")
        return 0


def run_profile_lifecycle(argv: list[str]) -> int:
    return LifecycleProfiler().profile()


def _worker_pids_csv(pidfile: Path) -> str:
    try:
        master = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return ""
    proc = run(["pgrep", "-P", str(master)], cwd=REPO_ROOT)
    return ",".join(pid for pid in proc.stdout.split() if pid.isdigit())


def run_profile_load(argv: list[str]) -> int:
    mode = argv[0] if argv else "read"
    if mode not in {"read", "write", "both"}:
        print("mode must be read|write|both", file=sys.stderr)
        return 2
    rest = argv[1:]
    concurrency = "32"
    if rest and re.match(r"^[0-9,]+$", rest[0]):
        concurrency, rest = rest[0], rest[1:]
    flame = Path(os.environ.get("FLAMEGRAPH_DIR", str(Path.home() / "FlameGraph")))
    if not shutil.which("perf") or not (flame / "stackcollapse-perf.pl").exists() or not (flame / "flamegraph.pl").exists():
        print("SKIP: perf or FlameGraph scripts unavailable", file=sys.stderr)
        return 0
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")).resolve()
    load_artifacts = test_root / "artifacts" / "load"
    outdir = load_artifacts / "flame"
    outdir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    passes = ["read", "write"] if mode == "both" else [mode]
    folded: list[tuple[str, Path]] = []
    for pass_mode in passes:
        base = outdir / f"{pass_mode}-{ts}"
        with (base.with_suffix(".loadlog")).open("w") as log:
            load = _popen([sys.executable, "-m", "cmdscripts.operator_runtime", "load", "nginx", "--mode", pass_mode, "--concurrency", concurrency, *rest], cwd=REPO_ROOT, env={"PYTHONPATH": "tests"}, stdout=log, stderr=log, start_new_session=True)
            pidfile = load_artifacts / "nginx" / "logs" / "nginx.pid"
            pids = ""
            for _ in range(120):
                if load.poll() is not None:
                    break
                pids = _worker_pids_csv(pidfile)
                if pids:
                    break
                time.sleep(1)
            if not pids:
                load.terminate()
                return 1
            perf_data = base.with_suffix(".perf.data")
            perf = _popen(["perf", "record", "-F", os.environ.get("PERF_FREQ", "997"), "-e", os.environ.get("PERF_EVENT", "task-clock"), "--call-graph", os.environ.get("CALLGRAPH", "dwarf") + ",8192", "-p", pids, "-o", str(perf_data), "--", "sleep", os.environ.get("MAX_RECORD_SECS", "180")])
            while load.poll() is None and perf.poll() is None:
                time.sleep(1)
            _safe_kill(perf.pid, signal.SIGINT)
            perf.wait(timeout=10)
            load.wait()
        script = _popen(["perf", "script", "-i", str(perf_data)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        collapse = _popen([str(flame / "stackcollapse-perf.pl")], stdout=(base.with_suffix(".folded")).open("w"), stdin=script.stdout)
        if script.stdout is not None:
            script.stdout.close()
        script.wait()
        collapse.wait()
        folded.append((pass_mode, base.with_suffix(".folded")))
    if mode == "both":
        combined = outdir / f"readwrite-{ts}.folded"
        with combined.open("w") as out:
            for name, path in folded:
                for line in path.read_text(errors="ignore").splitlines():
                    out.write(f"{name};{line}\n")
        svg = outdir / f"readwrite-{ts}.svg"
        with svg.open("w") as out:
            proc = _popen([str(flame / "flamegraph.pl"), "--title", "nginx-xrootd read | write", "--width", "1800", str(combined)], stdout=out)
            proc.wait()
    else:
        svg = outdir / f"{mode}-{ts}.svg"
        with svg.open("w") as out:
            proc = _popen([str(flame / "flamegraph.pl"), "--title", f"nginx-xrootd {mode}", "--width", "1600", str(folded[0][1])], stdout=out)
            proc.wait()
    print(svg)
    return 0


def _vg_module_frame_hits(logdir: Path) -> list[str]:
    """Triage: module-frame lines (exclude nginx core), mirroring the shell grep."""
    frame = re.compile(
        r"in (brix_|ngx_http_xrootd|ngx_stream_xrootd)"
        r"|/src/(token|webdav|s3|gsi|crypto|dashboard|read|session|cache|metrics|aio|path|fattr|tpc)/"
    )
    hits: list[str] = []
    for log in sorted(logdir.glob("vg.*.log")):
        for number, line in enumerate(log.read_text(errors="ignore").splitlines(), 1):
            if frame.search(line) and "src/core" not in line:
                hits.append(f"{log}:{number}:{line}")
    return hits


