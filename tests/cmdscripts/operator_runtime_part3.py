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

    def cold_start(self) -> int | None:
        start = time.time()
        if run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf)], cwd=REPO_ROOT).returncode != 0:
            return None
        if not _wait_tcp(BIND_HOST, self.port_anon, self.timeout):
            return None
        elapsed = int((time.time() - start) * 1000)
        self.settle()
        return elapsed

    def reload(self) -> int:
        base = self.init_count()
        start = time.time()
        run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf), "-s", "reload"], cwd=REPO_ROOT)
        self.wait_new_worker(base)
        _wait_tcp(BIND_HOST, self.port_anon, self.timeout)
        elapsed = int((time.time() - start) * 1000)
        self.settle()
        return elapsed

    def respawn(self) -> int:
        workers = self.worker_pids()
        base = self.init_count()
        start = time.time()
        if workers:
            _safe_kill(workers[0], signal.SIGKILL)
        self.wait_new_worker(base)
        elapsed = int((time.time() - start) * 1000)
        self.settle()
        return elapsed

    def shutdown(self) -> int:
        master = self.master_pid()
        start = time.time()
        run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf), "-s", "quit"], cwd=REPO_ROOT)
        _wait_master_exit(master, self.timeout)
        return int((time.time() - start) * 1000)

    def print_profile(self, timings: tuple[int, int, int, int]) -> None:
        cold_ms, reload_ms, respawn_ms, shutdown_ms = timings
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

    def profile(self) -> int:
        if not self.nginx.exists():
            print(f"FATAL: nginx binary not found/executable: {self.nginx}", file=sys.stderr)
            return 1
        self.provision()
        self.error_log.write_text("")
        cold_ms = self.cold_start()
        if cold_ms is None:
            return 1
        timings = (cold_ms, self.reload(), self.respawn(), self.shutdown())
        self.print_profile(timings)
        return 0


def _wait_master_exit(master: int | None, timeout: float) -> None:
    if master is None:
        return
    start = time.time()
    while time.time() - start < timeout:
        try:
            os.kill(master, 0)
            time.sleep(0.01)
        except OSError:
            return


def run_profile_lifecycle(argv: list[str]) -> int:
    return LifecycleProfiler().profile()


def _worker_pids_csv(pidfile: Path) -> str:
    try:
        master = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return ""
    proc = run(["pgrep", "-P", str(master)], cwd=REPO_ROOT)
    return ",".join(pid for pid in proc.stdout.split() if pid.isdigit())


def _load_profile_args(argv: list[str]) -> tuple[str, str, list[str]] | None:
    mode = argv[0] if argv else "read"
    if mode not in {"read", "write", "both"}:
        print("mode must be read|write|both", file=sys.stderr)
        return None
    rest = argv[1:]
    concurrency = "32"
    if rest and re.match(r"^[0-9,]+$", rest[0]):
        concurrency, rest = rest[0], rest[1:]
    return mode, concurrency, rest


def _flamegraph_dir() -> Path | None:
    flame = Path(os.environ.get("FLAMEGRAPH_DIR", str(Path.home() / "FlameGraph")))
    if not shutil.which("perf") or not (flame / "stackcollapse-perf.pl").exists() or not (flame / "flamegraph.pl").exists():
        print("SKIP: perf or FlameGraph scripts unavailable", file=sys.stderr)
        return None
    return flame


def _wait_load_pids(load, pidfile: Path) -> str:
    for _ in range(120):
        if load.poll() is not None:
            return ""
        pids = _worker_pids_csv(pidfile)
        if pids:
            return pids
        time.sleep(1)
    return ""


def _record_perf(load, pids: str, perf_data: Path):
    command = ["perf", "record", "-F", os.environ.get("PERF_FREQ", "997"),
               "-e", os.environ.get("PERF_EVENT", "task-clock"),
               "--call-graph", os.environ.get("CALLGRAPH", "dwarf") + ",8192",
               "-p", pids, "-o", str(perf_data), "--", "sleep",
               os.environ.get("MAX_RECORD_SECS", "180")]
    perf = _popen(command)
    while load.poll() is None and perf.poll() is None:
        time.sleep(1)
    _safe_kill(perf.pid, signal.SIGINT)
    perf.wait(timeout=10)
    load.wait()


def _collapse_perf(perf_data: Path, folded: Path, flame: Path) -> None:
    script = _popen(["perf", "script", "-i", str(perf_data)],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    with folded.open("w") as output:
        collapse = _popen([str(flame / "stackcollapse-perf.pl")],
                          stdout=output, stdin=script.stdout)
        if script.stdout is not None:
            script.stdout.close()
        script.wait()
        collapse.wait()


def _record_load_pass(pass_mode: str, concurrency: str, rest: list[str],
                      base: Path, load_artifacts: Path, flame: Path) -> Path | None:
    with base.with_suffix(".loadlog").open("w") as log:
        command = [sys.executable, "-m", "cmdscripts.operator_runtime", "load",
                   "nginx", "--mode", pass_mode, "--concurrency", concurrency,
                   *rest]
        load = _popen(command, cwd=REPO_ROOT, env={"PYTHONPATH": "tests"},
                      stdout=log, stderr=log, start_new_session=True)
        pids = _wait_load_pids(load, load_artifacts / "nginx/logs/nginx.pid")
        if not pids:
            load.terminate()
            return None
        perf_data = base.with_suffix(".perf.data")
        _record_perf(load, pids, perf_data)
    folded = base.with_suffix(".folded")
    _collapse_perf(perf_data, folded, flame)
    return folded


def _combined_folded(outdir: Path, timestamp: str,
                     folded: list[tuple[str, Path]]) -> Path:
    combined = outdir / f"readwrite-{timestamp}.folded"
    with combined.open("w") as output:
        for name, path in folded:
            for line in path.read_text(errors="ignore").splitlines():
                output.write(f"{name};{line}\n")
    return combined


def _flamegraph_settings(mode: str, timestamp: str, outdir: Path,
                         folded: list[tuple[str, Path]]) -> tuple[Path, str, str, str]:
    if mode == "both":
        return (_combined_folded(outdir, timestamp, folded),
                f"readwrite-{timestamp}.svg", "nginx-xrootd read | write", "1800")
    return folded[0][1], f"{mode}-{timestamp}.svg", f"nginx-xrootd {mode}", "1600"


def _render_flamegraph(mode: str, timestamp: str, outdir: Path,
                       flame: Path, folded: list[tuple[str, Path]]) -> Path:
    source, name, title, width = _flamegraph_settings(
        mode, timestamp, outdir, folded)
    svg = outdir / name
    with svg.open("w") as output:
        proc = _popen([str(flame / "flamegraph.pl"), "--title", title,
                       "--width", width, str(source)], stdout=output)
        proc.wait()
    return svg


def run_profile_load(argv: list[str]) -> int:
    parsed = _load_profile_args(argv)
    if parsed is None:
        return 2
    mode, concurrency, rest = parsed
    flame = _flamegraph_dir()
    if flame is None:
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
        path = _record_load_pass(pass_mode, concurrency, rest, base,
                                 load_artifacts, flame)
        if path is None:
            return 1
        folded.append((pass_mode, path))
    svg = _render_flamegraph(mode, ts, outdir, flame, folded)
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
