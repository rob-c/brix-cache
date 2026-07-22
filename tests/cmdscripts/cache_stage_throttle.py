"""Write-through stage watermark throttle command flow."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time
import urllib.request

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"


def filesystem_usage_percent(path: Path) -> int:
    result = run(["df", "--output=pcent", str(path)])
    if result.returncode == 0:
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if lines:
            digits = "".join(ch for ch in lines[-1] if ch.isdigit())
            if digits:
                return int(digits)
    stat = os.statvfs(path)
    used = stat.f_blocks - stat.f_bfree
    return int((used * 100) / stat.f_blocks)


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def write_config(prefix: Path, port: int, high: int, low: int, metrics_port: int, name: str) -> Path:
    root = prefix / "root"
    stage = prefix / "stage"
    logs = prefix / "logs"
    for path in (root, stage, logs):
        path.mkdir(parents=True, exist_ok=True)
    (root / "readme.txt").write_text(f"readable-content-{name}\n", encoding="utf-8")
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{port}; brix_root on; brix_auth none;
    brix_storage_backend posix:{root};
    brix_allow_write on; brix_upload_resume off;
    brix_write_through on; brix_wt_mode sync; brix_wt_origin {HOST}:1;
    brix_cache_wt_stage_root {stage};
    brix_wt_stage_high_watermark {high}%;
    brix_wt_stage_low_watermark {low}%;
}} }}
http {{ server {{ listen {BIND_HOST}:{metrics_port}; location /metrics {{ brix_metrics on; }} }} }}
""",
        encoding="utf-8",
    )
    return conf


def start_instance(
    base: Path,
    name: str,
    port: int,
    high: int,
    low: int,
    metrics_port: int,
    nginx_bin: str,
) -> tuple[bool, str, Path]:
    prefix = base / name
    conf = write_config(prefix, port, high, low, metrics_port, name)
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        return False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}", prefix
    return True, "", prefix


def fetch_metrics(port: int) -> str:
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/metrics", timeout=5) as response:
            return response.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def metric_positive(metrics: str, prefix: str) -> bool:
    for line in metrics.splitlines():
        if line.startswith(prefix):
            try:
                return float(line.split()[1]) > 0
            except (IndexError, ValueError):
                return False
    return False


def xrdfs_cat_text(port: int, path: str, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(xrdfs), f"root://{HOST}:{port}", "cat", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def xrdcp_put_bounded(xrdcp: Path, source: Path, url: str, timeout: int = 8) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [str(xrdcp), "-f", str(source), url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(exc.cmd, 124, exc.stdout or "", exc.stderr or "timed out")


def run_checks(
    base: Path,
    nginx_bin: str = NGINX_BIN,
    xrdcp: Path = XRDCP,
    xrdfs: Path = XRDFS,
) -> list[tuple[bool, str]]:
    if not os.access(xrdcp, os.X_OK) or not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP native xrdcp/xrdfs not built")]

    used = filesystem_usage_percent(base)
    if used < 10 or used > 94:
        return [(True, f"SKIP filesystem usage {used}% outside testable 10-94% band")]
    reject_high = used - 2
    reject_low = max(1, used - 5)
    wait_high = min(99, used + 3)
    wait_low = max(1, used - 3)

    reject_port, wait_port, reject_metrics, wait_metrics = cmdscript_ports("cache_stage_throttle")
    started: list[Path] = []
    for args in (
        ("reject", reject_port, reject_high, reject_low, reject_metrics),
        ("wait", wait_port, wait_high, wait_low, wait_metrics),
    ):
        ok, message, prefix = start_instance(base, *args, nginx_bin=nginx_bin)
        if not ok:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, message)]
        started.append(prefix)

    try:
        time.sleep(1)
        payload = base / "stage_thr_w.bin"
        payload.write_bytes(deterministic_bytes(4096, 113))

        results: list[tuple[bool, str]] = []
        reject_put = xrdcp_put_bounded(xrdcp, payload, f"root://{HOST}:{reject_port}//w.bin")
        results.append((reject_put.returncode != 0, "reject: root:// write failed (staging full)"))
        results.append((not (base / "reject" / "root" / "w.bin").exists(), "reject: no file created (shed before any write)"))

        read = xrdfs_cat_text(reject_port, "/readme.txt", xrdfs)
        results.append((read.returncode == 0 and read.stdout.strip() == "readable-content-reject", "reject: READ still works (reads never throttled)"))

        reject_m = fetch_metrics(reject_metrics)
        results.append((metric_positive(reject_m, 'brix_wt_stage_throttled_total{action="reject"}'), "reject: throttled_total{reject} > 0"))
        results.append(("brix_wt_stage_usage_ratio " in reject_m, "reject: wt_stage_usage_ratio gauge present"))

        wait_proc = subprocess.Popen(
            [str(xrdcp), "-f", str(payload), f"root://{HOST}:{wait_port}//w.bin"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        waited = False
        # Generous deadline: under a fully parallel suite the metric scrape and
        # the throttled write can each lag several seconds; success exits early.
        deadline = time.time() + 30
        try:
            while time.time() < deadline:
                wait_m = fetch_metrics(wait_metrics)
                if metric_positive(wait_m, 'brix_wt_stage_throttled_total{action="wait"}'):
                    waited = True
                    break
                if wait_proc.poll() is not None:
                    # The client may finish between polls — the counter is
                    # already committed server-side, so scrape once more.
                    wait_m = fetch_metrics(wait_metrics)
                    waited = metric_positive(
                        wait_m, 'brix_wt_stage_throttled_total{action="wait"}')
                    break
                time.sleep(0.5)
        finally:
            if wait_proc.poll() is None:
                wait_proc.terminate()
                try:
                    wait_proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    wait_proc.kill()
                    wait_proc.wait(timeout=2)
        results.append((waited, "wait: throttled_total{wait} > 0 (server issued kXR_wait)"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="stage_thr.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_stage_throttle: ALL PASS")
        return 0
    print("run_cache_stage_throttle: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
