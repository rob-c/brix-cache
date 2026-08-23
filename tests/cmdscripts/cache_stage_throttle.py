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


def _df_percent(result):
    if result.returncode != 0:
        return None
    last_line = _last_nonempty_line(result.stdout)
    if last_line is None:
        return None
    digits = "".join(filter(str.isdigit, last_line))
    return int(digits) if digits else None


def _last_nonempty_line(output):
    lines = list(filter(None, map(str.strip, output.splitlines())))
    return lines[-1] if lines else None


def filesystem_usage_percent(path: Path) -> int:
    percent = _df_percent(run(["df", "--output=pcent", str(path)]))
    if percent is not None:
        return percent
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


def _start_throttle_instances(base, nginx_bin, configurations):
    started = []
    for arguments in configurations:
        ok, message, prefix = start_instance(base, *arguments, nginx_bin=nginx_bin)
        if not ok:
            for item in reversed(started):
                stop_nginx(item)
            return None, message
        started.append(prefix)
    return started, ""


def _reject_results(base, xrdcp, xrdfs, payload, port, metrics_port):
    put = xrdcp_put_bounded(xrdcp, payload, f"root://{HOST}:{port}//w.bin")
    read = xrdfs_cat_text(port, "/readme.txt", xrdfs)
    metrics = fetch_metrics(metrics_port)
    return [
        (put.returncode != 0, "reject: root:// write failed (staging full)"),
        (not (base / "reject" / "root" / "w.bin").exists(),
         "reject: no file created (shed before any write)"),
        (_reject_read_ok(read), "reject: READ still works (reads never throttled)"),
        (metric_positive(metrics, 'brix_wt_stage_throttled_total{action="reject"}'),
         "reject: throttled_total{reject} > 0"),
        ("brix_wt_stage_usage_ratio " in metrics,
         "reject: wt_stage_usage_ratio gauge present"),
    ]


def _reject_read_ok(result):
    return result.returncode == 0 and result.stdout.strip() == "readable-content-reject"


def _wait_metric(process, metrics_port):
    deadline = time.time() + 30
    metric = 'brix_wt_stage_throttled_total{action="wait"}'
    while time.time() < deadline:
        if metric_positive(fetch_metrics(metrics_port), metric):
            return True
        if process.poll() is not None:
            return metric_positive(fetch_metrics(metrics_port), metric)
        time.sleep(0.5)
    return False


def _stop_wait_process(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def _wait_result(xrdcp, payload, port, metrics_port):
    process = subprocess.Popen(
        [str(xrdcp), "-f", str(payload), f"root://{HOST}:{port}//w.bin"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        waited = _wait_metric(process, metrics_port)
    finally:
        _stop_wait_process(process)
    return waited, "wait: throttled_total{wait} > 0 (server issued kXR_wait)"


def _watermarks(used):
    return used - 2, max(1, used - 5), min(99, used + 3), max(1, used - 3)


def _throttle_configurations(used):
    reject_high, reject_low, wait_high, wait_low = _watermarks(used)
    reject_port, wait_port, reject_metrics, wait_metrics = cmdscript_ports("cache_stage_throttle")
    configurations = (
        ("reject", reject_port, reject_high, reject_low, reject_metrics),
        ("wait", wait_port, wait_high, wait_low, wait_metrics),
    )
    return configurations, (reject_port, wait_port, reject_metrics, wait_metrics)


def _exercise_throttles(base, clients, ports):
    xrdcp, xrdfs = clients
    reject_port, wait_port, reject_metrics, wait_metrics = ports
    payload = base / "stage_thr_w.bin"
    payload.write_bytes(deterministic_bytes(4096, 113))
    results = _reject_results(base, xrdcp, xrdfs, payload, reject_port, reject_metrics)
    results.append(_wait_result(xrdcp, payload, wait_port, wait_metrics))
    return results


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
    configurations, ports = _throttle_configurations(used)
    started, message = _start_throttle_instances(base, nginx_bin, configurations)
    if started is None:
        return [(False, message)]

    try:
        time.sleep(1)
        return _exercise_throttles(base, (xrdcp, xrdfs), ports)
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="stage_thr.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    _print_results(results)
    return _result_code(results)


def _print_results(results):
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")


def _result_code(results):
    if all(ok for ok, _ in results):
        print("run_cache_stage_throttle: ALL PASS")
        return 0
    print("run_cache_stage_throttle: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
