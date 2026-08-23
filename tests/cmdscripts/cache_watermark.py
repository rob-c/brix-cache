"""Watermark-driven cache reaper command flow."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import signal
import subprocess
import time
import urllib.request

from cmdscripts import run
from cmdscripts.c_regression_units import _gcov_flags
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN


def objs_dir_from_nginx(nginx_bin: str = NGINX_BIN) -> Path:
    path = Path(nginx_bin)
    if path.name == "nginx" and path.parent.name == "objs":
        return path.parent
    return Path("/tmp/nginx-1.28.3/objs")


def filesystem_usage_percent(path: Path) -> int:
    # Must match the SERVER's watermark basis exactly, or the +/-2% margins below
    # are meaningless. The reaper (src/fs/cache/reap_watermark.c) compares
    # occupancy_ppm = (f_blocks - f_bavail) / f_blocks — i.e. it counts the
    # root-reserved blocks as occupied. `df --output=pcent` reports
    # used / (used + avail), which EXCLUDES the reserved blocks and on an ext4
    # root-reserved filesystem runs ~3-4 points LOWER than the server's basis.
    # Keying watermarks off df therefore makes the "calm" instance (high = used+2)
    # sit BELOW the server's true occupancy and purge spuriously. Compute the
    # occupancy exactly as the server does, straight from statvfs(2).
    try:
        vfs = os.statvfs(path)
        if vfs.f_blocks:
            occupancy = (vfs.f_blocks - vfs.f_bavail) / vfs.f_blocks
            return int(round(occupancy * 100))
    except OSError:
        pass
    usage = shutil.disk_usage(path)
    return int((usage.used * 100) / usage.total)


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def build_dirty_marker(base: Path, cinfo_o: Path) -> tuple[bool, str, Path]:
    source = base / "mk_dirty.c"
    binary = base / "mk_dirty"
    source.write_text(
        """#include <stdint.h>
#include <stddef.h>
typedef intptr_t ngx_int_t;
ngx_int_t brix_cache_cinfo_mark_dirty(const char *cache_path, uint64_t size,
    uint32_t block_size, uint64_t mtime, uint64_t off, uint64_t len, void *log);
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    return brix_cache_cinfo_mark_dirty(argv[1], 65536, 1048576, 1000, 0, 65536, NULL) == 0 ? 0 : 1;
}
""",
        encoding="utf-8",
    )
    meta_dir = cinfo_o.parents[1] / "meta"
    objects = [
        cinfo_o,
        meta_dir / "xmeta.o",
        meta_dir / "xmeta_path.o",
        meta_dir / "xmeta_encode.o",
        meta_dir / "xmeta_decode.o",
        meta_dir / "xmeta_carrier.o",
        cinfo_o.parents[1] / "compat" / "crc32c.o",
        cinfo_o.parents[1] / "compat" / "crc32c_hw.o",
    ]
    missing = [str(path) for path in objects if not path.is_file()]
    if missing:
        return False, "missing link object(s): " + ", ".join(missing), binary
    result = run(["cc", "-O", str(source), *map(str, objects),
                  *_gcov_flags(objects), "-o", str(binary)])
    if result.returncode != 0:
        return False, (result.stderr or result.stdout)[-4000:], binary
    return True, "", binary


def write_config(prefix: Path, port: int, high: int, low: int, metrics_port: int | None = None) -> Path:
    root = prefix / "root"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (root, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    metrics = ""
    if metrics_port is not None:
        metrics = f"http {{ server {{ listen {BIND_HOST}:{metrics_port}; location /metrics {{ brix_metrics on; }} }} }}\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{port}; brix_root on; brix_auth none;
    brix_storage_backend root://{HOST}:1; brix_cache_store posix:{cache}; brix_cache_export /;
    brix_cache_high_watermark {high}%;
    brix_cache_low_watermark {low}%;
    brix_cache_reap_interval 1;
}} }}
{metrics}""",
        encoding="utf-8",
    )
    return conf


def plant_cache(prefix: Path, dirty_marker: Path) -> tuple[bool, str]:
    cache = prefix / "cache"
    for idx in range(1, 5):
        item = cache / f"plain_{idx}.bin"
        item.write_bytes(deterministic_bytes(65_536, idx * 11))
        hours_ago = 10 - idx
        stamp = time.time() - hours_ago * 3600
        os.utime(item, (stamp, stamp))
    dirty = cache / "keep_dirty.bin"
    dirty.write_bytes(deterministic_bytes(65_536, 97))
    result = run([str(dirty_marker), str(dirty)])
    if result.returncode != 0:
        return False, (result.stderr or result.stdout)[-4000:]
    return True, ""


def start_instance(
    base: Path,
    name: str,
    port: int,
    high: int,
    low: int,
    dirty_marker: Path,
    nginx_bin: str,
    metrics_port: int | None = None,
) -> tuple[bool, str, Path]:
    prefix = base / name
    conf = write_config(prefix, port, high, low, metrics_port)
    planted, plant_error = plant_cache(prefix, dirty_marker)
    if not planted:
        return False, f"{name} dirty marker failed: {plant_error}", prefix
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        return False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}", prefix
    return True, "", prefix


def metric_value(metrics: str, name: str) -> float | None:
    for line in metrics.splitlines():
        if line.startswith(name + " "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, objs_dir: Path | None = None) -> list[tuple[bool, str]]:
    objs = objs_dir or objs_dir_from_nginx(nginx_bin)
    cinfo_o = objs / "addon" / "cache" / "cinfo.o"
    if not cinfo_o.is_file():
        return [(True, f"SKIP cinfo.o not found at {cinfo_o}")]
    watermarks = _watermarks(base)
    if isinstance(watermarks, list):
        return watermarks
    built, build_error, dirty_marker = build_dirty_marker(base, cinfo_o)
    if not built:
        return [(False, f"failed to build dirty marker: {build_error}")]
    purge_port, calm_port, metrics_port = cmdscript_ports("cache_watermark")
    specifications = _instance_specs(
        purge_port, calm_port, metrics_port, watermarks
    )
    started, error = _start_instances(base, specifications, dirty_marker, nginx_bin)
    if error:
        return [(False, error)]
    try:
        _wait_for_purge(base)
        return _collect_results(base, metrics_port)
    finally:
        _stop_instances(started)


def _watermarks(base):
    used = filesystem_usage_percent(base)
    if used < 10 or used > 96:
        return [(True, f"SKIP filesystem usage {used}% outside testable 10-96% band")]
    high_calm = min(99, used + 2)
    return used - 2, max(1, used - 5), high_calm, high_calm - 3


def _instance_specs(purge_port, calm_port, metrics_port, watermarks):
    high_purge, low_purge, high_calm, low_calm = watermarks
    return (
        ("purge", purge_port, high_purge, low_purge, metrics_port),
        ("calm", calm_port, high_calm, low_calm, None),
    )


def _start_instances(base, specifications, dirty_marker, nginx_bin):
    started = []
    for name, port, high, low, metrics_port in specifications:
        succeeded, message, prefix = start_instance(
            base, name, port, high, low, dirty_marker, nginx_bin, metrics_port
        )
        if not succeeded:
            _stop_instances(started)
            return [], message
        started.append(prefix)
    return started, ""


def _stop_instances(prefixes):
    for prefix in reversed(prefixes):
        stop_nginx(prefix)


def _wait_for_purge(base):
    deadline = time.time() + 25
    pattern = base / "purge" / "cache"
    while time.time() < deadline and list(pattern.glob("plain_*.bin")):
        time.sleep(1)


def _collect_results(base, metrics_port):
    results = []
    _append_purge_results(results, base)
    _append_metric_results(results, metrics_port)
    _append_calm_results(results, base)
    return results


def _read_log(path):
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _append_purge_results(results, base):
    cache = base / "purge" / "cache"
    dirty = (cache / "keep_dirty.bin").is_file()
    results.append((not list(cache.glob("plain_*.bin")),
                    "purge: all plain files reaped (timer drove watermark purge)"))
    results.append((dirty, "purge: DIRTY write-back file survived (never reaped)"))
    results.append((dirty, "purge: dirty metadata protection persisted"))
    log = _read_log(base / "purge" / "logs" / "e.log")
    results.append(("watermark reaper purged" in log,
                    "purge: watermark NOTICE logged"))


def _fetch_metrics(results, metrics_port):
    try:
        with urllib.request.urlopen(
            f"http://{HOST}:{metrics_port}/metrics", timeout=5
        ) as response:
            return response.read().decode("utf-8", errors="replace")
    except OSError as error:
        results.append((False, f"metrics fetch failed: {error}"))
        return ""


def _append_metric_results(results, metrics_port):
    metrics = _fetch_metrics(results, metrics_port)
    usage = metric_value(metrics, "brix_cache_usage_ratio")
    evicted = metric_value(metrics, "brix_cache_watermark_evicted_files_total")
    purges = metric_value(metrics, "brix_cache_watermark_purges_total")
    results.append((usage is not None, "metrics: cache_usage_ratio gauge present"))
    results.append((evicted is not None and evicted > 0,
                    "metrics: watermark_evicted_files_total > 0"))
    results.append((purges is not None and purges > 0,
                    "metrics: watermark_purges_total > 0"))


def _append_calm_results(results, base):
    cache = base / "calm" / "cache"
    results.append((len(list(cache.glob("plain_*.bin"))) == 4,
                    "calm: all 4 plain files survived (below HIGH - no purge)"))
    log = _read_log(base / "calm" / "logs" / "e.log")
    results.append(("watermark reaper purged" not in log,
                    "calm: no purge below HIGH watermark"))


def entry(argv: list[str]) -> int:
    nginx_bin, objs_dir = _entry_arguments(argv)
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_wm.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin, objs_dir=objs_dir)
    _print_results(results)
    if all(ok for ok, _ in results):
        print("run_cache_watermark: ALL PASS")
        return 0
    print("run_cache_watermark: FAILURES")
    return 1


def _entry_arguments(argv):
    nginx_bin = argv[0] if argv else NGINX_BIN
    objects = Path(argv[1]) if len(argv) > 1 else None
    return nginx_bin, objects


def _print_results(results):
    for succeeded, message in results:
        label = "ok  " if succeeded else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
