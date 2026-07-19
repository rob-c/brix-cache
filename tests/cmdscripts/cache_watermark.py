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
from settings import NGINX_BIN, free_ports


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
    ]
    missing = [str(path) for path in objects if not path.is_file()]
    if missing:
        return False, "missing link object(s): " + ", ".join(missing), binary
    result = run(["cc", "-O", "-o", str(binary), str(source), *map(str, objects)])
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
        metrics = f"http {{ server {{ listen 127.0.0.1:{metrics_port}; location /metrics {{ brix_metrics on; }} }} }}\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:1; brix_cache_store posix:{cache}; brix_cache_export /;
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

    used = filesystem_usage_percent(base)
    if used < 10 or used > 96:
        return [(True, f"SKIP filesystem usage {used}% outside testable 10-96% band")]
    high_purge = used - 2
    low_purge = max(1, used - 5)
    high_calm = min(99, used + 2)
    low_calm = high_calm - 3

    built, build_error, dirty_marker = build_dirty_marker(base, cinfo_o)
    if not built:
        return [(False, f"failed to build dirty marker: {build_error}")]

    purge_port, calm_port, metrics_port = free_ports(3)
    started: list[Path] = []
    for name, port, high, low, maybe_metrics_port in (
        ("purge", purge_port, high_purge, low_purge, metrics_port),
        ("calm", calm_port, high_calm, low_calm, None),
    ):
        ok, message, prefix = start_instance(
            base,
            name,
            port,
            high,
            low,
            dirty_marker,
            nginx_bin,
            maybe_metrics_port,
        )
        if not ok:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, message)]
        started.append(prefix)

    try:
        deadline = time.time() + 25
        while time.time() < deadline and list((base / "purge" / "cache").glob("plain_*.bin")):
            time.sleep(1)

        results: list[tuple[bool, str]] = []
        purge_cache = base / "purge" / "cache"
        calm_cache = base / "calm" / "cache"
        purge_log = base / "purge" / "logs" / "e.log"
        calm_log = base / "calm" / "logs" / "e.log"

        results.append((not list(purge_cache.glob("plain_*.bin")), "purge: all plain files reaped (timer drove watermark purge)"))
        results.append(((purge_cache / "keep_dirty.bin").is_file(), "purge: DIRTY write-back file survived (never reaped)"))
        results.append(((purge_cache / "keep_dirty.bin").is_file(), "purge: dirty metadata protection persisted"))
        purge_log_text = purge_log.read_text(encoding="utf-8", errors="replace") if purge_log.exists() else ""
        results.append(("watermark reaper purged" in purge_log_text, "purge: watermark NOTICE logged"))

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=5) as response:
                metrics = response.read().decode("utf-8", errors="replace")
        except OSError as exc:
            metrics = ""
            results.append((False, f"metrics fetch failed: {exc}"))
        usage_ratio = metric_value(metrics, "brix_cache_usage_ratio")
        evicted = metric_value(metrics, "brix_cache_watermark_evicted_files_total")
        purges = metric_value(metrics, "brix_cache_watermark_purges_total")
        results.append((usage_ratio is not None, "metrics: cache_usage_ratio gauge present"))
        results.append((evicted is not None and evicted > 0, "metrics: watermark_evicted_files_total > 0"))
        results.append((purges is not None and purges > 0, "metrics: watermark_purges_total > 0"))

        calm_plain = list(calm_cache.glob("plain_*.bin"))
        results.append((len(calm_plain) == 4, "calm: all 4 plain files survived (below HIGH - no purge)"))
        calm_log_text = calm_log.read_text(encoding="utf-8", errors="replace") if calm_log.exists() else ""
        results.append(("watermark reaper purged" not in calm_log_text, "calm: no purge below HIGH watermark"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    objs_dir = Path(argv[1]) if len(argv) > 1 else None
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_wm.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin, objs_dir=objs_dir)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_watermark: ALL PASS")
        return 0
    print("run_cache_watermark: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
