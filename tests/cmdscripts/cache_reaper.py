"""Stale-dirty cache reaper command flow."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import time

from cmdscripts import run
from cmdscripts.command_results import print_results
from cmdscripts.c_regression_units import _gcov_flags
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, NGINX_BIN


def _expression_1(objs_dir, nginx_bin):
    return (
        objs_dir or objs_dir_from_nginx(nginx_bin)
    )

def _expression_2(marker):
    return (
        [(False, f"mk_dirty failed: {(marker.stderr or marker.stdout)[-4000:]}")]
    )

def _expression_3(sidecar, dirty):
    return (
        [
                (sidecar.exists() or dirty.exists(), "planted dirty cache metadata"),
            ]
    )

def _expression_4(start):
    return (
        [(False, f"nginx failed to start: {(start.stderr or start.stdout)[-4000:]}")]
    )

def _expression_5(log):
    return (
        log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    )


def _phase_run_checks_1(deadline, dirty, sidecar):
    while time.time() < deadline and (dirty.exists() or sidecar.exists()):
        time.sleep(1)


def objs_dir_from_nginx(nginx_bin: str = NGINX_BIN) -> Path:
    path = Path(nginx_bin)
    if path.name == "nginx" and path.parent.name == "objs":
        return path.parent
    return Path("/tmp/nginx-1.28.3/objs")


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
    return brix_cache_cinfo_mark_dirty(argv[1], 4096, 1048576, 1000, 0, 4096, NULL)
           == 0 ? 0 : 1;
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


def write_config(base: Path, port: int) -> Path:
    root = base / "root"
    state = base / "state"
    logs = base / "logs"
    for path in (root, state, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = base / "nginx.conf"
    conf.write_text(
        f"""daemon on;
error_log {logs / 'error.log'} info;
pid {base / 'nginx.pid'};
env BRIX_CACHE_REAP_FIRST_MS=250;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {root};
        brix_auth none;
        brix_cache_state_root {state};
        brix_cache_dirty_max_age 1;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, objs_dir: Path | None = None) -> list[tuple[bool, str]]:
    objs = _expression_1(objs_dir, nginx_bin)
    cinfo_o = objs / "addon" / "cache" / "cinfo.o"
    if not cinfo_o.is_file():
        return [(True, f"SKIP cinfo.o not found at {cinfo_o}")]

    built, build_error, dirty_marker = build_dirty_marker(base, cinfo_o)
    if not built:
        return [(False, f"failed to build dirty marker: {build_error}")]

    port = cmdscript_ports("cache_reaper")[0]
    conf = write_config(base, port)
    dirty = base / "state" / "abandoned.bin"
    clean = base / "state" / "keepme.bin"
    dirty.write_bytes(deterministic_bytes(4096, 103))
    clean.write_bytes(deterministic_bytes(4096, 107))

    marker = run([str(dirty_marker), str(dirty)])
    if marker.returncode != 0:
        return _expression_2(marker)
    sidecar = dirty.with_name(dirty.name + ".cinfo")
    results: list[tuple[bool, str]] = _expression_3(sidecar, dirty)

    start = run([nginx_bin, "-p", str(base), "-c", str(conf)])
    if start.returncode != 0:
        return _expression_4(start)

    try:
        deadline = time.time() + 20
        _phase_run_checks_1(deadline, dirty, sidecar)

        log = base / "logs" / "error.log"
        log_text = _expression_5(log)
        results.extend(
            [
                (not dirty.exists(), "aged-dirty data file reaped"),
                (not sidecar.exists(), "dirty metadata sidecar reaped"),
                (clean.exists(), "clean file left untouched"),
                ("reaped stale-dirty file" in log_text, "reaper logged a WARN"),
            ]
        )
        return results
    finally:
        stop_nginx(base)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    objs_dir = Path(argv[1]) if len(argv) > 1 else None
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_reaper.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin, objs_dir=objs_dir)
    return print_results(results, "run_cache_reaper")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
