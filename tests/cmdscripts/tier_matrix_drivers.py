"""Direct Python port of ``tests/run_tier_matrix_drivers.sh``."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from cmdscripts.live_common import LiveFailure, LiveRun, random_file, sha256
from settings import BIND_HOST, HOST


BASE_PORT = 8520


def _user_line() -> str:
    return "user root; worker_processes 1;" if os.geteuid() == 0 else ""


def _backend_config(run: LiveRun, directory: Path, port: int, store_url: str) -> Path:
    return run.write(
        directory / "b.conf",
        f"""daemon on; {_user_line()} error_log {directory}/logs/e.log info; pid {directory}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {directory}/tmp; server {{ listen {BIND_HOST}:{port};
  location / {{ dav_methods PUT DELETE;
    brix_webdav on; brix_export {directory}/backend; brix_webdav_auth none;
    brix_allow_write on;
    brix_stage on; brix_stage_store {store_url};
    brix_stage_flush sync; }} }} }}
""",
    )


def _store_config(run: LiveRun, prefix: Path, export: Path, port: int) -> Path:
    return run.write(
        prefix / "s.conf",
        f"""daemon on; {_user_line()} error_log {prefix}/logs/e.log error; pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {export};
    brix_auth none; brix_allow_write on; }} }}
""",
    )


def test_stage_store(run: LiveRun, driver: str, port: int, store_url: str, remote_server: bool = False) -> tuple[bool, int]:
    directory = run.mkdir(driver)
    for name in ("backend", "store", "tmp", "logs"):
        (directory / name).mkdir()
    backend_port, store_port = port, port + 1
    if remote_server:
        store_prefix = run.mkdir(driver, "store-server")
        store_export = run.mkdir(driver, "store-server", "export")
        run.mkdir(driver, "store-server", "logs")
        store_config = _store_config(run, store_prefix, store_export, store_port)
        run.start_nginx(store_prefix, store_config, store_port)
        store_url = f"root://{HOST}:{store_port}"
    run.start_nginx(directory, _backend_config(run, directory, backend_port, store_url), backend_port)
    source = directory / "src.bin"
    digest = random_file(source, 900000)
    status = run.curl_status(f"http://{HOST}:{backend_port}/m.bin", "-T", str(source))
    body = run.curl_bytes(f"http://{HOST}:{backend_port}/m.bin")
    got = directory / "got.bin"
    got.write_bytes(body)
    passed = status == 201 and (directory / "backend/m.bin").exists() and sha256(got) == digest
    print(f"  {'ok  ' if passed else 'FAIL'} {driver} stage_store: PUT {status} -> backend -> GET byte-exact")
    run.stop_nginx(directory)
    return passed, port + 2


def run_port(nginx: Path | None = None) -> int:
    results: dict[str, str] = {}
    port = BASE_PORT
    with LiveRun("tiermx", nginx) as run:
        for driver, url, remote in (
            ("posix", f"posix:{run.root}/posix/store", False),
            ("pblock", f"pblock:{run.root}/pblock/store", False),
            ("xroot", "", True),
        ):
            passed, port = test_stage_store(run, driver, port, url, remote)
            results[driver] = "PASS" if passed else "FAIL"
        pool = os.environ.get("BRIX_TEST_RADOS_POOL")
        if pool:
            run.call(["rados", "-p", pool, "rm", "/m.bin"], check=False)
            passed, port = test_stage_store(run, "rados", port, f"rados://{pool}")
            results["rados"] = "PASS" if passed else "FAIL"
            run.call(["rados", "-p", pool, "rm", "/m.bin"], check=False)
        else:
            results["rados"] = "SKIP"
            print("  skip rados stage_store: set BRIX_TEST_RADOS_POOL")
    print("== stage_store driver matrix ==")
    for driver in ("posix", "pblock", "xroot", "rados"):
        print(f"  {driver:<8} {results[driver]}")
    return 1 if "FAIL" in results.values() else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return run_port(ns.nginx)
    except LiveFailure as exc:
        print(f"run_tier_matrix_drivers: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
