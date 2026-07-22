"""Direct Python port of ``tests/run_http_store_writable.sh``."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from cmdscripts.live_common import LiveFailure, LiveRun, random_file, sha256
from settings import BIND_HOST, HOST


ORIGIN_PORT = 8552
BACKEND_PORT = 8553


def _origin_config(run: LiveRun, directory: Path) -> Path:
    return run.write(
        directory / "nginx.conf",
        f"""daemon on; error_log {directory}/logs/e.log info; pid {directory}/nginx.pid;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {directory}/tmp; server {{ listen {BIND_HOST}:{ORIGIN_PORT};
  location / {{ dav_methods PUT DELETE; brix_webdav on; brix_export {directory}/root;
    brix_webdav_auth none; brix_allow_write on; }} }} }}
""",
    )


def _backend_config(run: LiveRun, directory: Path) -> Path:
    return run.write(
        directory / "nginx.conf",
        f"""daemon on; error_log {directory}/logs/e.log info; pid {directory}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {directory}/tmp; server {{ listen {BIND_HOST}:{BACKEND_PORT};
  location / {{ dav_methods PUT DELETE;
    brix_webdav on; brix_export {directory}/backend; brix_webdav_auth none; brix_allow_write on;
    brix_stage on; brix_stage_store http://{HOST}:{ORIGIN_PORT}; brix_stage_flush sync; }} }} }}
""",
    )


def run_port(nginx: Path | None = None) -> int:
    with LiveRun("htwr", nginx) as run:
        origin = run.mkdir("a")
        backend = run.mkdir("b")
        for directory, names in ((origin, ("root", "tmp", "logs")), (backend, ("backend", "tmp", "logs"))):
            for name in names:
                (directory / name).mkdir()
        source = run.root / "src.bin"
        digest = random_file(source, 350000)
        run.start_nginx(origin, _origin_config(run, origin), ORIGIN_PORT)
        run.start_nginx(backend, _backend_config(run, backend), BACKEND_PORT)
        url = f"http://{HOST}:{BACKEND_PORT}/h.bin"
        status = run.curl_status(url, "-T", str(source))
        stored = backend / "backend/h.bin"
        stored_ok = stored.exists() and sha256(stored) == digest
        got = run.root / "got.bin"
        got.write_bytes(run.curl_bytes(url))
        served_ok = sha256(got) == digest
        print(f"  {'ok  ' if status == 201 and stored_ok else 'FAIL'} HTTP stage PUT {status} -> sync flush to posix backend")
        print(f"  {'ok  ' if served_ok else 'FAIL'} GET byte-exact from backend")
        return 0 if status == 201 and stored_ok and served_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return run_port(ns.nginx)
    except LiveFailure as exc:
        print(f"run_http_store_writable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
