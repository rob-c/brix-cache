"""Writable S3 stage-store command flow."""

from __future__ import annotations

from pathlib import Path
import hashlib
import os
import signal
import time

import requests

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_s3_config(prefix: Path, port: int) -> Path:
    root = prefix / "s3root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
http {{ server {{ listen {BIND_HOST}:{port};
  location / {{ brix_s3 on; brix_export {root}; brix_s3_bucket xrdstage; brix_allow_write on; }} }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_webdav_config(prefix: Path, port: int, s3_port: int) -> Path:
    backend = prefix / "backend"
    tmp = prefix / "tmp"
    logs = prefix / "logs"
    for path in (backend, tmp, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {tmp}; server {{ listen {BIND_HOST}:{port};
  location / {{ dav_methods PUT DELETE;
    brix_webdav on; brix_export {backend}; brix_webdav_auth none; brix_allow_write on;
    brix_stage on; brix_stage_store s3://{HOST}:{s3_port}/xrdstage; brix_stage_flush sync; }} }} }}
""",
        encoding="utf-8",
    )
    return conf


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    s3_port, webdav_port = cmdscript_ports("s3_store_writable")
    s3 = base / "a"
    webdav = base / "b"
    s3_conf = write_s3_config(s3, s3_port)
    webdav_conf = write_webdav_config(webdav, webdav_port, s3_port)
    payload = deterministic_bytes(400_000, 61)
    expected_sha = sha256(payload)

    started: list[Path] = []
    for name, prefix, conf in (("A", s3, s3_conf), ("B", webdav, webdav_conf)):
        result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if result.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} fail: {(result.stderr or result.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        direct = requests.put(
            f"http://{HOST}:{s3_port}/xrdstage/ping.txt",
            data=b"hello\n",
            timeout=10,
        )
        results.append((direct.status_code in {200, 201, 204}, f"direct PUT to A ({direct.status_code})"))

        put = requests.put(f"http://{HOST}:{webdav_port}/o.bin", data=payload, timeout=30)
        backend = webdav / "backend" / "o.bin"
        results.append((put.status_code in {200, 201, 204}, f"WebDAV PUT status={put.status_code}"))
        results.append(
            (
                backend.exists() and sha256(backend.read_bytes()) == expected_sha,
                "object reached the posix backend byte-exact (flushed FROM the s3 stage)",
            )
        )

        got = requests.get(f"http://{HOST}:{webdav_port}/o.bin", timeout=30)
        results.append((got.status_code == 200 and sha256(got.content) == expected_sha, "GET byte-exact"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="s3wr.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_s3_store_writable: ALL PASS")
        return 0
    print("run_s3_store_writable: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
