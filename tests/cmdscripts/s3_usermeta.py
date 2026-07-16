"""S3 user-defined metadata command flow."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import time

import requests

from cmdscripts import run
from settings import NGINX_BIN, free_port


def write_config(prefix: Path, port: int) -> Path:
    root = prefix / "s3root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    server {{
        listen 127.0.0.1:{port};
        location / {{
            brix_s3 on;
            brix_storage_backend posix:{root};
            brix_s3_bucket testbucket;
            brix_allow_write on;
        }}
    }}
}}
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
    port = free_port()
    conf = write_config(base, port)
    start = run([nginx_bin, "-p", str(base), "-c", str(conf)])
    if start.returncode != 0:
        return [(False, "s3 start failed: " + (start.stderr or start.stdout)[-4000:])]

    try:
        time.sleep(1)
        bucket = f"http://127.0.0.1:{port}/testbucket"
        obj = f"{bucket}/obj.txt"
        copy = f"{bucket}/copy.txt"
        results: list[tuple[bool, str]] = []

        put = requests.put(
            obj,
            data=b"hello world",
            headers={"x-amz-meta-foo": "bar", "x-amz-meta-Color": "Blue"},
            timeout=10,
        )
        results.append((put.status_code == 200, "PUT 200"))

        head = requests.head(obj, timeout=10)
        results.append((head.headers.get("x-amz-meta-foo") == "bar", "HEAD echoes x-amz-meta-foo=bar"))
        results.append(
            (
                head.headers.get("x-amz-meta-color") == "Blue",
                "HEAD echoes x-amz-meta-color=Blue (key lowercased)",
            )
        )

        get = requests.get(obj, timeout=10)
        results.append(
            (
                get.headers.get("x-amz-meta-foo") == "bar" and get.content == b"hello world",
                "GET echoes the metadata and body",
            )
        )

        copied = requests.put(copy, headers={"x-amz-copy-source": "/testbucket/obj.txt"}, timeout=10)
        results.append((copied.status_code == 200, "COPY 200"))
        copy_head = requests.head(copy, timeout=10)
        results.append((copy_head.headers.get("x-amz-meta-foo") == "bar", "copied object carries x-amz-meta-foo=bar"))

        replaced = requests.put(
            obj,
            headers={
                "x-amz-copy-source": "/testbucket/obj.txt",
                "x-amz-metadata-directive": "REPLACE",
                "x-amz-meta-foo": "baz",
            },
            timeout=10,
        )
        results.append((replaced.status_code == 200, "REPLACE copy-self 200"))
        replaced_head = requests.head(obj, timeout=10)
        results.append((replaced_head.headers.get("x-amz-meta-foo") == "baz", "metadata replaced: foo=baz"))
        results.append((replaced_head.headers.get("x-amz-meta-color") is None, "old key dropped on REPLACE: color absent"))
        replaced_get = requests.get(obj, timeout=10)
        results.append((replaced_get.content == b"hello world", "bytes intact after metadata-only REPLACE"))
        return results
    finally:
        stop_nginx(base)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="s3_usermeta.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_s3_usermeta: ALL PASS")
        return 0
    print("run_s3_usermeta: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
