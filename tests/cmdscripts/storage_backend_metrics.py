"""Storage backend metrics command flow."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN


def write_config(prefix: Path, port: int) -> Path:
    export = prefix / "export"
    logs = prefix / "logs"
    export.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    brix_credential origin {{ token s3cr3t-tok; }}
    server {{
        listen {BIND_HOST}:{port};
        location / {{
            brix_webdav on; brix_export {export}; brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend root://{HOST}:19999;
            brix_storage_credential origin;
            brix_webdav_storage_staging on;
        }}
        location /metrics {{ brix_metrics on; }}
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


def fetch_metrics(port: int) -> str:
    result = subprocess.run(
        ["curl", "-s", f"http://{HOST}:{port}/metrics"],
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    port = cmdscript_ports("storage_backend_metrics")[0]
    conf = write_config(base, port)
    start = run([nginx_bin, "-p", str(base), "-c", str(conf)])
    if start.returncode != 0:
        return [(False, "start failed: " + (start.stderr or start.stdout)[-4000:])]

    try:
        time.sleep(1)
        out = fetch_metrics(port)
        line = next((item for item in out.splitlines() if item.startswith("brix_storage_backend_info")), "")
        return [
            (bool(line), "info gauge present"),
            ('backend="xroot"' in line, 'backend="xroot"'),
            ('auth="token"' in line, 'auth="token"'),
            ('staging="1"' in line, 'staging="1"'),
            ('origin="127.0.0.1:19999"' in line, "origin host:port"),  # net-literal-allow: metric origin label value under test
        ]
    finally:
        stop_nginx(base)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sb_metrics.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_storage_backend_metrics: ALL PASS")
        return 0
    print("run_storage_backend_metrics: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
