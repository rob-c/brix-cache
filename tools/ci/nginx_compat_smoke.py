#!/usr/bin/env python3
"""Exercise a specific nginx binary and its matching dynamic BriX modules.

Uses only the Python standard library, a private prefix and loopback listeners;
it neither starts the test fleet nor requires an installed XRootD client.
Pass --xrdcp explicitly to add a byte-exact root:// read. The matrix also runs
tests/test_bind_migration.py to exercise root:// and multi-worker lifecycle.
Every run retains its config and logs in a unique directory under --work-dir.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module-dir", type=Path, required=True)
    parser.add_argument("--stream-module", type=Path,
                        help="override ngx_stream_module.so for distro nginx")
    parser.add_argument("--work-dir", type=Path, required=True,
                        help="parent for the private run directory and logs")
    parser.add_argument("--xrdcp", type=Path,
                        help="optional explicit client for a root:// read")
    return parser.parse_args(argv)


def _executable(path):
    binary = path.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"binary is missing or not executable: {binary}")
    return binary


def _artifacts(args):
    nginx = _executable(args.nginx)
    if args.xrdcp:
        _executable(args.xrdcp)
    return nginx, _modules(args)


def _modules(args):
    modules = [
        args.stream_module or args.module_dir / "ngx_stream_module.so",
        args.module_dir / "ngx_stream_brix_module.so",
        args.module_dir / "ngx_http_brix_xrdhttp_filter_module.so",
    ]
    for module in modules:
        if not module.is_file():
            raise RuntimeError(f"required dynamic module is missing: {module}")
    return [module.resolve() for module in modules]


def _quote(value):
    """Quote paths in nginx configuration, rejecting control characters."""
    value = str(value)
    if any(ord(char) < 32 for char in value):
        raise ValueError("nginx paths must not contain control characters")
    return json.dumps(value, ensure_ascii=False)


def _config(work, modules, http_port, root_port):
    loaders = "\n".join(f"load_module {_quote(module)};" for module in modules)
    temp_paths = "\n".join(
        f"    {name}_temp_path {_quote(work / name)};"
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
    )
    return f"""{loaders}
worker_processes 1;
daemon off;
pid {_quote(work / 'nginx.pid')};
error_log {_quote(work / 'error.log')} info;
thread_pool default threads=2 max_queue=256;
events {{ worker_connections 64; }}
http {{
    access_log off;
{temp_paths}
    server {{
        listen 127.0.0.1:{http_port};
        location / {{
            brix_webdav on;
            brix_storage_backend {_quote('posix:' + str(work / 'data'))};
            brix_webdav_auth none;
            brix_allow_write on;
            brix_read_only on;
        }}
    }}
}}
stream {{
    server {{
        listen 127.0.0.1:{root_port};
        brix_root on;
        brix_storage_backend {_quote('posix:' + str(work / 'data'))};
        brix_auth none;
        brix_min_sec_level none;
        brix_allow_write on;
        brix_read_only on;
        brix_access_log {_quote(work / 'root-access.log')};
    }}
}}
"""


def _request(port, method, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _snapshot(data):
    """Capture namespace and contents without treating access times as writes."""
    snapshot = {}
    for path in sorted(data.rglob("*")):
        content = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        snapshot[str(path.relative_to(data))] = (path.lstat().st_mode, content)
    return snapshot


def _check_http(port, data, payload):
    if _request(port, "GET", "/seed.bin") != (200, payload):
        raise RuntimeError("WebDAV GET did not return byte-exact data with HTTP 200")
    print("PASS: WebDAV GET returns byte-exact data", flush=True)
    status, _ = _request(port, "GET", "/missing.bin")
    if status != 404:
        raise RuntimeError(f"missing WebDAV object returned {status}, expected 404")
    print("PASS: missing WebDAV object returns 404", flush=True)
    # Startup may create backend metadata. Freeze the baseline after readiness.
    baseline = _snapshot(data)
    mutations = (("PUT", "/new.bin", b"denied"),
                 ("DELETE", "/seed.bin", None), ("MKCOL", "/newdir", None))
    for method, path, body in mutations:
        status, _ = _request(port, method, path, body)
        if status != 403:
            raise RuntimeError(f"read-only {method} returned {status}, expected 403")
    if _snapshot(data) != baseline:
        raise RuntimeError("read-only requests changed the export")
    print("PASS: read-only PUT, DELETE, MKCOL return 403 without export changes", flush=True)


def _signal_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


@contextmanager
def _running_nginx(command, work):
    """Own and reap one process group, including children of a crashed master."""
    with (work / "console.log").open("w", encoding="utf-8") as console:
        process = subprocess.Popen(command, cwd=work, stdout=console, stderr=console,
                                   start_new_session=True)
        try:
            yield process
        finally:
            _signal_group(process, signal.SIGQUIT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            finally:
                _signal_group(process, signal.SIGKILL)
                process.wait(timeout=5)


def _wait_ready(process, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"nginx exited during startup: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("nginx did not become ready within 10 seconds")


def _check_root(xrdcp, work, port, payload):
    destination = work / "download.bin"
    result = subprocess.run(
        [str(xrdcp.resolve()), "-f", f"root://127.0.0.1:{port}//seed.bin",
         str(destination)], capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise RuntimeError(f"xrdcp failed ({result.returncode}): {result.stderr}")
    if destination.read_bytes() != payload:
        raise RuntimeError("root:// read did not return byte-exact data")
    print("PASS: xrdcp returns byte-exact data over root://", flush=True)


def _prepare(work):
    # Only this run's disposable tree is opened for root's de-escalated worker.
    work.chmod(0o755)
    data = work / "data"
    data.mkdir(mode=0o777)
    data.chmod(0o777)
    payload = b"BriX nginx compatibility smoke\n" + os.urandom(64 * 1024)
    seed = data / "seed.bin"
    seed.write_bytes(payload)
    seed.chmod(0o666)
    return data, payload


@contextmanager
def _reserved_ports():
    """Hold two distinct kernel-assigned loopback ports until config validation."""
    with ExitStack() as reservations:
        sockets = [reservations.enter_context(socket.socket()) for _ in range(2)]
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        yield [listener.getsockname()[1] for listener in sockets]


def _validate_configuration(nginx, modules, work):
    with _reserved_ports() as (http_port, root_port):
        config = work / "nginx.conf"
        config.write_text(_config(work, modules, http_port, root_port), encoding="utf-8")
        command = [str(nginx), "-p", str(work) + "/", "-c", str(config),
                   "-e", str(work / "error.log")]
        result = subprocess.run(command + ["-t"], capture_output=True,
                                text=True, timeout=30)
        (work / "config-test.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(f"nginx -t failed ({result.returncode}): {result.stderr}")
    print("PASS: nginx -t loads the stream core and both BriX modules", flush=True)
    return command, http_port, root_port


def _exercise(args, nginx, modules, work):
    data, payload = _prepare(work)
    command, http_port, root_port = _validate_configuration(nginx, modules, work)
    with _running_nginx(command, work) as process:
        _wait_ready(process, http_port)
        _check_http(http_port, data, payload)
        if args.xrdcp:
            _check_root(args.xrdcp, work, root_port, payload)
        if process.poll() is not None:
            raise RuntimeError(f"nginx exited during smoke checks: {process.returncode}")
    log = (work / "error.log").read_text(encoding="utf-8", errors="replace")
    if "exited on signal" in log:
        raise RuntimeError("nginx reported a worker crash; see error.log")


def main(argv=None):
    args = _arguments(argv)
    try:
        nginx, modules = _artifacts(args)
        args.work_dir.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="smoke-", dir=args.work_dir.resolve()))
        print(f"nginx compatibility smoke: {nginx}\nLogs: {work}", flush=True)
        _exercise(args, nginx, modules, work)
    except (OSError, RuntimeError, ValueError, http.client.HTTPException,
            subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: nginx compatibility smoke; private nginx stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
