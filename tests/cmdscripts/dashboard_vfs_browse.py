"""Dashboard VFS browser command flow."""

from __future__ import annotations

from pathlib import Path
import hashlib
import hmac
import json
import os
import signal
import subprocess
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

PASSWORD = "vfsb"


def dashboard_cookie(now: int | None = None) -> str:
    ts = int(time.time()) if now is None else int(now)
    digest = hmac.new(PASSWORD.encode(), str(ts).encode(), hashlib.sha256).hexdigest()
    return f"xrd_dashboard={digest}.{ts}"


def write_config(prefix: Path, posix_port: int, dash_port: int, off_port: int, pblock_port: int) -> Path:
    posix_root = prefix / "posix_root"
    pblock_root = prefix / "pblock_root"
    logs = prefix / "logs"
    tmp = prefix / "tmp"
    (posix_root / "subdir").mkdir(parents=True, exist_ok=True)
    pblock_root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    (posix_root / "hello.txt").write_text("posix payload", encoding="utf-8")
    (posix_root / "subdir" / "inner.txt").write_text("nested", encoding="utf-8")
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 128; }}
http {{
    client_body_temp_path {tmp};
    server {{
        listen {BIND_HOST}:{posix_port};
        location / {{
            brix_webdav on;
            brix_export {posix_root};
            brix_webdav_auth none;
            brix_storage_backend posix;
        }}
    }}
    server {{
        listen {BIND_HOST}:{pblock_port};
        location / {{
            dav_methods PUT;
            brix_webdav on;
            brix_export {pblock_root};
            brix_webdav_auth none;
            brix_allow_write on;
            brix_storage_backend pblock;
        }}
    }}
    server {{
        listen {BIND_HOST}:{dash_port};
        location /brix/ {{
            brix_dashboard on;
            brix_dashboard_password "{PASSWORD}";
            brix_dashboard_vfs_browse on;
        }}
    }}
    server {{
        listen {BIND_HOST}:{off_port};
        location /brix/ {{
            brix_dashboard on;
            brix_dashboard_password "{PASSWORD}";
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


def curl(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["curl", *args], capture_output=True, text=True)


def curl_body(url: str, cookie: str | None = None) -> str:
    args = ["-s"]
    if cookie:
        args.extend(["-H", f"Cookie: {cookie}"])
    args.append(url)
    return curl(args).stdout


def curl_code(url: str, cookie: str | None = None) -> str:
    args = ["-s", "-o", "/dev/null", "-w", "%{http_code}"]
    if cookie:
        args.extend(["-H", f"Cookie: {cookie}"])
    args.append(url)
    return curl(args).stdout.strip()


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    posix_port, dash_port, off_port, pblock_port = cmdscript_ports("dashboard_vfs_browse")
    conf = write_config(base, posix_port, dash_port, off_port, pblock_port)
    test = run([nginx_bin, "-t", "-c", str(conf), "-p", str(base)])
    results = [(test.returncode == 0, "config parses (brix_dashboard_vfs_browse)")]
    if test.returncode != 0:
        results[0] = (False, "config parses (brix_dashboard_vfs_browse): " + (test.stderr or test.stdout)[-4000:])
        return results

    start = run([nginx_bin, "-c", str(conf), "-p", str(base)])
    if start.returncode != 0:
        results.append((False, "nginx start failed: " + (start.stderr or start.stdout)[-4000:]))
        return results
    try:
        time.sleep(0.6)
        _exercise_dashboard(base, dash_port, off_port, pblock_port, results)
    finally:
        stop_nginx(base)
    return results


def _exercise_dashboard(base, dash_port, off_port, pblock_port, results):
    cookie = dashboard_cookie()
    api = f"http://{HOST}:{dash_port}/brix/api/v1"
    source = _seed_pblock(base, pblock_port, results)
    exports = _check_census(api, cookie, results)
    posix_index = _export_index(exports, "posix")
    pblock_index = _export_index(exports, "pblock")
    _check_posix_listing(api, cookie, posix_index, results)
    _check_pblock_listing(api, cookie, pblock_index, results)
    _check_pblock_download(base, api, cookie, pblock_index, source, results)
    _check_access_guards(api, cookie, posix_index, off_port, results)


def _seed_pblock(base, port, results):
    source = base / "pb_src.bin"
    source.write_text("pblock payload bytes", encoding="utf-8")
    status = curl([
        "-s", "-o", "/dev/null", "-w", "%{http_code}", "-T", str(source),
        f"http://{HOST}:{port}/stored.bin",
    ]).stdout.strip()
    results.append((status in {"201", "204"},
                    f"pblock seeded via WebDAV PUT ({status})"))
    return source


def _json_body(url, cookie, fallback):
    try:
        return json.loads(curl_body(url, cookie))
    except json.JSONDecodeError:
        return fallback


def _check_census(api, cookie, results):
    exports = _json_body(f"{api}/vfs", cookie, {"exports": []}).get("exports", [])
    backends = {item.get("backend") for item in exports}
    results.append(({"posix", "pblock"} <= backends,
                    "census lists posix + pblock exports"))
    return exports


def _export_index(exports, backend):
    return next((item.get("index") for item in exports
                 if item.get("backend") == backend), None)


def _check_posix_listing(api, cookie, export_index, results):
    if export_index is None:
        results.append((False, "posix export absent from census"))
        return
    listing = _json_body(
        f"{api}/vfs/files?export={export_index}&path=/", cookie, {}
    )
    entries = listing.get("entries", [])
    results.append((_valid_posix_entries(entries),
                    "posix export lists via VFS (size+kind)"))


def _valid_posix_entries(entries):
    hello = next((item for item in entries if item.get("name") == "hello.txt"), {})
    valid_file = hello.get("size") == 13 and hello.get("type") == "file"
    return valid_file and _has_directory(entries)


def _has_directory(entries):
    return any(item.get("type") == "dir" for item in entries)


def _check_pblock_listing(api, cookie, export_index, results):
    if export_index is None:
        results.append((False, "pblock export absent from census"))
        return
    text = curl_body(f"{api}/vfs/files?export={export_index}&path=/", cookie)
    entries = _decode_json(text).get("entries", [])
    logical = any(item.get("name") == "stored.bin" for item in entries)
    results.append((logical and "catalog.db" not in text,
                    "pblock export shows the LOGICAL namespace"))


def _decode_json(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _check_pblock_download(base, api, cookie, export_index, source, results):
    output = base / "pb_out.bin"
    download = subprocess.run(
        ["curl", "-s", "-H", f"Cookie: {cookie}",
         f"{api}/vfs/download?export={export_index}&path=/stored.bin",
         "-o", str(output)], capture_output=True, text=True,
    )
    valid = download.returncode == 0 and output.exists()
    valid = valid and output.read_bytes() == source.read_bytes()
    results.append((valid, "pblock download byte-exact through VFS"))


def _check_access_guards(api, cookie, export_index, off_port, results):
    files = f"{api}/vfs/files?export={export_index}&path=/"
    results.append((curl_code(files) == "401", "unauthenticated -> 401"))
    traversal = f"{api}/vfs/files?export={export_index}&path=/../../../etc"
    results.append((curl_code(traversal, cookie) == "400",
                    "traversal path rejected (400)"))
    disabled = f"http://{HOST}:{off_port}/brix/api/v1/vfs"
    results.append((curl_code(disabled, cookie) == "404", "feature off -> 404"))


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="dash_vfs.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    _print_results(results)
    return 0 if all(ok for ok, _ in results) else 1


def _print_results(results):
    for passed, message in results:
        label = "ok  " if passed else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
