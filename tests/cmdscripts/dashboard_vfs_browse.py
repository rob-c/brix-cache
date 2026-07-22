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
        cookie = dashboard_cookie()
        api = f"http://{HOST}:{dash_port}/brix/api/v1"
        pb_src = base / "pb_src.bin"
        pb_src.write_text("pblock payload bytes", encoding="utf-8")
        put = curl(["-s", "-o", "/dev/null", "-w", "%{http_code}", "-T", str(pb_src), f"http://{HOST}:{pblock_port}/stored.bin"]).stdout.strip()
        results.append((put in {"201", "204"}, f"pblock seeded via WebDAV PUT ({put})"))

        census_text = curl_body(f"{api}/vfs", cookie)
        try:
            census = json.loads(census_text)
        except json.JSONDecodeError:
            census = {"exports": []}
        exports = census.get("exports", [])
        results.append(
            (
                any(item.get("backend") == "posix" for item in exports)
                and any(item.get("backend") == "pblock" for item in exports),
                "census lists posix + pblock exports",
            )
        )
        posix_idx = next((item.get("index") for item in exports if item.get("backend") == "posix"), None)
        pblock_idx = next((item.get("index") for item in exports if item.get("backend") == "pblock"), None)

        posix_listing = json.loads(curl_body(f"{api}/vfs/files?export={posix_idx}&path=/", cookie)) if posix_idx is not None else {}
        entries = posix_listing.get("entries", [])
        hello = next((item for item in entries if item.get("name") == "hello.txt"), {})
        results.append(
            (
                hello.get("size") == 13
                and hello.get("type") == "file"
                and any(item.get("type") == "dir" for item in entries),
                "posix export lists via VFS (size+kind)",
            )
        )

        pblock_listing_text = curl_body(f"{api}/vfs/files?export={pblock_idx}&path=/", cookie) if pblock_idx is not None else ""
        try:
            pblock_listing = json.loads(pblock_listing_text)
        except json.JSONDecodeError:
            pblock_listing = {}
        pblock_entries = pblock_listing.get("entries", [])
        results.append(
            (
                any(item.get("name") == "stored.bin" for item in pblock_entries)
                and "catalog.db" not in pblock_listing_text,
                "pblock export shows the LOGICAL namespace",
            )
        )

        pb_out = base / "pb_out.bin"
        download = subprocess.run(
            [
                "curl",
                "-s",
                "-H",
                f"Cookie: {cookie}",
                f"{api}/vfs/download?export={pblock_idx}&path=/stored.bin",
                "-o",
                str(pb_out),
            ],
            capture_output=True,
            text=True,
        )
        results.append(
            (
                download.returncode == 0
                and pb_out.exists()
                and pb_out.read_bytes() == pb_src.read_bytes(),
                "pblock download byte-exact through VFS",
            )
        )

        results.append((curl_code(f"{api}/vfs/files?export={posix_idx}&path=/") == "401", "unauthenticated -> 401"))
        results.append((curl_code(f"{api}/vfs/files?export={posix_idx}&path=/../../../etc", cookie) == "400", "traversal path rejected (400)"))
        results.append((curl_code(f"http://{HOST}:{off_port}/brix/api/v1/vfs", cookie) == "404", "feature off -> 404"))
    finally:
        stop_nginx(base)

    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="dash_vfs.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
