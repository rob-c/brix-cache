"""WebDAV credential flow over a token-auth root:// origin."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import sys
import time

from cmdscripts import run
from settings import NGINX_BIN, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKE_TOKEN = REPO_ROOT / "utils" / "make_token.py"
CURL = "curl"


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def make_token(base: Path) -> tuple[bool, str]:
    tok = base / "tok"
    init = subprocess.run(
        [sys.executable, str(MAKE_TOKEN), "init", str(tok)],
        capture_output=True,
        text=True,
    )
    if init.returncode != 0:
        return False, "make_token.py init failed: " + (init.stderr or init.stdout)[-1000:]
    gen = subprocess.run(
        [
            sys.executable,
            str(MAKE_TOKEN),
            "gen",
            "--scope",
            "storage.read:/ storage.modify:/",
            "--output",
            str(base / "token.jwt"),
            str(tok),
        ],
        capture_output=True,
        text=True,
    )
    if gen.returncode != 0:
        return False, "make_token.py gen failed: " + (gen.stderr or gen.stdout)[-1000:]
    return True, ""


def write_origin_config(prefix: Path, port: int, token_dir: Path) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_export {root};
    brix_auth token; brix_token_jwks {token_dir / 'jwks.json'};
    brix_token_issuer https://test.example.com; brix_token_audience nginx-xrootd;
    brix_allow_write on;
}} }}
""",
        encoding="utf-8",
    )
    return conf


def write_webdav_config(prefix: Path, port: int, origin_port: int, token_file: Path | None) -> Path:
    export = prefix / "export"
    logs = prefix / "logs"
    export.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    credential_block = ""
    credential_ref = ""
    if token_file is not None:
        credential_block = f"    brix_credential origin {{ token_file {token_file}; }}\n"
        credential_ref = "            brix_storage_credential origin;\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
{credential_block}    server {{
        listen 127.0.0.1:{port};
        location / {{
            brix_webdav on; brix_export {export}; brix_webdav_auth none;
            brix_storage_backend root://127.0.0.1:{origin_port};
{credential_ref}        }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start_nginx(nginx_bin: str, prefix: Path, conf: Path) -> subprocess.CompletedProcess:
    return run([nginx_bin, "-p", str(prefix), "-c", str(conf)])


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def curl_get(port: int, path: str, dest: Path) -> tuple[str, bytes]:
    result = subprocess.run(
        [CURL, "-s", "-o", str(dest), "-w", "%{http_code}", f"http://127.0.0.1:{port}{path}"],
        capture_output=True,
        text=True,
    )
    body = dest.read_bytes() if dest.exists() else b""
    return result.stdout.strip(), body


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    token_ok, token_msg = make_token(base)
    if not token_ok:
        return [(False, "SKIP: " + token_msg)]

    origin_port, webdav_port, negative_port = free_ports(3)
    origin = base / "o"
    webdav = base / "w"
    negative = base / "n"
    token_dir = base / "tok"
    token_file = base / "token.jwt"

    origin_conf = write_origin_config(origin, origin_port, token_dir)
    webdav_conf = write_webdav_config(webdav, webdav_port, origin_port, token_file)
    negative_conf = write_webdav_config(negative, negative_port, origin_port, None)
    (origin / "root" / "a.bin").write_bytes(deterministic_bytes(250_000, 29))

    started: list[Path] = []
    for name, prefix, conf in (
        ("O", origin, origin_conf),
        ("W", webdav, webdav_conf),
        ("N", negative, negative_conf),
    ):
        proc = start_nginx(nginx_bin, prefix, conf)
        if proc.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(proc.stderr or proc.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        good_code, good_body = curl_get(webdav_port, "/a.bin", base / "cred_dav_a.got")
        expected = (origin / "root" / "a.bin").read_bytes()
        results = [
            (
                good_code == "200" and good_body == expected,
                f"GET byte-exact (ztn-authenticated via http-scope credential, code={good_code})",
            )
        ]

        bad_code, bad_body = curl_get(negative_port, "/a.bin", base / "cred_dav_n.got")
        unauth_succeeded = bad_code == "200" and bad_body == expected
        results.append((not unauth_succeeded, f"unauthenticated GET correctly failed (code={bad_code})"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_dav.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_webdav_xroot: ALL PASS")
        return 0
    print("run_credential_webdav_xroot: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
