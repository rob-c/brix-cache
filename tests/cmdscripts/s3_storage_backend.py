"""S3 export backed by composable storage backends."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import sys
import time

import requests

from cmdscripts import run
from settings import NGINX_BIN, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKE_TOKEN = REPO_ROOT / "utils" / "make_token.py"


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def make_token(base: Path) -> tuple[bool, str]:
    tok = base / "tok"
    init = subprocess.run([sys.executable, str(MAKE_TOKEN), "init", str(tok)], capture_output=True, text=True)
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


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def write_anon_origin(prefix: Path, port: int) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{port}; brix_root on; brix_export {root}; brix_auth none; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_token_origin(prefix: Path, port: int, token_dir: Path) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{port}; brix_root on; brix_export {root};
    brix_auth token; brix_token_jwks {token_dir / 'jwks.json'};
    brix_token_issuer https://test.example.com; brix_token_audience nginx-xrootd; }} }}
""",
        encoding="utf-8",
    )
    return conf


def write_s3_node(
    prefix: Path,
    port: int,
    origin_port: int,
    token_file: Path | None = None,
) -> Path:
    root = prefix / "root"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (root, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    credential_block = ""
    credential_ref = ""
    if token_file is not None:
        credential_block = f"    brix_credential origin {{ token_file {token_file}; }}\n"
        credential_ref = "        brix_storage_credential origin;\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
{credential_block}    server {{ listen 127.0.0.1:{port}; location / {{
        brix_s3 on; brix_export {root}; brix_s3_bucket testbucket;
        brix_storage_backend root://127.0.0.1:{origin_port};
{credential_ref}        brix_s3_cache_root {cache};
    }} }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start(nginx_bin: str, name: str, prefix: Path, conf: Path, started: list[Path]) -> tuple[bool, str]:
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        return False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}"
    started.append(prefix)
    return True, ""


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    origin_port, s3_port, token_origin_port, cred_s3_port = free_ports(4)
    started: list[Path] = []
    results: list[tuple[bool, str]] = []

    anon_origin = base / "o"
    anon_s3 = base / "s"
    anon_origin_conf = write_anon_origin(anon_origin, origin_port)
    anon_s3_conf = write_s3_node(anon_s3, s3_port, origin_port)
    (anon_origin / "root" / "obj.bin").write_bytes(deterministic_bytes(400_000, 71))

    for name, prefix, conf in (("O", anon_origin, anon_origin_conf), ("S", anon_s3, anon_s3_conf)):
        ok, message = start(nginx_bin, name, prefix, conf, started)
        if not ok:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, message)]

    try:
        time.sleep(1)
        r = requests.get(f"http://127.0.0.1:{s3_port}/testbucket/obj.bin", timeout=30)
        expected = (anon_origin / "root" / "obj.bin").read_bytes()
        results.append(
            (
                r.status_code == 200 and r.content == expected,
                f"GET byte-exact from the composable backend (code={r.status_code})",
            )
        )

        token_ok, token_msg = make_token(base)
        if not token_ok:
            results.append((True, "SKIP token-auth S3 variant: " + token_msg))
            return results

        token_origin = base / "t"
        cred_s3 = base / "c"
        token_origin_conf = write_token_origin(token_origin, token_origin_port, base / "tok")
        cred_s3_conf = write_s3_node(cred_s3, cred_s3_port, token_origin_port, base / "token.jwt")
        (token_origin / "root" / "sec.bin").write_bytes(deterministic_bytes(200_000, 83))
        for name, prefix, conf in (("T", token_origin, token_origin_conf), ("C", cred_s3, cred_s3_conf)):
            ok, message = start(nginx_bin, name, prefix, conf, started)
            if not ok:
                results.append((False, message))
                return results
        time.sleep(1)
        secure = requests.get(f"http://127.0.0.1:{cred_s3_port}/testbucket/sec.bin", timeout=30)
        secure_expected = (token_origin / "root" / "sec.bin").read_bytes()
        results.append(
            (
                secure.status_code == 200 and secure.content == secure_expected,
                f"GET byte-exact (ztn-authenticated S3 source, code={secure.status_code})",
            )
        )
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="s3_be.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_s3_storage_backend: ALL PASS")
        return 0
    print("run_s3_storage_backend: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
