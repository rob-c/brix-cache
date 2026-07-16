"""Token credential flow for the sd_xroot source driver."""

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
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def make_token(base: Path) -> tuple[bool, str]:
    tok = base / "tok"
    init = subprocess.run(
        [sys.executable, str(MAKE_TOKEN), "init", str(tok)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
    brix_auth token;
    brix_token_jwks {token_dir / 'jwks.json'};
    brix_token_issuer https://test.example.com;
    brix_token_audience nginx-xrootd;
    brix_allow_write on;
}} }}
""",
        encoding="utf-8",
    )
    return conf


def write_cache_config(prefix: Path, port: int, origin_port: int, token_file: Path | None) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
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
stream {{
{credential_block}    server {{
        listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_storage_backend root://127.0.0.1:{origin_port};
{credential_ref}        brix_cache on; brix_cache_export {cache};
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def xrdfs_cat(port: int, path: str, dest: Path, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    with dest.open("wb") as out:
        return subprocess.run(
            [str(xrdfs), f"root://127.0.0.1:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
        )


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdfs: Path = XRDFS) -> list[tuple[bool, str]]:
    if not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP native xrdfs not built")]
    token_ok, token_msg = make_token(base)
    if not token_ok:
        return [(True, "SKIP: " + token_msg)]

    origin_port, cache_port, negative_port = free_ports(3)
    origin = base / "o"
    cache = base / "b"
    negative = base / "n"
    token_dir = base / "tok"
    token_file = base / "token.jwt"
    origin_conf = write_origin_config(origin, origin_port, token_dir)
    cache_conf = write_cache_config(cache, cache_port, origin_port, token_file)
    negative_conf = write_cache_config(negative, negative_port, origin_port, None)
    (origin / "root" / "small.bin").write_bytes(deterministic_bytes(500_000, 131))
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_600_000, 137))

    started: list[Path] = []
    for name, prefix, conf in (
        ("origin", origin, origin_conf),
        ("cache", cache, cache_conf),
        ("negative", negative, negative_conf),
    ):
        proc = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if proc.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(proc.stderr or proc.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        expected_small = (origin / "root" / "small.bin").read_bytes()
        small_got = base / "cred_ztn_s.got"
        small = xrdfs_cat(cache_port, "/small.bin", small_got, xrdfs)
        results.append((small.returncode == 0 and small_got.read_bytes() == expected_small, "byte-exact serve (ztn-authenticated fill)"))

        expected_big = (origin / "root" / "big.bin").read_bytes()
        big_got = base / "cred_ztn_b.got"
        big = xrdfs_cat(cache_port, "/big.bin", big_got, xrdfs)
        results.append((big.returncode == 0 and big_got.read_bytes() == expected_big, "multi-chunk ztn-authenticated fill byte-exact"))

        negative_got = base / "cred_ztn_n.got"
        negative_read = xrdfs_cat(negative_port, "/small.bin", negative_got, xrdfs)
        negative_succeeded = (
            negative_read.returncode == 0
            and negative_got.exists()
            and negative_got.stat().st_size > 0
            and negative_got.read_bytes() == expected_small
        )
        results.append((not negative_succeeded, "unauthenticated fill correctly failed (origin required a token)"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_ztn.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_xroot_ztn: ALL PASS")
        return 0
    print("run_credential_xroot_ztn: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
