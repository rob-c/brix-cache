"""Bearer credential flow for the sd_http source driver."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from settings import NGINX_BIN, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"
TOKEN = "s3cr3t-bearer-tok-42"


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def write_origin_config(prefix: Path, port: int, token: str = TOKEN) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{port};
        location / {{
            if ($http_authorization != "Bearer {token}") {{ return 401; }}
            root {root};
        }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def write_node_config(
    prefix: Path,
    port: int,
    origin_port: int,
    credential: str | None,
) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    credential_block = ""
    credential_ref = ""
    if credential is not None:
        credential_block = f"    brix_credential web {{ {credential}; }}\n"
        credential_ref = "        brix_storage_credential web;\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
{credential_block}    server {{
        listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_storage_backend http://127.0.0.1:{origin_port};
{credential_ref}        brix_cache on; brix_cache_export {cache};
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start_nginx(nginx_bin: str, prefix: Path, conf: Path) -> subprocess.CompletedProcess:
    return run([nginx_bin, "-p", str(prefix), "-c", str(conf)])


def stop_nginx(prefix: Path) -> None:
    pidfile = prefix / "nginx.pid"
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def xrdfs_cat(port: int, path: str, dest: Path, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    with dest.open("wb") as out:
        return subprocess.run(
            [str(xrdfs), f"root://127.0.0.1:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
            text=False,
        )


def client_detail(result: subprocess.CompletedProcess) -> str:
    stderr = result.stderr.decode("utf-8", "replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
    return stderr.strip().splitlines()[-1] if stderr.strip() else f"rc={result.returncode}"


def run_checks(
    base: Path,
    nginx_bin: str = NGINX_BIN,
    xrdfs: Path = XRDFS,
) -> list[tuple[bool, str]]:
    origin_port, bearer_port, negative_port = free_ports(3)
    origin = base / "o"
    bearer = base / "b"
    negative = base / "n"
    token_file = base / "token_file"
    token_file.write_text(TOKEN, encoding="utf-8")
    results: list[tuple[bool, str]] = []

    origin_conf = write_origin_config(origin, origin_port)
    bearer_conf = write_node_config(bearer, bearer_port, origin_port, f"token {TOKEN}")
    negative_conf = write_node_config(negative, negative_port, origin_port, None)
    (origin / "root" / "small.bin").write_bytes(deterministic_bytes(500_000, 11))
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_600_000, 19))

    started: list[Path] = []
    for name, prefix, conf in (
        ("O", origin, origin_conf),
        ("B", bearer, bearer_conf),
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
        small_got = base / "cred_http_s.got"
        small = xrdfs_cat(bearer_port, "/small.bin", small_got, xrdfs)
        results.append(
            (
                small.returncode == 0
                and small_got.read_bytes() == (origin / "root" / "small.bin").read_bytes(),
                "byte-exact serve (authenticated fill)"
                if small.returncode == 0
                else f"byte-exact serve (authenticated fill): {client_detail(small)}",
            )
        )

        big_got = base / "cred_http_b.got"
        big = xrdfs_cat(bearer_port, "/big.bin", big_got, xrdfs)
        results.append(
            (
                big.returncode == 0
                and big_got.read_bytes() == (origin / "root" / "big.bin").read_bytes(),
                "multi-chunk authenticated fill byte-exact"
                if big.returncode == 0
                else f"multi-chunk authenticated fill byte-exact: {client_detail(big)}",
            )
        )

        negative_got = base / "cred_http_n.got"
        xrdfs_cat(negative_port, "/small.bin", negative_got, xrdfs)
        unauth_succeeded = (
            negative_got.exists()
            and negative_got.stat().st_size > 0
            and negative_got.read_bytes() == (origin / "root" / "small.bin").read_bytes()
        )
        results.append((not unauth_succeeded, "unauthenticated fill correctly failed"))

        stop_nginx(bearer)
        started.remove(bearer)
        time.sleep(0.3)
        bearer_token_file_conf = write_node_config(
            bearer,
            bearer_port,
            origin_port,
            f"token_file {token_file}",
        )
        proc = start_nginx(nginx_bin, bearer, bearer_token_file_conf)
        if proc.returncode != 0:
            results.append((False, f"B(token_file) start failed: {(proc.stderr or proc.stdout)[-4000:]}"))
        else:
            started.append(bearer)
            time.sleep(1)
            token_file_got = base / "cred_http_tf.got"
            token_file_read = xrdfs_cat(bearer_port, "/small.bin", token_file_got, xrdfs)
            results.append(
                (
                    token_file_read.returncode == 0
                    and token_file_got.read_bytes() == (origin / "root" / "small.bin").read_bytes(),
                    "token_file credential authenticated fill byte-exact"
                    if token_file_read.returncode == 0
                    else f"token_file credential authenticated fill byte-exact: {client_detail(token_file_read)}",
                )
            )
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)

    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_http.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_http_bearer: ALL PASS")
        return 0
    print("run_credential_http_bearer: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
