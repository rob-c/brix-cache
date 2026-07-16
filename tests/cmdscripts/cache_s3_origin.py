"""Read cache with an S3 source backend."""

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
AKID = "AKIDTEST"
SECRET = "SECRETTESTKEY0123456789"


def deterministic_bytes(size: int, seed: int) -> bytes:
    return bytes((seed + i) % 251 for i in range(size))


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def write_config(prefix: Path, s3_port: int, node_port: int) -> Path:
    s3root = prefix / "s3root"
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (s3root, export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}

http {{
    server {{
        listen 127.0.0.1:{s3_port};
        location / {{
            brix_s3 on;
            brix_export {s3root};
            brix_s3_bucket testbucket;
            brix_s3_access_key {AKID};
            brix_s3_secret_key {SECRET};
            brix_s3_region us-east-1;
            brix_allow_write on;
        }}
    }}
}}

stream {{
    brix_credential s3origin {{
        s3_access_key {AKID};
        s3_secret_key {SECRET};
        s3_region us-east-1;
    }}
    server {{
        listen 127.0.0.1:{node_port};
        brix_root on;
        brix_export {export};
        brix_auth none;
        brix_storage_backend s3://127.0.0.1:{s3_port}/testbucket;
        brix_storage_credential s3origin;
        brix_cache_store posix:{cache};
        brix_cache_export /;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def xrdfs_cat(port: int, path: str, dest: Path | None = None, xrdfs: Path = XRDFS) -> subprocess.CompletedProcess:
    cmd = [str(xrdfs), f"root://127.0.0.1:{port}", "cat", path]
    try:
        if dest is None:
            return subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        with dest.open("wb") as out:
            return subprocess.run(
                cmd,
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=60,
            )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, stdout=b"", stderr=b"xrdfs cat timed out after 60s")


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdfs: Path = XRDFS) -> list[tuple[bool, str]]:
    if not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP cache S3 origin data plane (native xrdfs not built)")]

    s3_port, node_port = free_ports(2)
    conf = write_config(base, s3_port, node_port)
    (base / "s3root" / "hello.bin").write_bytes(deterministic_bytes(700_000, 41))

    result = run([nginx_bin, "-p", str(base), "-c", str(conf)])
    if result.returncode != 0:
        return [(False, f"nginx start failed: {(result.stderr or result.stdout)[-4000:]}")]

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        expected_hello = (base / "s3root" / "hello.bin").read_bytes()

        cold_got = base / "cache_s3_1.got"
        cold = xrdfs_cat(node_port, "/hello.bin", cold_got, xrdfs)
        results.append((cold.returncode == 0 and cold_got.read_bytes() == expected_hello, "S3 origin fill byte-exact"))
        results.append(((base / "cache" / "hello.bin").exists(), "object landed in the local cache"))

        warm_got = base / "cache_s3_2.got"
        warm = xrdfs_cat(node_port, "/hello.bin", warm_got, xrdfs)
        results.append((warm.returncode == 0 and warm_got.read_bytes() == expected_hello, "warm cache hit byte-exact"))

        (base / "s3root" / "big.bin").write_bytes(deterministic_bytes(2_750_000, 43))
        big_got = base / "cache_s3_big.got"
        big = xrdfs_cat(node_port, "/big.bin", big_got, xrdfs)
        expected_big = (base / "s3root" / "big.bin").read_bytes()
        results.append((big.returncode == 0 and big_got.read_bytes() == expected_big, "multi-chunk S3 fill byte-exact"))

        missing = xrdfs_cat(node_port, "/nope.bin", None, xrdfs)
        missing_err = missing.stderr.decode("utf-8", errors="replace").lower()
        results.append(
            (
                missing.returncode != 0
                and any(token in missing_err for token in ("not found", "notfound", "no such", "3011", "error")),
                "missing object reported as error",
            )
        )
        return results
    finally:
        stop_nginx(base)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cache_s3.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_s3_origin: ALL PASS")
        return 0
    print("run_cache_s3_origin: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
