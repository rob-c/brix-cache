"""Sliced cache fills through a GSI-authenticated origin credential."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from settings import CA_CERT, CA_DIR, NGINX_BIN, SERVER_CERT, SERVER_KEY, TEST_ROOT, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"
PROXY_STD = Path(TEST_ROOT) / "pki" / "user" / "proxy_std.pem"


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


def proxy_is_fresh(proxy: Path) -> bool:
    if not proxy.is_file():
        return False
    result = run(["openssl", "x509", "-in", str(proxy), "-noout", "-checkend", "300"])
    return result.returncode == 0


def ensure_pki(base: Path) -> tuple[bool, str]:
    required = [Path(CA_CERT), Path(SERVER_CERT), PROXY_STD]
    if all(path.is_file() for path in required) and proxy_is_fresh(PROXY_STD):
        return True, ""
    pki_log = base / "pki.log"
    result = subprocess.run(
        ["python3", "-c", "import pki_helpers; pki_helpers.blitz_test_pki()"],
        cwd=REPO_ROOT / "tests",
        env={**os.environ, "PYTHONPATH": "."},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    pki_log.write_text(result.stdout or "", encoding="utf-8")
    if result.returncode != 0:
        return False, "SKIP: PKI provisioning failed: " + (result.stdout or "")[-1000:]
    return True, ""


def write_origin_config(prefix: Path, port: int) -> Path:
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
    brix_auth gsi;
    brix_certificate {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca {CA_CERT};
    brix_allow_write on;
}} }}
""",
        encoding="utf-8",
    )
    return conf


def write_cache_config(prefix: Path, port: int, origin_port: int, with_credential: bool) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    credential_block = ""
    credential_ref = ""
    if with_credential:
        credential_block = f"    brix_credential origin {{ x509_proxy {PROXY_STD}; ca_dir {CA_DIR}; }}\n"
        credential_ref = "    brix_storage_credential origin;\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
{credential_block}    server {{
    listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
    brix_storage_backend root://127.0.0.1:{origin_port};
{credential_ref}    brix_cache_store posix:{cache}; brix_cache_export /;
    brix_cache_slice_size 1m;
}} }}
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
    pki_ok, pki_message = ensure_pki(base)
    if not pki_ok:
        return [(True, pki_message)]

    origin_port, cache_port, negative_port = free_ports(3)
    origin = base / "o"
    cache = base / "b"
    negative = base / "n"
    origin_conf = write_origin_config(origin, origin_port)
    cache_conf = write_cache_config(cache, cache_port, origin_port, with_credential=True)
    negative_conf = write_cache_config(negative, negative_port, origin_port, with_credential=False)
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_600_000, 127))

    started: list[Path] = []
    for name, prefix, conf in (
        ("origin", origin, origin_conf),
        ("cache", cache, cache_conf),
        ("negative", negative, negative_conf),
    ):
        result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if result.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(result.stderr or result.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        expected = (origin / "root" / "big.bin").read_bytes()
        good_got = base / "slice_gsi_b.got"
        good = xrdfs_cat(cache_port, "/big.bin", good_got, xrdfs)
        results = [
            (
                good.returncode == 0 and good_got.read_bytes() == expected,
                "multi-slice GSI-authenticated fill byte-exact",
            )
        ]

        warm_got = base / "slice_gsi_b2.got"
        warm = xrdfs_cat(cache_port, "/big.bin", warm_got, xrdfs)
        results.append((warm.returncode == 0 and warm_got.read_bytes() == expected, "warm multi-slice byte-exact"))

        negative_got = base / "slice_gsi_n.got"
        negative_result = xrdfs_cat(negative_port, "/big.bin", negative_got, xrdfs)
        negative_succeeded = (
            negative_result.returncode == 0
            and negative_got.exists()
            and negative_got.stat().st_size > 0
            and negative_got.read_bytes() == expected
        )
        results.append((not negative_succeeded, "unauthenticated slice fill correctly failed (origin required GSI)"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="slice_gsi.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_slice_gsi_legacy: ALL PASS")
        return 0
    print("run_cache_slice_gsi_legacy: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
