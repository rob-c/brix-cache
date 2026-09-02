"""Sliced cache fills through a GSI-authenticated origin credential."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess

from cmdscripts import run
from cmdscripts.cache_source_helpers import (start_servers, stop_servers,
                                             wait_workers_ready)
from cmdscripts.command_results import print_results, selected_binary
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, CA_CERT, CA_DIR, HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY, TEST_ROOT

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
    # Refresh only the proxy when the CA/hostcert already exist — a full
    # blitz_test_pki() would regenerate the CA and desync the standing fleet,
    # failing every concurrent TLS/GSI test. See live_common.refresh_shared_pki.
    from cmdscripts.live_common import refresh_shared_pki  # noqa: PLC0415
    ok, msg = refresh_shared_pki(base)
    return ok, ("SKIP: " + msg if not ok else "")


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
    listen {BIND_HOST}:{port}; brix_root on; brix_export {root};
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
    listen {BIND_HOST}:{port}; brix_root on; brix_export {export}; brix_auth none;
    brix_storage_backend root://{HOST}:{origin_port};
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
            [str(xrdfs), f"root://{HOST}:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
        )


def _read_exact(port, destination, expected, xrdfs):
    result = xrdfs_cat(port, "/big.bin", destination, xrdfs)
    if result.returncode != 0:
        return False
    return destination.read_bytes() == expected


def _negative_succeeded(port, destination, expected, xrdfs):
    result = xrdfs_cat(port, "/big.bin", destination, xrdfs)
    if result.returncode != 0:
        return False
    if not destination.exists():
        return False
    if destination.stat().st_size <= 0:
        return False
    return destination.read_bytes() == expected


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdfs: Path = XRDFS) -> list[tuple[bool, str]]:
    if not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP native xrdfs not built")]
    pki_ok, pki_message = ensure_pki(base)
    if not pki_ok:
        return [(True, pki_message)]

    origin_port, cache_port, negative_port = cmdscript_ports("cache_slice_gsi_legacy")
    origin = base / "o"
    cache = base / "b"
    negative = base / "n"
    origin_conf = write_origin_config(origin, origin_port)
    cache_conf = write_cache_config(cache, cache_port, origin_port, with_credential=True)
    negative_conf = write_cache_config(negative, negative_port, origin_port, with_credential=False)
    (origin / "root" / "big.bin").write_bytes(deterministic_bytes(2_600_000, 127))

    specifications = (
        ("origin", origin, origin_conf),
        ("cache", cache, cache_conf),
        ("negative", negative, negative_conf),
    )
    started, failure = start_servers(nginx_bin, specifications, run, stop_nginx)
    if failure:
        return [failure]

    try:
        wait_workers_ready(HOST, [(origin_port, "root"), (cache_port, "root"),
                                  (negative_port, "root")])
        expected = (origin / "root" / "big.bin").read_bytes()
        good_got = base / "slice_gsi_b.got"
        results = [
            (
                _read_exact(cache_port, good_got, expected, xrdfs),
                "multi-slice GSI-authenticated fill byte-exact",
            )
        ]

        warm_got = base / "slice_gsi_b2.got"
        warm_ok = _read_exact(cache_port, warm_got, expected, xrdfs)
        results.append((warm_ok, "warm multi-slice byte-exact"))

        negative_got = base / "slice_gsi_n.got"
        negative_succeeded = _negative_succeeded(
            negative_port, negative_got, expected, xrdfs,
        )
        results.append((not negative_succeeded, "unauthenticated slice fill correctly failed (origin required GSI)"))
        return results
    finally:
        stop_servers(started, stop_nginx)


def entry(argv: list[str]) -> int:
    nginx_bin = selected_binary(argv, NGINX_BIN)
    import tempfile

    with tempfile.TemporaryDirectory(prefix="slice_gsi.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    return print_results(results, "run_cache_slice_gsi_legacy")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
