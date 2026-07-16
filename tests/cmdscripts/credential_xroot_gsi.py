"""GSI credential flow for root:// cache fills."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from cmdscripts.credential_xroot_gsi_writeback import (
    ensure_pki,
    split_proxy,
    deterministic_bytes,
)
from settings import CA_CERT, CA_DIR, NGINX_BIN, SERVER_CERT, SERVER_KEY, TEST_ROOT, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDFS = REPO_ROOT / "client" / "bin" / "xrdfs"
PROXY_STD = Path(TEST_ROOT) / "pki" / "user" / "proxy_std.pem"


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


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


def write_proxy_node_config(prefix: Path, port: int, origin_port: int, ca_dir: Path | str) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential origin {{ x509_proxy {PROXY_STD}; ca_dir {ca_dir}; }}
    server {{
        listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_storage_backend root://127.0.0.1:{origin_port};
        brix_storage_credential origin;
        brix_cache on; brix_cache_export {cache};
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def write_cert_key_node_config(prefix: Path, port: int, origin_port: int, cert_part: Path, key_part: Path) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential origin {{ x509_cert {cert_part}; x509_key {key_part}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_storage_backend root://127.0.0.1:{origin_port};
        brix_storage_credential origin;
        brix_cache on; brix_cache_export {cache};
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def write_anonymous_node_config(prefix: Path, port: int, origin_port: int) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    logs = prefix / "logs"
    for path in (export, cache, logs):
        path.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
    brix_storage_backend root://127.0.0.1:{origin_port};
    brix_cache on; brix_cache_export {cache};
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


def same_bytes(path: Path, expected: bytes) -> bool:
    return path.exists() and path.read_bytes() == expected


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdfs: Path = XRDFS) -> list[tuple[bool, str]]:
    if not os.access(xrdfs, os.X_OK):
        return [(True, "SKIP native xrdfs not built")]
    pki_ok, pki_message = ensure_pki(base)
    if not pki_ok:
        return [(True, pki_message)]

    origin_port, proxy_port, anon_port, wrong_ca_port, cert_key_port = free_ports(5)
    origin = base / "o"
    proxy_node = base / "b"
    anon_node = base / "n"
    wrong_ca_node = base / "v"
    cert_key_node = base / "c"
    bad_ca = base / "badca"
    bad_ca.mkdir(parents=True, exist_ok=True)

    cert_key_node.mkdir(parents=True, exist_ok=True)
    cert_part = cert_key_node / "cert.pem"
    key_part = cert_key_node / "key.pem"
    split_ok, split_message = split_proxy(PROXY_STD, cert_part, key_part)
    if not split_ok:
        return [(False, split_message)]

    small = deterministic_bytes(500_000, 37)
    big = deterministic_bytes(2_600_000, 73)
    origin_conf = write_origin_config(origin, origin_port)
    (origin / "root" / "small.bin").write_bytes(small)
    (origin / "root" / "big.bin").write_bytes(big)
    configs = [
        ("origin", origin, origin_conf),
        ("proxy", proxy_node, write_proxy_node_config(proxy_node, proxy_port, origin_port, CA_DIR)),
        ("anonymous", anon_node, write_anonymous_node_config(anon_node, anon_port, origin_port)),
        ("wrong-ca", wrong_ca_node, write_proxy_node_config(wrong_ca_node, wrong_ca_port, origin_port, bad_ca)),
        ("cert-key", cert_key_node, write_cert_key_node_config(cert_key_node, cert_key_port, origin_port, cert_part, key_part)),
    ]

    started: list[Path] = []
    for name, prefix, conf in configs:
        proc = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if proc.returncode != 0:
            for item in reversed(started):
                stop_nginx(item)
            return [(False, f"{name} start failed: {(proc.stderr or proc.stdout)[-4000:]}")]
        started.append(prefix)

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        small_got = base / "cred_gsi_s.got"
        small_result = xrdfs_cat(proxy_port, "/small.bin", small_got, xrdfs)
        results.append(
            (
                small_result.returncode == 0 and same_bytes(small_got, small),
                "byte-exact serve (GSI-authenticated fill)",
            )
        )

        big_got = base / "cred_gsi_b.got"
        big_result = xrdfs_cat(proxy_port, "/big.bin", big_got, xrdfs)
        results.append(
            (
                big_result.returncode == 0 and same_bytes(big_got, big),
                "multi-chunk GSI-authenticated fill byte-exact",
            )
        )

        cert_key_got = base / "cred_gsi_c.got"
        cert_key_result = xrdfs_cat(cert_key_port, "/small.bin", cert_key_got, xrdfs)
        results.append(
            (
                cert_key_result.returncode == 0 and same_bytes(cert_key_got, small),
                "cert+key credential authenticated the GSI fill",
            )
        )

        anon_got = base / "cred_gsi_n.got"
        xrdfs_cat(anon_port, "/small.bin", anon_got, xrdfs)
        results.append((not same_bytes(anon_got, small), "unauthenticated fill correctly failed (origin required GSI)"))

        wrong_ca_got = base / "cred_gsi_v.got"
        xrdfs_cat(wrong_ca_port, "/small.bin", wrong_ca_got, xrdfs)
        results.append((not same_bytes(wrong_ca_got, small), "fill correctly refused (origin cert not verifiable against the wrong CA)"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_gsi.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_xroot_gsi: ALL PASS")
        return 0
    print("run_credential_xroot_gsi: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
