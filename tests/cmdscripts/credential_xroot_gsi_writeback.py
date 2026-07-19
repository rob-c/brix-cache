"""GSI credential flow for root:// write-back flushes."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from settings import CA_CERT, CA_DIR, NGINX_BIN, SERVER_CERT, SERVER_KEY, TEST_ROOT, free_ports

REPO_ROOT = Path(__file__).resolve().parents[2]
XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"
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


def split_proxy(proxy: Path, cert_part: Path, key_part: Path) -> tuple[bool, str]:
    text = proxy.read_text(encoding="utf-8")
    cert_lines: list[str] = []
    key_lines: list[str] = []
    in_cert = False
    in_key = False
    for line in text.splitlines():
        if line == "-----BEGIN CERTIFICATE-----":
            in_cert = True
        if in_cert:
            cert_lines.append(line)
        if line == "-----END CERTIFICATE-----":
            in_cert = False
        if line.startswith("-----BEGIN") and line.endswith("PRIVATE KEY-----"):
            in_key = True
        if in_key:
            key_lines.append(line)
        if line.startswith("-----END") and line.endswith("PRIVATE KEY-----"):
            in_key = False
    if not cert_lines or not key_lines:
        return False, "proxy did not contain both certificate and private key material"
    cert_part.write_text("\n".join(cert_lines) + "\n", encoding="utf-8")
    key_part.write_text("\n".join(key_lines) + "\n", encoding="utf-8")
    key_part.chmod(0o600)
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


def write_node_config(
    prefix: Path,
    port: int,
    origin_port: int,
    cert_part: Path | None,
    key_part: Path | None,
) -> Path:
    export = prefix / "export"
    cache = prefix / "cache"
    staging = prefix / "staging"
    logs = prefix / "logs"
    for path in (export, cache, staging, logs):
        path.mkdir(parents=True, exist_ok=True)
    credential_block = ""
    credential_ref = ""
    if cert_part is not None and key_part is not None:
        credential_block = f"    brix_credential origin {{ x509_cert {cert_part}; x509_key {key_part}; ca_dir {CA_DIR}; }}\n"
        credential_ref = "        brix_storage_credential origin;\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
{credential_block}    server {{
        listen 127.0.0.1:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_allow_write on;
        brix_storage_backend root://127.0.0.1:{origin_port};
{credential_ref}        brix_cache_store posix:{cache};
        brix_stage on; brix_stage_store posix:{staging}; brix_stage_flush async;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def xrdcp_put(port: int, source: Path, dest: str, xrdcp: Path = XRDCP) -> subprocess.CompletedProcess:
    return run([str(xrdcp), "-f", str(source), f"root://127.0.0.1:{port}//{dest}"])


def wait_for_bytes(path: Path, expected: bytes, attempts: int) -> bool:
    for _ in range(attempts):
        if path.exists() and path.read_bytes() == expected:
            return True
        time.sleep(0.5)
    return path.exists() and path.read_bytes() == expected


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdcp: Path = XRDCP) -> list[tuple[bool, str]]:
    if not os.access(xrdcp, os.X_OK):
        return [(True, "SKIP native xrdcp not built")]
    pki_ok, pki_message = ensure_pki(base)
    if not pki_ok:
        return [(True, pki_message)]

    origin_port, write_port, negative_port = free_ports(3)
    origin = base / "o"
    writer = base / "w"
    negative = base / "n"
    cert_part = writer / "cert.pem"
    key_part = writer / "key.pem"
    writer.mkdir(parents=True, exist_ok=True)
    split_ok, split_message = split_proxy(PROXY_STD, cert_part, key_part)
    if not split_ok:
        return [(False, split_message)]

    origin_conf = write_origin_config(origin, origin_port)
    writer_conf = write_node_config(writer, write_port, origin_port, cert_part, key_part)
    negative_conf = write_node_config(negative, negative_port, origin_port, None, None)

    payload = base / "cred_gsi_wb_src.bin"
    payload_bytes = deterministic_bytes(400_000, 149)
    payload.write_bytes(payload_bytes)

    started: list[Path] = []
    for name, prefix, conf in (
        ("origin", origin, origin_conf),
        ("writer", writer, writer_conf),
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
        put = xrdcp_put(write_port, payload, "wb.bin", xrdcp)
        landed = put.returncode == 0 and wait_for_bytes(origin / "root" / "wb.bin", payload_bytes, attempts=20)
        results.append((landed, "flush authenticated + wrote through to the GSI origin byte-exact"))

        xrdcp_put(negative_port, payload, "nb.bin", xrdcp)
        nlanded = wait_for_bytes(origin / "root" / "nb.bin", payload_bytes, attempts=10)
        results.append((not nlanded, "anonymous flush correctly rejected by the GSI origin"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_gsi_wb.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_xroot_gsi_writeback: ALL PASS")
        return 0
    print("run_credential_xroot_gsi_writeback: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
