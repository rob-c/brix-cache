"""GSI credential flow for root:// write-back flushes."""

from __future__ import annotations

from pathlib import Path
import os
import re
import signal
import subprocess
import time

from cmdscripts import run
from cmdscripts.cache_source_helpers import start_servers, stop_servers
from cmdscripts.command_results import print_results, selected_binary
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, CA_CERT, CA_DIR, HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY, TEST_ROOT

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
    certificates = _pem_blocks(text, "CERTIFICATE")
    private_keys = _private_key_blocks(text)
    if not certificates or not private_keys:
        return False, "proxy did not contain both certificate and private key material"
    cert_part.write_text("\n".join(certificates) + "\n", encoding="utf-8")
    key_part.write_text("\n".join(private_keys) + "\n", encoding="utf-8")
    key_part.chmod(0o600)
    return True, ""


def _pem_blocks(text, label):
    pattern = rf"-----BEGIN {label}-----.*?-----END {label}-----"
    return re.findall(pattern, text, flags=re.DOTALL)


def _private_key_blocks(text):
    pattern = r"-----BEGIN ([^-\n]*PRIVATE KEY)-----.*?-----END \1-----"
    matches = re.finditer(pattern, text, flags=re.DOTALL)
    return [match.group(0) for match in matches]


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
        listen {BIND_HOST}:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_allow_write on;
        brix_storage_backend root://{HOST}:{origin_port};
{credential_ref}        brix_cache_store posix:{cache};
        brix_stage on; brix_stage_store posix:{staging}; brix_stage_flush async;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def xrdcp_put(port: int, source: Path, dest: str, xrdcp: Path = XRDCP) -> subprocess.CompletedProcess:
    return run([str(xrdcp), "-f", str(source), f"root://{HOST}:{port}//{dest}"])


def wait_for_bytes(path: Path, expected: bytes, attempts: int) -> bool:
    for _ in range(attempts):
        if path.exists() and path.read_bytes() == expected:
            return True
        time.sleep(0.5)
    return path.exists() and path.read_bytes() == expected


def _prepare_proxy(base, writer):
    pki_ok, pki_message = ensure_pki(base)
    if not pki_ok:
        return None, None, [(True, pki_message)]
    cert_part = writer / "cert.pem"
    key_part = writer / "key.pem"
    writer.mkdir(parents=True, exist_ok=True)
    split_ok, split_message = split_proxy(PROXY_STD, cert_part, key_part)
    if not split_ok:
        return None, None, [(False, split_message)]
    return cert_part, key_part, None


def _write_landed(port, payload, destination, expected, attempts, xrdcp):
    result = xrdcp_put(port, payload, destination.name, xrdcp)
    if result.returncode != 0:
        return False
    return wait_for_bytes(destination, expected, attempts=attempts)


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdcp: Path = XRDCP) -> list[tuple[bool, str]]:
    if not os.access(xrdcp, os.X_OK):
        return [(True, "SKIP native xrdcp not built")]

    origin_port, write_port, negative_port = cmdscript_ports("credential_xroot_gsi_writeback")
    origin = base / "o"
    writer = base / "w"
    negative = base / "n"
    cert_part, key_part, preparation_failure = _prepare_proxy(base, writer)
    if preparation_failure:
        return preparation_failure

    origin_conf = write_origin_config(origin, origin_port)
    writer_conf = write_node_config(writer, write_port, origin_port, cert_part, key_part)
    negative_conf = write_node_config(negative, negative_port, origin_port, None, None)

    payload = base / "cred_gsi_wb_src.bin"
    payload_bytes = deterministic_bytes(400_000, 149)
    payload.write_bytes(payload_bytes)

    specifications = (
        ("origin", origin, origin_conf),
        ("writer", writer, writer_conf),
        ("negative", negative, negative_conf),
    )
    started, failure = start_servers(nginx_bin, specifications, run, stop_nginx)
    if failure:
        return [failure]

    try:
        time.sleep(1)
        results: list[tuple[bool, str]] = []
        landed = _write_landed(
            write_port, payload, origin / "root" / "wb.bin",
            payload_bytes, 20, xrdcp,
        )
        results.append((landed, "flush authenticated + wrote through to the GSI origin byte-exact"))

        xrdcp_put(negative_port, payload, "nb.bin", xrdcp)
        nlanded = wait_for_bytes(origin / "root" / "nb.bin", payload_bytes, attempts=10)
        results.append((not nlanded, "anonymous flush correctly rejected by the GSI origin"))
        return results
    finally:
        stop_servers(started, stop_nginx)


def entry(argv: list[str]) -> int:
    nginx_bin = selected_binary(argv, NGINX_BIN)
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_gsi_wb.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    return print_results(results, "run_credential_xroot_gsi_writeback")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
