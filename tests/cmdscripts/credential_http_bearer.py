"""Bearer credential flow for the sd_http source driver."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import subprocess
import time

from cmdscripts import run
from cmdscripts.cache_source_helpers import start_servers, stop_servers
from cmdscripts.command_results import print_results, selected_binary
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

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
        listen {BIND_HOST}:{port};
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
        listen {BIND_HOST}:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_storage_backend http://{HOST}:{origin_port};
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
            [str(xrdfs), f"root://{HOST}:{port}", "cat", path],
            stdout=out,
            stderr=subprocess.PIPE,
            text=False,
        )


def client_detail(result: subprocess.CompletedProcess) -> str:
    stderr = result.stderr.decode("utf-8", "replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
    return stderr.strip().splitlines()[-1] if stderr.strip() else f"rc={result.returncode}"


def _transfer_check(port, source, destination, expected, label, xrdfs):
    result = xrdfs_cat(port, source, destination, xrdfs)
    passed = _successful_content(result, destination, expected)
    message = label if result.returncode == 0 else f"{label}: {client_detail(result)}"
    return passed, message


def _successful_content(result, destination, expected):
    if result.returncode != 0:
        return False
    return destination.read_bytes() == expected


def _unauthenticated_fill_succeeded(port, destination, expected, xrdfs):
    xrdfs_cat(port, "/small.bin", destination, xrdfs)
    if not destination.exists():
        return False
    if destination.stat().st_size <= 0:
        return False
    return destination.read_bytes() == expected


def _token_file_check(base, nginx_bin, bearer, port, origin_port,
                      token_file, started, expected, xrdfs):
    stop_nginx(bearer)
    started.remove(bearer)
    time.sleep(0.3)
    config = write_node_config(bearer, port, origin_port, f"token_file {token_file}")
    process = start_nginx(nginx_bin, bearer, config)
    if process.returncode != 0:
        output = process.stderr or process.stdout
        return False, f"B(token_file) start failed: {output[-4000:]}"
    started.append(bearer)
    time.sleep(1)
    return _transfer_check(
        port, "/small.bin", base / "cred_http_tf.got", expected,
        "token_file credential authenticated fill byte-exact", xrdfs,
    )


def run_checks(
    base: Path,
    nginx_bin: str = NGINX_BIN,
    xrdfs: Path = XRDFS,
) -> list[tuple[bool, str]]:
    origin_port, bearer_port, negative_port = cmdscript_ports("credential_http_bearer")
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

    specifications = (
        ("O", origin, origin_conf),
        ("B", bearer, bearer_conf),
        ("N", negative, negative_conf),
    )
    started, failure = start_servers(nginx_bin, specifications, run, stop_nginx)
    if failure:
        return [failure]

    try:
        time.sleep(1)
        expected_small = (origin / "root" / "small.bin").read_bytes()
        expected_big = (origin / "root" / "big.bin").read_bytes()
        results.append(_transfer_check(
            bearer_port, "/small.bin", base / "cred_http_s.got",
            expected_small, "byte-exact serve (authenticated fill)", xrdfs,
        ))
        results.append(_transfer_check(
            bearer_port, "/big.bin", base / "cred_http_b.got", expected_big,
            "multi-chunk authenticated fill byte-exact", xrdfs,
        ))
        unauth_succeeded = _unauthenticated_fill_succeeded(
            negative_port, base / "cred_http_n.got", expected_small, xrdfs,
        )
        results.append((not unauth_succeeded, "unauthenticated fill correctly failed"))
        results.append(_token_file_check(
            base, nginx_bin, bearer, bearer_port, origin_port, token_file,
            started, expected_small, xrdfs,
        ))
    finally:
        stop_servers(started, stop_nginx)

    return results


def entry(argv: list[str]) -> int:
    nginx_bin = selected_binary(argv, NGINX_BIN)
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_http.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    return print_results(results, "run_credential_http_bearer")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
