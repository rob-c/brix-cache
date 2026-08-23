"""Token credential flow for root:// write-through flushes."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import socket
import subprocess
import sys
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST, NGINX_BIN

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKE_TOKEN = REPO_ROOT / "utils" / "make_token.py"
XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"


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
            "storage.read:/ storage.modify:/ storage.create:/",
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
    listen {BIND_HOST}:{port}; brix_root on; brix_export {root};
    brix_auth token; brix_token_jwks {token_dir / 'jwks.json'};
    brix_token_issuer https://test.example.com; brix_token_audience nginx-xrootd;
    brix_allow_write on; brix_upload_resume off;
}} }}
""",
        encoding="utf-8",
    )
    return conf


def write_node_config(prefix: Path, port: int, origin_port: int, token_file: Path | None) -> Path:
    export = prefix / "export"
    logs = prefix / "logs"
    export.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    credential_block = ""
    credential_ref = ""
    if token_file is not None:
        credential_block = f"    brix_credential origin {{ token_file {token_file}; }}\n"
        credential_ref = "        brix_wt_credential origin;\n"
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on; error_log {logs / 'e.log'} info; pid {prefix / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
{credential_block}    server {{
        listen {BIND_HOST}:{port}; brix_root on; brix_export {export}; brix_auth none;
        brix_allow_write on; brix_upload_resume off;
        brix_write_through on; brix_wt_mode sync;
        brix_wt_origin root://{HOST}:{origin_port};
{credential_ref}    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def xrdcp_put(port: int, source: Path, dest: str, xrdcp: Path = XRDCP) -> subprocess.CompletedProcess:
    return run([str(xrdcp), "-f", str(source), f"root://{HOST}:{port}//{dest}"])


def wait_listening(ports: list[int], timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    for port in ports:
        while True:
            try:
                with socket.create_connection((HOST, port), timeout=0.5):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    return False
                time.sleep(0.1)
    return True


def _log_tail(prefix: Path, lines: int = 8) -> str:
    try:
        text = (prefix / "logs" / "e.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "<no log>"
    return " | ".join(text.strip().splitlines()[-lines:])


def _put_diag(put: subprocess.CompletedProcess, origin: Path, writer: Path) -> str:
    return (
        f" [xrdcp rc={put.returncode} stderr={(put.stderr or '').strip()[-300:]!r}"
        f" origin_log: {_log_tail(origin)}"
        f" writer_log: {_log_tail(writer)}]"
    )


def run_checks(base: Path, nginx_bin: str = NGINX_BIN, xrdcp: Path = XRDCP) -> list[tuple[bool, str]]:
    if not os.access(xrdcp, os.X_OK):
        return [(True, "SKIP native xrdcp not built")]
    token_ok, token_msg = make_token(base)
    if not token_ok:
        return [(True, "SKIP: " + token_msg)]
    scenario = _prepare_scenario(base)
    started, error = _start_services(nginx_bin, scenario["services"])
    if error:
        return [(False, error)]
    try:
        if not wait_listening(scenario["ports"]):
            return [_listening_failure(scenario)]
        return _exercise_write_through(scenario, xrdcp)
    finally:
        _stop_services(started)


def _prepare_scenario(base):
    origin_port, writer_port, negative_port = cmdscript_ports("credential_wt_ztn")
    origin = base / "o"
    writer = base / "b"
    negative = base / "n"
    token_dir = base / "tok"
    token_file = base / "token.jwt"
    origin_conf = write_origin_config(origin, origin_port, token_dir)
    writer_conf = write_node_config(writer, writer_port, origin_port, token_file)
    negative_conf = write_node_config(negative, negative_port, origin_port, None)
    small = base / "cred_wt_small.bin"
    big = base / "cred_wt_big.bin"
    small.write_bytes(deterministic_bytes(300_000, 157))
    big.write_bytes(deterministic_bytes(2_600_000, 163))
    services = (("origin", origin, origin_conf),
                ("writer", writer, writer_conf),
                ("negative", negative, negative_conf))
    return {"origin": origin, "writer": writer, "negative": negative,
            "small": small, "big": big, "services": services,
            "ports": [origin_port, writer_port, negative_port],
            "writer_port": writer_port, "negative_port": negative_port}


def _start_services(nginx_bin, services):
    started = []
    for name, prefix, conf in services:
        proc = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
        if proc.returncode != 0:
            _stop_services(started)
            message = f"{name} start failed: {(proc.stderr or proc.stdout)[-4000:]}"
            return [], message
        started.append(prefix)
    return started, ""


def _stop_services(prefixes):
    for prefix in reversed(prefixes):
        stop_nginx(prefix)


def _listening_failure(scenario):
    message = "ad-hoc servers never started listening"
    message += f" [origin_log: {_log_tail(scenario['origin'])}"
    message += f" writer_log: {_log_tail(scenario['writer'])}]"
    return False, message


def _exercise_write_through(scenario, xrdcp):
    results = []
    results.append(_positive_write_result(
        scenario, xrdcp, "small", "w.bin",
        "flushed byte-exact to token origin (ztn write-back)",
    ))
    results.append(_positive_write_result(
        scenario, xrdcp, "big", "wbig.bin",
        "multi-chunk ztn write-back byte-exact",
    ))
    results.append(_negative_write_result(scenario, xrdcp))
    return results


def _positive_write_result(scenario, xrdcp, source_key, destination, message):
    source = scenario[source_key]
    put = xrdcp_put(scenario["writer_port"], source, destination, xrdcp)
    target = scenario["origin"] / "root" / destination
    succeeded = put.returncode == 0 and target.exists()
    succeeded = succeeded and target.read_bytes() == source.read_bytes()
    if succeeded:
        return True, message
    diagnostic = _put_diag(put, scenario["origin"], scenario["writer"])
    return False, message + diagnostic


def _negative_write_result(scenario, xrdcp):
    source = scenario["small"]
    xrdcp_put(scenario["negative_port"], source, "nw.bin", xrdcp)
    target = scenario["origin"] / "root" / "nw.bin"
    reached = target.exists() and target.read_bytes() == source.read_bytes()
    return not reached, "unauthenticated write-back failed to reach token origin"


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_wt.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    _print_results(results)
    if all(ok for ok, _ in results):
        print("run_credential_wt_ztn: ALL PASS")
        return 0
    print("run_credential_wt_ztn: FAILURES")
    return 1


def _print_results(results):
    for succeeded, message in results:
        label = "ok  " if succeeded else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
