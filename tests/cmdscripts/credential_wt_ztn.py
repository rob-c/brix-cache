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
        if not wait_listening([origin_port, writer_port, negative_port]):
            return [(False, "ad-hoc servers never started listening"
                     f" [origin_log: {_log_tail(origin)} writer_log: {_log_tail(writer)}]")]
        results: list[tuple[bool, str]] = []
        small_put = xrdcp_put(writer_port, small, "w.bin", xrdcp)
        small_ok = (
            small_put.returncode == 0
            and (origin / "root" / "w.bin").exists()
            and (origin / "root" / "w.bin").read_bytes() == small.read_bytes()
        )
        results.append(
            (
                small_ok,
                "flushed byte-exact to token origin (ztn write-back)"
                + ("" if small_ok else _put_diag(small_put, origin, writer)),
            )
        )

        big_put = xrdcp_put(writer_port, big, "wbig.bin", xrdcp)
        big_ok = (
            big_put.returncode == 0
            and (origin / "root" / "wbig.bin").exists()
            and (origin / "root" / "wbig.bin").read_bytes() == big.read_bytes()
        )
        results.append(
            (
                big_ok,
                "multi-chunk ztn write-back byte-exact"
                + ("" if big_ok else _put_diag(big_put, origin, writer)),
            )
        )

        xrdcp_put(negative_port, small, "nw.bin", xrdcp)
        negative_succeeded = (
            (origin / "root" / "nw.bin").exists()
            and (origin / "root" / "nw.bin").read_bytes() == small.read_bytes()
        )
        results.append((not negative_succeeded, "unauthenticated write-back correctly failed to reach the token origin"))
        return results
    finally:
        for prefix in reversed(started):
            stop_nginx(prefix)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_wt.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_wt_ztn: ALL PASS")
        return 0
    print("run_credential_wt_ztn: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
