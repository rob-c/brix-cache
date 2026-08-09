"""Python ports for top-level operator/runtime shell entrypoints."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cmdscripts.compile_run import REPO_ROOT, result, run
from settings import BIND_HOST, HOST, TEST_PORT_START
from port_ladder import PORT_COUNT


TESTS = REPO_ROOT / "tests"


def run_valgrind(argv: list[str]) -> int:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(os.environ.get("PKI_DIR", str(test_root / "pki")))
    token_dir = Path(os.environ.get("TOKEN_DIR", str(test_root / "tokens")))
    vg_work = Path(os.environ.get("VG_WORK", "/tmp/xrd-vg"))
    template = Path(os.environ.get("TEMPLATE", str(TESTS / "valgrind/nginx.conf.in")))
    supp = Path(os.environ.get("SUPP", str(TESTS / "valgrind/valgrind.supp")))
    results = vg_work / "results.txt"
    logdir = vg_work / "logs"
    for path in (logdir, vg_work / "tmp", vg_work / "data", vg_work / "conf"):
        path.mkdir(parents=True, exist_ok=True)
    results.write_text("")

    def note(text: str) -> None:
        with results.open("a") as handle:
            handle.write(text + "\n")

    if not shutil.which("valgrind"):
        note("MISSING valgrind")
        note("FINISHED")
        return 1
    if not os.access(nginx, os.X_OK):
        note(f"MISSING nginx binary {nginx}")
        note("FINISHED")
        return 1
    ca_cert = pki_dir / "ca/ca.pem"
    client_cert, client_key = pki_dir / "user/usercert.pem", pki_dir / "user/userkey.pem"
    required = [ca_cert, pki_dir / "server/hostcert.pem", pki_dir / "server/hostkey.pem", token_dir / "jwks.json"]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        note("MISSING fixture " + ", ".join(missing))
        note("FINISHED")
        return 1
    (vg_work / "data/vgtest.txt").write_text(f"valgrind harness payload {int(time.time())}\n")
    values = {
        "{WORK}": str(vg_work),
        "{CA_DIR}": str(pki_dir / "ca"),
        "{CA_CERT}": str(ca_cert),
        "{SERVER_CERT}": str(pki_dir / "server/hostcert.pem"),
        "{SERVER_KEY}": str(pki_dir / "server/hostkey.pem"),
        "{CLIENT_CERT}": str(client_cert),
        "{CLIENT_KEY}": str(client_key),
        "{TOKEN_DIR}": str(token_dir),
        "{GSI_TLS_PORT}": os.environ.get("GSI_TLS_PORT", "28444"),
        "{HTTP_PORT}": os.environ.get("HTTP_PORT", "28080"),
        "{S3_PORT}": os.environ.get("S3_PORT", "29051"),
        "{METRICS_PORT}": os.environ.get("METRICS_PORT", "29100"),
    }
    conf = vg_work / "conf/nginx.conf"
    rendered = template.read_text()
    for key, value in values.items():
        rendered = rendered.replace(key, value)
    conf.write_text(rendered)
    tested = run([str(nginx), "-t", "-p", str(vg_work), "-c", str(conf)], cwd=REPO_ROOT)
    if tested.returncode != 0:
        note("CONFIG INVALID")
        note("FINISHED")
        return 1
    # Reap any prior harness bound to this unique config path (valgrind's visible
    # cmdline is the nginx invocation, so match the config, not the process name).
    run(["pkill", "-9", "-f", str(conf)], cwd=REPO_ROOT)
    time.sleep(2)
    for old in logdir.glob("vg.*.log"):
        old.unlink()
    vg = _popen(
        [
            "valgrind",
            "--leak-check=full",
            "--show-leak-kinds=definite,indirect",
            "--track-fds=yes",
            "--trace-children=yes",
            "--child-silent-after-fork=no",
            "--error-exitcode=0",
            "--num-callers=30",
            f"--suppressions={supp}",
            f"--log-file={logdir}/vg.%p.log",
            str(nginx),
            "-p",
            str(vg_work),
            "-c",
            str(conf),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    http_port, gsi_port = values["{HTTP_PORT}"], values["{GSI_TLS_PORT}"]
    s3_port, metrics_port = values["{S3_PORT}"], values["{METRICS_PORT}"]
    # Valgrind boots the worker ~20x slower than native.
    for second in range(1, 121):
        if _wait_tcp(BIND_HOST, int(http_port), 1.0):
            note(f"up after {second}s")
            break
    curl = shutil.which("curl") or "curl"

    def code(*args: str) -> str:
        return run([curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", *args], cwd=REPO_ROOT).stdout.strip()

    # ---- Exercise every external-handle path (mirrors run_valgrind.sh) ----
    jwt_path = token_dir / "upstream.jwt"
    jwt = jwt_path.read_text().strip() if jwt_path.exists() else ""
    base = f"http://{HOST}:{http_port}"
    note(
        f"jwt valid={code('-H', f'Authorization: Bearer {jwt}', f'{base}/vgtest.txt')}"
        f" garbage={code('-H', 'Authorization: Bearer aa.bb.cc', f'{base}/vgtest.txt')}"
        f" malformed={code('-H', 'Authorization: Bearer xyz', f'{base}/vgtest.txt')}"
        f" put={code('-T', str(vg_work / 'data/vgtest.txt'), '-H', f'Authorization: Bearer {jwt}', f'{base}/put.txt')}"
    )
    tls = f"https://{HOST}:{gsi_port}"
    x509 = ["--cert", str(client_cert), "--key", str(client_key), "--cacert", str(ca_cert)]
    gsi_line = f"gsi usercert={code('-k', *x509, f'{tls}/vgtest.txt')}"
    proxy_cert, proxy_key = pki_dir / "user/proxy.pem", pki_dir / "user/proxykey.pem"
    if proxy_cert.exists() and proxy_key.exists():
        gsi_line += f" proxycert={code('-k', '--cert', str(proxy_cert), '--key', str(proxy_key), '--cacert', str(ca_cert), f'{tls}/vgtest.txt')}"
    gsi_line += f" noclientcert={code('-k', f'{tls}/vgtest.txt')}"
    note(gsi_line)
    minted = run(
        [
            curl, "-s", "-X", "POST",
            "-d", "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&scope=storage.read:/ storage.write:/&expires_in=600",
            f"{base}/.oauth2/token",
        ],
        cwd=REPO_ROOT,
    ).stdout
    macaroon_line = f"macaroon mint_bytes={len(minted)}"
    token = re.search(r'"(?:macaroon|access_token)"[: ]*"([^"]*)"', minted)
    if token:
        macaroon_line += f" use={code('-H', f'Authorization: Bearer {token.group(1)}', f'{base}/vgtest.txt')}"
    note(macaroon_line)
    note(
        f"tpc pull={code('-k', *x509, '-X', 'COPY', '-H', f'Source: {tls}/vgtest.txt', f'{tls}/tpc_pulled.txt')}"
        f" push_unreach={code('-k', *x509, '-X', 'COPY', '-H', 'Destination: https://127.0.0.1:1/dead.txt', f'{tls}/vgtest.txt')}"  # net-literal-allow: deliberately-unreachable TPC push destination (port 1)
    )
    note(
        f"s3 badsig={code('-H', 'Authorization: AWS4-HMAC-SHA256 Credential=x/y, SignedHeaders=host, Signature=dead', f'http://{HOST}:{s3_port}/testbucket/vgtest.txt')}"
        f" anon={code(f'http://{HOST}:{s3_port}/testbucket/vgtest.txt')}"
        f" | metrics={code(f'http://{HOST}:{metrics_port}/metrics')}"
    )

    # ---- Shutdown: SIGQUIT the master so the worker exits cleanly and its
    # valgrind dumps a complete report; the master's own log is discarded below
    # (its reap NULL-derefs in nginx-core ngx_unlock_mutexes under valgrind). ----
    time.sleep(2)
    pidfile = logdir / "nginx.pid"
    master = pidfile.read_text().strip() if pidfile.exists() else ""
    bound = run(["pgrep", "-f", str(conf)], cwd=REPO_ROOT).stdout.split()
    workers = [p for p in bound if p not in (str(vg.pid), master)]
    if master.isdigit():
        _safe_kill(int(master), signal.SIGQUIT)
    if workers:
        worker = int(workers[0])
        for _ in range(180):
            try:
                os.kill(worker, 0)
            except OSError:
                break
            time.sleep(1)
    time.sleep(2)
    for pid in run(["pgrep", "-f", str(conf)], cwd=REPO_ROOT).stdout.split():
        _safe_kill(int(pid), signal.SIGKILL)
    _safe_kill(vg.pid, signal.SIGKILL)
    time.sleep(1)
    master_log = logdir / f"vg.{master}.log"
    if master.isdigit() and master_log.exists():
        master_log.rename(logdir / f"vg.master-{master}.discarded")

    note("---- vg logs ----")
    logs = sorted(logdir.glob("vg.*.log"))
    for log in logs:
        text = log.read_text(errors="ignore")
        leakish = len(re.findall(r"definitely lost|indirectly lost|Invalid (?:read|write)|uninitialised", text))
        summary = ""
        for line in text.splitlines():
            if "ERROR SUMMARY" in line:
                summary = line
        note(f"{log.name}: leakish={leakish}  {summary}")
    note("---- MODULE-FRAME HITS (should be empty) ----")
    hits = _vg_module_frame_hits(logdir)
    for hit in hits or ["(none)"]:
        note(hit)
    note(f"DONE logs={len(logs)}")
    print(results)
    return 0


RUNNERS = {
    "suite": run_suite,
    "load": run_load,
    "profile-lifecycle": run_profile_lifecycle,
    "profile-load": run_profile_load,
    "valgrind": run_valgrind,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    selected = list(names or [])
    if not selected:
        return [result(True, "operator runtime ports are importable; execution is opt-in")]
    results = []
    for name in selected:
        runner = RUNNERS.get(name)
        if runner is None:
            results.append(result(False, f"unknown operator runtime port: {name}"))
            continue
        if os.environ.get("PHASE81_RUN_OPERATOR_RUNTIME") != "1":
            results.append(result(True, f"SKIP {name}: set PHASE81_RUN_OPERATOR_RUNTIME=1 to execute"))
            continue
        rc = runner([])
        results.append(result(rc == 0, f"{name} exited {rc}"))
    return results


def entry(argv: list[str]) -> int:
    if argv and argv[0] in RUNNERS:
        return RUNNERS[argv[0]](argv[1:])
    with tempfile.TemporaryDirectory(prefix="operator_runtime.") as tmp:
        results = run_checks(Path(tmp), argv)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
