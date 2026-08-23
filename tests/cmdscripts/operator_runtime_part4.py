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
    del argv
    context = _valgrind_context()
    _prepare_valgrind_directories(context)
    if not _valgrind_requirements(context):
        return 1
    values = _valgrind_values(context)
    config = _render_valgrind_config(context, values)
    if not _valid_valgrind_config(context, config):
        return 1
    process = _start_valgrind(context, config)
    _wait_for_valgrind(values, context)
    _exercise_valgrind(context, values)
    master = _shutdown_valgrind(context, config, process)
    _discard_master_log(context, master)
    _summarize_valgrind(context)
    print(context["results"])
    return 0


def _valgrind_context():
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(os.environ.get("PKI_DIR", str(test_root / "pki")))
    token_dir = Path(os.environ.get("TOKEN_DIR", str(test_root / "tokens")))
    work = Path(os.environ.get("VG_WORK", "/tmp/xrd-vg"))
    return {
        "nginx": Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")),
        "pki": pki_dir,
        "tokens": token_dir,
        "work": work,
        "template": Path(os.environ.get(
            "TEMPLATE", str(TESTS / "valgrind/nginx.conf.in")
        )),
        "suppression": Path(os.environ.get(
            "SUPP", str(TESTS / "valgrind/valgrind.supp")
        )),
        "results": work / "results.txt",
        "logs": work / "logs",
    }


def _prepare_valgrind_directories(context):
    work = context["work"]
    for path in (context["logs"], work / "tmp", work / "data", work / "conf"):
        path.mkdir(parents=True, exist_ok=True)
    context["results"].write_text("")


def _vg_note(context, text):
    with context["results"].open("a") as handle:
        handle.write(text + "\n")


def _valgrind_requirements(context):
    if not shutil.which("valgrind"):
        _vg_finished_missing(context, "valgrind")
        return False
    if not os.access(context["nginx"], os.X_OK):
        _vg_finished_missing(context, f"nginx binary {context['nginx']}")
        return False
    required = _valgrind_required_files(context)
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        _vg_finished_missing(context, "fixture " + ", ".join(missing))
        return False
    payload = f"valgrind harness payload {int(time.time())}\n"
    (context["work"] / "data/vgtest.txt").write_text(payload)
    return True


def _vg_finished_missing(context, detail):
    _vg_note(context, "MISSING " + detail)
    _vg_note(context, "FINISHED")


def _valgrind_required_files(context):
    pki = context["pki"]
    return [pki / "ca/ca.pem", pki / "server/hostcert.pem",
            pki / "server/hostkey.pem", context["tokens"] / "jwks.json"]


def _valgrind_values(context):
    pki, tokens, work = context["pki"], context["tokens"], context["work"]
    return {
        "{WORK}": str(work),
        "{CA_DIR}": str(pki / "ca"),
        "{CA_CERT}": str(pki / "ca/ca.pem"),
        "{SERVER_CERT}": str(pki / "server/hostcert.pem"),
        "{SERVER_KEY}": str(pki / "server/hostkey.pem"),
        "{CLIENT_CERT}": str(pki / "user/usercert.pem"),
        "{CLIENT_KEY}": str(pki / "user/userkey.pem"),
        "{TOKEN_DIR}": str(tokens),
        "{GSI_TLS_PORT}": os.environ.get("GSI_TLS_PORT", "28444"),
        "{HTTP_PORT}": os.environ.get("HTTP_PORT", "28080"),
        "{S3_PORT}": os.environ.get("S3_PORT", "29051"),
        "{METRICS_PORT}": os.environ.get("METRICS_PORT", "29100"),
    }


def _render_valgrind_config(context, values):
    rendered = context["template"].read_text()
    for key, value in values.items():
        rendered = rendered.replace(key, value)
    config = context["work"] / "conf/nginx.conf"
    config.write_text(rendered)
    return config


def _valid_valgrind_config(context, config):
    tested = run([
        str(context["nginx"]), "-t", "-p", str(context["work"]), "-c", str(config)
    ], cwd=REPO_ROOT)
    if tested.returncode == 0:
        return True
    _vg_note(context, "CONFIG INVALID")
    _vg_note(context, "FINISHED")
    return False


def _start_valgrind(context, config):
    run(["pkill", "-9", "-f", str(config)], cwd=REPO_ROOT)
    time.sleep(2)
    for old in context["logs"].glob("vg.*.log"):
        old.unlink()
    command = [
        "valgrind", "--leak-check=full",
        "--show-leak-kinds=definite,indirect", "--track-fds=yes",
        "--trace-children=yes", "--child-silent-after-fork=no",
        "--error-exitcode=0", "--num-callers=30",
        f"--suppressions={context['suppression']}",
        f"--log-file={context['logs']}/vg.%p.log",
        str(context["nginx"]), "-p", str(context["work"]), "-c", str(config),
    ]
    return _popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_for_valgrind(values, context):
    port = int(values["{HTTP_PORT}"])
    for second in range(1, 121):
        if _wait_tcp(BIND_HOST, port, 1.0):
            _vg_note(context, f"up after {second}s")
            return


def _http_code(curl, *args):
    command = [curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", *args]
    return run(command, cwd=REPO_ROOT).stdout.strip()


def _exercise_valgrind(context, values):
    curl = shutil.which("curl") or "curl"
    pki = context["pki"]
    client_cert = pki / "user/usercert.pem"
    client_key = pki / "user/userkey.pem"
    ca_cert = pki / "ca/ca.pem"
    base = f"http://{HOST}:{values['{HTTP_PORT}']}"
    tls = f"https://{HOST}:{values['{GSI_TLS_PORT}']}"
    x509 = ["--cert", str(client_cert), "--key", str(client_key),
            "--cacert", str(ca_cert)]
    _exercise_jwt(context, curl, base)
    _exercise_gsi(context, curl, tls, x509, ca_cert)
    _exercise_macaroon(context, curl, base)
    _exercise_tpc(context, curl, tls, x509)
    _exercise_s3_metrics(context, curl, values)


def _exercise_jwt(context, curl, base):
    token_path = context["tokens"] / "upstream.jwt"
    token = token_path.read_text().strip() if token_path.exists() else ""
    source = context["work"] / "data/vgtest.txt"
    valid = _http_code(curl, "-H", f"Authorization: Bearer {token}",
                       f"{base}/vgtest.txt")
    garbage = _http_code(curl, "-H", "Authorization: Bearer aa.bb.cc",
                         f"{base}/vgtest.txt")
    malformed = _http_code(curl, "-H", "Authorization: Bearer xyz",
                           f"{base}/vgtest.txt")
    put = _http_code(curl, "-T", str(source), "-H",
                     f"Authorization: Bearer {token}", f"{base}/put.txt")
    _vg_note(context, f"jwt valid={valid} garbage={garbage} malformed={malformed} put={put}")


def _exercise_gsi(context, curl, tls, x509, ca_cert):
    line = f"gsi usercert={_http_code(curl, '-k', *x509, f'{tls}/vgtest.txt')}"
    proxy_cert = context["pki"] / "user/proxy.pem"
    proxy_key = context["pki"] / "user/proxykey.pem"
    if proxy_cert.exists() and proxy_key.exists():
        proxy = _http_code(
            curl, "-k", "--cert", str(proxy_cert), "--key", str(proxy_key),
            "--cacert", str(ca_cert), f"{tls}/vgtest.txt",
        )
        line += f" proxycert={proxy}"
    line += f" noclientcert={_http_code(curl, '-k', f'{tls}/vgtest.txt')}"
    _vg_note(context, line)


def _exercise_macaroon(context, curl, base):
    minted = run([
        curl, "-s", "-X", "POST",
        "-d", "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&"
              "scope=storage.read:/ storage.write:/&expires_in=600",
        f"{base}/.oauth2/token",
    ], cwd=REPO_ROOT).stdout
    line = f"macaroon mint_bytes={len(minted)}"
    token = re.search(r'"(?:macaroon|access_token)"[: ]*"([^"]*)"', minted)
    if token:
        used = _http_code(
            curl, "-H", f"Authorization: Bearer {token.group(1)}",
            f"{base}/vgtest.txt",
        )
        line += f" use={used}"
    _vg_note(context, line)


def _exercise_tpc(context, curl, tls, x509):
    pull = _http_code(
        curl, "-k", *x509, "-X", "COPY", "-H",
        f"Source: {tls}/vgtest.txt", f"{tls}/tpc_pulled.txt",
    )
    push = _http_code(
        curl, "-k", *x509, "-X", "COPY", "-H",
        "Destination: https://127.0.0.1:1/dead.txt", f"{tls}/vgtest.txt",
    )
    _vg_note(context, f"tpc pull={pull} push_unreach={push}")


def _exercise_s3_metrics(context, curl, values):
    s3 = f"http://{HOST}:{values['{S3_PORT}']}/testbucket/vgtest.txt"
    badsig = _http_code(
        curl, "-H",
        "Authorization: AWS4-HMAC-SHA256 Credential=x/y, "
        "SignedHeaders=host, Signature=dead", s3,
    )
    anonymous = _http_code(curl, s3)
    metrics = _http_code(curl, f"http://{HOST}:{values['{METRICS_PORT}']}/metrics")
    _vg_note(context, f"s3 badsig={badsig} anon={anonymous} | metrics={metrics}")


def _shutdown_valgrind(context, config, process):
    time.sleep(2)
    master, workers = _valgrind_processes(context, config, process)
    _graceful_worker_shutdown(master, workers)
    _kill_valgrind_processes(config, process)
    return master


def _valgrind_processes(context, config, process):
    pidfile = context["logs"] / "nginx.pid"
    master = pidfile.read_text().strip() if pidfile.exists() else ""
    bound = run(["pgrep", "-f", str(config)], cwd=REPO_ROOT).stdout.split()
    workers = [pid for pid in bound if pid not in (str(process.pid), master)]
    return master, workers


def _graceful_worker_shutdown(master, workers):
    if master.isdigit():
        _safe_kill(int(master), signal.SIGQUIT)
    if workers:
        _wait_for_worker(int(workers[0]))


def _kill_valgrind_processes(config, process):
    time.sleep(2)
    for pid in run(["pgrep", "-f", str(config)], cwd=REPO_ROOT).stdout.split():
        _safe_kill(int(pid), signal.SIGKILL)
    _safe_kill(process.pid, signal.SIGKILL)
    time.sleep(1)


def _wait_for_worker(worker):
    for _ in range(180):
        try:
            os.kill(worker, 0)
        except OSError:
            return
        time.sleep(1)


def _discard_master_log(context, master):
    path = context["logs"] / f"vg.{master}.log"
    if master.isdigit() and path.exists():
        path.rename(context["logs"] / f"vg.master-{master}.discarded")


def _summarize_valgrind(context):
    _vg_note(context, "---- vg logs ----")
    logs = sorted(context["logs"].glob("vg.*.log"))
    for log in logs:
        _summarize_valgrind_log(context, log)
    _vg_note(context, "---- MODULE-FRAME HITS (should be empty) ----")
    hits = _vg_module_frame_hits(context["logs"])
    for hit in hits or ["(none)"]:
        _vg_note(context, hit)
    _vg_note(context, f"DONE logs={len(logs)}")


def _summarize_valgrind_log(context, log):
    text = log.read_text(errors="ignore")
    pattern = r"definitely lost|indirectly lost|Invalid (?:read|write)|uninitialised"
    leakish = len(re.findall(pattern, text))
    summaries = [line for line in text.splitlines() if "ERROR SUMMARY" in line]
    summary = summaries[-1] if summaries else ""
    _vg_note(context, f"{log.name}: leakish={leakish}  {summary}")


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
    direct = _direct_runner(argv)
    if direct is not None:
        return direct
    with tempfile.TemporaryDirectory(prefix="operator_runtime.") as tmp:
        results = run_checks(Path(tmp), argv)
    _print_operator_results(results)
    return 0 if all(ok for ok, _ in results) else 1


def _direct_runner(argv):
    if not argv or argv[0] not in RUNNERS:
        return None
    return RUNNERS[argv[0]](argv[1:])


def _print_operator_results(results):
    for passed, message in results:
        label = "ok  " if passed else "FAIL"
        print(f"  {label} {message}")


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
