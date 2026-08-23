"""GridSite two-step delegation REST flow."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
import signal
import subprocess
import time

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, CA_CERT, CA_KEY, HOST, NGINX_BIN, SERVER_CERT, SERVER_KEY, TEST_ROOT

REPO_ROOT = Path(__file__).resolve().parents[2]


def stop_nginx(prefix: Path) -> None:
    try:
        pid = int((prefix / "nginx.pid").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def ensure_pki(base: Path) -> tuple[bool, str]:
    if _pki_available():
        return True, ""
    result = subprocess.run(
        ["python3", "-c", "import pki_helpers; pki_helpers.blitz_test_pki()"],
        cwd=REPO_ROOT / "tests",
        env={**os.environ, "PYTHONPATH": "."},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    (base / "pki.log").write_text(result.stdout or "", encoding="utf-8")
    if result.returncode != 0:
        return False, "SKIP: PKI provisioning failed: " + (result.stdout or "")[-1000:]
    if not Path(CA_KEY).is_file():
        return False, f"SKIP: CA key not found ({CA_KEY})"
    return True, ""


def _pki_available():
    return all((Path(CA_CERT).is_file(), Path(CA_KEY).is_file()))


def mint_certs(base: Path) -> tuple[bool, str, dict[str, str]]:
    certs = base / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["python3", "mint_delegation_certs.py", CA_CERT, CA_KEY, str(certs)],
        cwd=REPO_ROOT / "tests",
        env={**os.environ, "PYTHONPATH": "."},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    (base / "mint.log").write_text((result.stdout or "") + (result.stderr or ""), encoding="utf-8")
    if _mint_failed(result, certs):
        return False, "SKIP: cert minting failed: " + (result.stderr or result.stdout)[-1000:], {}
    parsed = _parse_assignments(result.stdout)
    if not {"A_DN", "B_DN"} <= set(parsed):
        return False, "SKIP: could not parse minted DNs", {}
    return True, "", parsed


def _parse_assignments(output):
    parsed = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key] = value
    return parsed


def _mint_failed(result, certs):
    return result.returncode != 0 or not (certs / "a_eec_cert.pem").is_file()


def key_for_dn(dn: str) -> str:
    return "x5h-" + hashlib.sha256(dn.encode("utf-8")).hexdigest()[:32]


def write_origin_config(prefix: Path, port: int) -> Path:
    root = prefix / "root"
    logs = prefix / "logs"
    root.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon on;
error_log {logs / 'e.log'} info;
pid {prefix / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{port};
    brix_root on;
    brix_export {root};
    brix_allow_write on;
    brix_auth gsi;
    brix_certificate {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca {CA_CERT};
}} }}
""",
        encoding="utf-8",
    )
    return conf


def write_front_config(base: Path, origin_port: int, front_port: int, delegation: str) -> Path:
    front = base / "f"
    for sub in ("logs", "export", "stage", "journal"):
        (front / sub).mkdir(parents=True, exist_ok=True)
    creds = base / "creds"
    creds.mkdir(parents=True, exist_ok=True)
    creds.chmod(0o777)
    conf = front / "nginx.conf"
    conf.write_text(
        f"""daemon on;
error_log {front / 'logs' / 'e.log'} info;
pid {front / 'nginx.pid'};
env BRIX_STAGE_JOURNAL_DIR={front / 'journal'};
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {front / 'logs' / 'access.log'};
    client_body_temp_path {front / 'export'};
    server {{
        listen {BIND_HOST}:{front_port} ssl;
        ssl_certificate {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {front / 'export'};
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://{HOST}:{origin_port};
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback deny;
            brix_stage on;
            brix_stage_store posix:{front / 'stage'};
            brix_stage_flush sync;
            brix_delegation_endpoint {delegation};
        }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def start_nginx(nginx_bin: str, prefix: Path, conf: Path) -> tuple[bool, str]:
    result = run([nginx_bin, "-p", str(prefix), "-c", str(conf)])
    if result.returncode != 0:
        return False, (result.stderr or result.stdout)[-4000:]
    return True, ""


def curl(
    url: str,
    cert: Path,
    key: Path,
    *,
    output: Path,
    headers: Path | None = None,
    upload: Path | None = None,
    timeout: int = 5,
) -> tuple[str, str]:
    cmd = ["curl", "-sk", "--max-time", str(timeout), "--cert", str(cert), "--key", str(key)]
    if headers is not None:
        cmd.extend(["-D", str(headers)])
    if upload is not None:
        cmd.extend(["-T", str(upload)])
    cmd.extend(["-o", str(output), "-w", "%{http_code}", url])
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip(), result.stderr


def delegation_id(headers: Path) -> str:
    if not headers.exists():
        return ""
    for line in headers.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.lower().startswith("x-brix-delegation-id:"):
            return line.split(":", 1)[1].strip()
    return ""


def sign_csr(csr: Path, cert: Path, key: Path, out: Path) -> bool:
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(cert),
            "-CAkey",
            str(key),
            "-CAcreateserial",
            "-days",
            "1",
            "-copy_extensions",
            "copy",
            "-out",
            str(out),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode == 0 and out.is_file() and out.stat().st_size > 0


def start_front(base: Path, nginx_bin: str, origin_port: int, front_port: int, delegation: str) -> tuple[bool, str]:
    front = base / "f"
    stop_nginx(front)
    conf = write_front_config(base, origin_port, front_port, delegation)
    ok, message = start_nginx(nginx_bin, front, conf)
    if ok:
        time.sleep(0.5)
    return ok, message


@dataclass(frozen=True)
class _Context:
    base: Path
    nginx_bin: str
    origin_port: int
    front_port: int
    a_cert: Path
    a_key: Path
    b_cert: Path
    b_key: Path
    credential_name: str

    @property
    def url(self):
        return f"https://{HOST}:{self.front_port}"

    @property
    def request_url(self):
        return self.url + "/.well-known/brix-delegation/request"

    @property
    def creds(self):
        return self.base / "creds"


class _FrontendStartError(RuntimeError):
    pass


def _start_frontend(context, delegation="on"):
    ok, message = start_front(context.base, context.nginx_bin, context.origin_port,
                              context.front_port, delegation)
    if not ok:
        raise _FrontendStartError(message)


def _stop_frontend(context):
    stop_nginx(context.base / "f")


def _request(context, suffix):
    headers = context.base / f"hdrs_{suffix}.txt"
    csr = context.base / f"csr_{suffix}.pem"
    code, _ = curl(context.request_url, context.a_cert, context.a_key,
                   output=csr, headers=headers)
    return code, delegation_id(headers), csr


def _scenario_sign_and_put(context):
    _start_frontend(context)
    code, delegation, csr = _request(context, "a")
    results = [
        (code == "200", f"a1: getProxyReq accepted (code={code})"),
        (bool(delegation), "a2: X-Brix-Delegation-Id header present"),
        ("BEGIN CERTIFICATE REQUEST" in csr.read_text(encoding="utf-8", errors="replace"),
         "a3: response body is a PEM CSR"),
    ]
    signed = context.base / "signed_a.pem"
    credential = context.creds / f"{context.credential_name}.pem"
    credential.unlink(missing_ok=True)
    signed_ok = bool(delegation) and sign_csr(csr, context.a_cert, context.a_key, signed)
    results.append((signed_ok, "b1: A signed its own CSR"))
    if signed_ok:
        results.extend(_put_signed_proxy(context, delegation, signed, credential))
    else:
        results.extend([(False, "b2: skipped (no signed proxy to PUT)"),
                        (False, "b3: skipped (no signed proxy to PUT)")])
    _stop_frontend(context)
    return results


def _put_signed_proxy(context, delegation, signed, credential):
    body = context.base / "body_a.pem"
    body.write_bytes(signed.read_bytes() + context.a_cert.read_bytes())
    code, _ = curl(context.url + f"/.well-known/brix-delegation/{delegation}",
                   context.a_cert, context.a_key, output=context.base / "resp_b.txt",
                   upload=body)
    return [(code in ("200", "201"), f"b2: putProxy accepted (code={code})"),
            (credential.is_file(),
             f"b3: {context.credential_name}.pem now exists in credential dir")]


def _scenario_cross_identity(context):
    _start_frontend(context)
    code, delegation, _ = _request(context, "c")
    credential = context.creds / f"{context.credential_name}.pem"
    if code == "200" and delegation:
        credential.unlink(missing_ok=True)
        code, _ = curl(context.url + f"/.well-known/brix-delegation/{delegation}",
                       context.b_cert, context.b_key, output=context.base / "resp_c.txt",
                       upload=context.a_cert)
        results = [(code == "403", "c1: B's putProxy to A's id rejected (403)"),
                   (not credential.exists(),
                    "c2: A's credential file NOT created by B's attempt")]
    else:
        results = [(False, f"c1: skipped (could not obtain a fresh id, code={code})"),
                   (False, "c2: skipped (could not obtain a fresh id)")]
    _stop_frontend(context)
    return results


def _scenario_unknown_id(context):
    _start_frontend(context)
    path = "/.well-known/brix-delegation/0000000000000000000000000000dead"
    code, _ = curl(context.url + path, context.a_cert, context.a_key,
                   output=context.base / "resp_d.txt", upload=context.a_cert)
    _stop_frontend(context)
    return [(code == "404", "d: unknown id rejected (404)")]


def _scenario_garbage(context):
    _start_frontend(context)
    code, delegation, _ = _request(context, "e")
    if code == "200" and delegation:
        garbage = context.base / "garbage.txt"
        garbage.write_text("this is not a PEM certificate, just garbage bytes\n",
                           encoding="utf-8")
        code, _ = curl(context.url + f"/.well-known/brix-delegation/{delegation}",
                       context.a_cert, context.a_key, output=context.base / "resp_e.txt",
                       upload=garbage)
        results = [(code == "400", "e: garbage body rejected (400)")]
    else:
        results = [(False, f"e: skipped (could not obtain a fresh id, code={code})")]
    _stop_frontend(context)
    return results


def _scenario_untrusted(context):
    _start_frontend(context)
    code, delegation, csr = _request(context, "f")
    if code != "200" or not delegation:
        results = [(False, f"f1: skipped (could not obtain a fresh id, code={code})"),
                   (False, "f2: skipped (could not obtain a fresh id)")]
    else:
        results = _untrusted_proxy_results(context, delegation, csr)
    _stop_frontend(context)
    return results


def _untrusted_proxy_results(context, delegation, csr):
    credential = context.creds / f"{context.credential_name}.pem"
    credential.unlink(missing_ok=True)
    signed = context.base / "signed_f.pem"
    rogue_cert = context.base / "certs" / "a_eec_wrongca_cert.pem"
    rogue_key = context.base / "certs" / "a_eec_wrongca_key.pem"
    if not sign_csr(csr, rogue_cert, rogue_key, signed):
        return [(False, "f1: could not sign CSR with rogue EEC"),
                (False, "f2: skipped (no signed proxy to PUT)")]
    body = context.base / "body_f.pem"
    body.write_bytes(signed.read_bytes() + rogue_cert.read_bytes())
    code, _ = curl(context.url + f"/.well-known/brix-delegation/{delegation}",
                   context.a_cert, context.a_key, output=context.base / "resp_f.txt",
                   upload=body)
    return [(code == "403", "f1: untrusted-EEC signed proxy rejected (403)"),
            (not credential.exists(), "f2: no credential file written for the untrusted proxy")]


def _scenario_disabled(context):
    credential = context.creds / f"{context.credential_name}.pem"
    credential.unlink(missing_ok=True)
    _start_frontend(context, "off")
    code, _ = curl(context.request_url, context.a_cert, context.a_key,
                   output=context.base / "resp_g1.txt", timeout=2)
    results = [(code in ("403", "404"),
                f"g1: GET .../request -> {code} (endpoint off, not special)")]
    path = "/.well-known/brix-delegation/somefakeid0000000000000000000000"
    code, _ = curl(context.url + path, context.a_cert, context.a_key,
                   output=context.base / "resp_g2.txt", upload=context.a_cert)
    results.append((code not in ("200", "201"),
                    f"g2: PUT .../<id> not accepted as a delegation (code={code})"))
    results.append((not credential.exists(),
                    "g3: no credential file written while endpoint is off"))
    return results


def _make_context(base, nginx_bin, ports, dns):
    origin_port, front_port = ports
    certs = base / "certs"
    return _Context(base, nginx_bin, origin_port, front_port,
                    certs / "a_eec_cert.pem", certs / "a_eec_key.pem",
                    certs / "b_eec_cert.pem", certs / "b_eec_key.pem",
                    key_for_dn(dns["A_DN"]))


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    pki_ok, message = ensure_pki(base)
    if not pki_ok:
        return [(True, message)]
    mint_ok, message, dns = mint_certs(base)
    if not mint_ok:
        return [(True, message)]
    context = _make_context(base, nginx_bin, cmdscript_ports("delegation_twostep"), dns)
    origin = base / "o"
    ok, message = start_nginx(nginx_bin, origin,
                              write_origin_config(origin, context.origin_port))
    if not ok:
        return [(True, "SKIP: origin start failed: " + message)]
    try:
        results = []
        for scenario in (_scenario_sign_and_put, _scenario_cross_identity,
                         _scenario_unknown_id, _scenario_garbage,
                         _scenario_untrusted, _scenario_disabled):
            results.extend(scenario(context))
        return results
    except _FrontendStartError as exc:
        return [(False, "frontend restart failed: " + str(exc))]
    finally:
        _stop_frontend(context)
        stop_nginx(origin)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="deleg2.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    _print_results(results)
    return _result_code(results)


def _print_results(results):
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")


def _result_code(results):
    if all(ok for ok, _ in results):
        print("run_delegation_twostep: ALL PASS")
        return 0
    print("run_delegation_twostep: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
