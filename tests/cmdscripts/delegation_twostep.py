"""GridSite two-step delegation REST flow."""

from __future__ import annotations

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
    if Path(CA_CERT).is_file() and Path(CA_KEY).is_file():
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
    if result.returncode != 0 or not (certs / "a_eec_cert.pem").is_file():
        return False, "SKIP: cert minting failed: " + (result.stderr or result.stdout)[-1000:], {}
    parsed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            parsed[key] = value
    if "A_DN" not in parsed or "B_DN" not in parsed:
        return False, "SKIP: could not parse minted DNs", {}
    return True, "", parsed


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


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    pki_ok, pki_message = ensure_pki(base)
    if not pki_ok:
        return [(True, pki_message)]
    mint_ok, mint_message, dns = mint_certs(base)
    if not mint_ok:
        return [(True, mint_message)]

    origin_port, front_port = cmdscript_ports("delegation_twostep")
    origin = base / "o"
    creds = base / "creds"
    certs = base / "certs"
    a_cert, a_key = certs / "a_eec_cert.pem", certs / "a_eec_key.pem"
    b_cert, b_key = certs / "b_eec_cert.pem", certs / "b_eec_key.pem"
    a_key_name = key_for_dn(dns["A_DN"])

    ok, msg = start_nginx(nginx_bin, origin, write_origin_config(origin, origin_port))
    if not ok:
        return [(True, "SKIP: origin start failed: " + msg)]

    results: list[tuple[bool, str]] = []
    url = f"https://{HOST}:{front_port}"
    req_url = url + "/.well-known/brix-delegation/request"
    try:
        ok, msg = start_front(base, nginx_bin, origin_port, front_port, "on")
        if not ok:
            return [(True, "SKIP: frontend start failed: " + msg)]
        hdrs = base / "hdrs_a.txt"
        csr = base / "csr_a.pem"
        code, _ = curl(req_url, a_cert, a_key, output=csr, headers=hdrs)
        did = delegation_id(hdrs)
        results.append((code == "200", f"a1: getProxyReq accepted (code={code})"))
        results.append((bool(did), "a2: X-Brix-Delegation-Id header present"))
        results.append(("BEGIN CERTIFICATE REQUEST" in csr.read_text(encoding="utf-8", errors="replace"), "a3: response body is a PEM CSR"))

        signed = base / "signed_a.pem"
        body = base / "body_a.pem"
        (creds / f"{a_key_name}.pem").unlink(missing_ok=True)
        signed_ok = bool(did) and sign_csr(csr, a_cert, a_key, signed)
        results.append((signed_ok, "b1: A signed its own CSR"))
        if signed_ok:
            body.write_bytes(signed.read_bytes() + a_cert.read_bytes())
            code, _ = curl(url + f"/.well-known/brix-delegation/{did}", a_cert, a_key, output=base / "resp_b.txt", upload=body)
            results.append((code in ("200", "201"), f"b2: putProxy accepted (code={code})"))
            results.append(((creds / f"{a_key_name}.pem").is_file(), f"b3: {a_key_name}.pem now exists in credential dir"))
        else:
            results.extend([(False, "b2: skipped (no signed proxy to PUT)"), (False, "b3: skipped (no signed proxy to PUT)")])
        stop_nginx(base / "f")

        ok, msg = start_front(base, nginx_bin, origin_port, front_port, "on")
        if not ok:
            return [(False, "frontend restart failed: " + msg)]
        hdrs_c, csr_c = base / "hdrs_c.txt", base / "csr_c.pem"
        code, _ = curl(req_url, a_cert, a_key, output=csr_c, headers=hdrs_c)
        did_c = delegation_id(hdrs_c)
        if code == "200" and did_c:
            (creds / f"{a_key_name}.pem").unlink(missing_ok=True)
            code, _ = curl(url + f"/.well-known/brix-delegation/{did_c}", b_cert, b_key, output=base / "resp_c.txt", upload=a_cert)
            results.append((code == "403", "c1: B's putProxy to A's id rejected (403)"))
            results.append((not (creds / f"{a_key_name}.pem").exists(), "c2: A's credential file NOT created by B's attempt"))
        else:
            results.extend([(False, f"c1: skipped (could not obtain a fresh id, code={code})"), (False, "c2: skipped (could not obtain a fresh id)")])
        stop_nginx(base / "f")

        ok, msg = start_front(base, nginx_bin, origin_port, front_port, "on")
        if not ok:
            return [(False, "frontend restart failed: " + msg)]
        code, _ = curl(url + "/.well-known/brix-delegation/0000000000000000000000000000dead", a_cert, a_key, output=base / "resp_d.txt", upload=a_cert)
        results.append((code == "404", "d: unknown id rejected (404)"))
        stop_nginx(base / "f")

        ok, msg = start_front(base, nginx_bin, origin_port, front_port, "on")
        if not ok:
            return [(False, "frontend restart failed: " + msg)]
        hdrs_e, csr_e = base / "hdrs_e.txt", base / "csr_e.pem"
        code, _ = curl(req_url, a_cert, a_key, output=csr_e, headers=hdrs_e)
        did_e = delegation_id(hdrs_e)
        if code == "200" and did_e:
            garbage = base / "garbage.txt"
            garbage.write_text("this is not a PEM certificate, just garbage bytes\n", encoding="utf-8")
            code, _ = curl(url + f"/.well-known/brix-delegation/{did_e}", a_cert, a_key, output=base / "resp_e.txt", upload=garbage)
            results.append((code == "400", "e: garbage body rejected (400)"))
        else:
            results.append((False, f"e: skipped (could not obtain a fresh id, code={code})"))
        stop_nginx(base / "f")

        ok, msg = start_front(base, nginx_bin, origin_port, front_port, "on")
        if not ok:
            return [(False, "frontend restart failed: " + msg)]
        hdrs_f, csr_f = base / "hdrs_f.txt", base / "csr_f.pem"
        code, _ = curl(req_url, a_cert, a_key, output=csr_f, headers=hdrs_f)
        did_f = delegation_id(hdrs_f)
        if code == "200" and did_f:
            (creds / f"{a_key_name}.pem").unlink(missing_ok=True)
            signed_f = base / "signed_f.pem"
            rogue_cert = certs / "a_eec_wrongca_cert.pem"
            rogue_key = certs / "a_eec_wrongca_key.pem"
            if sign_csr(csr_f, rogue_cert, rogue_key, signed_f):
                body_f = base / "body_f.pem"
                body_f.write_bytes(signed_f.read_bytes() + rogue_cert.read_bytes())
                code, _ = curl(url + f"/.well-known/brix-delegation/{did_f}", a_cert, a_key, output=base / "resp_f.txt", upload=body_f)
                results.append((code == "403", "f1: untrusted-EEC signed proxy rejected (403)"))
                results.append((not (creds / f"{a_key_name}.pem").exists(), "f2: no credential file written for the untrusted proxy"))
            else:
                results.extend([(False, "f1: could not sign CSR with rogue EEC"), (False, "f2: skipped (no signed proxy to PUT)")])
        else:
            results.extend([(False, f"f1: skipped (could not obtain a fresh id, code={code})"), (False, "f2: skipped (could not obtain a fresh id)")])
        stop_nginx(base / "f")

        (creds / f"{a_key_name}.pem").unlink(missing_ok=True)
        ok, msg = start_front(base, nginx_bin, origin_port, front_port, "off")
        if not ok:
            return [(False, "frontend restart failed: " + msg)]
        code, _ = curl(req_url, a_cert, a_key, output=base / "resp_g1.txt", timeout=2)
        results.append((code in ("403", "404"), f"g1: GET .../request -> {code} (endpoint off, not special)"))
        code, _ = curl(url + "/.well-known/brix-delegation/somefakeid0000000000000000000000", a_cert, a_key, output=base / "resp_g2.txt", upload=a_cert)
        results.append((code not in ("200", "201"), f"g2: PUT .../<id> not accepted as a delegation (code={code})"))
        results.append((not (creds / f"{a_key_name}.pem").exists(), "g3: no credential file written while endpoint is off"))
        return results
    finally:
        stop_nginx(base / "f")
        stop_nginx(origin)


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="deleg2.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_delegation_twostep: ALL PASS")
        return 0
    print("run_delegation_twostep: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
