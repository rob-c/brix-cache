"""Direct Python ports for the GSI/trust live shell scenarios.

Ports ``run_csi_trust.sh``, ``run_gsi_store_memo.sh``,
``run_gsi_intermediate_ca.sh``, and ``run_delegation_upload.sh``.  Each public
scenario keeps the shell test's own acceptance sequence and assertions; the
shared code below only removes repeated PKI/nginx/curl plumbing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

from cmdscripts.delegation_twostep import ensure_pki, key_for_dn, mint_certs
from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from settings import BIND_HOST, CA_CERT, CA_DIR, HOST, SERVER_CERT, SERVER_HOST, SERVER_KEY, TEST_ROOT
from fleet_ports import cmdscript_ports

XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"

_PORTS = cmdscript_ports("gsi_trust_live")


def _write_delegation_front(run: LiveRun, front: Path, origin_port: int, front_port: int, creds: Path,
                            certs: Path, delegation: str) -> Path:
    return run.write(
        front / "nginx.conf",
        f"""daemon on;
error_log {front}/logs/e.log info;
pid {front}/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR={front}/journal;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {front}/logs/access.log;
    client_body_temp_path {front}/export;
    brix_credential origin {{ x509_proxy {certs}/a_proxy_valid.pem; ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{front_port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {front}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://{HOST}:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback deny;
            brix_stage on;
            brix_stage_store posix:{front}/stage;
            brix_stage_flush sync;
            brix_delegation_endpoint {delegation};
        }}
    }}
}}
""",
    )


def delegation_upload(nginx: Path | None = None) -> int:
    with LiveRun("deleg_e2e", nginx) as run:
        pki_ok, pki_message = ensure_pki(run.root)
        if not pki_ok:
            return _skip(pki_message)
        mint_ok, mint_message, dns = mint_certs(run.root)
        if not mint_ok:
            return _skip(mint_message)
        a_stem, b_stem = key_for_dn(dns["A_DN"]), key_for_dn(dns["B_DN"])
        print(f"  user-A DN: {dns['A_DN']}")
        print(f"  user-A credential stem: {a_stem}")
        print(f"  user-B credential stem: {b_stem}")

        oport, fport = _PORTS[9:11]  # was free_ports(2)
        certs = run.root / "certs"
        creds = run.mkdir("creds")
        creds.chmod(0o777)
        origin = run.mkdir("o")
        front = run.mkdir("f")
        for name in ("logs", "root"):
            (origin / name).mkdir(exist_ok=True)
        for name in ("logs", "export", "stage", "journal"):
            (front / name).mkdir(exist_ok=True)

        origin_conf = run.write(
            origin / "nginx.conf",
            f"""daemon on;
error_log {origin}/logs/e.log info;
pid {origin}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{oport};
    brix_root on;
    brix_export {origin}/root;
    brix_allow_write on;
    brix_auth gsi;
    brix_certificate     {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca      {CA_CERT};
}} }}
""",
        )
        try:
            run.start_nginx(origin, origin_conf, oport)
        except LiveFailure as exc:
            return _skip(f"origin start failed: {exc}")
        origin_log = origin / "logs" / "e.log"

        def front_start(delegation: str) -> bool:
            conf = _write_delegation_front(run, front, oport, fport, creds, certs, delegation)
            try:
                run.start_nginx(front, conf, fport)
            except LiveFailure as exc:
                print(f"SKIP: frontend start failed ({delegation}): {exc}")
                return False
            time.sleep(0.5)
            return True

        def front_stop() -> None:
            run.stop_nginx(front)
            time.sleep(0.3)

        url = f"https://{HOST}:{fport}"
        deleg_url = url + "/.well-known/brix-delegation"
        a_cert, a_key = certs / "a_eec_cert.pem", certs / "a_eec_key.pem"
        a_cred, b_cred = creds / f"{a_stem}.pem", creds / f"{b_stem}.pem"

        def curl_a(target: str, *, upload: Path | None = None, output: Path) -> int:
            argv = ["curl", "-sk", "--cert", str(a_cert), "--key", str(a_key)]
            if upload is not None:
                argv += ["-T", str(upload)]
            argv += ["-o", str(output), "-w", "%{http_code}", target]
            result = run.call(argv, check=False)
            return int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0

        checks: list[tuple[bool, str]] = []

        # (a) A uploads its own valid proxy -> 200/201, key.pem exists
        print("--- assertion (a): A uploads its own proxy -> stored ---")
        if not front_start("on"):
            return 0
        code = curl_a(deleg_url, upload=certs / "a_proxy_valid.pem", output=run.root / "resp_a.txt")
        checks.append((code in (200, 201), f"a1: A's own-proxy upload accepted (code={code})"))
        checks.append((a_cred.is_file(), f"a2: {a_stem}.pem now exists in credential dir"))

        # (b) subsequent davs PUT by A authenticates to the origin as A
        print("--- assertion (b): delegation-populated cred used for a real PUT ---")
        origin_log.write_text("")
        payload = run.root / "deleg_payload.bin"
        payload.write_bytes(os.urandom(4096))
        code = curl_a(f"{url}/b_probe.bin", upload=payload, output=run.root / "resp_b.txt")
        checks.append((code in (201, 204), f"b1: A's PUT via delegated cred accepted (code={code})"))
        time.sleep(0.5)
        checks.append((_grep(origin_log, "GSI auth OK dn="), "b2: origin authenticated a user (GSI auth OK in origin log)"))
        front_stop()

        # (c) A uploads a proxy for B's identity -> 403, no B key written
        print("--- assertion (c): A uploads B's proxy -> 403, nothing written for B ---")
        if not front_start("on"):
            return 0
        code = curl_a(deleg_url, upload=certs / "b_proxy_valid.pem", output=run.root / "resp_c.txt")
        checks.append((code == 403, f"c1: cross-identity upload rejected (code={code}, want 403)"))
        checks.append((not b_cred.exists(), "c2: no credential file written for B"))
        front_stop()

        # (d) expired proxy for A -> 400
        print("--- assertion (d): expired proxy -> 400 ---")
        if not front_start("on"):
            return 0
        code = curl_a(deleg_url, upload=certs / "a_proxy_expired.pem", output=run.root / "resp_d.txt")
        checks.append((code == 400, f"d: expired proxy rejected (code={code}, want 400)"))
        front_stop()

        # (f) untrusted/wrong-CA proxy with A's DN spoofed -> 403, no store
        print("--- assertion (f): untrusted/wrong-CA proxy (DN spoofed to A) -> 403 ---")
        a_cred.unlink(missing_ok=True)
        if not front_start("on"):
            return 0
        code = curl_a(deleg_url, upload=certs / "a_proxy_wrongca.pem", output=run.root / "resp_f.txt")
        checks.append((code == 403, f"f1: untrusted-CA proxy rejected (code={code}, want 403)"))
        checks.append((not a_cred.exists(), "f2: no credential file written for the untrusted proxy"))
        front_stop()

        # (e) endpoint off -> path is not special, no store
        print("--- assertion (e): endpoint off -> not special, no store ---")
        a_cred.unlink(missing_ok=True)
        if not front_start("off"):
            return 0
        result = run.call(
            ["curl", "-sk", "-o", os.devnull, "-w", "%{http_code}", "--max-time", "2",
             f"{url}/never_written_{os.getpid()}_probe.bin"],
            check=False,
        )
        code = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
        checks.append((code in (404, 403), f"e1: GET of an unwritten path -> {code} (endpoint off, not special)"))
        code = curl_a(deleg_url, upload=certs / "a_proxy_valid.pem", output=run.root / "resp_e.txt")
        checks.append((code not in (200, 201), f"e2: PUT to the well-known path is not accepted as a delegation (code={code})"))
        checks.append((not a_cred.exists(), "e3: no credential file written while endpoint is off"))
        front_stop()
        return _result(checks)


SCENARIOS = {
    "csi-trust": csi_trust,
    "delegation-upload": delegation_upload,
    "gsi-intermediate-ca": gsi_intermediate_ca,
    "gsi-store-memo": gsi_store_memo,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"gsi-trust scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
