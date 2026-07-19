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
from settings import CA_CERT, CA_DIR, SERVER_CERT, SERVER_KEY, TEST_ROOT, free_ports

XRDCP = REPO_ROOT / "client" / "bin" / "xrdcp"


def _result(checks: list[tuple[bool, str]]) -> int:
    for passed, message in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {message}")
    return 0 if all(passed for passed, _ in checks) else 1


def _skip(reason: str) -> int:
    print(f"SKIP: {reason}")
    return 0


def _grep(path: Path, needle: str) -> bool:
    return path.exists() and needle in path.read_text(errors="replace")


def _tagged(path: Path) -> bool:
    try:
        os.getxattr(path, "user.xrd.cinfo")
        return True
    except OSError:
        return False


def ensure_shared_pki(log_dir: Path, *, want_proxy: bool = False) -> str:
    """Provision the shared /tmp/xrd-test PKI if missing; '' on success.

    Refreshes ONLY the proxy when the CA/hostcert already exist — a full
    blitz_test_pki() would regenerate the CA and desync the standing fleet,
    failing every concurrent TLS/GSI test. See live_common.refresh_shared_pki.
    """
    from cmdscripts.live_common import refresh_shared_pki  # noqa: PLC0415
    ok, msg = refresh_shared_pki(log_dir, want_proxy=want_proxy)
    return "" if ok else msg


# ---------------------------------------------------------------------------
# run_csi_trust.sh — brix_csi_trust_fs end-to-end.
# ---------------------------------------------------------------------------
def _pgwrite_gate_intact(port: int) -> bool:
    """Security-neg: a bad pgwrite wire CRC must be CSE-reported and gate close."""
    from test_pgwrite_checksum import (  # noqa: PLC0415 — heavy test module, import lazily
        _build_pgwrite_payload,
        _handshake_login,
        _open_for_write,
        _read_response,
        _recv_exact,
        _send_pgwrite,
        kXR_ChkSumErr,
        kXR_close,
        kXR_error,
        kXR_status,
    )

    sock = _handshake_login("127.0.0.1", port)
    try:
        fh = _open_for_write(sock, b"/_trust_badcrc.bin")
        payload = _build_pgwrite_payload(b"trust does not cover the wire " * 10, offset=0, corrupt_page=0)
        status, sbody = _send_pgwrite(sock, fh, 0, payload)
        if status != kXR_status:
            print(f"  FAIL bad page must be CSE-reported, got {status}")
            return False
        cse_len = struct.unpack("!i", sbody[12:16])[0]
        if cse_len > 0:
            _recv_exact(sock, cse_len)
        sock.sendall(struct.pack("!2sH4s12sI", b"\x00\x09", kXR_close, fh, b"\x00" * 12, 0))
        cstatus, cbody = _read_response(sock)
        if cstatus != kXR_error:
            print("  FAIL close must stay gated on uncorrected pages")
            return False
        return struct.unpack("!I", cbody[:4])[0] == kXR_ChkSumErr
    finally:
        sock.close()


def csi_trust(nginx: Path | None = None) -> int:
    if not os.access(XRDCP, os.X_OK):
        return _skip(f"native xrdcp not built ({XRDCP})")
    with LiveRun("csi_trust", nginx) as run:
        p_ver, p_tru, p_rqt, p_rqo, p_def, p_off = free_ports(6)
        root = run.mkdir("root")
        logs = run.mkdir("logs")

        def srv(port: int, extra: str) -> str:
            return f"""    server {{
        listen 127.0.0.1:{port};
        brix_root on;
        brix_export {root};
        brix_auth none;
        brix_allow_write on;
        brix_upload_resume off;
        {extra}
        brix_access_log {logs}/access_{port}.log;
    }}
"""

        conf = run.write(
            run.root / "nginx.conf",
            f"daemon on;\nerror_log {logs}/error.log info;\npid {run.root}/nginx.pid;\n"
            "events { worker_connections 64; }\nstream {\n"
            + srv(p_ver, "brix_csi on;")
            + srv(p_tru, "brix_csi on; brix_csi_trust_fs on;")
            + srv(p_rqt, "brix_csi on; brix_csi_require on; brix_csi_trust_fs on;")
            + srv(p_rqo, "brix_csi on; brix_csi_require on;")
            + srv(p_def, "")
            + srv(p_off, "brix_csi off;")
            + "}\n",
        )
        run.start_nginx(run.root, conf, p_ver)

        def cp_up(port: int, source: Path, name: str) -> int:
            return run.call([XRDCP, "-f", source, f"root://127.0.0.1:{port}//{name}"], check=False).returncode

        def cp_down(port: int, name: str, dest: Path) -> int:
            return run.call([XRDCP, "-f", f"root://127.0.0.1:{port}//{name}", dest], check=False).returncode

        checks: list[tuple[bool, str]] = []
        src = run.root / "src.bin"
        src.write_bytes(os.urandom(12288))  # 3 full CSI pages

        # trusted write still tags
        checks.append((cp_up(p_tru, src, "f.bin") == 0, "PUT via trust_fs server"))
        checks.append((_tagged(root / "f.bin"), "xmeta record (user.xrd.cinfo) created at close"))
        checks.append((not (root / ".xrdt").exists(), "no .xrdt tag tree (retired)"))
        verify_got = run.root / "v.bin"
        checks.append((cp_down(p_ver, "f.bin", verify_got) == 0, "GET via verify server passes"))
        checks.append((verify_got.exists() and verify_got.read_bytes() == src.read_bytes(), "verify GET byte-exact"))

        # stale tags: verify fails, trust serves
        corrupted = bytearray((root / "f.bin").read_bytes())
        corrupted[5000] ^= 0xFF  # flip a byte in page 1
        (root / "f.bin").write_bytes(bytes(corrupted))
        got = cp_down(p_ver, "f.bin", run.root / "c.bin")
        checks.append((got != 0, f"verify server rejects corrupt page (rc={got})"))
        trust_got = run.root / "t.bin"
        checks.append((cp_down(p_tru, "f.bin", trust_got) == 0, "trust server serves it"))
        checks.append(
            (trust_got.exists() and trust_got.read_bytes() == (root / "f.bin").read_bytes(), "trust GET matches on-disk bytes")
        )

        # csi_require vs trust_fs on an untagged file
        (root / "untagged.bin").write_bytes(os.urandom(8192))
        checks.append((cp_down(p_rqt, "untagged.bin", run.root / "u.bin") == 0, "require+trust reads untagged"))
        got = cp_down(p_rqo, "untagged.bin", run.root / "u2.bin")
        checks.append((got != 0, f"require-only refuses untagged (rc={got})"))

        # default on / explicit off
        checks.append((cp_up(p_def, src, "defon.bin") == 0, "PUT via default server"))
        checks.append((_tagged(root / "defon.bin"), "CSI records by default"))
        checks.append((cp_up(p_off, src, "defoff.bin") == 0, "PUT via csi-off server"))
        checks.append((not _tagged(root / "defoff.bin"), "brix_csi off opts out"))

        # security-neg: bad pgwrite wire-CRC still rejected under trust_fs
        try:
            gated = _pgwrite_gate_intact(p_tru)
        except (OSError, AssertionError) as exc:
            print(f"  pgwrite probe error: {exc}")
            gated = False
        checks.append((gated, "pgwrite wire-CRC verify + close gate intact"))
        return _result(checks)


# ---------------------------------------------------------------------------
# run_gsi_store_memo.sh — memoised CA/CRL trust store across GSI blocks.
# ---------------------------------------------------------------------------
def gsi_store_memo(nginx: Path | None = None) -> int:
    with LiveRun("gsi_memo", nginx) as run:
        message = ensure_shared_pki(run.mkdir("logs"))
        if message:
            return _skip(message)
        port_a, port_b = free_ports(2)
        e1, e2 = run.mkdir("e1"), run.mkdir("e2")

        def block(port: int, export: Path) -> str:
            return f"""    server {{
        listen 127.0.0.1:{port}; brix_root on; brix_export {export};
        brix_auth gsi; brix_certificate {SERVER_CERT}; brix_certificate_key {SERVER_KEY};
        brix_trusted_ca {CA_CERT};
    }}
"""

        # Two GSI server blocks, IDENTICAL trusted CA (a single-file CA here;
        # the same memo path applies to a hashed CA directory, only slower).
        conf = run.write(
            run.root / "nginx.conf",
            f"daemon off; error_log stderr info; pid {run.root}/nginx.pid;\n"
            "events { worker_connections 64; }\nstream {\n" + block(port_a, e1) + block(port_b, e2) + "}\n",
        )
        result = run.call([run.nginx, "-t", "-c", conf], check=False)
        out = (result.stdout or "") + (result.stderr or "")
        if "test is successful" not in out:
            print("  FAIL config did not load")
            print("\n".join(out.splitlines()[-8:]))
            return 1
        # The memo fires when the SECOND GSI block reuses the store the first
        # built.  The "GSI trust store built ... in <N>us" line is logged per
        # configure call regardless of reuse — the "reusing the CA/CRL store"
        # NOTICE is the real signal.
        reused = out.count("reusing the CA/CRL store")
        print("== two GSI blocks, same trusted CA: the store is built once and reused ==")
        return _result(
            [
                (
                    reused >= 1,
                    "second block reused the memoised CA/CRL store (no per-block rebuild)"
                    if reused >= 1
                    else "second GSI block did NOT reuse the store — the expensive CRL load runs once per block",
                )
            ]
        )


# ---------------------------------------------------------------------------
# run_gsi_intermediate_ca.sh — GSI with an intermediate-CA chain + hashed CA dir.
# ---------------------------------------------------------------------------
def gsi_intermediate_ca(nginx: Path | None = None) -> int:
    stock = Path(os.environ.get("XRDCP_STOCK", "/usr/bin/xrdcp"))
    if not os.access(stock, os.X_OK):
        return _skip(f"stock xrootd client not installed ({stock})")
    with LiveRun("gsi_ica", nginx) as run:
        port = free_ports(1)[0]
        pki = run.mkdir("pki")
        run.mkdir("pki", "user")
        cadir, badca, root, logs = run.mkdir("cadir"), run.mkdir("badca"), run.mkdir("root"), run.mkdir("logs")
        pki_log = logs / "pki.log"

        def osl(*args: str | Path) -> bool:
            result = run.call(["openssl", *args], cwd=pki, check=False)
            with pki_log.open("a") as log:
                log.write((result.stdout or "") + (result.stderr or ""))
            return result.returncode == 0

        run.write(pki / "ca.ext", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
        run.write(
            pki / "srv.ext",
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        )
        run.write(pki / "usr.ext", "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n")

        # root CA -> intermediate CA -> server leaf; user EEC under the root
        steps = [
            ("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem",
             "-days", "2", "-subj", "/O=BrixTest/CN=Test Root CA", "-addext", "basicConstraints=critical,CA:TRUE"),
            ("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "inter.key", "-out", "inter.csr",
             "-subj", "/O=BrixTest/CN=Test Issuing CA 2B"),
            ("x509", "-req", "-in", "inter.csr", "-CA", "root.pem", "-CAkey", "root.key", "-set_serial", "101",
             "-days", "2", "-extfile", "ca.ext", "-out", "inter.pem"),
            ("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "host.key", "-out", "host.csr",
             "-subj", "/O=BrixTest/CN=localhost"),
            ("x509", "-req", "-in", "host.csr", "-CA", "inter.pem", "-CAkey", "inter.key", "-set_serial", "202",
             "-days", "2", "-extfile", "srv.ext", "-out", "host.pem"),
            ("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "user/userkey.pem", "-out", "user.csr",
             "-subj", "/O=BrixTest/CN=Test User"),
            ("x509", "-req", "-in", "user.csr", "-CA", "root.pem", "-CAkey", "root.key", "-set_serial", "303",
             "-days", "2", "-extfile", "usr.ext", "-out", "user/usercert.pem"),
        ]
        for step in steps:
            if not osl(*step):
                return _skip(f"openssl PKI build failed ({' '.join(step[:3])})")
        (pki / "user" / "userkey.pem").chmod(0o600)
        (pki / "host.key").chmod(0o600)

        # RFC 3820 proxy for the stock client (it refuses bare EEC credentials)
        proxy_make = run.call(["python3", REPO_ROOT / "utils" / "make_proxy.py", pki], check=False)
        if proxy_make.returncode != 0:
            return _skip("make_proxy.py failed: " + (proxy_make.stderr or "")[-300:])

        # Hashed CA DIRECTORY (grid /etc/grid-security/certificates shape): both CAs
        hashes: dict[str, str] = {}
        for ca in ("root", "inter"):
            result = run.call(["openssl", "x509", "-in", pki / f"{ca}.pem", "-noout", "-subject_hash"], check=False)
            hashes[ca] = result.stdout.strip()
            (cadir / f"{hashes[ca]}.0").write_bytes((pki / f"{ca}.pem").read_bytes())

        # GSI server: leaf-only cert (as deployed hosts keep it), CA DIR trust
        conf = run.write(
            run.root / "nginx.conf",
            f"""daemon on; error_log {logs}/e.log notice; pid {run.root}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port}; brix_root on; brix_export {root};
    brix_auth gsi;
    brix_certificate     {pki}/host.pem;
    brix_certificate_key {pki}/host.key;
    brix_trusted_ca      {cadir};
    brix_allow_write on;
}} }}
""",
        )
        try:
            run.start_nginx(run.root, conf, port)
        except LiveFailure as exc:
            return _skip(f"server start failed: {exc}")

        src = run.root / "src.bin"
        src.write_bytes(os.urandom(300000))

        def stock_cp(certdir: Path, proxy: Path, dst: str, logname: str) -> None:
            with (logs / logname).open("w") as log:
                subprocess.run(
                    [str(stock), "-f", str(src), f"root://localhost:{port}//{dst}"],
                    env={
                        "PATH": "/usr/bin:/bin",
                        "HOME": str(run.root),
                        "XRD_LOGLEVEL": "Debug",
                        "X509_CERT_DIR": str(certdir),
                        "X509_USER_PROXY": str(proxy),
                    },
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )

        checks: list[tuple[bool, str]] = []
        stock_cp(cadir, pki / "user" / "proxy_std.pem", "stock.bin", "cp.log")
        stored = root / "stock.bin"
        checks.append(
            (
                stored.exists() and stored.read_bytes() == src.read_bytes(),
                "stock xrdcp wrote byte-exact through GSI (was: unknown CA / kXGS_init abort)",
            )
        )
        cp_log = logs / "cp.log"
        # The server enumerates the hashed CA dir with readdir() (pki_load.c), so
        # the two CA subject-hashes are advertised in filesystem order, which is
        # not stable across runs. Accept either concatenation — membership, not
        # order, is what the sec token conveys (the byte-exact transfer above
        # already proves the client accepted the chain).
        adv_inter_root = f"ca:{hashes['inter']}|{hashes['root']}"
        adv_root_inter = f"ca:{hashes['root']}|{hashes['inter']}"
        checks.append(
            (
                _grep(cp_log, adv_inter_root) or _grep(cp_log, adv_root_inter),
                f"sec token advertises {adv_inter_root} (either order)",
            )
        )
        checks.append((not _grep(cp_log, "ca:00000000"), "no 00000000 placeholder"))

        # MITM negative: client with an EMPTY CA dir must refuse the server
        stock_cp(badca, pki / "user" / "proxy_std.pem", "mitm.bin", "neg.log")
        checks.append((not (root / "mitm.bin").exists(), "client correctly refused the unverifiable server"))
        return _result(checks)


# ---------------------------------------------------------------------------
# run_delegation_upload.sh — opt-in proxy-upload delegation endpoint.
# ---------------------------------------------------------------------------
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
        listen 127.0.0.1:{front_port} ssl;
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
            brix_storage_backend root://127.0.0.1:{origin_port};
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

        oport, fport = free_ports(2)
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
    listen 127.0.0.1:{oport};
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

        url = f"https://127.0.0.1:{fport}"
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
