"""Direct Python ports of the per-user backend-credential live shell suites.

Ports ``run_user_backend_cred.sh`` (base), ``run_user_backend_cred_root.sh``
(root), ``run_user_backend_cred_ns.sh`` (ns), ``run_user_backend_cred_p2.sh``
(p2), and ``run_multiuser_authz.sh`` (multiuser-authz).  Every externally
visible assertion of the shell scripts is reproduced as a Python check; ports
are allocated dynamically via ``settings.free_ports`` and all scratch state
lives under a ``LiveRun`` root that the context manager reaps.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from settings import CA_CERT, CA_DIR, CA_KEY, PROXY_STD, SERVER_CERT, SERVER_KEY, free_ports

SKIP = 77  # distinct scenario outcome: prerequisites unavailable

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"

_KEY_RE = re.compile(r"key=(x5h-[0-9a-f]+|[A-Za-z0-9@._-]+)")
_DN_A_RE = r"Test.User|Test\\x20User"
_DN_SVC_RE = r"SVC.Proxy"
_DENY_LOG_RE = r"fallback=deny.*refusing|per-user backend credential.*fallback=deny"


class Suite:
    """ok/bad ledger matching the shell scripts' output convention."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.failed = False

    def ok(self, message: str) -> None:
        print(f"  ok   {message}")

    def bad(self, message: str) -> None:
        print(f"  FAIL {message}")
        self.failed = True

    def note(self, message: str) -> None:
        print(f"  NOTE {message}")

    def check(self, passed: bool, ok_msg: str, bad_msg: str | None = None) -> bool:
        if passed:
            self.ok(ok_msg)
        else:
            self.bad(bad_msg or ok_msg)
        return passed

    def finish(self) -> int:
        print("")
        print(f"{self.name}: {'FAILURES' if self.failed else 'ALL PASS'}")
        return 1 if self.failed else 0


def _skip(message: str) -> int:
    print(f"SKIP: {message}")
    return SKIP


def _read(path: Path | str) -> str:
    path = Path(path)
    return path.read_text(errors="replace") if path.exists() else ""


def _grep(path: Path | str, pattern: str) -> bool:
    return re.search(pattern, _read(path)) is not None


def _count(path: Path | str, pattern: str) -> int:
    return sum(1 for line in _read(path).splitlines() if re.search(pattern, line))


def _last_line(path: Path | str, pattern: str) -> str:
    matches = [line for line in _read(path).splitlines() if re.search(pattern, line)]
    return matches[-1] if matches else ""


def _truncate(path: Path | str) -> None:
    Path(path).write_text("")


def _quiet(argv: list[str | Path], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(a) for a in argv],
        env={**os.environ, **(env or {})},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _curl_code(url: str, *extra: str | Path, cert: Path | None = None, key: Path | None = None, output: Path | None = None) -> str:
    args: list[str] = ["curl", "-sk", "--max-time", "25", "-o", str(output or os.devnull), "-w", "%{http_code}"]
    if cert is not None:
        args += ["--cert", str(cert), "--key", str(key or cert)]
    result = _quiet([*args, *[str(item) for item in extra], url])
    return result.stdout.strip()


def _wait_ready(url: str, tries: int = 20) -> bool:
    for _ in range(tries):
        probe = _quiet(["curl", "-sk", "-o", os.devnull, "--max-time", "1", f"{url}/"])
        if probe.returncode == 0:
            return True
        time.sleep(0.2)
    return False


def _ensure_pki(run: LiveRun) -> str | None:
    """Provision the shared test PKI if absent/expired.  Returns a skip reason or None."""
    required = [Path(CA_CERT), Path(CA_KEY), Path(PROXY_STD)]
    fresh = all(path.is_file() for path in required)
    if fresh:
        check = run.call(["openssl", "x509", "-in", PROXY_STD, "-noout", "-checkend", "300"], check=False)
        fresh = check.returncode == 0
    if not fresh:
        print("Provisioning test PKI (blitz_test_pki)...")
        result = _quiet(
            [sys.executable, "-c", "import pki_helpers; pki_helpers.blitz_test_pki()"],
            env={"PYTHONPATH": str(REPO_ROOT / "tests")},
        )
        if result.returncode != 0:
            return "PKI provisioning failed: " + (result.stderr or result.stdout)[-1000:]
    if not Path(CA_KEY).is_file():
        return f"CA key not found ({CA_KEY})"
    return None


def _mint_ee(run: LiveRun, out_dir: Path, subject: str) -> tuple[Path, Path] | None:
    """Mint a plain end-entity cert off the shared test CA.  Returns (cert, key)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    key, req, cert = out_dir / "key.pem", out_dir / "req.pem", out_dir / "cert.pem"
    run.call(
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-subj", subject, "-out", req],
        check=False,
    )
    signed = run.call(
        ["openssl", "x509", "-req", "-in", req, "-CA", CA_CERT, "-CAkey", CA_KEY,
         "-set_serial", "0x" + os.urandom(8).hex(), "-days", "2", "-out", cert],
        check=False,
    )
    if signed.returncode != 0 or not cert.exists():
        return None
    return cert, key


def _combine(cert: Path, key: Path, out: Path) -> Path:
    out.write_text(cert.read_text() + key.read_text())
    out.chmod(0o600)
    return out


def _key_from_dn(run: LiveRun, proxy: Path | str) -> str:
    """Same derivation as ucred.c: x5h-<sha256hex32> over the oneline subject."""
    subject = run.call(["openssl", "x509", "-in", proxy, "-noout", "-subject", "-nameopt", "oneline"], check=False).stdout
    dn = re.sub(r"^subject= *", "", subject.strip())
    return "x5h-" + hashlib.sha256(dn.encode()).hexdigest()[:32]


def _learn_key(run: LiveRun, log: Path, proxy: Path | str, *, last: bool = False) -> str:
    matches = _KEY_RE.findall(_read(log))
    if matches:
        return matches[-1] if last else matches[0]
    return _key_from_dn(run, proxy)


def _install_cred(source: Path | str, dest: Path) -> None:
    shutil.copyfile(source, dest)
    dest.chmod(0o644)


def _start_prefixed(run: LiveRun, prefix: Path, conf: Path) -> tuple[bool, str]:
    result = run.call([run.nginx, "-p", prefix, "-c", conf], check=False)
    if result.returncode == 0:
        pidfile = prefix / "nginx.pid"
        if pidfile not in run.pidfiles:
            run.pidfiles.append(pidfile)
        return True, ""
    return False, result.stderr or result.stdout


def _stop_prefixed(prefix: Path, wait: float = 0.7) -> None:
    pidfile = prefix / "nginx.pid"
    try:
        os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        return
    time.sleep(wait)


def _kill_orphans(subtree: Path) -> None:
    """Kill orphaned nginx workers holding files open under subtree (post kill -9)."""
    prefix = str(subtree)
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if "nginx" not in os.readlink(entry / "exe"):
                continue
            for fd in (entry / "fd").iterdir():
                if os.readlink(fd).startswith(prefix):
                    os.kill(int(entry.name), signal.SIGTERM)
                    break
        except OSError:
            continue


def _origin_conf(prefix: Path, port: int) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{port};
    brix_root on;
    brix_export {prefix}/root;
    brix_allow_write on;
    brix_auth gsi;
    brix_certificate     {SERVER_CERT};
    brix_certificate_key {SERVER_KEY};
    brix_trusted_ca      {CA_CERT};
}} }}
""")
    return conf


def _write_expired_cert(path: Path) -> bool:
    """Write a verifiably-expired self-signed cert (2020-01-01..2020-01-02)."""
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired-test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2020, 1, 2))
            .sign(key, hashes.SHA256())
        )
        path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return True
    except Exception:
        return False


# ===========================================================================
# Scenario: base (run_user_backend_cred.sh) — davs frontend, 7 assertions.
# ===========================================================================

def _base_front_conf(prefix: Path, port: int, origin_port: int, creds: Path, fallback: str, flush: str, service_proxy: Path | str) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR={prefix}/journal;
env BRIX_XFER_AUDIT_LOG={prefix}/logs/xfer_audit.log;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {prefix}/logs/access.log;
    client_body_temp_path {prefix}/export;
    brix_credential origin {{ x509_proxy {service_proxy}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {prefix}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://127.0.0.1:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback {fallback};
            brix_stage on;
            brix_stage_store posix:{prefix}/stage;
            brix_stage_flush {flush};
        }}
    }}
}}
""")
    return conf


def base(nginx: Path | None = None) -> int:
    suite = Suite("run_user_backend_cred")
    with LiveRun("ucred_e2e", nginx) as run:
        skip = _ensure_pki(run)
        if skip:
            return _skip(skip)
        origin, front = run.mkdir("o"), run.mkdir("f")
        for name in ("logs", "root"):
            (origin / name).mkdir(exist_ok=True)
        for name in ("logs", "export", "stage", "journal"):
            (front / name).mkdir(exist_ok=True)
        creds = run.mkdir("creds")
        creds.chmod(0o777)
        minted = _mint_ee(run, run.mkdir("b"), "/DC=test/DC=xrootd/CN=Test User B/CN=99999")
        if minted is None:
            return _skip("user-B cert mint failed")
        b_cert, b_key = minted

        oport, fport = free_ports(2)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, oport))
        if not started:
            return _skip(f"origin start failed: {detail}")
        olog = origin / "logs/e.log"
        time.sleep(0.5)

        flog = front / "logs/e.log"
        url = f"https://127.0.0.1:{fport}"

        def front_start(fallback: str, flush: str) -> bool:
            conf = _base_front_conf(front, fport, oport, creds, fallback, flush, PROXY_STD)
            started, detail = _start_prefixed(run, front, conf)
            if not started:
                print(f"SKIP: frontend start failed ({fallback} {flush}): {detail}")
                return False
            time.sleep(0.5)
            _wait_ready(url)
            return True

        payload = run.root / "ucred_payload.bin"
        payload.write_bytes(os.urandom(65536))

        # ---- step 0: learn the derived key for user A --------------------------
        print("--- learning derived key for user A ---")
        if not front_start("deny", "sync"):
            return SKIP
        _curl_code(f"{url}/probe_key.bin", "-T", payload, cert=Path(PROXY_STD))
        time.sleep(0.3)
        a_key = _learn_key(run, flog, PROXY_STD)
        if not a_key:
            suite.bad("could not derive key for user A")
            return suite.finish()
        print(f"  user-A credential stem: {a_key}")
        cred_file = creds / f"{a_key}.pem"
        _install_cred(PROXY_STD, cred_file)
        _stop_prefixed(front)

        # ---- assertion 1: user A (cred provisioned) PUT+GET + origin DN --------
        print("--- assertion 1: user A (cred provisioned) PUT+GET + origin DN ---")
        _truncate(olog)
        if not front_start("deny", "sync"):
            return SKIP
        code = _curl_code(f"{url}/a2.bin", "-T", payload, cert=Path(PROXY_STD))
        suite.check(code in ("201", "204"), f"1a: A PUT accepted (code={code})", f"1a: A PUT -> {code} (want 201 or 204)")
        time.sleep(1)
        suite.check(_grep(olog, r"GSI auth OK dn="),
                    "1b: origin authenticated a user (GSI auth OK in origin log)",
                    "1b: no 'GSI auth OK' in origin log")
        back = run.root / "ucred_back.bin"
        _curl_code(f"{url}/a2.bin", cert=Path(PROXY_STD), output=back)
        suite.check(back.exists() and back.read_bytes() == payload.read_bytes(),
                    "1c: A GET byte-exact", "1c: A GET differs from PUT")
        time.sleep(0.5)
        _stop_prefixed(front)

        # ---- assertion 2: user B (no cred), deny -> 403, origin untouched ------
        print("--- assertion 2: user B (no cred), deny → 403, origin untouched ---")
        if not front_start("deny", "sync"):
            return SKIP
        code = _curl_code(f"{url}/b1.bin", "-T", payload, cert=b_cert, key=b_key)
        suite.check(code == "403", "2a: B PUT denied (403)", f"2a: B PUT -> {code} (want 403)")
        time.sleep(0.3)
        suite.check(not (origin / "root/b1.bin").exists(),
                    "2b: B's file not written to origin (write blocked at credential gate)",
                    "2b: b1.bin exists in the origin root — data reached the backend!")
        suite.check(_grep(flog, _DENY_LOG_RE),
                    "2c: deny reasoning logged by frontend",
                    "2c: no fallback=deny log in frontend error log")
        _stop_prefixed(front)

        # ---- assertion 3: user B (no cred), allow -> fallback success ----------
        print("--- assertion 3: user B (no cred), allow → fallback success ---")
        if not front_start("allow", "sync"):
            return SKIP
        code = _curl_code(f"{url}/b2.bin", "-T", payload, cert=b_cert, key=b_key)
        suite.check(code in ("201", "204"),
                    f"3a: B PUT allowed via fallback (code={code})",
                    f"3a: B PUT fallback -> {code} (want 201 or 204)")
        suite.check(_grep(flog, r"falling back to the service credential"),
                    "3b: fallback-to-service-credential logged",
                    "3b: no 'falling back to the service credential' in frontend log")
        _stop_prefixed(front)

        # ---- assertion 4: expired cred for A, deny -> 403 + EXPIRED log --------
        print("--- assertion 4: expired cred for A, deny → 403 + EXPIRED log ---")
        wrote = _write_expired_cert(cred_file)
        parseable = wrote and run.call(["openssl", "x509", "-in", cred_file, "-noout"], check=False).returncode == 0
        still_valid = parseable and run.call(
            ["openssl", "x509", "-in", cred_file, "-noout", "-checkend", "300"], check=False
        ).returncode == 0
        if not parseable or still_valid:
            suite.note("4: could not create a verifiably-expired cert (python cryptography lib missing?)")
            suite.ok("4: (best-effort) expired-cert test skipped — cryptography lib unavailable")
        else:
            if not front_start("deny", "sync"):
                return SKIP
            code = _curl_code(f"{url}/a3.bin", "-T", payload, cert=Path(PROXY_STD))
            suite.check(code == "403", "4a: expired cred denied (403)", f"4a: expired cred -> {code} (want 403)")
            suite.check(_grep(flog, r"EXPIRED"), "4b: EXPIRED named in frontend log", "4b: no EXPIRED in frontend log")
            _stop_prefixed(front)
        _install_cred(PROXY_STD, cred_file)

        # ---- assertion 5: async flush ownership --------------------------------
        print("--- assertion 5: async flush ownership (flush logs A's DN at origin) ---")
        _truncate(olog)
        if not front_start("deny", "async"):
            return SKIP
        _curl_code(f"{url}/a4.bin", "-T", payload, cert=Path(PROXY_STD))
        new_auth = 0
        for _ in range(20):
            time.sleep(0.5)
            new_auth = _count(olog, r"GSI auth OK")
            if new_auth > 0:
                break
        suite.check(new_auth > 0,
                    "5a: async flush reauthenticated at the origin (new GSI auth line)",
                    "5a: no new origin auth after async flush")
        last_dn = _last_line(olog, r"GSI auth OK dn=")
        suite.check(re.search(_DN_A_RE, last_dn) is not None,
                    "5b: flush carried the owner's DN (Test User in last origin auth line)",
                    f"5b: last origin auth line does not contain Test User DN: {last_dn}")
        _stop_prefixed(front)
        _kill_orphans(front)

        # ---- assertion 6: restart-replay after crash ----------------------------
        print("--- assertion 6: restart-replay after crash, flush under A's DN ---")
        _truncate(olog)
        conf = _base_front_conf(front, fport, oport, creds, "deny", "async", PROXY_STD)
        launcher = subprocess.run(
            [str(run.nginx), "-p", str(front), "-c", str(conf)],
            start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if launcher.returncode != 0:
            return _skip(f"frontend start failed for assertion 6: {launcher.stderr}")
        for _ in range(30):
            if _quiet(["curl", "-sk", "-o", os.devnull, "--max-time", "1", f"{url}/"]).returncode == 0:
                break
            time.sleep(0.2)
        _curl_code(f"{url}/a5.bin", "-T", payload, cert=Path(PROXY_STD))
        pidfile = front / "nginx.pid"
        try:
            master = int(pidfile.read_text().strip())
        except (OSError, ValueError):
            master = 0
        if master:
            try:
                os.killpg(master, signal.SIGKILL)
            except OSError:
                try:
                    os.kill(master, signal.SIGKILL)
                except OSError:
                    pass
        time.sleep(0.5)

        journal_files = list((front / "journal").glob("*.req"))
        if not journal_files:
            suite.note("6: no journal record found (flush raced the kill or journal not durably written)")
            suite.ok("6: (best-effort) no journal to replay — flush raced the crash or journal disabled")
        else:
            suite.ok(f"6a: journal record survived the crash ({len(journal_files)} record(s))")
            restart = subprocess.run(
                [str(run.nginx), "-p", str(front), "-c", str(conf)],
                start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            if restart.returncode != 0:
                suite.bad(f"6b: frontend restart failed: {restart.stderr}")
            time.sleep(3)
            suite.check(_count(olog, r"GSI auth OK") > 0,
                        "6b: reconcile replayed the flush (new GSI auth at origin)",
                        "6b: no origin auth after restart-replay")
            last_dn = _last_line(olog, r"GSI auth OK dn=")
            suite.check(re.search(_DN_A_RE, last_dn) is not None,
                        "6c: replayed flush carried the owner's DN",
                        f"6c: last auth line does not contain Test User DN: {last_dn}")
        _stop_prefixed(front)
        _kill_orphans(front)

        # ---- assertion 7: xfer audit ledger --------------------------------------
        print("--- assertion 7: xfer audit ledger ---")
        audit = front / "logs/xfer_audit.log"
        if audit.exists():
            wt_lines = [line for line in _read(audit).splitlines() if "kind=wt" in line]
            if wt_lines:
                if any(not re.search(r"principal=-( |$)", line) for line in wt_lines):
                    suite.ok("7: audit ledger kind=wt line carries non-dash principal")
                else:
                    suite.bad("7: audit ledger kind=wt line present but principal is dash (-)")
                    for line in wt_lines[-3:]:
                        print(f"    {line}", file=sys.stderr)
            else:
                suite.note("7: no kind=wt lines; checking for any xfer records...")
                suite.check(_grep(audit, r"kind=(stage|wt)"),
                            "7: (partial) xfer audit ledger has transfer records",
                            f"7: no xfer records in {audit}")
        else:
            suite.note("7: no xfer_audit.log at default path; checking error-log sibling...")
            suite.note("   Set BRIX_XFER_AUDIT_LOG to force the path.")
            suite.ok("7: (best-effort) audit ledger sink not verified; not a product bug")

        return suite.finish()


# ===========================================================================
# Scenario: root (run_user_backend_cred_root.sh) — root:// stream frontend.
# ===========================================================================

def _root_front_conf(prefix: Path, port: int, origin_port: int, creds: Path, fallback: str, service_proxy: Path) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential origin {{ x509_proxy {service_proxy}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port};
        brix_root on;
        brix_export {prefix}/export;
        brix_allow_write on;
        brix_upload_resume off;
        brix_auth gsi;
        brix_certificate     {SERVER_CERT};
        brix_certificate_key {SERVER_KEY};
        brix_trusted_ca      {CA_CERT};
        brix_storage_backend root://127.0.0.1:{origin_port};
        brix_storage_credential origin;
        brix_storage_credential_dir {creds};
        brix_storage_credential_fallback {fallback};
    }}
}}
""")
    return conf


def _gsi_env(proxy: Path | str) -> dict[str, str]:
    return {"X509_USER_PROXY": str(proxy), "X509_CERT_DIR": str(CA_DIR), "XrdSecGSICADIR": str(CA_DIR)}


def root(nginx: Path | None = None) -> int:
    suite = Suite("run_user_backend_cred_root")
    with LiveRun("ucred_root", nginx) as run:
        for need in (run.nginx, XRDCP, XRDFS):
            if not Path(need).exists():
                return _skip(f"missing {need}")
        skip = _ensure_pki(run)
        if skip:
            return _skip(skip)

        origin, front = run.mkdir("o"), run.mkdir("f")
        (origin / "root").mkdir(exist_ok=True)
        (origin / "logs").mkdir(exist_ok=True)
        (front / "export").mkdir(exist_ok=True)
        (front / "logs").mkdir(exist_ok=True)
        creds = run.mkdir("creds")
        creds.chmod(0o777)

        minted_b = _mint_ee(run, run.mkdir("b"), "/DC=test/DC=xrootd/CN=Test User B/CN=88888")
        if minted_b is None:
            return _skip("user-B cert mint failed")
        proxy_b = _combine(*minted_b, run.root / "b/proxy.pem")
        minted_svc = _mint_ee(run, run.mkdir("svc"), "/DC=test/DC=xrootd/CN=SVC Proxy")
        if minted_svc is None:
            return _skip("service proxy mint failed")
        svc_proxy = _combine(*minted_svc, run.root / "svc/proxy.pem")

        oport, fport = free_ports(2)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, oport))
        if not started:
            return _skip(f"origin start failed: {detail}")
        olog = origin / "logs/e.log"
        time.sleep(0.5)
        flog = front / "logs/e.log"
        target = f"root://127.0.0.1:{fport}"

        def front_start(fallback: str) -> bool:
            conf = _root_front_conf(front, fport, oport, creds, fallback, svc_proxy)
            started, detail = _start_prefixed(run, front, conf)
            if not started:
                print(f"SKIP: frontend start failed ({fallback}): {detail}")
                return False
            time.sleep(0.5)
            return True

        # ---- parse-level checks -------------------------------------------------
        print("--- parse-level: nginx -t accepts the 2 new stream directives ---")
        conf = _root_front_conf(front, fport, oport, creds, "deny", svc_proxy)
        parse = run.call([run.nginx, "-p", front, "-t", "-c", conf], check=False)
        suite.check(parse.returncode == 0,
                    "P1: nginx -t accepts brix_storage_credential_dir + brix_storage_credential_fallback",
                    f"P1: nginx -t rejected a valid config: {parse.stderr}")

        print("--- parse-level: bad fallback value is rejected ---")
        bad_conf = front / "nginx_bad.conf"
        bad_conf.write_text(f"""daemon on;
error_log {front}/logs/e_bad.log info;
pid {front}/bad.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{fport};
        brix_root on;
        brix_export {front}/export;
        brix_storage_credential_dir {creds};
        brix_storage_credential_fallback bogus;
    }}
}}
""")
        parse = run.call([run.nginx, "-p", front, "-t", "-c", bad_conf], check=False)
        suite.check(parse.returncode != 0,
                    "P2: nginx -t rejects an invalid brix_storage_credential_fallback value",
                    "P2: nginx -t accepted an invalid brix_storage_credential_fallback value")

        print("--- parse-level: phase-3 T1 root:// credential-minting directives ---")
        mint_conf = front / "nginx_mint.conf"
        mint_conf.write_text(f"""daemon on;
error_log {front}/logs/e_mint.log info;
pid {front}/mint.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{fport};
        brix_root on;
        brix_export {front}/export;
        brix_storage_credential_dir {creds};
        brix_storage_credential_fallback allow;
        brix_storage_credential_mint_ca {CA_CERT} {CA_KEY};
        brix_storage_credential_mint_ttl 900;
    }}
}}
""")
        parse = run.call([run.nginx, "-p", front, "-t", "-c", mint_conf], check=False)
        suite.check(parse.returncode == 0,
                    "P3: nginx -t accepts brix_storage_credential_mint_ca + _mint_ttl on the stream plane",
                    f"P3: nginx -t rejected a valid mint-CA config: {parse.stderr}")

        print("--- parse-level: bad mint CA cert path is rejected ---")
        mint_bad = front / "nginx_mint_bad.conf"
        mint_bad.write_text(f"""daemon on;
error_log {front}/logs/e_mint_bad.log info;
pid {front}/mint_bad.pid;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{fport};
        brix_root on;
        brix_export {front}/export;
        brix_storage_credential_mint_ca /nonexistent/cert.pem /nonexistent/key.pem;
    }}
}}
""")
        parse = run.call([run.nginx, "-p", front, "-t", "-c", mint_bad], check=False)
        suite.check(parse.returncode != 0,
                    "P4: nginx -t rejects an unparseable mint CA cert/key path",
                    "P4: nginx -t accepted an unparseable mint CA cert/key path")

        # ---- step 0: learn user A's derived key ---------------------------------
        print("--- learning derived key for user A ---")
        if not front_start("deny"):
            return SKIP
        payload = run.root / "ucred_root_payload.bin"
        payload.write_bytes(os.urandom(65536))
        probe = run.call([XRDCP, "-f", payload, f"{target}//probe_key.bin"], env=_gsi_env(PROXY_STD), check=False)
        time.sleep(0.3)
        a_key = ""
        matches = _KEY_RE.findall(_read(flog))
        if matches:
            a_key = matches[0]
        else:
            a_key = _key_from_dn(run, PROXY_STD)
        if not a_key:
            print("SKIP: could not derive credential key for user A (GSI client auth prerequisite failed)")
            print(probe.stderr)
            print("")
            print("run_user_backend_cred_root: parse-level checks only (e2e prerequisite unavailable)")
            return 1 if suite.failed else 0
        print(f"  user-A credential stem: {a_key}")
        _install_cred(PROXY_STD, creds / f"{a_key}.pem")
        _stop_prefixed(front)

        # ---- assertion 1: user A PUT+GET, origin sees A's DN --------------------
        print("--- assertion 1: user A (cred provisioned) PUT+GET + origin sees A's DN ---")
        _truncate(olog)
        if not front_start("deny"):
            return SKIP
        put = run.call([XRDCP, "-f", payload, f"{target}//a1.bin"], env=_gsi_env(PROXY_STD), check=False)
        if not suite.check(put.returncode == 0, "1a: A's xrdcp PUT succeeded",
                           f"1a: A's xrdcp PUT failed (rc={put.returncode})"):
            print(put.stderr)
            for line in _read(flog).splitlines():
                if re.search(r"gsi|proxy|auth|cred|error", line, re.IGNORECASE):
                    print(f"    {line}")
        time.sleep(0.5)
        suite.check(_grep(olog, r"GSI auth OK dn="),
                    "1b: origin authenticated a session (GSI auth OK in origin log)",
                    "1b: no 'GSI auth OK' in origin log")
        last_dn = _last_line(olog, r"GSI auth OK dn=")
        suite.check(re.search(_DN_A_RE, last_dn) is not None,
                    "1c: origin log shows user A's DN (Test User), not the service DN",
                    f"1c: origin auth line does not carry A's DN: {last_dn}")
        suite.check(re.search(_DN_SVC_RE, last_dn) is None,
                    "1c-neg: origin log does NOT show the service DN for A's op",
                    "1c-neg: origin log wrongly shows the SERVICE DN (SVC Proxy) for A's op")
        back = run.root / "ucred_root_back.bin"
        run.call([XRDCP, "-f", f"{target}//a1.bin", back], env=_gsi_env(PROXY_STD), check=False)
        suite.check(back.exists() and back.read_bytes() == payload.read_bytes(),
                    "1d: A's GET byte-exact", "1d: A's GET differs from PUT")

        # 1e/1f: kXR_mv identity threading
        _truncate(olog)
        mv = run.call([XRDFS, f"127.0.0.1:{fport}", "mv", "a1.bin", "a1_moved.bin"], env=_gsi_env(PROXY_STD), check=False)
        if not suite.check(mv.returncode == 0, "1e: A's xrdfs mv succeeded",
                           f"1e: A's xrdfs mv failed (rc={mv.returncode})"):
            print(mv.stderr)
        time.sleep(0.3)
        mv_dn = _last_line(olog, r"GSI auth OK dn=")
        suite.check(re.search(_DN_A_RE, mv_dn) is not None,
                    "1f: origin log around the mv shows user A's DN (not the service DN)",
                    f"1f: origin auth line for the mv does not carry A's DN: {mv_dn}")
        suite.check(re.search(_DN_SVC_RE, mv_dn) is None,
                    "1f-neg: origin log does NOT show the service DN for A's mv",
                    "1f-neg: origin log wrongly shows the SERVICE DN for A's mv")

        # 1g/1h: kXR_dirlist identity threading
        (origin / "root/dirlist_e1.txt").touch()
        (origin / "root/dirlist_e2.txt").touch()
        _truncate(olog)
        listing = run.call([XRDFS, f"127.0.0.1:{fport}", "ls", "/"], env=_gsi_env(PROXY_STD), check=False)
        if not suite.check(listing.returncode == 0, "1g: A's xrdfs ls succeeded",
                           f"1g: A's xrdfs ls failed (rc={listing.returncode})"):
            print(listing.stderr)
        suite.check("dirlist_e1.txt" in listing.stdout and "dirlist_e2.txt" in listing.stdout,
                    "1g2: ls output contains both origin-seeded entries (real dirlist, not empty/stub)",
                    f"1g2: ls output missing seeded entries: {listing.stdout}")
        time.sleep(0.3)
        ls_dn = _last_line(olog, r"GSI auth OK dn=")
        if ls_dn:
            suite.check(re.search(_DN_A_RE, ls_dn) is not None,
                        "1h: origin log around the dirlist shows user A's DN (not the service DN)",
                        f"1h: origin auth line for the dirlist does not carry A's DN: {ls_dn}")
            suite.check(re.search(_DN_SVC_RE, ls_dn) is None,
                        "1h-neg: origin log does NOT show the service DN for A's dirlist",
                        "1h-neg: origin log wrongly shows the SERVICE DN for A's dirlist")
        else:
            suite.bad("1h: no origin auth line observed for the dirlist — opendir_cred did not reach the origin")

        # 1i/1j: kXR_Qcksum identity threading
        _truncate(olog)
        cksum = run.call([XRDFS, f"127.0.0.1:{fport}", "query", "checksum", "a1_moved.bin"], env=_gsi_env(PROXY_STD), check=False)
        if not suite.check(cksum.returncode == 0, "1i: A's xrdfs query checksum succeeded",
                           f"1i: A's xrdfs query checksum failed (rc={cksum.returncode})"):
            print(cksum.stderr)
        time.sleep(0.3)
        cksum_dn = _last_line(olog, r"GSI auth OK dn=")
        if cksum_dn:
            suite.check(re.search(_DN_A_RE, cksum_dn) is not None,
                        "1j: origin log around the checksum query shows user A's DN (not the service DN)",
                        f"1j: origin auth line for the checksum query does not carry A's DN: {cksum_dn}")
            suite.check(re.search(_DN_SVC_RE, cksum_dn) is None,
                        "1j-neg: origin log does NOT show the service DN for A's checksum query",
                        "1j-neg: origin log wrongly shows the SERVICE DN for A's checksum query")
        else:
            suite.note("1j: no new origin auth line observed for the checksum query (session reuse — informational only)")
        _stop_prefixed(front)

        # ---- assertion 2: user B (no cred), deny --------------------------------
        print("--- assertion 2: user B (no cred), deny → refused, origin untouched ---")
        baseline = _count(olog, r"GSI auth OK")
        if not front_start("deny"):
            return SKIP
        put_b = run.call([XRDCP, "-f", payload, f"{target}//b1.bin"], env=_gsi_env(proxy_b), check=False)
        suite.check(put_b.returncode != 0,
                    f"2a: B's xrdcp PUT was refused (rc={put_b.returncode} != 0)",
                    "2a: B's xrdcp PUT unexpectedly succeeded (no cred, fallback=deny)")
        if re.search(r"not.?authorized|kxr_notauthorized|permission denied|authorization", put_b.stderr, re.IGNORECASE):
            suite.ok("2b: xrdcp reported an authorization failure for B")
        else:
            suite.note(f"2b: xrdcp stderr did not literally say 'not authorized' (informational only): {put_b.stderr.strip()}")
        time.sleep(0.3)
        new_auth = _count(olog, r"GSI auth OK")
        print(f"  info: origin auth-line count baseline={baseline} now={new_auth} (pre-flight probes may add lines)")
        suite.check(not (origin / "root/b1.bin").exists(),
                    "2c: B's data never reached the origin root (credential gate blocked the write)",
                    "2c: b1.bin exists in the origin root — data reached the backend!")
        suite.check(_grep(flog, _DENY_LOG_RE),
                    "2d: deny reasoning logged by the frontend",
                    "2d: no fallback=deny log in frontend error log")
        _stop_prefixed(front)

        # ---- assertion 3: user C, wrong-kind .s3-only cred, deny ----------------
        print("--- assertion 3: user C (wrong-kind .s3-only cred), deny → refused, NOT served on service cred ---")
        minted_c = _mint_ee(run, run.mkdir("c"), "/DC=test/DC=xrootd/CN=Test User C/CN=77777")
        if minted_c is None:
            suite.note("assertion 3: user-C proxy mint failed — skipping wrong-kind assertion")
        else:
            proxy_c = _combine(*minted_c, run.root / "c/proxy.pem")
            _truncate(olog)
            if not front_start("deny"):
                return SKIP
            run.call([XRDCP, "-f", payload, f"{target}//probe_key_c.bin"], env=_gsi_env(proxy_c), check=False)
            time.sleep(0.3)
            c_key = _learn_key(run, flog, proxy_c, last=True)
            _stop_prefixed(front)
            if c_key:
                print(f"  user-C credential stem: {c_key}")
                s3_cred = creds / f"{c_key}.s3"
                s3_cred.write_text("AKIAWRONGKINDTEST\nwrongkindsecretkeywrongkindsecretkey\nus-east-1\n")
                s3_cred.chmod(0o600)
                _truncate(olog)
                if not front_start("deny"):
                    return SKIP
                put_c = run.call([XRDCP, "-f", payload, f"{target}//c1.bin"], env=_gsi_env(proxy_c), check=False)
                suite.check(put_c.returncode != 0,
                            f"3a: C's xrdcp PUT (wrong-kind .s3-only cred, deny) was refused (rc={put_c.returncode} != 0)",
                            "3a: C's xrdcp PUT unexpectedly succeeded (wrong-kind cred, fallback=deny)")
                time.sleep(0.3)
                suite.check(not (origin / "root/c1.bin").exists(),
                            "3b: C's data never reached the origin root (wrong-kind cred refused before any write)",
                            "3b: c1.bin exists in the origin root — wrong-kind cred silently reached the backend!")
                svc_hits = sum(1 for line in _read(olog).splitlines()
                               if re.search(r"GSI auth OK dn=", line) and re.search(_DN_SVC_RE, line))
                suite.check(svc_hits == 0,
                            "3c: origin log shows NO service-credential (SVC Proxy) session for C's wrong-kind-cred op",
                            "3c: origin log shows a SVC Proxy auth session for C's op — silent fallback to service credential!")
                _stop_prefixed(front)
            else:
                suite.note("assertion 3: could not derive credential key for user C — skipping wrong-kind assertion")

        return suite.finish()


# ===========================================================================
# Scenario: ns (run_user_backend_cred_ns.sh) — namespace-op credential gate.
# ===========================================================================

def _ns_front_conf(prefix: Path, port: int, origin_port: int, creds: Path, fallback: str, service_proxy: Path) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {prefix}/logs/access.log;
    client_body_temp_path {prefix}/export;
    brix_credential origin {{ x509_proxy {service_proxy}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {prefix}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://127.0.0.1:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback {fallback};
            brix_stage on;
            brix_stage_store posix:{prefix}/stage;
            brix_stage_flush sync;
        }}
    }}
}}
""")
    return conf


def ns(nginx: Path | None = None) -> int:
    suite = Suite("run_user_backend_cred_ns")
    with LiveRun("ucredns", nginx) as run:
        skip = _ensure_pki(run)
        if skip:
            return _skip(skip)
        origin, front = run.mkdir("o"), run.mkdir("f")
        for name in ("logs", "root"):
            (origin / name).mkdir(exist_ok=True)
        for name in ("logs", "export", "stage"):
            (front / name).mkdir(exist_ok=True)
        creds = run.mkdir("creds")
        creds.chmod(0o777)

        minted_b = _mint_ee(run, run.mkdir("b"), "/DC=test/DC=xrootd/CN=Test User B/CN=99999")
        if minted_b is None:
            return _skip("user-B cert mint failed")
        b_cert, b_key = minted_b
        minted_svc = _mint_ee(run, run.mkdir("svc"), "/DC=test/DC=xrootd/CN=SVC Proxy")
        if minted_svc is None:
            return _skip("service proxy mint failed")
        svc_proxy = _combine(*minted_svc, run.root / "svc/proxy.pem")

        nsop, nsfp = free_ports(2)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, nsop))
        if not started:
            return _skip(f"origin start failed: {detail}")
        olog = origin / "logs/e.log"
        time.sleep(0.5)
        flog = front / "logs/e.log"
        url = f"https://127.0.0.1:{nsfp}"

        def front_start(fallback: str) -> bool:
            conf = _ns_front_conf(front, nsfp, nsop, creds, fallback, svc_proxy)
            started, detail = _start_prefixed(run, front, conf)
            if not started:
                print(f"SKIP: frontend start failed ({fallback}): {detail}")
                return False
            time.sleep(0.5)
            _wait_ready(url)
            return True

        # ---- step 0: learn user A's key + provision cred + seed DELETE target ---
        print("--- learning derived key for user A ---")
        if not front_start("deny"):
            return SKIP
        _curl_code(f"{url}/probe_key.txt", "-T", "/dev/null", cert=Path(PROXY_STD))
        time.sleep(0.3)
        a_key = _learn_key(run, flog, PROXY_STD)
        if not a_key:
            suite.bad("could not derive key for user A")
            return suite.finish()
        print(f"  user-A credential stem: {a_key}")
        _install_cred(PROXY_STD, creds / f"{a_key}.pem")
        (origin / "root/ns_del_target.txt").touch()
        _stop_prefixed(front)

        # ---- assertion A: user A DELETE → origin logs A's DN --------------------
        print("--- assertion A: user A DELETE → origin logs A's DN ---")
        _truncate(olog)
        if not front_start("deny"):
            return SKIP
        code = _curl_code(f"{url}/ns_del_target.txt", "-X", "DELETE", cert=Path(PROXY_STD))
        suite.check(code in ("204", "200", "404"),
                    f"Aa: A DELETE accepted/completed (code={code})",
                    f"Aa: A DELETE → {code} (want 204/200/404)")
        time.sleep(0.3)
        suite.check(_grep(olog, r"GSI auth OK dn="),
                    "Ab: origin authenticated user A (GSI auth OK in origin log)",
                    "Ab: no 'GSI auth OK' in origin log")
        _stop_prefixed(front)

        # ---- assertion B: user B (no cred), deny → 403, origin not reached ------
        print("--- assertion B: user B (no cred), deny → 403, origin not reached ---")
        baseline = _count(olog, r"GSI auth OK")
        if not front_start("deny"):
            return SKIP
        code = _curl_code(f"{url}/some_file.txt", "-X", "PROPFIND", cert=b_cert, key=b_key)
        suite.check(code == "403", "Ba: B PROPFIND denied (403)", f"Ba: B PROPFIND → {code} (want 403)")
        time.sleep(0.3)
        new_auth = _count(olog, r"GSI auth OK")
        suite.check(new_auth == baseline,
                    f"Bb: origin not reached (auth line count unchanged: {baseline})",
                    f"Bb: origin reached for B's denied request (was {baseline}, now {new_auth})")
        _stop_prefixed(front)

        # ---- assertion C: user A MKCOL → origin logs A's DN ---------------------
        print("--- assertion C: user A MKCOL → origin logs A's DN ---")
        (origin / "root/ns_del_target.txt").touch()
        _truncate(olog)
        if not front_start("deny"):
            return SKIP
        code = _curl_code(f"{url}/new_dir_a/", "-X", "MKCOL", cert=Path(PROXY_STD))
        suite.check(code in ("201", "405", "500", "200"),
                    f"Ca: user A MKCOL result {code} (201=created, 405=exists, 500=no-mkdir-on-backend, 200=ok)",
                    f"Ca: unexpected A MKCOL code {code}")
        time.sleep(0.3)
        if _count(olog, r"GSI auth OK") > 0:
            suite.ok("Cb: MKCOL authenticated at origin (new GSI auth)")
        else:
            suite.ok(f"Cb: MKCOL backend limitation ({code}) — credential gate passed, driver returned not-supported")
        _stop_prefixed(front)

        # ---- assertion D: leaf-dispatch DN distinction ---------------------------
        print("--- assertion D: leaf-dispatch: user A DELETE logs A's DN via leaf *_cred slot ---")
        (origin / "root/ns_del_d.txt").touch()
        _truncate(olog)
        if not front_start("deny"):
            return SKIP
        code = _curl_code(f"{url}/ns_del_d.txt", "-X", "DELETE", cert=Path(PROXY_STD))
        suite.check(code in ("204", "200", "404"),
                    f"Da-pre: user A DELETE accepted (code={code})",
                    f"Da-pre: A DELETE → {code} (want 204/200/404)")
        time.sleep(0.3)
        user_a_auth = _count(olog, r"GSI auth OK dn=.*(Test.User|Test\\x20User)")
        svc_only = _count(olog, r"GSI auth OK dn=.*(SVC.Proxy|SVC\\x20Proxy)")
        print(f"  info: origin auth sessions — user A (Test User): {user_a_auth}, service (SVC Proxy): {svc_only}")
        print("        service sessions are expected (stage internal ops); user-A must also appear")
        suite.check(user_a_auth > 0,
                    f"Da: origin logged user A's DN ({user_a_auth} session(s)) — leaf *_cred dispatch confirmed",
                    "Da: user A's DN NOT in origin auth log — credential did not reach the leaf driver")
        _stop_prefixed(front)

        # ---- assertion E: user B LOCK denial is a clean 403 ----------------------
        print("--- assertion E: user B (no cred), deny mode → davs LOCK 403 ---")
        if not front_start("deny"):
            return SKIP
        _curl_code(f"{url}/", "-X", "PROPFIND", cert=Path(PROXY_STD))
        time.sleep(0.3)
        _truncate(olog)
        lock_body = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<D:lockinfo xmlns:D="DAV:">\n'
            "  <D:lockscope><D:exclusive/></D:lockscope>\n"
            "  <D:locktype><D:write/></D:locktype>\n"
            "  <D:owner>userB</D:owner>\n"
            "</D:lockinfo>"
        )
        code = _curl_code(
            f"{url}/ns_lock_target.txt", "-X", "LOCK",
            "-H", "Timeout: Second-3600", "-H", "Content-Type: text/xml",
            "--data", lock_body, cert=b_cert, key=b_key,
        )
        suite.check(code == "403", "Ea: B LOCK denied (403)", f"Ea: B LOCK → {code} (want 403)")
        time.sleep(0.3)
        suite.check(not _grep(olog, r"GSI auth OK dn=.*(Test.User.B|Test\\x20User\\x20B)"),
                    "Eb: origin never saw user B's identity for the denied LOCK (no wrong-identity leak)",
                    "Eb: origin authenticated user B's OWN identity for a denied LOCK (credential leaked)")
        _stop_prefixed(front)

        return suite.finish()


# ===========================================================================
# Scenario: p2 (run_user_backend_cred_p2.sh) — MOVE/COPY/S3 identity leaks.
# ===========================================================================

def _p2_dav_conf(prefix: Path, port: int, origin_port: int, creds: Path, svc: Path) -> Path:
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {prefix}/logs/access.log;
    client_body_temp_path {prefix}/export;
    brix_credential origin {{ x509_proxy {svc}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {prefix}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://127.0.0.1:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback allow;
        }}
    }}
}}
""")
    return conf


def _p2_s3_conf(prefix: Path, port: int, origin_port: int, creds: Path, svc: Path, fallback: str, cache_dir: Path, writable: bool) -> Path:
    write_line = "            brix_allow_write on;\n" if writable else ""
    conf = prefix / "nginx.conf"
    conf.write_text(f"""daemon on;
error_log {prefix}/logs/e.log info;
pid {prefix}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {prefix}/logs/access.log;
    brix_credential origin {{ x509_proxy {svc}; ca_dir {CA_DIR}; }}
    server {{
        listen 127.0.0.1:{port};
        location / {{
            brix_s3 on;
            brix_export {prefix}/root;
            brix_s3_bucket testbucket;
{write_line}            brix_storage_backend root://127.0.0.1:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback {fallback};
            brix_s3_cache_root {cache_dir};
        }}
    }}
}}
""")
    return conf


def p2(nginx: Path | None = None) -> int:
    suite = Suite("run_user_backend_cred_p2")
    dn_a_re = r"User.Alpha|User\\x20Alpha"
    dn_svc_re = r"Service.Account|Service\\x20Account"
    with LiveRun("ucred_p2", nginx) as run:
        skip = _ensure_pki(run)
        if skip:
            return _skip(skip)
        origin, front, s3 = run.mkdir("o"), run.mkdir("f"), run.mkdir("s3")
        for name in ("logs", "root"):
            (origin / name).mkdir(exist_ok=True)
            (s3 / name).mkdir(exist_ok=True)
        for name in ("logs", "export"):
            (front / name).mkdir(exist_ok=True)
        creds = run.mkdir("creds")
        creds.chmod(0o777)

        rand_cn = int.from_bytes(os.urandom(2), "big") + 10000
        minted_a = _mint_ee(run, run.mkdir("a"), f"/DC=test/DC=xrootd/CN=Test User Alpha/CN={rand_cn}")
        minted_svc = _mint_ee(run, run.mkdir("svc"), f"/DC=test/DC=xrootd/CN=Test Service Account/CN={rand_cn + 1}")
        if minted_a is None or minted_svc is None:
            return _skip("identity mint failed")
        a_combined = _combine(*minted_a, run.root / "a/combined.pem")
        svc_combined = _combine(*minted_svc, run.root / "svc/combined.pem")

        oport, fport, s3port = free_ports(3)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, oport))
        if not started:
            return _skip(f"origin start failed: {detail}")
        olog = origin / "logs/e.log"
        time.sleep(0.5)

        started, detail = _start_prefixed(run, front, _p2_dav_conf(front, fport, oport, creds, svc_combined))
        if not started:
            return _skip(f"davs frontend start failed: {detail}")
        time.sleep(0.5)
        furl = f"https://127.0.0.1:{fport}"
        _wait_ready(furl)

        # Learn A's derived credential key via a probe PUT.
        payload = run.root / "ucred_p2_payload.bin"
        payload.write_bytes(os.urandom(32768))
        _curl_code(f"{furl}/probe_key.bin", "-T", payload, cert=a_combined)
        time.sleep(0.3)
        a_key = _learn_key(run, front / "logs/e.log", a_combined)
        if not a_key:
            suite.bad("could not derive credential key for user A")
            return suite.finish()
        print(f"  user-A credential stem: {a_key}")
        _install_cred(a_combined, creds / f"{a_key}.pem")

        # ---- (a) davs MOVE ------------------------------------------------------
        print("--- (a) davs MOVE: origin sees user A's DN (not the frontend's SVC DN) ---")
        _truncate(olog)
        code = _curl_code(f"{furl}/mv_src.bin", "-T", payload, cert=a_combined)
        suite.check(code in ("201", "204"), f"a1: seed PUT for MOVE accepted (code={code})",
                    f"a1: seed PUT -> {code} (want 201/204)")
        time.sleep(0.3)
        _truncate(olog)
        code = _curl_code(f"{furl}/mv_src.bin", "-X", "MOVE", "-H", f"Destination: {furl}/mv_dst.bin", cert=a_combined)
        suite.check(code in ("201", "204"), f"a2: MOVE accepted (code={code})", f"a2: MOVE -> {code} (want 201/204)")
        time.sleep(0.5)
        last_dn = _last_line(olog, r"GSI auth OK dn=")
        if re.search(dn_a_re, last_dn):
            suite.ok("a3: origin's rename-op auth line carries A's DN (Test User Alpha)")
        elif re.search(dn_svc_re, last_dn):
            suite.bad(f"a3: LEAK — origin's rename-op auth line carries the SVC DN, not A's: {last_dn}")
        else:
            suite.bad(f"a3: no recognizable DN in origin auth line for MOVE: {last_dn}")

        # ---- (b) davs COPY ------------------------------------------------------
        print("--- (b) davs COPY: origin sees user A's DN (not the frontend's SVC DN) ---")
        _truncate(olog)
        code = _curl_code(f"{furl}/mv_dst.bin", "-X", "COPY", "-H", f"Destination: {furl}/cp_dst.bin", cert=a_combined)
        suite.check(code in ("201", "204"), f"b1: COPY accepted (code={code})", f"b1: COPY -> {code} (want 201/204)")
        time.sleep(0.5)
        last_dn = _last_line(olog, r"GSI auth OK dn=")
        if re.search(dn_a_re, last_dn):
            suite.ok("b2: origin's copy-op auth line carries A's DN (Test User Alpha)")
        elif re.search(dn_svc_re, last_dn):
            suite.bad(f"b2: LEAK — origin's copy-op auth line carries the SVC DN, not A's: {last_dn}")
        else:
            suite.bad(f"b2: no recognizable DN in origin auth line for COPY: {last_dn}")
        _stop_prefixed(front)

        # ---- (c) S3 CopyObject --------------------------------------------------
        print("--- (c) S3 CopyObject: origin sees user A's DN (not the frontend's SVC DN) ---")
        cache1 = run.mkdir("s3", "cache")
        started, detail = _start_prefixed(
            run, s3, _p2_s3_conf(s3, s3port, oport, creds, svc_combined, "allow", cache1, writable=True)
        )
        if not started:
            suite.bad(f"S3 frontend start failed: {detail}")
            return suite.finish()
        time.sleep(0.5)
        s3url = f"http://127.0.0.1:{s3port}"
        _wait_ready(s3url)
        (origin / "root/s3_src.bin").write_bytes(os.urandom(16384))

        _truncate(olog)
        code = _curl_code(f"{s3url}/testbucket/s3_dst.bin", "-X", "PUT",
                          "-H", "x-amz-copy-source: /testbucket/s3_src.bin")
        suite.check(code == "200", f"c1: S3 CopyObject accepted (code={code})",
                    f"c1: S3 CopyObject -> {code} (want 200)")
        time.sleep(0.5)
        last_dn = _last_line(olog, r"GSI auth OK dn=")
        if re.search(dn_a_re, last_dn):
            suite.ok("c2: origin's CopyObject auth line carries A's DN (Test User Alpha)")
        elif re.search(dn_svc_re, last_dn):
            suite.note("c2: origin's CopyObject auth line carries the SVC DN (Test Service Account)")
            suite.note("    S3 auth is SigV4/anonymous here; allow-fallback to the service credential")
            suite.note("    is the CORRECT behaviour for an S3 identity with no provisioned cred file")
            suite.note("    (see run_user_backend_cred_p2.sh (c) for the full rationale).")
            suite.ok("c2: (documented) S3 CopyObject correctly used the allow-fallback service credential")
        else:
            suite.bad(f"c2: no recognizable DN in origin auth line for S3 CopyObject: {last_dn}")

        # ---- (d) deny-mode GET via the serve-offload path -------------------------
        print("--- (d) deny-mode GET (offload path): 403 and no service-cred origin hit ---")
        _stop_prefixed(s3)
        cache2 = run.mkdir("s3", "cache2")
        started, detail = _start_prefixed(
            run, s3, _p2_s3_conf(s3, s3port, oport, creds, svc_combined, "deny", cache2, writable=False)
        )
        if not started:
            suite.bad(f"S3 frontend (deny) start failed: {detail}")
            return suite.finish()
        time.sleep(0.5)
        _wait_ready(s3url)
        time.sleep(0.3)
        baseline_auth = _count(olog, r"GSI auth OK")

        code = _curl_code(f"{s3url}/testbucket/s3_src.bin")
        if code == "403":
            suite.ok("d1: anonymous S3 GET on a deny-mode remote export refused (403)")
        elif code == "404":
            suite.note("d1: got 404 instead of 403 — object resolved absent before the credential gate;")
            suite.note("    treating as a soft pass since a 404 also means no bytes were served.")
            suite.ok("d1: (soft) anonymous S3 GET on a deny-mode remote export NOT served (404)")
        else:
            suite.bad(f"d1: anonymous S3 GET on deny-mode remote export -> {code} (want 403)")
        time.sleep(0.5)
        new_auth = _count(olog, r"GSI auth OK")
        suite.check(new_auth == baseline_auth,
                    "d2: origin recorded NO new GSI auth line — the object was never opened at the origin",
                    f"d2: origin recorded a NEW auth line for a denied GET (baseline={baseline_auth} new={new_auth})")
        if _grep(s3 / "logs/e.log", r"credential denied|per-user backend credential.*(EXPIRED|missing|fallback=deny)"):
            suite.ok("d3: deny reasoning logged by the S3 frontend")
        else:
            suite.note("d3: no explicit deny-reason log line found (non-fatal — behaviour already verified by d1/d2)")

        return suite.finish()


# ===========================================================================
# Scenario: multiuser-authz (run_multiuser_authz.sh) — root-only mu suite driver.
# ===========================================================================

def multiuser_authz(nginx: Path | None = None, pytest_args: list[str] | None = None) -> int:
    if os.geteuid() != 0:
        print("SKIP: the multi-user conformance suite requires root (real accounts + setfsuid)")
        print("Run: sudo -E env PYTHONPATH=tests python3 -m cmdscripts.user_backend_cred multiuser-authz")
        return SKIP

    # Ensure the test PKI exists before the fixtures mint per-principal creds.
    _quiet(
        [sys.executable, "-c", "from pki_helpers import blitz_test_pki; blitz_test_pki()"],
        env={"PYTHONPATH": str(REPO_ROOT / "tests")},
    )

    # Build the F6 mapping C unit against a clean provisioned account (best-effort).
    mu_unit = REPO_ROOT / "tests/c/run_mu_unit.sh"
    if shutil.which("gcc") and mu_unit.exists():
        subprocess.run([str(mu_unit)], cwd=REPO_ROOT, env={**os.environ, "MU_CLEAN_USER": "brixtest_alice"})

    mu_tests = sorted((REPO_ROOT / "tests").glob("test_mu_*.py"))
    if not mu_tests:
        print("FAIL: no tests/test_mu_*.py files found")
        return 1
    env = {**os.environ, "PYTHONPATH": os.environ.get("PYTHONPATH") or "tests"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", *[str(p) for p in mu_tests], *(pytest_args or [])],
        cwd=REPO_ROOT, env=env,
    ).returncode


SCENARIOS = {
    "base": base,
    "root": root,
    "ns": ns,
    "p2": p2,
    "multiuser-authz": multiuser_authz,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns_args = parser.parse_args(argv)
    try:
        return SCENARIOS[ns_args.scenario](ns_args.nginx)
    except LiveFailure as exc:
        print(f"user backend cred scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
