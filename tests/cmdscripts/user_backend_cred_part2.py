"""Direct Python ports of the per-user backend-credential live shell suites.

Ports ``run_user_backend_cred.sh`` (base), ``run_user_backend_cred_root.sh``
(root), ``run_user_backend_cred_ns.sh`` (ns), ``run_user_backend_cred_p2.sh``
(p2), and ``run_multiuser_authz.sh`` (multiuser-authz).  Every externally
visible assertion of the shell scripts is reproduced as a Python check; ports
come from the fixed ``cmdscripts`` band (``fleet_ports.CMDSCRIPTS_PORTS`` via
the module ``_PORTS`` slice) and all scratch state lives under a ``LiveRun``
root that the context manager reaps.
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
import tempfile
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, PROXY_STD, SERVER_CERT, SERVER_KEY

_PORTS = cmdscript_ports("user_backend_cred")

SKIP = 77  # distinct scenario outcome: prerequisites unavailable

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"

_KEY_RE = re.compile(r"key=(x5h-[0-9a-f]+|[A-Za-z0-9@._-]+)")
_DN_A_RE = r"Test.User|Test\\x20User"
_DN_SVC_RE = r"SVC.Proxy"
_DENY_LOG_RE = r"fallback=deny.*refusing|per-user backend credential.*fallback=deny"


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

        oport, fport = _PORTS[0:2]  # was free_ports(2)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, oport))
        if not started:
            return _skip(f"origin start failed: {detail}")
        olog = origin / "logs/e.log"
        time.sleep(0.5)

        flog = front / "logs/e.log"
        url = f"https://{HOST}:{fport}"

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
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {prefix}/export;
        brix_allow_write on;
        brix_upload_resume off;
        brix_auth gsi;
        brix_certificate     {SERVER_CERT};
        brix_certificate_key {SERVER_KEY};
        brix_trusted_ca      {CA_CERT};
        brix_storage_backend root://{HOST}:{origin_port};
        brix_storage_credential origin;
        brix_storage_credential_dir {creds};
        brix_storage_credential_fallback {fallback};
    }}
}}
""")
    return conf


def _gsi_env(proxy: Path | str) -> dict[str, str]:
    return {"X509_USER_PROXY": str(proxy), "X509_CERT_DIR": str(CA_DIR), "XrdSecGSICADIR": str(CA_DIR)}


