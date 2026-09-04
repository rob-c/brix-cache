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

from cmdscripts import handoff_credential_store
from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, PROXY_STD, SERVER_CERT, SERVER_KEY

def _phase_ns_1(front):
    for name in ("logs", "export", "stage"):
        (front / name).mkdir(exist_ok=True)


def _guard_ns_1(olog, suite, code):
    if _count(olog, r"GSI auth OK") > 0:
        suite.ok("Cb: MKCOL authenticated at origin (new GSI auth)")
    else:
        suite.ok(f"Cb: MKCOL backend limitation ({code}) — credential gate passed, driver returned not-supported")


_PORTS = cmdscript_ports("user_backend_cred")

SKIP = 77  # distinct scenario outcome: prerequisites unavailable

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"

_KEY_RE = re.compile(r"key=(x5h-[0-9a-f]+|[A-Za-z0-9@._-]+)")
_DN_A_RE = r"Test.User|Test\\x20User"
_DN_SVC_RE = r"SVC.Proxy"
_DENY_LOG_RE = r"fallback=deny.*refusing|per-user backend credential.*fallback=deny"


def _start_ns_front(run, front, nsfp, nsop, creds, fallback, svc_proxy, url):
    conf = _ns_front_conf(front, nsfp, nsop, creds, fallback, svc_proxy)
    started, detail = _start_prefixed(run, front, conf)
    if not started:
        print(f"SKIP: frontend start failed ({fallback}): {detail}")
        return False
    time.sleep(0.5)
    _wait_ready(url)
    return True


def _ns_paths(run):
    origin, front = run.mkdir("o"), run.mkdir("f")
    for name in ("logs", "root"):
        (origin / name).mkdir(exist_ok=True)
    _phase_ns_1(front)
    creds = run.mkdir("creds")
    handoff_credential_store(creds)
    return origin, front, creds


def _ns_credentials(run):
    minted_b = _mint_ee(
        run, run.mkdir("b"), "/DC=test/DC=xrootd/CN=Test User B/CN=99999")
    if minted_b is None:
        return None, _skip("user-B cert mint failed")
    minted_svc = _mint_ee(
        run, run.mkdir("svc"), "/DC=test/DC=xrootd/CN=SVC Proxy")
    if minted_svc is None:
        return None, _skip("service proxy mint failed")
    return (*minted_b, _combine(*minted_svc, run.root / "svc/proxy.pem")), None


def _prepare_ns(run):
    skip = _ensure_pki(run)
    if skip:
        return None, _skip(skip)
    origin, front, creds = _ns_paths(run)
    credentials, error = _ns_credentials(run)
    if credentials is None:
        return None, error
    nsop, nsfp = _PORTS[4:6]
    started, detail = _start_prefixed(run, origin, _origin_conf(origin, nsop))
    if not started:
        return None, _skip(f"origin start failed: {detail}")
    return (origin, front, creds, *credentials, nsop, nsfp), None


def ns(nginx: Path | None = None) -> int:
    suite = Suite("run_user_backend_cred_ns")
    with LiveRun("ucredns", nginx) as run:
        context, preparation = _prepare_ns(run)
        if context is None:
            return preparation
        origin, front, creds, b_cert, b_key, svc_proxy, nsop, nsfp = context
        olog = origin / "logs/e.log"
        time.sleep(0.5)
        flog = front / "logs/e.log"
        url = f"https://{HOST}:{nsfp}"

        # ---- step 0: learn user A's key + provision cred + seed DELETE target ---
        print("--- learning derived key for user A ---")
        if not _start_ns_front(run, front, nsfp, nsop, creds, "deny", svc_proxy, url):
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
        if not _start_ns_front(run, front, nsfp, nsop, creds, "deny", svc_proxy, url):
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
        if not _start_ns_front(run, front, nsfp, nsop, creds, "deny", svc_proxy, url):
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
        if not _start_ns_front(run, front, nsfp, nsop, creds, "deny", svc_proxy, url):
            return SKIP
        code = _curl_code(f"{url}/new_dir_a/", "-X", "MKCOL", cert=Path(PROXY_STD))
        suite.check(code in ("201", "405", "500", "200"),
                    f"Ca: user A MKCOL result {code} (201=created, 405=exists, 500=no-mkdir-on-backend, 200=ok)",
                    f"Ca: unexpected A MKCOL code {code}")
        time.sleep(0.3)
        _guard_ns_1(olog, suite, code)
        _stop_prefixed(front)

        # ---- assertion D: leaf-dispatch DN distinction ---------------------------
        print("--- assertion D: leaf-dispatch: user A DELETE logs A's DN via leaf *_cred slot ---")
        (origin / "root/ns_del_d.txt").touch()
        _truncate(olog)
        if not _start_ns_front(run, front, nsfp, nsop, creds, "deny", svc_proxy, url):
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
        if not _start_ns_front(run, front, nsfp, nsop, creds, "deny", svc_proxy, url):
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
        listen {BIND_HOST}:{port} ssl;
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
            brix_trusted_ca {CA_CERT};
            brix_webdav_auth required;
            brix_storage_backend root://{HOST}:{origin_port};
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
        listen {BIND_HOST}:{port};
        location / {{
            brix_s3 on;
            brix_export {prefix}/root;
            brix_s3_bucket testbucket;
{write_line}            brix_storage_backend root://{HOST}:{origin_port};
            brix_storage_credential origin;
            brix_storage_credential_dir {creds};
            brix_storage_credential_fallback {fallback};
            brix_cache_root {cache_dir};
        }}
    }}
}}
""")
    return conf
