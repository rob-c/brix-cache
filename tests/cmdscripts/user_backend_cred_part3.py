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
from types import SimpleNamespace

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


def root(nginx: Path | None = None) -> int:
    suite = Suite("run_user_backend_cred_root")
    with LiveRun("ucred_root", nginx) as run:
        result, state = _prepare_root_state(run, suite)
        if result is not None:
            return result
        _root_parse_checks(state)
        result = _root_learn_credential(state)
        if result is not None:
            return result
        result = _root_user_a_transfer(state)
        if result is not None:
            return result
        _root_user_a_move(state)
        _root_user_a_dirlist(state)
        _root_user_a_checksum(state)
        result = _root_user_b_denied(state)
        if result is not None:
            return result
        result = _root_wrong_kind_denied(state)
        if result is not None:
            return result
        return suite.finish()


def _root_directories(run):
    origin, front = run.mkdir("o"), run.mkdir("f")
    for path in (origin / "root", origin / "logs", front / "export",
                 front / "logs"):
        path.mkdir(exist_ok=True)
    creds = run.mkdir("creds")
    creds.chmod(0o777)
    return origin, front, creds


def _root_identities(run):
    minted_b = _mint_ee(
        run, run.mkdir("b"), "/DC=test/DC=xrootd/CN=Test User B/CN=88888")
    if minted_b is None:
        return _skip("user-B cert mint failed"), None
    proxy_b = _combine(*minted_b, run.root / "b/proxy.pem")
    minted_svc = _mint_ee(
        run, run.mkdir("svc"), "/DC=test/DC=xrootd/CN=SVC Proxy")
    if minted_svc is None:
        return _skip("service proxy mint failed"), None
    service_proxy = _combine(*minted_svc, run.root / "svc/proxy.pem")
    return None, (proxy_b, service_proxy)


def _prepare_root_state(run, suite):
    missing = next(
        (path for path in (run.nginx, XRDCP, XRDFS) if not Path(path).exists()),
        None)
    if missing is not None:
        return _skip(f"missing {missing}"), None
    skip = _ensure_pki(run)
    if skip:
        return _skip(skip), None
    origin, front, creds = _root_directories(run)
    result, identities = _root_identities(run)
    if result is not None:
        return result, None
    proxy_b, service_proxy = identities
    origin_port, front_port = _PORTS[2:4]
    started, detail = _start_prefixed(
        run, origin, _origin_conf(origin, origin_port))
    if not started:
        return _skip(f"origin start failed: {detail}"), None
    time.sleep(0.5)
    state = SimpleNamespace(
        run=run, suite=suite, origin=origin, front=front, creds=creds,
        proxy_b=proxy_b, service_proxy=service_proxy,
        origin_port=origin_port, front_port=front_port,
        origin_log=origin / "logs/e.log", front_log=front / "logs/e.log",
        target=f"root://{HOST}:{front_port}", payload=None)
    return None, state


def _root_values(state):
    return (state.run, state.suite, state.origin, state.front, state.creds,
            state.proxy_b, state.service_proxy, state.origin_port,
            state.front_port, state.origin_log, state.front_log,
            state.target, state.payload)


def _root_front_start(state, fallback: str) -> bool:
    conf = _root_front_conf(
        state.front, state.front_port, state.origin_port, state.creds,
        fallback, state.service_proxy)
    started, detail = _start_prefixed(state.run, state.front, conf)
    if not started:
        print(f"SKIP: frontend start failed ({fallback}): {detail}")
        return False
    time.sleep(0.5)
    return True

def _root_parse_checks(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
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
    listen {BIND_HOST}:{fport};
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
    listen {BIND_HOST}:{fport};
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
    listen {BIND_HOST}:{fport};
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


def _root_learn_credential(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # ---- step 0: learn user A's derived key ---------------------------------
    print("--- learning derived key for user A ---")
    if not _root_front_start(state, "deny"):
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

    state.payload = payload
    return None

def _root_user_a_transfer(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # ---- assertion 1: user A PUT+GET, origin sees A's DN --------------------
    print("--- assertion 1: user A (cred provisioned) PUT+GET + origin sees A's DN ---")
    _truncate(olog)
    if not _root_front_start(state, "deny"):
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

    return None

def _root_user_a_move(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # 1e/1f: kXR_mv identity threading
    _truncate(olog)
    mv = run.call([XRDFS, f"{HOST}:{fport}", "mv", "a1.bin", "a1_moved.bin"], env=_gsi_env(PROXY_STD), check=False)
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


def _root_user_a_dirlist(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # 1g/1h: kXR_dirlist identity threading
    (origin / "root/dirlist_e1.txt").touch()
    (origin / "root/dirlist_e2.txt").touch()
    _truncate(olog)
    listing = run.call([XRDFS, f"{HOST}:{fport}", "ls", "/"], env=_gsi_env(PROXY_STD), check=False)
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


def _root_user_a_checksum(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # 1i/1j: kXR_Qcksum identity threading
    _truncate(olog)
    cksum = run.call([XRDFS, f"{HOST}:{fport}", "query", "checksum", "a1_moved.bin"], env=_gsi_env(PROXY_STD), check=False)
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


def _root_user_b_denied(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # ---- assertion 2: user B (no cred), deny --------------------------------
    print("--- assertion 2: user B (no cred), deny → refused, origin untouched ---")
    baseline = _count(olog, r"GSI auth OK")
    if not _root_front_start(state, "deny"):
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

    return None

def _root_wrong_kind_denied(state):
    (run, suite, origin, front, creds, proxy_b, svc_proxy, oport,
     fport, olog, flog, target, payload) = _root_values(state)
    # ---- assertion 3: user C, wrong-kind .s3-only cred, deny ----------------
    print("--- assertion 3: user C (wrong-kind .s3-only cred), deny → refused, NOT served on service cred ---")
    minted_c = _mint_ee(run, run.mkdir("c"), "/DC=test/DC=xrootd/CN=Test User C/CN=77777")
    if minted_c is None:
        suite.note("assertion 3: user-C proxy mint failed — skipping wrong-kind assertion")
        return None
    proxy_c = _combine(*minted_c, run.root / "c/proxy.pem")
    _truncate(olog)
    if not _root_front_start(state, "deny"):
        return SKIP
    run.call([XRDCP, "-f", payload, f"{target}//probe_key_c.bin"],
             env=_gsi_env(proxy_c), check=False)
    time.sleep(0.3)
    c_key = _learn_key(run, flog, proxy_c, last=True)
    _stop_prefixed(front)
    if not c_key:
        suite.note(
            "assertion 3: could not derive credential key for user C — skipping wrong-kind assertion")
        return None
    return _root_check_wrong_kind(state, proxy_c, c_key)


def _root_service_auth_hits(origin_log):
    return sum(
        1 for line in _read(origin_log).splitlines()
        if all((re.search(r"GSI auth OK dn=", line),
                re.search(_DN_SVC_RE, line))))


def _root_check_wrong_kind(state, proxy_c, credential_key):
    print(f"  user-C credential stem: {credential_key}")
    credential = state.creds / f"{credential_key}.s3"
    credential.write_text(
        "AKIAWRONGKINDTEST\nwrongkindsecretkeywrongkindsecretkey\nus-east-1\n")
    credential.chmod(0o600)
    _truncate(state.origin_log)
    if not _root_front_start(state, "deny"):
        return SKIP
    result = state.run.call(
        [XRDCP, "-f", state.payload, f"{state.target}//c1.bin"],
        env=_gsi_env(proxy_c), check=False)
    state.suite.check(
        result.returncode != 0,
        f"3a: C's xrdcp PUT (wrong-kind .s3-only cred, deny) was refused "
        f"(rc={result.returncode} != 0)",
        "3a: C's xrdcp PUT unexpectedly succeeded (wrong-kind cred, fallback=deny)")
    time.sleep(0.3)
    state.suite.check(
        not (state.origin / "root/c1.bin").exists(),
        "3b: C's data never reached the origin root (wrong-kind cred refused before any write)",
        "3b: c1.bin exists in the origin root — wrong-kind cred silently reached the backend!")
    state.suite.check(
        _root_service_auth_hits(state.origin_log) == 0,
        "3c: origin log shows NO service-credential session for C's wrong-kind op",
        "3c: origin log shows a service credential for C's op — silent fallback!")
    _stop_prefixed(state.front)
    return None


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
            brix_storage_credential_fallback {fallback};
            brix_stage on;
            brix_stage_store posix:{prefix}/stage;
            brix_stage_flush sync;
        }}
    }}
}}
""")
    return conf
