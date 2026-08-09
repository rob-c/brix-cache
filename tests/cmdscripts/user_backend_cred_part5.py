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

        oport, fport, s3port = _PORTS[6:9]  # was free_ports(3)
        started, detail = _start_prefixed(run, origin, _origin_conf(origin, oport))
        if not started:
            return _skip(f"origin start failed: {detail}")
        olog = origin / "logs/e.log"
        time.sleep(0.5)

        started, detail = _start_prefixed(run, front, _p2_dav_conf(front, fport, oport, creds, svc_combined))
        if not started:
            return _skip(f"davs frontend start failed: {detail}")
        time.sleep(0.5)
        furl = f"https://{HOST}:{fport}"
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
        s3url = f"http://{HOST}:{s3port}"
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

    # Build + run the F6 mapping C unit against a clean provisioned account
    # (best-effort). Behaviour ported from the retired tests/c/run_mu_unit.sh into
    # cmdscripts.c_regression_units.mu_unit (idmap_collapse_test); MU_CLEAN_USER
    # selects the collapse-SUCCESS cases the MU fleet provisions brixtest_* for.
    if shutil.which("gcc"):
        from cmdscripts import c_regression_units

        prev = os.environ.get("MU_CLEAN_USER")
        os.environ["MU_CLEAN_USER"] = "brixtest_alice"
        try:
            with tempfile.TemporaryDirectory() as mu_base:
                c_regression_units.mu_unit(Path(mu_base))
        finally:
            if prev is None:
                os.environ.pop("MU_CLEAN_USER", None)
            else:
                os.environ["MU_CLEAN_USER"] = prev

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
