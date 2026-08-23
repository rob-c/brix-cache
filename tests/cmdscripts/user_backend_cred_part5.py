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


class _P2Scenario:
    def __init__(self, run):
        self.run = run
        self.suite = Suite("run_user_backend_cred_p2")
        self.origin = run.mkdir("o")
        self.front = run.mkdir("f")
        self.s3 = run.mkdir("s3")
        _make_p2_directories(self.origin, self.front, self.s3)
        self.creds = run.mkdir("creds")
        self.creds.chmod(0o777)
        self.origin_port, self.front_port, self.s3_port = _PORTS[6:9]
        self.origin_log = self.origin / "logs/e.log"
        self.user_dn = r"User.Alpha|User\\x20Alpha"
        self.service_dn = r"Service.Account|Service\\x20Account"

    def prepare_credentials(self):
        random_cn = int.from_bytes(os.urandom(2), "big") + 10000
        user = _mint_ee(
            self.run, self.run.mkdir("a"),
            f"/DC=test/DC=xrootd/CN=Test User Alpha/CN={random_cn}",
        )
        service = _mint_ee(
            self.run, self.run.mkdir("svc"),
            f"/DC=test/DC=xrootd/CN=Test Service Account/CN={random_cn + 1}",
        )
        if user is None or service is None:
            return False
        self.user_credential = _combine(*user, self.run.root / "a/combined.pem")
        self.service_credential = _combine(
            *service, self.run.root / "svc/combined.pem"
        )
        return True

    def start_origin_and_front(self):
        started, detail = _start_prefixed(
            self.run, self.origin, _origin_conf(self.origin, self.origin_port)
        )
        if not started:
            return f"origin start failed: {detail}"
        time.sleep(0.5)
        config = _p2_dav_conf(
            self.front, self.front_port, self.origin_port, self.creds,
            self.service_credential,
        )
        started, detail = _start_prefixed(self.run, self.front, config)
        if not started:
            return f"davs frontend start failed: {detail}"
        time.sleep(0.5)
        self.front_url = f"https://{HOST}:{self.front_port}"
        _wait_ready(self.front_url)
        return ""

    def learn_user_key(self):
        self.payload = self.run.root / "ucred_p2_payload.bin"
        self.payload.write_bytes(os.urandom(32768))
        _curl_code(
            f"{self.front_url}/probe_key.bin", "-T", self.payload,
            cert=self.user_credential,
        )
        time.sleep(0.3)
        key = _learn_key(
            self.run, self.front / "logs/e.log", self.user_credential
        )
        if not key:
            self.suite.bad("could not derive credential key for user A")
            return False
        print(f"  user-A credential stem: {key}")
        _install_cred(self.user_credential, self.creds / f"{key}.pem")
        return True

    def dav_move(self):
        _truncate(self.origin_log)
        code = _curl_code(
            f"{self.front_url}/mv_src.bin", "-T", self.payload,
            cert=self.user_credential,
        )
        self.suite.check(
            code in ("201", "204"), f"a1: seed PUT accepted ({code})",
            f"a1: seed PUT -> {code}",
        )
        _truncate(self.origin_log)
        code = _curl_code(
            f"{self.front_url}/mv_src.bin", "-X", "MOVE", "-H",
            f"Destination: {self.front_url}/mv_dst.bin",
            cert=self.user_credential,
        )
        self.suite.check(
            code in ("201", "204"), f"a2: MOVE accepted ({code})",
            f"a2: MOVE -> {code}",
        )
        time.sleep(0.5)
        self._check_origin_identity("a3", "MOVE", allow_service=False)

    def dav_copy(self):
        _truncate(self.origin_log)
        code = _curl_code(
            f"{self.front_url}/mv_dst.bin", "-X", "COPY", "-H",
            f"Destination: {self.front_url}/cp_dst.bin",
            cert=self.user_credential,
        )
        self.suite.check(
            code in ("201", "204"), f"b1: COPY accepted ({code})",
            f"b1: COPY -> {code}",
        )
        time.sleep(0.5)
        self._check_origin_identity("b2", "COPY", allow_service=False)
        _stop_prefixed(self.front)

    def _check_origin_identity(self, label, operation, allow_service):
        line = _last_line(self.origin_log, r"GSI auth OK dn=")
        if re.search(self.user_dn, line):
            self.suite.ok(f"{label}: {operation} origin used user A")
        elif allow_service and re.search(self.service_dn, line):
            self.suite.ok(f"{label}: {operation} used documented service fallback")
        elif re.search(self.service_dn, line):
            self.suite.bad(f"{label}: service identity leaked into {operation}: {line}")
        else:
            self.suite.bad(f"{label}: no recognizable origin identity: {line}")

    def s3_copy(self):
        cache = self.run.mkdir("s3", "cache")
        config = _p2_s3_conf(
            self.s3, self.s3_port, self.origin_port, self.creds,
            self.service_credential, "allow", cache, writable=True,
        )
        started, detail = _start_prefixed(self.run, self.s3, config)
        if not started:
            self.suite.bad(f"S3 frontend start failed: {detail}")
            return False
        time.sleep(0.5)
        self.s3_url = f"http://{HOST}:{self.s3_port}"
        _wait_ready(self.s3_url)
        (self.origin / "root/s3_src.bin").write_bytes(os.urandom(16384))
        _truncate(self.origin_log)
        code = _curl_code(
            f"{self.s3_url}/testbucket/s3_dst.bin", "-X", "PUT",
            "-H", "x-amz-copy-source: /testbucket/s3_src.bin",
        )
        self.suite.check(
            code == "200", f"c1: S3 CopyObject accepted ({code})",
            f"c1: S3 CopyObject -> {code}",
        )
        time.sleep(0.5)
        self._check_origin_identity("c2", "S3 CopyObject", allow_service=True)
        return True

    def deny_get(self):
        _stop_prefixed(self.s3)
        cache = self.run.mkdir("s3", "cache2")
        config = _p2_s3_conf(
            self.s3, self.s3_port, self.origin_port, self.creds,
            self.service_credential, "deny", cache, writable=False,
        )
        started, detail = _start_prefixed(self.run, self.s3, config)
        if not started:
            self.suite.bad(f"S3 deny frontend start failed: {detail}")
            return
        time.sleep(0.5)
        _wait_ready(self.s3_url)
        baseline = _count(self.origin_log, r"GSI auth OK")
        code = _curl_code(f"{self.s3_url}/testbucket/s3_src.bin")
        self._record_deny_status(code)
        time.sleep(0.5)
        current = _count(self.origin_log, r"GSI auth OK")
        self.suite.check(
            current == baseline, "d2: denied object never opened at origin",
            f"d2: origin auth count changed ({baseline} -> {current})",
        )
        pattern = r"credential denied|per-user backend credential.*(EXPIRED|missing|fallback=deny)"
        if _grep(self.s3 / "logs/e.log", pattern):
            self.suite.ok("d3: deny reasoning logged")
        else:
            self.suite.note("d3: no explicit deny-reason log (non-fatal)")

    def _record_deny_status(self, code):
        if code == "403":
            self.suite.ok("d1: anonymous deny-mode GET refused (403)")
        elif code == "404":
            self.suite.ok("d1: anonymous deny-mode GET not served (404)")
        else:
            self.suite.bad(f"d1: deny-mode GET -> {code}; expected 403")

    def execute(self):
        self.dav_move()
        self.dav_copy()
        if self.s3_copy():
            self.deny_get()
        return self.suite.finish()


def _make_p2_directories(origin, front, s3):
    for name in ("logs", "root"):
        (origin / name).mkdir(exist_ok=True)
        (s3 / name).mkdir(exist_ok=True)
    for name in ("logs", "export"):
        (front / name).mkdir(exist_ok=True)


def p2(nginx: Path | None = None) -> int:
    with LiveRun("ucred_p2", nginx) as run:
        missing = _ensure_pki(run)
        if missing:
            return _skip(missing)
        scenario = _P2Scenario(run)
        if not scenario.prepare_credentials():
            return _skip("identity mint failed")
        start_error = scenario.start_origin_and_front()
        if start_error:
            return _skip(start_error)
        if not scenario.learn_user_key():
            return scenario.suite.finish()
        return scenario.execute()


# ===========================================================================
# Scenario: multiuser-authz (run_multiuser_authz.sh) — root-only mu suite driver.
# ===========================================================================

def multiuser_authz(nginx: Path | None = None, pytest_args: list[str] | None = None) -> int:
    del nginx
    if os.geteuid() != 0:
        print("SKIP: the multi-user conformance suite requires root (real accounts + setfsuid)")
        print("Run: sudo -E env PYTHONPATH=tests python3 -m cmdscripts.user_backend_cred multiuser-authz")
        return SKIP
    _provision_multiuser_pki()
    _run_multiuser_c_unit()
    return _run_multiuser_pytest(pytest_args)


def _provision_multiuser_pki():
    _quiet(
        [sys.executable, "-c", "from pki_helpers import blitz_test_pki; blitz_test_pki()"],
        env={"PYTHONPATH": str(REPO_ROOT / "tests")},
    )


def _run_multiuser_c_unit():
    if not shutil.which("gcc"):
        return
    from cmdscripts import c_regression_units
    previous = os.environ.get("MU_CLEAN_USER")
    os.environ["MU_CLEAN_USER"] = "brixtest_alice"
    try:
        with tempfile.TemporaryDirectory() as mu_base:
            c_regression_units.mu_unit(Path(mu_base))
    finally:
        _restore_environment("MU_CLEAN_USER", previous)


def _restore_environment(name, previous):
    if previous is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = previous


def _run_multiuser_pytest(pytest_args):
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
