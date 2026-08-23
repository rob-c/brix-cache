"""Direct Python ports for the pblock storage-driver live shell scenarios.

Ports ``run_pblock_root.sh``, ``run_pblock_webdav.sh``,
``run_pblock_writethrough.sh``, and ``run_pblock_meta_gsi.sh``.  Each public
scenario keeps its shell test's own acceptance sequence and assertions; ports
are allocated dynamically instead of the scripts' fixed literals.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, random_file, sha256
from cmdscripts.c_regression_units import _gcov_flags
from lib_py.pki import regenerate_pki
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, TEST_ROOT
from fleet_ports import cmdscript_ports

_PORTS = cmdscript_ports("pblock_live")

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"
XRDDIAG = REPO_ROOT / "client/bin/xrddiag"
XRDADLER32 = REPO_ROOT / "client/bin/xrdadler32"
XRDCRC32C = REPO_ROOT / "client/bin/xrdcrc32c"
LIBXRDC = REPO_ROOT / "client/libbrix.a"
PROTOLIB = REPO_ROOT / "shared/xrdproto/libxrdproto.a"
META_BENCH_SRC = REPO_ROOT / "tests/tools/pblock_meta_bench.c"

PKI_DIR = Path(TEST_ROOT) / "pki"
CA_CERT = PKI_DIR / "ca/ca.pem"
CA_DIR = PKI_DIR / "ca"
SERVER_CERT = PKI_DIR / "server/hostcert.pem"
SERVER_KEY = PKI_DIR / "server/hostkey.pem"
PROXY_STD = PKI_DIR / "user/proxy_std.pem"

CLIENT_REQUIREMENTS = {
    "pblock-root": (XRDCP, XRDFS, XRDADLER32, XRDCRC32C),
    "pblock-webdav": (),
    "pblock-writethrough": (XRDCP,),
    "pblock-meta-gsi": (XRDFS, XRDDIAG),
    "pblock-lab": (XRDCP,),
}


def _pblock_lab_on(nginx, port):
    checks = []
    with LiveRun("pblock_lab_on", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        config = _lab_conf(run, port, "?lab=1")
        run.start_nginx(run.root, config, port)
        time.sleep(1)
        hub = f"root://{HOST}:{port}/"
        sidecar = run.root / "root/pblock.opts"
        checks.append((
            sidecar.is_file(),
            "pblock.opts sidecar written by config",
        ))
        checks.append((
            sidecar.is_file() and "lab=1" in sidecar.read_text(),
            "sidecar carries lab=1",
        ))
        source = run.root / "src.bin"
        random_file(source, 700000)
        received = run.root / "clean.got"
        put_status = run.call(
            [XRDCP, "-f", source, f"{hub}f.bin"], check=False).returncode
        get_status = run.call(
            [XRDCP, "-f", f"{hub}f.bin", received], check=False).returncode
        checks.append((put_status == 0, "PUT clean (gate on, no rule)"))
        checks.append((get_status == 0, "GET clean before fault"))
        checks.append((
            received.exists() and sha256(received) == sha256(source),
            "GET clean byte-exact",
        ))
        _ctl_set(run.root / "root/catalog.db", "fault.pread", "errno=EIO", 1)
        faulted = run.root / "faulted.got"
        fault_status = run.call(
            [XRDCP, "-f", f"{hub}f.bin", faulted], check=False).returncode
        checks.append((
            fault_status != 0,
            "GET after fault.pread=EIO fails (snapshot-at-open)",
        ))
    return checks


def _pblock_lab_off(nginx, port):
    checks = []
    with LiveRun("pblock_lab_off", nginx) as run:
        run.mkdir("root")
        run.mkdir("logs")
        config = _lab_conf(run, port, "")
        run.start_nginx(run.root, config, port)
        time.sleep(1)
        hub = f"root://{HOST}:{port}/"
        source = run.root / "src.bin"
        random_file(source, 700000)
        checks.append((
            not (run.root / "root/pblock.opts").exists(),
            "no sidecar when tail absent (production path)",
        ))
        put_status = run.call(
            [XRDCP, "-f", source, f"{hub}f.bin"], check=False).returncode
        checks.append((put_status == 0, "PUT (gate off)"))
        _ctl_set(run.root / "root/catalog.db", "fault.pread", "errno=EIO", 1)
        received = run.root / "off.got"
        get_status = run.call(
            [XRDCP, "-f", f"{hub}f.bin", received], check=False).returncode
        inert = all((
            get_status == 0,
            received.exists(),
            sha256(received) == sha256(source),
        ))
        checks.append((
            inert,
            "GET ignores fault with gate off (fail-closed master gate)",
        ))
    return checks


def pblock_lab(nginx: Path | None = None) -> int:
    """Verify that pblock fault rules are active only behind the lab gate."""
    checks = _pblock_lab_on(nginx, _PORTS[4])
    checks += _pblock_lab_off(nginx, _PORTS[5])
    return _checks(checks)
def _ensure_pki(run: LiveRun) -> bool:
    """Provision the fleet CA-signed PKI on demand; refresh an expired proxy WITHOUT
    regenerating the CA.  A full regen (regenerate_pki/blitz_test_pki) rebuilds the
    CA and desyncs the standing fleet — it loaded its certs at startup, so freshly
    minted proxies then chain to a CA the fleet no longer trusts and every
    concurrent GSI/TLS test fails.  refresh_shared_pki refreshes only the proxy
    when the CA/hostcert exist.  See live_common.refresh_shared_pki."""
    from cmdscripts.live_common import refresh_shared_pki  # noqa: PLC0415
    ok, msg = refresh_shared_pki(run.root, want_proxy=True)
    if not ok:
        print(f"SKIP: {msg}")
    return ok


def _build_meta_bench(run: LiveRun) -> Path:
    bench = run.root / "pblock_meta_bench"
    build = run.call(
        [
            "cc", "-O2", "-Wall", "-I", REPO_ROOT / "client/lib", "-I", REPO_ROOT / "src",
            "-DXRDPROTO_NO_NGX", META_BENCH_SRC, LIBXRDC, PROTOLIB,
            "-lssl", "-lcrypto", "-lz", "-lkrb5", "-lk5crypto", "-lcom_err", "-lzstd",
            "-llzma", "-lbrotlienc", "-lbrotlidec", "-lbz2", "-l:liblz4.so.1",
            "-luring", "-lpthread", *_gcov_flags([LIBXRDC, PROTOLIB]), "-o", bench,
        ],
        check=False,
    )
    if build.returncode:
        raise LiveFailure(f"harness build failed: {build.stderr}")
    return bench


from split_continuation import load as _load_pblock_meta
_load_pblock_meta(globals(), __file__, "_pblock_meta_gsi.py")

def selftest(nginx: Path | None = None) -> int:
    """Port of the shell's --selftest mode: drives the umbrella three ways
    (success / fault-injection / security-negative)."""
    rc = 0
    print("[selftest] 1/3 success: a healthy run must PASS")
    if pblock_meta_gsi(nginx) == 0:
        print("  ok   success")
    else:
        print("  FAIL success")
        rc = 1
    print("[selftest] 2/3 fault: an unsatisfiable p99 ceiling (1ms) must FAIL")
    if pblock_meta_gsi(nginx, p99_ceil_ms=1) == 0:
        print("  FAIL fault-not-detected")
        rc = 1
    else:
        print("  ok   fault detected")
    print("[selftest] 3/3 security-neg: an invalid GSI proxy must be rejected")
    if pblock_meta_gsi(nginx, proxy_override="/dev/null") == 0:
        print("  FAIL gsi-bypass")
        rc = 1
    else:
        print("  ok   GSI gate enforced")
    print(("selftest PASS", "selftest FAIL")[rc != 0])
    return rc


SCENARIOS = {
    "pblock-root": pblock_root,
    "pblock-webdav": pblock_webdav,
    "pblock-writethrough": pblock_writethrough,
    "pblock-meta-gsi": pblock_meta_gsi,
    "pblock-lab": pblock_lab,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="three-way selftest of pblock-meta-gsi")
    parser.add_argument("scenario", nargs="?", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        if ns.selftest:
            return selftest(ns.nginx)
        if not ns.scenario:
            parser.error("scenario required unless --selftest")
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"pblock scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
