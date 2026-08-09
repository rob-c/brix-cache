"""Direct Python ports for the credential-forwarding matrix live shell scenarios.

Ports ``run_fwd_brix_brix.sh`` (pairing C), ``run_fwd_brix_xrootd.sh``
(pairing A), ``run_fwd_xrootd_brix.sh`` (pairing B),
``fwd_b_token_forward_probe.sh`` (the pairing-B token evidence probe), and
``run_transparent_relay.sh``.  The :class:`ForwardHarness` below is the Python
port of the shared shell library ``tests/lib/fwd_matrix.sh`` — node spawners,
PKI/token minting, per-cell scoped teardown, and the backend-identity
assertions.  Each public scenario contains its shell script's own acceptance
sequence and PASS/FAIL/GAP/UNSUPPORTED/SKIP cell verdicts.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Iterator, NamedTuple

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from lib_py.util import wait_tcp
from settings import BIND_HOST, CA_CERT, CA_DIR, CA_KEY, HOST, SERVER_CERT, SERVER_KEY
from ephemeral_port import free_ports

BRIX_XRDCP = REPO_ROOT / "client/bin/xrdcp"
BRIX_XRDFS = REPO_ROOT / "client/bin/xrdfs"
XROOTD_BIN = Path(os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
SYS_XRDCP = shutil.which("xrdcp")

A_CN, B_CN, SVC_CN = "Fwd User A", "Fwd User B", "Fwd Service"
A_SUB, B_SUB = "fwd-user-a", "fwd-user-b"
TOK_AUD = "nginx-xrootd"


def fwd_brix_xrootd(nginx: Path | None = None) -> int:
    """Port of run_fwd_brix_xrootd.sh — pairing A, brix-front -> xrootd-back."""
    with ForwardHarness("a", nginx) as h:
        reason = h.preflight(need_xrootd=True)
        if reason:
            print(f"run_fwd_brix_xrootd: pairing A SKIPPED wholesale ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        print("== credential-forwarding matrix — PAIRING A (brix-front -> xrootd-back) ==")
        for wire in ("RR", "HH", "HR", "RH"):
            for cred in ("gsi", "token"):
                with h.cell():
                    _run_cell_a(h, wire, cred)
        return _outcome(h, "run_fwd_brix_xrootd")


# ===========================================================================
# Pairing B — run_fwd_xrootd_brix.sh (stock-pss-front -> brix-back)
# ===========================================================================

_B_TOKEN_GAP = ("stock xrootd v5.9.6 does not forward the client WLCG token to the origin "
                "(pss/pfc/persona all proven not to carry the bearer — see "
                "fwd_b_token_forward_probe.sh); brix-back would authenticate the service, "
                "not fwd-user-a")


def _run_cell_b(h: ForwardHarness, wire: str, cred: str) -> None:
    key = f"B {wire} {cred}"
    verdict, why = h.feasibility_probe("B", h.hop2(wire), cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return
    # Token forwarding through a stock xrootd front is a PROVEN stock blocker
    # (XrdPssConfig: "We don't support credential forwarding, yet").
    if cred == "token":
        h.record(key, "GAP", _B_TOKEN_GAP)
        return
    if SYS_XRDCP is None:
        h.record(key, "SKIP", "system xrdcp absent — cannot drive the stock pss front")
        return

    bport, fport = free_ports(2)
    if cred == "gsi":
        bextra = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                  f"        brix_certificate_key {SERVER_KEY};\n"
                  f"        brix_trusted_ca      {CA_CERT};")
    else:
        bextra = (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
                  f"        brix_token_issuer   {h.tok_issuer};\n"
                  f"        brix_token_audience {TOK_AUD};")
    blog = h.spawn_brix_node(f"bbk_{wire}_{cred}", "root", bport, "", bextra)
    if blog is None:
        h.record(key, "FAIL", "brix backend start failed")
        return
    bexport = h.prefix / f"bbk_{wire}_{cred}/export"
    h.spawn_xrootd_node(f"bfront_{wire}_{cred}", "pss", fport, f"{HOST}:{bport}", cred)

    blog.write_text("")
    payload = h.prefix / "payloadB_A.bin"
    payload.write_bytes(os.urandom(65536))
    if cred == "gsi":
        env = h.gsi_env(h.proxy_a)
    else:
        env = {"BEARER_TOKEN": h.token_a.read_text().strip()}
    _call([SYS_XRDCP, "-f", payload, f"root://{HOST}:{fport}//posB_{wire}.bin"],
          env_add=env, timeout=60)
    time.sleep(0.5)

    blog_text = blog.read_text(errors="replace") if blog.is_file() else ""
    if h.assert_backend_identity("brix", blog, A_CN) or h.assert_backend_identity("brix", blog, A_SUB):
        if (bexport / f"posB_{wire}.bin").is_file():
            h.record(key, "PASS", "stock pss forwarded userA identity to brix-back")
        else:
            h.record(key, "GAP", "userA authenticated at brix-back but no bytes (pss delegated auth only)")
        return
    if re.search(r"GSI auth OK dn=|valid token sub=", blog_text):
        h.record(key, "GAP", "stock pss forwarded its own service identity, not userA (documented stock limitation)")
    elif not blog_text.strip() or not re.search(r"auth|login|token", blog_text):
        h.record(key, "GAP", "stock pss forwarded no client credential to brix-back (anonymous forward)")
    else:
        h.record(key, "GAP", "brix-back saw a non-userA identity from the stock pss front")


def fwd_xrootd_brix(nginx: Path | None = None) -> int:
    """Port of run_fwd_xrootd_brix.sh — pairing B, xrootd-front -> brix-back."""
    with ForwardHarness("b", nginx) as h:
        reason = h.preflight(need_xrootd=True)
        if reason:
            print(f"run_fwd_xrootd_brix: pairing B SKIPPED wholesale ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        print("== credential-forwarding matrix — PAIRING B (xrootd-front -> brix-back) ==")
        for wire in ("RR", "HR", "HH", "RH"):
            for cred in ("gsi", "token"):
                with h.cell():
                    _run_cell_b(h, wire, cred)
        return _outcome(h, "run_fwd_xrootd_brix")


# ===========================================================================
# fwd_b_token_forward_probe.sh — empirical pairing-B token-forwarding probe
# ===========================================================================

def _probe_front_sec_block(h: ForwardHarness, d: Path) -> str:
    (d / "scitokens.cfg").write_text(f"""[Global]
audience = {TOK_AUD}
[Issuer test]
issuer = {h.tok_issuer}
base_path = /
default_user = fwduser
""")
    sec_lib = Path("/usr/lib64/libXrdSec-5.so")
    if not sec_lib.is_file():
        sec_lib = Path("/usr/lib/libXrdSec-5.so")
    return (f"xrd.tls   {SERVER_CERT} {SERVER_KEY}\n"
            f"xrd.tlsca certdir {CA_DIR}\n"
            f"xrootd.seclib {sec_lib}\n"
            "sec.protocol ztn\n"
            "sec.protbind * ztn\n"
            "ofs.authorize 1\n"
            f"ofs.authlib libXrdAccSciTokens-5.so config={d}/scitokens.cfg")


_PROBE_CFG = {
    "fwd": "ofs.osslib libXrdPss.so\npss.origin {origin}\npss.setopt DebugLevel 0",
    "pfc": ("ofs.osslib libXrdPfc.so\npfc.osslib libXrdPss.so\npss.origin {origin}\n"
            "pss.setopt DebugLevel 0\npfc.blocksize 1M"),
    "persona": ("ofs.osslib libXrdPss.so\npss.origin {origin}\npss.persona client\n"
                "pss.setopt DebugLevel 0"),
}


def _probe_spawn_front(h: ForwardHarness, role: str, variant: str, port: int, backhost: str) -> Path:
    d = h.run.mkdir(role)
    for sub in ("data", "admin", "run", "pfc", "scitok_cache"):
        (d / sub).mkdir(exist_ok=True)
    cfg, log = d / "x.cfg", d / "x.log"
    log.write_text("")
    localroot = d / ("pfc" if variant == "pfc" else "data")
    origin = f"roots://{backhost}/"     # ztn requires TLS to the origin
    cfg.write_text(f"""all.role server
all.export /
oss.localroot {localroot}
all.adminpath {d}/admin
all.pidpath   {d}/run
xrd.port {port}
xrd.network nodnr
xrd.allow host *
xrd.trace off
{_PROBE_CFG[variant].format(origin=origin)}
{_probe_front_sec_block(h, d)}
""")
    h.spawn_bwrap_xrootd(d, cfg, log, port)
    return log


def _grep_tail(log: Path, pattern: str, count: int) -> list[str]:
    if not log.is_file():
        return []
    lines = [line for line in log.read_text(errors="replace").splitlines()
             if re.search(pattern, line, re.I)]
    return lines[-count:]


def _probe_variant(h: ForwardHarness, variant: str, probe_results: list[tuple[str, str, str]]) -> None:
    def rec(status: str, detail: str) -> None:
        probe_results.append((variant, status, detail))
        print(f"  [{status}] {variant:<26} {detail}")

    bport, fport = free_ports(2)
    bextra = (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
              f"        brix_token_issuer   {h.tok_issuer};\n"
              f"        brix_token_audience {TOK_AUD};")
    blog = h.spawn_brix_node("bbk_tok_" + variant, "roots", bport, "", bextra)
    if blog is None:
        rec("SKIP", "brix token backend failed to start")
        return
    bexport = h.prefix / f"bbk_tok_{variant}/export"
    front_log = _probe_spawn_front(h, f"sf_{variant}", variant, fport, f"{HOST}:{bport}")

    if not wait_tcp(HOST, fport, 2):
        why = ";".join(_grep_tail(front_log, r"Config|error|persona|unsupported|unable", 3))
        rec("BLOCKED", f"front did not listen: {why or f'see {front_log}'}")
        return

    blog.write_text("")
    payload = h.prefix / f"pl_{variant}.bin"
    payload.write_bytes(os.urandom(65536))
    env = {"BEARER_TOKEN": h.token_a.read_text().strip(), "XrdSecPROTOCOL": "ztn",
           "X509_CERT_DIR": CA_DIR, "X509_CERT_FILE": CA_CERT, "XrdSecGSICADIR": CA_DIR,
           "XRD_CONNECTIONWINDOW": "8", "XRD_CONNECTIONRETRY": "1",
           "XRD_REQUESTTIMEOUT": "12", "XRD_STREAMTIMEOUT": "12",
           "XRD_TIMEOUTRESOLUTION": "1"}
    _call([SYS_XRDCP, "-f", payload, f"roots://{HOST}:{fport}//probe_{variant}.bin"],
          env_add=env, timeout=40)
    time.sleep(0.8)

    blog_text = blog.read_text(errors="replace") if blog.is_file() else ""
    if re.search(r'valid token sub="?fwd-user-a"?', blog_text):
        if (bexport / f"probe_{variant}.bin").is_file():
            rec("PASS", "brix-back authenticated END USER (sub=fwd-user-a) AND bytes landed")
        else:
            rec("PARTIAL", "brix-back authenticated sub=fwd-user-a but no bytes")
    elif re.search(r"valid token sub=", blog_text):
        sub = re.findall(r'valid token sub="?[^" ]+', blog_text)[-1]
        rec("WRONG_ID", f"brix-back authenticated a NON-userA token: {sub}")
    elif re.search(r"token|auth|login|Auth", blog_text):
        rec("NO_FWD", "brix-back saw auth activity but NOT userA's token (see below)")
    else:
        rec("NO_FWD", "brix-back authenticated NOBODY — token NOT forwarded (anonymous)")

    print(f"    --- brix-back auth-relevant log ({variant}) ---")
    for line in _grep_tail(blog, r"token|auth|login|ztn|handshake|anonymous|entity|sub=", 8):
        print(f"      {line}")
    print(f"    --- stock front auth/config log ({variant}) ---")
    for line in _grep_tail(front_log, r"ztn|token|persona|forward|Config|login|auth|error", 8):
        print(f"      {line}")


def token_forward_probe(nginx: Path | None = None) -> int:
    """Port of fwd_b_token_forward_probe.sh — evidence probe, never a FAIL gate."""
    with ForwardHarness("bprobe", nginx) as h:
        reason = h.preflight(need_xrootd=True)
        if reason:
            print(f"fwd_b_token_forward_probe: probe SKIPPED ({reason})")
            return 0
        if SYS_XRDCP is None:
            print("fwd_b_token_forward_probe: probe SKIPPED (system xrdcp absent)")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("fwd_b_token_forward_probe: probe SKIPPED (token authority)")
            return 0
        print("== PAIRING B token-forwarding EMPIRICAL PROBE (stock front -> brix-back roots://) ==")
        probe_results: list[tuple[str, str, str]] = []
        for variant in ("fwd", "pfc", "persona"):
            with h.cell():
                _probe_variant(h, variant, probe_results)
        print("\n---- probe summary ----")
        for variant, status, detail in probe_results:
            print(f"  {variant:<10} {status:<10} {detail}")
        return 0


# ===========================================================================
# run_transparent_relay.sh — root:// tap/relay passthrough + opcode logging
# ===========================================================================

def transparent_relay(nginx: Path | None = None) -> int:
    """Port of run_transparent_relay.sh."""
    if not os.access(BRIX_XRDFS, os.X_OK):
        print(f"run_transparent_relay: SKIP (missing {BRIX_XRDFS})")
        return 0
    with LiveRun("relay", nginx) as run:
        origin_port, relay_port = free_ports(2)
        origin, relay = run.mkdir("o"), run.mkdir("n")
        (origin / "root").mkdir()
        (origin / "logs").mkdir()
        (relay / "logs").mkdir()
        origin_conf = run.write(origin / "nginx.conf", f"""daemon on; error_log {origin}/logs/e.log info; pid {origin}/pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{origin_port}; brix_root on; brix_export {origin}/root; brix_auth none; }} }}
""")
        relay_conf = run.write(relay / "nginx.conf", f"""daemon on; error_log {relay}/logs/e.log info; pid {relay}/pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen {BIND_HOST}:{relay_port}; brix_root on;
    brix_transparent_proxy {HOST}:{origin_port};
}} }}
""")
        # Root harness: these configs pin no `user`, so the always-on
        # de-escalation drops workers to `nobody`, which cannot traverse the
        # 0700 mkdtemp tree — the export's confined-ops open EACCESes and the
        # node never serves. Open the tree for that worker (this direct launch
        # bypasses ForwardHarness._start_nginx, so the opening is repeated here).
        from cmdscripts import open_tree_for_worker  # noqa: PLC0415
        for prefix, conf, port in ((origin, origin_conf, origin_port), (relay, relay_conf, relay_port)):
            open_tree_for_worker(run.root, conf)
            result = _call([run.nginx, "-p", prefix, "-c", conf],
                           env_drop=("NGINX",))
            if result.returncode:
                print(f"start failed: {result.stderr.strip()}")
                return 2
            run.pidfiles.append(prefix / "pid")
        time.sleep(1)
        payload = origin / "root/f.bin"
        payload.write_bytes(os.urandom(300000))

        got = run.root / "relay_a.got"
        _call([BRIX_XRDFS, f"root://{HOST}:{relay_port}", "cat", "/f.bin"],
              stdout_to=got, timeout=60)
        stat = _call([BRIX_XRDFS, f"root://{HOST}:{relay_port}", "stat", "/f.bin"], timeout=60)
        time.sleep(0.5)
        relay_log = (relay / "logs/e.log").read_text(errors="replace")
        checks = [
            (got.is_file() and got.read_bytes() == payload.read_bytes(), "relay passthrough byte-exact"),
            (stat.returncode == 0, "stat via relay"),
            ('"op":"open"' in relay_log, "tap logged open"),
            ('"op":"stat"' in relay_log, "tap logged stat"),
        ]
        for passed, message in checks:
            print(f"  {'ok  ' if passed else 'FAIL'} {message}")
        return 0 if all(passed for passed, _ in checks) else 1


SCENARIOS = {
    "fwd-brix-brix": fwd_brix_brix,
    "fwd-brix-xrootd": fwd_brix_xrootd,
    "fwd-xrootd-brix": fwd_xrootd_brix,
    "token-forward-probe": token_forward_probe,
    "transparent-relay": transparent_relay,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"fwd matrix scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
