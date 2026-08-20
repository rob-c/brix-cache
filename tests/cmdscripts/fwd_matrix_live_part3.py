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


def _outcome(harness: ForwardHarness, label: str) -> int:
    harness.summary(label)
    if harness.any_fail:
        print(f"{label}: FAIL cells present")
    else:
        print(f"{label}: no FAIL cells")
    return harness.any_fail


# ===========================================================================
# Pairing C — run_fwd_brix_brix.sh (brix-front -> brix-back)
# ===========================================================================

def _c_backend_extra(h: ForwardHarness, proto: str, cred: str) -> str:
    if proto == "root":
        if cred == "gsi":
            return (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                    f"        brix_certificate_key {SERVER_KEY};\n"
                    f"        brix_trusted_ca      {CA_CERT};")
        return (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
                f"        brix_token_issuer   {h.tok_issuer};\n"
                f"        brix_token_audience {TOK_AUD};")
    if cred == "gsi":
        return "brix_webdav_auth required;"
    return (f"brix_webdav_auth required;\n            brix_webdav_token_jwks     {h.tok_jwks};\n"
            f"            brix_webdav_token_issuer   {h.tok_issuer};\n"
            f"            brix_webdav_token_audience {TOK_AUD};")


def _spawn_c_front(h: ForwardHarness, role: str, fproto: str, cred: str, fport: int,
                   burl: str, cred_dir: Path) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    leg = h.backend_leg_config("C", "root" if burl.startswith("root") else "https", cred, burl, cred_dir)
    if fproto == "root":
        if cred == "gsi":
            auth = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                    f"        brix_certificate_key {SERVER_KEY};\n"
                    f"        brix_trusted_ca      {CA_CERT};")
        else:
            auth = (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
                    f"        brix_token_issuer   {h.tok_issuer};\n"
                    f"        brix_token_audience {TOK_AUD};")
        conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    brix_credential origin_ca {{ ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{fport};
        brix_root on;
        brix_export {d}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {auth}
        {leg}
    }}
}}
""")
    else:
        auth = f"brix_webdav_cafile {CA_CERT}; brix_webdav_auth required;"
        if cred != "gsi":
            auth += (f"\n            brix_webdav_token_jwks     {h.tok_jwks};\n"
                     f"            brix_webdav_token_issuer   {h.tok_issuer};\n"
                     f"            brix_webdav_token_audience {TOK_AUD};")
        conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    brix_credential origin_ca {{ ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{fport} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {d}/export;
            {auth}
            {leg}
        }}
    }}
}}
""")
    if not h._start_nginx(d, conf, f"C front {role}"):
        return None
    h.last_log = log
    return log


_C_TOK_GAP = r"backend has NO credential|serve offload: materialise failed|getxattr lock on .* failed"
_C_WOB_GAP = r"root:// write to a whole-object storage backend is not supported"
_C_UNSUP = (r"cannot scope a session to a user credential|not.?implemented|unsupported|"
            r"no per-user|cannot present|passthrough.*unavailable|" + _C_WOB_GAP + "|" + _C_TOK_GAP)


def _run_cell_c(h: ForwardHarness, wire: str, cred: str) -> None:
    hop1, hop2 = h.hop1(wire), h.hop2(wire)
    key = f"C {wire} {cred}"
    verdict, why = h.feasibility_probe("C", hop2, cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    bport, fport = free_ports(2)
    if hop2 == "root":
        bproto, burl = "root", f"root://{HOST}:{bport}"
    else:
        bproto, burl = "davs", f"https://{HOST}:{bport}"
    fproto = "root" if hop1 == "root" else "davs"

    blog = h.spawn_brix_node(f"cbk_{wire}_{cred}", bproto, bport, "", _c_backend_extra(h, bproto, cred))
    if blog is None:
        h.record(key, "FAIL", "brix backend start failed")
        return
    bexport = h.prefix / f"cbk_{wire}_{cred}/export"
    cred_dir = h.run.mkdir(f"creds_c_{wire}_{cred}")
    cred_dir.chmod(0o777)
    flog = _spawn_c_front(h, f"cfr_{wire}_{cred}", fproto, cred, fport, burl, cred_dir)
    if flog is None:
        h.record(key, "FAIL", "brix front start failed")
        return
    if cred == "gsi":
        h.install_gsi_cred(cred_dir, flog, hop1, fport)

    # ---- positive: userA two-hop PUT+GET + backend sees A ----
    blog.write_text("")
    pos = h.front_put_get(hop1, cred, fport, f"posC_{wire}.bin", "A")
    if not pos.get_ok:
        ftext = flog.read_text(errors="replace") if flog.is_file() else ""
        if re.search(_C_UNSUP, ftext, re.I):
            why = "front cannot forward credential on this path"
            if "cannot scope a session to a user credential" in ftext:
                why = ('backend "http" driver cannot scope a session to a per-user credential '
                       "(Phase-70 https-backend-leg gap)")
            if re.search(_C_WOB_GAP, ftext):
                why = ("root:// front -> whole-object https backend WRITE unsupported — the "
                       "block-write path (kXR_write/pgwrite) needs a staged-commit adapter to PUT "
                       "the object; sd_http has no random-write open (Phase-70 root->http-backend write gap)")
            if re.search(_C_TOK_GAP, ftext):
                why = ("backend leg did not receive the passed-through bearer — sd_xroot/serve-offload "
                       "needs a static brix_storage_credential (Phase-70 token passthrough gap)")
            h.record(key, "UNSUPPORTED", f"{why} (put_ok={int(pos.put_ok)})")
        else:
            h.record(key, "FAIL", f"userA two-hop PUT/GET not byte-exact (put_ok={int(pos.put_ok)})")
        return
    time.sleep(0.4)
    if not (h.assert_backend_identity("brix", blog, A_CN) or h.assert_backend_identity("brix", blog, A_SUB)):
        h.record(key, "FAIL", f"backend log did not show userA (DN={A_CN} / sub={A_SUB})")
        return
    # ---- negative: userB denied on backend leg, no bytes ----
    neg = h.front_put_get(hop1, cred, fport, f"negC_{wire}.bin", "B")
    if not h.assert_denied("root" if hop1 == "root" else "https", neg):
        h.record(key, "FAIL", f"userB not denied on backend leg (deny_obs={neg.deny_obs})")
        return
    if (bexport / f"negC_{wire}.bin").is_file():
        h.record(key, "FAIL", "userB bytes reached the backend store")
        return
    h.record(key, "PASS", "userA at backend, userB denied, no leak (passthrough)")


def fwd_brix_brix(nginx: Path | None = None) -> int:
    """Port of run_fwd_brix_brix.sh — pairing C, brix-front -> brix-back."""
    with ForwardHarness("c", nginx) as h:
        reason = h.preflight()
        if reason:
            print(f"run_fwd_brix_brix: environment SKIP ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        print("== credential-forwarding matrix — PAIRING C (brix-front -> brix-back) ==")
        for wire in ("RR", "HH", "HR", "RH"):
            for cred in ("gsi", "token"):
                with h.cell():
                    _run_cell_c(h, wire, cred)
        unsupported = sum(1 for _, outcome, _ in h.results if outcome == "UNSUPPORTED")
        rc = _outcome(h, "run_fwd_brix_brix")
        if unsupported:
            print(f"  !! pairing C has {unsupported} UNSUPPORTED cell(s) — REAL Phase-70 gap(s) to flag (spec §9.4)")
        return rc


# ===========================================================================
# Pairing A — run_fwd_brix_xrootd.sh (brix-front -> stock-xrootd-back)
# ===========================================================================

def _spawn_a_front_root(h: ForwardHarness, role: str, port: int, svc_block: str, server_extra: str) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    {svc_block}
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {d}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {server_extra}
    }}
}}
""")
    if not h._start_nginx(d, conf, f"A front {role}"):
        return None
    h.last_log = log
    return log


def _spawn_a_front_davs(h: ForwardHarness, role: str, port: int, leg: str) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    conf = h.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
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
            brix_export {d}/export;
            brix_webdav_cafile {CA_CERT};
            brix_webdav_auth required;
            {leg}
        }}
    }}
}}
""")
    if not h._start_nginx(d, conf, f"A davs front {role}"):
        return None
    h.last_log = log
    return log


def _run_cell_a(h: ForwardHarness, wire: str, cred: str) -> None:
    hop1, hop2 = h.hop1(wire), h.hop2(wire)
    key = f"A {wire} {cred}"
    verdict, why = h.feasibility_probe("A", hop2, cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    oport, fport = free_ports(2)

    if cred == "token":
        blog = h.spawn_xrootd_node(f"obk_{wire}_{cred}", "origin", oport, "", "token")
        if blog is None:
            h.record(key, "FAIL", "stock token origin start failed")
            return
        burl = f"roots://{HOST}:{oport}"
    elif hop2 == "https":
        blog = h.spawn_xrootd_node(f"obk_{wire}_{cred}", "xrdhttp", oport, "", "gsi")
        if blog is None:
            h.record(key, "FAIL", "stock XrdHttp origin start failed")
            return
        burl = f"https://{HOST}:{oport}"
    else:
        blog = h.spawn_xrootd_node(f"obk_{wire}_{cred}", "origin", oport, "", "gsi")
        burl = f"root://{HOST}:{oport}"

    cred_dir = h.run.mkdir(f"creds_{wire}_{cred}")
    cred_dir.chmod(0o777)
    # TOKEN cells keep the root-front bearer-passthrough path (a stock ztn
    # backend is roots://-only), so their front proto is pinned to root.
    fhop1 = "root" if cred == "token" else hop1
    leg = h.backend_leg_config("A", hop2, cred, burl, cred_dir)
    if fhop1 == "root":
        if cred == "token":
            svc_block = f"brix_credential origin_ca {{ ca_dir {CA_DIR}; }}"
            auth_block = (f"brix_auth token;\n        brix_tls on;\n"
                          f"        brix_certificate     {SERVER_CERT};\n"
                          f"        brix_certificate_key {SERVER_KEY};\n"
                          f"        brix_token_jwks     {h.tok_jwks};\n"
                          f"        brix_token_issuer   {h.tok_issuer};\n"
                          f"        brix_token_audience {TOK_AUD};")
        else:
            svc_block = f"brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}"
            auth_block = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                          f"        brix_certificate_key {SERVER_KEY};\n"
                          f"        brix_trusted_ca      {CA_CERT};")
        flog = _spawn_a_front_root(h, f"afront_{wire}_{cred}", fport, svc_block, f"{auth_block}\n        {leg}")
    else:
        flog = _spawn_a_front_davs(h, f"afront_{wire}_{cred}", fport, leg)
    if flog is None:
        h.record(key, "FAIL", "brix front start failed")
        return

    if cred == "gsi":
        h.install_gsi_cred(cred_dir, flog, fhop1, fport)
    time.sleep(0.5)

    # ---- positive: userA PUT+GET, backend sees A (retry once past the
    # probe-connection cred-miss race) ----
    if blog is not None:
        blog.write_text("")
    pos = h.front_put_get(fhop1, cred, fport, f"posA_{wire}.bin", "A")
    if not pos.get_ok:
        time.sleep(0.4)
        pos = h.front_put_get(fhop1, cred, fport, f"posA2_{wire}.bin", "A")
    if not pos.get_ok:
        detail = f"userA two-hop PUT/GET not byte-exact (put_ok={int(pos.put_ok)})"
        if cred == "token" and pos.deny_obs:
            detail += f" client={pos.deny_obs}"
        ftext = flog.read_text(errors="replace") if flog.is_file() else ""
        if cred == "token":
            evidence = [line for line in ftext.splitlines()
                        if re.search(r"kXR 3028|origin TLS handshake failed|ztn", line, re.I)]
            if evidence:
                detail = f"front->stock-origin ztn/TLS leg failed (put_ok={int(pos.put_ok)}): {evidence[-1]}"
        h.record(key, "FAIL", detail)
        return
    time.sleep(0.4)
    expect_id = A_SUB if cred == "token" else ("fwd-user-a" if hop2 == "https" else A_CN)
    if not h.assert_backend_identity("stock", blog, expect_id):
        h.record(key, "FAIL", f"backend log did not show userA ({expect_id})")
        return
    # ---- negative: userB denied on the backend leg, no bytes ----
    obdir = h.prefix / f"obk_{wire}_{cred}/data"
    neg = h.front_put_get(fhop1, cred, fport, f"negB_{wire}.bin", "B")
    if not h.assert_denied("root" if fhop1 == "root" else "https", neg):
        h.record(key, "FAIL", f"userB was NOT denied on backend leg (deny_obs={neg.deny_obs})")
        return
    if (obdir / f"negB_{wire}.bin").is_file():
        h.record(key, "FAIL", "userB bytes reached the backend store")
        return
    h.record(key, "PASS", "userA DN at backend, userB denied, no leak")
