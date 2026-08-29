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
from cmdscripts.fwd_matrix_cell_a import run_cell_a as _run_cell_a_operation
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
    return (f"brix_webdav_auth required;\n            brix_token_jwks     {h.tok_jwks};\n"
            f"            brix_token_issuer   {h.tok_issuer};\n"
            f"            brix_token_audience {TOK_AUD};")


def _c_root_auth(h, cred):
    if cred == "gsi":
        return (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                f"        brix_certificate_key {SERVER_KEY};\n"
                f"        brix_trusted_ca      {CA_CERT};")
    return (f"brix_auth token;\n        brix_token_jwks     {h.tok_jwks};\n"
            f"        brix_token_issuer   {h.tok_issuer};\n"
            f"        brix_token_audience {TOK_AUD};")


def _c_davs_auth(h, cred):
    auth = f"brix_trusted_ca {CA_CERT}; brix_webdav_auth required;"
    if cred == "gsi":
        return auth
    return auth + (f"\n            brix_token_jwks     {h.tok_jwks};\n"
                   f"            brix_token_issuer   {h.tok_issuer};\n"
                   f"            brix_token_audience {TOK_AUD};")


def _c_root_front_config(h, directory, log, port, cred, leg):
    auth = _c_root_auth(h, cred)
    return f"""daemon on;
error_log {log} info;
pid {directory}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    brix_credential origin_ca {{ ca_dir {CA_DIR}; }}
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {directory}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {auth}
        {leg}
    }}
}}
"""


def _c_davs_front_config(h, directory, log, port, cred, leg):
    auth = _c_davs_auth(h, cred)
    return f"""daemon on;
error_log {log} info;
pid {directory}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {directory}/logs/access.log;
    client_body_temp_path {directory}/export;
    brix_credential origin {{ x509_proxy {h.svc_proxy}; ca_dir {CA_DIR}; }}
    brix_credential origin_ca {{ ca_dir {CA_DIR}; }}
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
            brix_export {directory}/export;
            {auth}
            {leg}
        }}
    }}
}}
"""


def _spawn_c_front(h: ForwardHarness, role: str, fproto: str, cred: str, fport: int,
                   burl: str, cred_dir: Path) -> Path | None:
    d = h.run.mkdir(role)
    for sub in ("export", "logs"):
        (d / sub).mkdir(exist_ok=True)
    log = d / "logs/e.log"
    leg = h.backend_leg_config("C", "root" if burl.startswith("root") else "https", cred, burl, cred_dir)
    builders = {"root": _c_root_front_config, "davs": _c_davs_front_config}
    text = builders[fproto](h, d, log, fport, cred, leg)
    conf = h.run.write(d / "nginx.conf", text)
    if not h._start_nginx(d, conf, f"C front {role}"):
        return None
    h.last_log = log
    return log


_C_TOK_GAP = r"backend has NO credential|serve offload: materialise failed|getxattr lock on .* failed"
_C_WOB_GAP = r"root:// write to a whole-object storage backend is not supported"
_C_UNSUP = (r"cannot scope a session to a user credential|not.?implemented|unsupported|"
            r"no per-user|cannot present|passthrough.*unavailable|" + _C_WOB_GAP + "|" + _C_TOK_GAP)


def _c_cell_supported(h, key, hop2, cred):
    verdict, why = h.feasibility_probe("C", hop2, cred)
    if verdict != "SUPPORTED":
        h.record(key, verdict, why)
        return False
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return False
    return True


def _c_backend_location(hop2, port):
    if hop2 == "root":
        return "root", f"root://{HOST}:{port}"
    return "davs", f"https://{HOST}:{port}"


def _prepare_c_cell(h, wire, cred, key, hop1, hop2):
    backend_port, front_port = free_ports(2)
    backend_proto, backend_url = _c_backend_location(hop2, backend_port)
    front_proto = "root" if hop1 == "root" else "davs"
    backend_log = h.spawn_brix_node(
        f"cbk_{wire}_{cred}", backend_proto, backend_port, "",
        _c_backend_extra(h, backend_proto, cred),
    )
    if backend_log is None:
        h.record(key, "FAIL", "brix backend start failed")
        return None
    credential_dir = h.run.mkdir(f"creds_c_{wire}_{cred}")
    credential_dir.chmod(0o777)
    front_log = _spawn_c_front(
        h, f"cfr_{wire}_{cred}", front_proto, cred, front_port,
        backend_url, credential_dir,
    )
    if front_log is None:
        h.record(key, "FAIL", "brix front start failed")
        return None
    if cred == "gsi":
        h.install_gsi_cred(credential_dir, front_log, hop1, front_port)
    backend_export = h.prefix / f"cbk_{wire}_{cred}/export"
    return backend_log, front_log, backend_export, front_port


def _c_gap_reason(front_text):
    if "cannot scope a session to a user credential" in front_text:
        return ('backend "http" driver cannot scope a session to a per-user credential '
                "(Phase-70 https-backend-leg gap)")
    if re.search(_C_WOB_GAP, front_text):
        return ("root:// front -> whole-object https backend WRITE unsupported — the "
                "block-write path needs a staged-commit adapter")
    if re.search(_C_TOK_GAP, front_text):
        return ("backend leg did not receive the passed-through bearer — "
                "a static storage credential is still required")
    return "front cannot forward credential on this path"


def _record_c_positive_failure(h, key, front_log, result):
    front_text = front_log.read_text(errors="replace") if front_log.is_file() else ""
    if re.search(_C_UNSUP, front_text, re.I):
        reason = _c_gap_reason(front_text)
        h.record(key, "UNSUPPORTED", f"{reason} (put_ok={int(result.put_ok)})")
        return
    h.record(key, "FAIL", f"userA two-hop PUT/GET not byte-exact (put_ok={int(result.put_ok)})")


def _c_positive(h, key, wire, cred, hop1, port, backend_log, front_log):
    backend_log.write_text("")
    result = h.front_put_get(hop1, cred, port, f"posC_{wire}.bin", "A")
    if not result.get_ok:
        _record_c_positive_failure(h, key, front_log, result)
        return False
    time.sleep(0.4)
    identities = (
        h.assert_backend_identity("brix", backend_log, A_CN),
        h.assert_backend_identity("brix", backend_log, A_SUB),
    )
    if not any(identities):
        h.record(key, "FAIL", f"backend log did not show userA (DN={A_CN} / sub={A_SUB})")
        return False
    return True


def _c_negative(h, key, wire, cred, hop1, port, backend_export):
    result = h.front_put_get(hop1, cred, port, f"negC_{wire}.bin", "B")
    protocol = "root" if hop1 == "root" else "https"
    if not h.assert_denied(protocol, result):
        h.record(key, "FAIL", f"userB not denied on backend leg (deny_obs={result.deny_obs})")
        return
    if (backend_export / f"negC_{wire}.bin").is_file():
        h.record(key, "FAIL", "userB bytes reached the backend store")
        return
    h.record(key, "PASS", "userA at backend, userB denied, no leak (passthrough)")


def _run_cell_c(h: ForwardHarness, wire: str, cred: str) -> None:
    hop1, hop2 = h.hop1(wire), h.hop2(wire)
    key = f"C {wire} {cred}"
    if not _c_cell_supported(h, key, hop2, cred):
        return
    prepared = _prepare_c_cell(h, wire, cred, key, hop1, hop2)
    if prepared is None:
        return
    backend_log, front_log, backend_export, front_port = prepared
    if not _c_positive(
        h, key, wire, cred, hop1, front_port, backend_log, front_log
    ):
        return
    _c_negative(h, key, wire, cred, hop1, front_port, backend_export)


def _prepare_pairing_c(harness):
    reason = harness.preflight()
    if reason:
        print(f"run_fwd_brix_brix: environment SKIP ({reason})")
        return False
    if not harness.mint_pki():
        return False
    if not harness.mint_token():
        print("  (token authority unavailable — token cells will SKIP)")
        harness.tok_jwks = None
    return True


def _run_pairing_c_cells(harness):
    for wire in ("RR", "HH", "HR", "RH"):
        for credential in ("gsi", "token"):
            with harness.cell():
                _run_cell_c(harness, wire, credential)


def _finish_pairing_c(harness):
    unsupported = sum(
        outcome == "UNSUPPORTED" for _key, outcome, _reason in harness.results
    )
    exit_code = _outcome(harness, "run_fwd_brix_brix")
    if unsupported:
        print(f"  !! pairing C has {unsupported} UNSUPPORTED cell(s) — REAL Phase-70 gap(s) to flag (spec §9.4)")
    return exit_code


def fwd_brix_brix(nginx: Path | None = None) -> int:
    """Run pairing C: brix front to brix backend."""
    with ForwardHarness("c", nginx) as harness:
        if not _prepare_pairing_c(harness):
            return 0
        print("== credential-forwarding matrix — PAIRING C (brix-front -> brix-back) ==")
        _run_pairing_c_cells(harness)
        return _finish_pairing_c(harness)


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
            brix_trusted_ca {CA_CERT};
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
    _run_cell_a_operation(h, wire, cred, globals())
