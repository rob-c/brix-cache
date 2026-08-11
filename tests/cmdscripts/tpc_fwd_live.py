"""Direct Python ports of the TPC credential-forwarding live shell scenarios.

Ports ``run_tpc_fwd_root.sh`` (native root:// TPC, ``xrdcp --tpc delegate``
PULL), ``run_tpc_fwd_webdav.sh`` (WebDAV/HTTP third-party COPY PULL), and
``run_tpc_delegation_nginx.sh`` (GSI proxy delegation with nginx as a real
fileserver on both ends).  The TPC topology/driver code below is the Python
port of ``tests/lib/tpc_fwd.sh``; PKI/token minting and node plumbing come from
:class:`cmdscripts.fwd_matrix_live.ForwardHarness` (the ``fwd_matrix.sh``
port).

PROOF STANDARD (spec §2): a TPC PULL asks the DESTINATION to copy a file from
a SOURCE; positive = byte-exact copy AND the SOURCE authenticated userA
(source-log GSI DN / token sub — the delegated end-user identity, not a
service credential); negative = userB (no / wrong delegated cred) → SOURCE
denies + DEST file absent.
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import NamedTuple

from cmdscripts.fwd_matrix_live import (
    A_CN, A_SUB, BRIX_XRDCP, TOK_AUD, XROOTD_BIN, ForwardHarness, _call,
)
from cmdscripts.live_common import (
    LiveFailure, LiveRun, REPO_ROOT, inject_nginx_load_modules,
)
from fleet_ports import cmdscript_ports
from lib_py.util import wait_tcp
from settings import BIND_HOST, CA_CERT, CA_DIR, HOST, SERVER_CERT, SERVER_HOST, SERVER_KEY, TEST_ROOT

_PORTS = cmdscript_ports("tpc_fwd_live")

# A NAME (matches the cert DNS:localhost SAN) so the GSI client does NOT fall
# back to reverse-DNS, which forbids proxy delegation.
TPC_HOST = SERVER_HOST


def _token_root_tpc(harness, bearer_mode):
    config = ("brix_tpc_allow_local on;\n        brix_tpc_allow_private on;\n"
              "        brix_tpc_outbound_tls on;")
    if bearer_mode == "passthrough":
        return config + "\n        brix_tpc_outbound_passthrough on;"
    if bearer_mode:
        return config + f"\n        brix_tpc_outbound_bearer_file {bearer_mode};"
    return config


def _root_destination_blocks(harness, credential, bearer_mode):
    if credential == "gsi":
        auth = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                f"        brix_certificate_key {SERVER_KEY};\n"
                f"        brix_trusted_ca      {CA_CERT};")
        tpc = ("brix_tpc_allow_local on;\n        brix_tpc_allow_private on;\n"
               "        brix_tpc_delegate on;\n        brix_gsi_signed_dh require;")
        return auth, tpc
    auth = (f"brix_auth token;\n        brix_certificate     {SERVER_CERT};\n"
            f"        brix_certificate_key {SERVER_KEY};\n"
            f"        brix_token_jwks      {harness.tok_jwks};\n"
            f"        brix_token_issuer    {harness.tok_issuer};\n"
            f"        brix_token_audience  {TOK_AUD};")
    return auth, _token_root_tpc(harness, bearer_mode)


def _copied_file_ok(returned, successes, destination, source):
    if returned not in successes:
        return False
    return destination.is_file() and destination.read_bytes() == source.read_bytes()


def _identity_file(user_a, user_b, who):
    return user_a if who == "A" else user_b


def _webdav_copy_command(harness, credential, who, source_url, destination_url):
    if credential == "token":
        token = _identity_file(harness.token_a, harness.token_b, who).read_text().strip()
        return ["curl", "-sk", "-H", f"Authorization: Bearer {token}",
                "-X", "COPY", destination_url, "-H", "Credential: none",
                "-H", f"Source: {source_url}",
                "-H", f"TransferHeaderAuthorization: Bearer {token}",
                "-w", "%{http_code}", "-o", os.devnull]
    proxy = _identity_file(harness.proxy_a, harness.proxy_b, who)
    command = ["curl", "-sk", "--cert", str(proxy), "--key", str(proxy),
               "-X", "COPY", destination_url, "-H", "Credential: none",
               "-H", f"Source: {source_url}"]
    if who == "A":
        delegated = base64.b64encode(proxy.read_bytes()).decode()
        command.extend(["-H", f"X-Brix-Delegate-Proxy: {delegated}"])
    command.extend(["-w", "%{http_code}", "-o", os.devnull])
    return command


def _root_copy_process(harness, credential, who, source_url, destination_url):
    command = [BRIX_XRDCP, "-f", "--tpc", "delegate", source_url, destination_url]
    if credential != "gsi":
        token = _identity_file(harness.token_a, harness.token_b, who)
        return _call(command, env_add=harness.token_env(token), timeout=90)
    proxy = _identity_file(harness.proxy_a, harness.proxy_b, who)
    env = harness.gsi_env(proxy)
    drop = ()
    if who == "A":
        env["XRDC_GSI_DELEGATE"] = "1"
    else:
        drop = ("XRDC_GSI_DELEGATE",)
    return _call(command, env_add=env, env_drop=drop, timeout=90)


class TpcResult(NamedTuple):
    copy_ok: bool
    deny_obs: str


class TpcHarness(ForwardHarness):
    """ForwardHarness + the TPC source/dest emitters and PULL drivers."""

    # -- SOURCE emitters ----------------------------------------------------
    def spawn_brix_source_root(self, role: str, cred: str, port: int) -> Path | None:
        if cred == "gsi":
            extra = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                     f"        brix_certificate_key {SERVER_KEY};\n"
                     f"        brix_trusted_ca      {CA_CERT};")
        else:
            # ztn requires TLS on the wire; the token source advertises its
            # certificate so the outbound TPC session can upgrade to roots://.
            extra = (f"brix_auth token;\n        brix_certificate     {SERVER_CERT};\n"
                     f"        brix_certificate_key {SERVER_KEY};\n"
                     f"        brix_token_jwks      {self.tok_jwks};\n"
                     f"        brix_token_issuer    {self.tok_issuer};\n"
                     f"        brix_token_audience  {TOK_AUD};")
        return self.spawn_brix_node(role, "root", port, "", extra)

    def spawn_brix_source_dav(self, role: str, cred: str, port: int) -> Path | None:
        d = self.run.mkdir(role)
        for sub in ("export", "logs"):
            (d / sub).mkdir(exist_ok=True)
        log = d / "logs/e.log"
        if cred == "gsi":
            sslblock = f"""listen {BIND_HOST}:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;"""
            authblock = (f"brix_trusted_ca {CA_CERT};\n"
                         "            brix_webdav_auth required;")
        else:
            # TOKEN source is deliberately TOKEN-ONLY (no ssl_verify_client, no
            # proxy_certs) so the ONLY credential that authenticates the pull
            # leg is the forwarded bearer — proving forwarding unambiguously.
            sslblock = (f"listen {BIND_HOST}:{port} ssl;\n"
                        f"        ssl_certificate     {SERVER_CERT};\n"
                        f"        ssl_certificate_key {SERVER_KEY};")
            authblock = (f"brix_trusted_ca {CA_CERT};\n"
                         "            brix_webdav_auth required;\n"
                         f"            brix_token_jwks     {self.tok_jwks};\n"
                         f"            brix_token_issuer   {self.tok_issuer};\n"
                         f"            brix_token_audience {TOK_AUD};")
        conf = self.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    server {{
        {sslblock}
        client_max_body_size 1g;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {d}/export;
            {authblock}
        }}
    }}
}}
""")
        if not self._start_nginx(d, conf, f"dav source {role}"):
            return None
        self.last_log = log
        return log

    # -- DESTINATION (TPC coordinator) emitters ------------------------------
    def spawn_brix_dest_root(self, role: str, cred: str, port: int,
                             bearer_mode: str = "") -> Path | None:
        d = self.run.mkdir(role)
        for sub in ("export", "logs"):
            (d / sub).mkdir(exist_ok=True)
        log = d / "logs/e.log"
        auth, tpc = _root_destination_blocks(self, cred, bearer_mode)
        conf = self.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=4 max_queue=65536;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen {BIND_HOST}:{port};
        brix_root on;
        brix_export {d}/export;
        brix_allow_write on;
        brix_upload_resume off;
        {auth}
        {tpc}
    }}
}}
""")
        if not self._start_nginx(d, conf, f"root dest {role}"):
            return None
        time.sleep(0.1)  # shell used 0.7s here vs 0.6s elsewhere
        self.last_log = log
        return log

    def spawn_brix_dest_dav(self, role: str, cred: str, port: int,
                            static_mode: str = "") -> Path | None:
        d = self.run.mkdir(role)
        for sub in ("export", "logs", "cred"):
            (d / sub).mkdir(exist_ok=True)
        log = d / "logs/e.log"
        if cred == "gsi":
            auth = (f"brix_trusted_ca {CA_CERT};\n"
                    "            brix_webdav_auth required;\n"
                    "            brix_backend_delegation passthrough;\n"
                    f"            brix_storage_credential_dir {d}/cred;")
            static_cert = ""
            if static_mode != "nostatic":
                static_cert = (f"brix_webdav_tpc_cert   {SERVER_CERT};\n"
                               f"            brix_webdav_tpc_key    {SERVER_KEY};")
            tpc = ("brix_webdav_tpc on;\n            brix_webdav_tpc_allow_local on;\n"
                   f"            {static_cert}\n"
                   f"            brix_webdav_tpc_cafile {CA_CERT};\n"
                   "            brix_webdav_tpc_timeout 15;")
        else:
            auth = (f"brix_trusted_ca {CA_CERT};\n"
                    "            brix_webdav_auth required;\n"
                    f"            brix_token_jwks     {self.tok_jwks};\n"
                    f"            brix_token_issuer   {self.tok_issuer};\n"
                    f"            brix_token_audience {TOK_AUD};")
            tpc = ("brix_webdav_tpc on;\n            brix_webdav_tpc_allow_local on;\n"
                   f"            brix_webdav_tpc_cafile {CA_CERT};\n"
                   "            brix_webdav_tpc_timeout 15;")
        conf = self.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    access_log {d}/logs/access.log;
    client_body_temp_path {d}/export;
    server {{
        listen {BIND_HOST}:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;
        client_max_body_size 1g;
        location / {{
            brix_webdav on;
            brix_allow_write on;
            brix_export {d}/export;
            {auth}
            {tpc}
        }}
    }}
}}
""")
        if not self._start_nginx(d, conf, f"dav dest {role}"):
            return None
        self.last_log = log
        return log

    # -- PULL drivers ---------------------------------------------------------
    def drive_tpc_webdav(self, cred: str, sport: int, dport: int, obj: str, who: str) -> TpcResult:
        src_url = f"https://{TPC_HOST}:{sport}/tpcsrc.bin"
        dst_url = f"https://{TPC_HOST}:{dport}/{obj}"
        dexport = self.prefix / "dstdav/export"
        argv = _webdav_copy_command(self, cred, who, src_url, dst_url)
        code = _call(argv, timeout=90).stdout.strip()
        copy_ok = _copied_file_ok(code, ("200", "201", "204"), dexport / obj,
                                  self.prefix / "tpcsrc.bin")
        return TpcResult(copy_ok, code)

    def drive_tpc_root(self, cred: str, sport: int, dport: int, obj: str, who: str) -> TpcResult:
        src_url = f"root://{TPC_HOST}:{sport}//tpcsrc.bin"
        dst_url = f"root://{TPC_HOST}:{dport}//{obj}"
        dexport = self.prefix / "dstroot/export"
        proc = _root_copy_process(self, cred, who, src_url, dst_url)
        (self.prefix / f"tpc_{who}.err").write_text(proc.stderr or "")
        copy_ok = _copied_file_ok(proc.returncode, (0,), dexport / obj,
                                  self.prefix / "tpcsrc.bin")
        return TpcResult(copy_ok, f"rc={proc.returncode}")

    # -- assertions -------------------------------------------------------------
    def assert_source_identity(self, kind: str, cred: str, log: Path | None) -> bool:
        expect = A_CN if cred == "gsi" else A_SUB
        return self.assert_backend_identity(kind, log, expect)

    @staticmethod
    def assert_tpc_denied(result: TpcResult, dstfile: Path) -> bool:
        return not result.copy_ok and not dstfile.is_file()


def _tpc_outcome(h: TpcHarness, label: str) -> int:
    h.summary(label)
    gaps = sum(1 for _, outcome, _ in h.results if outcome == "GAP")
    if gaps:
        print(f"  ({gaps} GAP cell(s) — documented delegation limitation, evidence attached)")
    print(f"{label}: {'FAIL cells present' if h.any_fail else 'no FAIL cells'}")
    return h.any_fail


def _grep_last(log: Path, pattern: str) -> str:
    if not log.is_file():
        return ""
    lines = [line for line in log.read_text(errors="replace").splitlines()
             if re.search(pattern, line, re.I)]
    return lines[-1] if lines else ""


# ===========================================================================
# run_tpc_fwd_root.sh — native root:// TPC flavor (PULL)
# ===========================================================================

def _root_cell_bb(h: TpcHarness, cred: str) -> None:
    key = f"root bb {cred}"
    if _root_token_unavailable(h, cred):
        h.record(key, "SKIP", "token authority unavailable")
        return
    topology = _start_root_bb(h, cred, key)
    if topology is None:
        return
    sport, dport, slog, dlog = topology
    slog.write_text("")
    pos = h.drive_tpc_root(cred, sport, dport, "posA.bin", "A")
    if not pos.copy_ok:
        _record_root_positive_failure(h, key, cred, pos, dlog)
        return
    time.sleep(0.3)
    if not h.assert_source_identity("brix", cred, slog):
        _record_root_identity_failure(h, key, cred, slog)
        return
    neg = h.drive_tpc_root(cred, sport, dport, "negB.bin", "B")
    _record_root_negative(h, key, cred, neg)


def _root_token_unavailable(harness, credential):
    return credential == "token" and harness.tok_jwks is None


def _start_root_bb(harness, credential, key):
    sport, dport = _PORTS[0:2]
    source_log = harness.spawn_brix_source_root("srcroot", credential, sport)
    if source_log is None:
        harness.record(key, "FAIL", "brix root source start failed")
        return None
    source = harness.prefix / "tpcsrc.bin"
    (harness.prefix / "srcroot/export/tpcsrc.bin").write_bytes(source.read_bytes())
    bearer = "passthrough" if credential == "token" else ""
    destination_log = harness.spawn_brix_dest_root("dstroot", credential, dport, bearer)
    if destination_log is None:
        harness.record(key, "FAIL", "brix root dest start failed")
        return None
    return sport, dport, source_log, destination_log


def _record_root_positive_failure(harness, key, credential, result, destination_log):
    if credential == "token":
        evidence = _grep_last(destination_log, r"ztn|token|tls|3028|auth|passthrough")
        message = f"userA passthrough token pull did not complete ({result.deny_obs}): {evidence}"
    else:
        lines = (harness.prefix / "tpc_A.err").read_text(errors="replace").splitlines()
        tail = lines[-1] if lines else ""
        message = f"userA delegated GSI pull not byte-exact ({result.deny_obs}): {tail}"
    harness.record(key, "FAIL", message)


def _record_root_identity_failure(harness, key, credential, source_log):
    if credential == "token":
        identity = f"userA (sub={A_SUB}) on the forwarded pull leg"
    else:
        identity = f"userA (DN={A_CN}) on the pull leg"
    harness.record(key, "FAIL", f"source did not authenticate {identity} — check {source_log}")


def _record_root_negative(h, key, cred, neg):
    if h.assert_tpc_denied(neg, h.prefix / "dstroot/export/negB.bin"):
        if cred == "token":
            h.record(key, "PASS", "source authenticated userA (forwarded inbound bearer, passthrough); userB (wrong-issuer) denied, no bytes")
        else:
            h.record(key, "PASS", "source authenticated userA (delegated proxy); userB (no delegation) denied, no bytes")
    else:
        h.record(key, "FAIL", f"userB not denied ({neg.deny_obs}) or bytes leaked to dest")


def _root_cell_sb(h: TpcHarness, cred: str) -> None:
    key = f"root stock-src->brix-dest {cred}"
    if not os.access(XROOTD_BIN, os.X_OK):
        h.record(key, "SKIP", "stock xrootd absent")
        return
    if cred == "token":
        h.record(key, "GAP", "stock xrootd delegates GSI credentials only for TPC (docs/man/xrdcp.1) — "
                             "token delegation to/from a stock peer is an upstream limitation")
        return
    sport, dport = _PORTS[2:4]  # was free_ports(2)
    slog = h.spawn_xrootd_node("stocksrc", "origin", sport, "", "gsi")
    if slog is None or not wait_tcp(BIND_HOST, sport, 3):
        h.record(key, "SKIP", "stock GSI origin did not come up")
        return
    data = h.prefix / "stocksrc/data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "tpcsrc.bin").write_bytes((h.prefix / "tpcsrc.bin").read_bytes())

    if h.spawn_brix_dest_root("dstroot", "gsi", dport, "") is None:
        h.record(key, "FAIL", "brix root dest start failed")
        return

    slog.write_text("")
    pos = h.drive_tpc_root("gsi", sport, dport, "posA.bin", "A")
    if not pos.copy_ok:
        tail = (h.prefix / "tpc_A.err").read_text(errors="replace").splitlines()
        h.record(key, "FAIL", f"userA delegated pull from stock source not byte-exact ({pos.deny_obs}): {tail[-1] if tail else ''}")
        return
    time.sleep(0.3)
    if not h.assert_source_identity("stock", "gsi", slog):
        h.record(key, "FAIL", f"stock source did not log userA (login as ...CN={A_CN}) — check {slog}")
        return
    neg = h.drive_tpc_root("gsi", sport, dport, "negB.bin", "B")
    if h.assert_tpc_denied(neg, h.prefix / "dstroot/export/negB.bin"):
        h.record(key, "PASS", "stock source authenticated userA (delegated proxy); userB denied, no bytes")
    else:
        h.record(key, "FAIL", f"userB not denied ({neg.deny_obs}) or bytes leaked")


def _root_cell_bs(h: TpcHarness, cred: str) -> None:
    key = f"root brix-src->stock-dest {cred}"
    if not os.access(XROOTD_BIN, os.X_OK):
        h.record(key, "SKIP", "stock xrootd absent")
        return
    if cred == "token":
        h.record(key, "GAP", "stock xrootd delegates GSI only (docs/man/xrdcp.1) — "
                             "a stock dest cannot forward a token to a brix source")
        return
    h.record(key, "SKIP", "stock xrootd dest is the TPC coordinator (upstream code); the brix puller "
                          "under test is exercised by the stock-src->brix-dest and brix-src->brix-dest GSI cells")

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "tpc_fwd_live_part2.py")
