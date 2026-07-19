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
from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from lib_py.util import wait_tcp
from settings import CA_CERT, CA_DIR, SERVER_CERT, SERVER_KEY, TEST_ROOT, free_ports

# A NAME (matches the cert DNS:localhost SAN) so the GSI client does NOT fall
# back to reverse-DNS, which forbids proxy delegation.
TPC_HOST = "localhost"


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
            sslblock = f"""listen 127.0.0.1:{port} ssl;
        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client optional;
        ssl_verify_depth 10;
        brix_webdav_proxy_certs on;"""
            authblock = (f"brix_webdav_cafile {CA_CERT};\n"
                         "            brix_webdav_auth required;")
        else:
            # TOKEN source is deliberately TOKEN-ONLY (no ssl_verify_client, no
            # proxy_certs) so the ONLY credential that authenticates the pull
            # leg is the forwarded bearer — proving forwarding unambiguously.
            sslblock = (f"listen 127.0.0.1:{port} ssl;\n"
                        f"        ssl_certificate     {SERVER_CERT};\n"
                        f"        ssl_certificate_key {SERVER_KEY};")
            authblock = (f"brix_webdav_cafile {CA_CERT};\n"
                         "            brix_webdav_auth required;\n"
                         f"            brix_webdav_token_jwks     {self.tok_jwks};\n"
                         f"            brix_webdav_token_issuer   {self.tok_issuer};\n"
                         f"            brix_webdav_token_audience {TOK_AUD};")
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
        if cred == "gsi":
            auth = (f"brix_auth gsi;\n        brix_certificate     {SERVER_CERT};\n"
                    f"        brix_certificate_key {SERVER_KEY};\n"
                    f"        brix_trusted_ca      {CA_CERT};")
            tpc = ("brix_tpc_allow_local on;\n        brix_tpc_allow_private on;\n"
                   "        brix_tpc_delegate on;\n        brix_gsi_signed_dh require;")
        else:
            auth = (f"brix_auth token;\n        brix_certificate     {SERVER_CERT};\n"
                    f"        brix_certificate_key {SERVER_KEY};\n"
                    f"        brix_token_jwks      {self.tok_jwks};\n"
                    f"        brix_token_issuer    {self.tok_issuer};\n"
                    f"        brix_token_audience  {TOK_AUD};")
            tpc = ("brix_tpc_allow_local on;\n        brix_tpc_allow_private on;\n"
                   "        brix_tpc_outbound_tls on;")
            if bearer_mode == "passthrough":
                tpc += "\n        brix_tpc_outbound_passthrough on;"
            elif bearer_mode:
                tpc += f"\n        brix_tpc_outbound_bearer_file {bearer_mode};"
        conf = self.run.write(d / "nginx.conf", f"""daemon on;
error_log {log} info;
pid {d}/nginx.pid;
worker_processes 1;
thread_pool default threads=4 max_queue=65536;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{port};
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
            auth = (f"brix_webdav_cafile {CA_CERT};\n"
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
            auth = (f"brix_webdav_cafile {CA_CERT};\n"
                    "            brix_webdav_auth required;\n"
                    f"            brix_webdav_token_jwks     {self.tok_jwks};\n"
                    f"            brix_webdav_token_issuer   {self.tok_issuer};\n"
                    f"            brix_webdav_token_audience {TOK_AUD};")
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
        listen 127.0.0.1:{port} ssl;
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
        if cred == "token":
            jwt = (self.token_a if who == "A" else self.token_b).read_text().strip()
            argv = ["curl", "-sk", "-H", f"Authorization: Bearer {jwt}",
                    "-X", "COPY", dst_url,
                    "-H", "Credential: none", "-H", f"Source: {src_url}",
                    "-H", f"TransferHeaderAuthorization: Bearer {jwt}",
                    "-w", "%{http_code}", "-o", os.devnull]
        else:
            px = self.proxy_a if who == "A" else self.proxy_b
            argv = ["curl", "-sk", "--cert", str(px), "--key", str(px),
                    "-X", "COPY", dst_url,
                    "-H", "Credential: none", "-H", f"Source: {src_url}"]
            if who == "A":
                # userA DELEGATES its own full proxy to the DEST (base64 PEM,
                # one line; leaf DN bound to the client cert userA
                # authenticates with).  The DEST presents THAT proxy to the
                # source → source authenticates userA.
                deleg_b64 = base64.b64encode(px.read_bytes()).decode()
                argv += ["-H", f"X-Brix-Delegate-Proxy: {deleg_b64}"]
            argv += ["-w", "%{http_code}", "-o", os.devnull]
        code = _call(argv, timeout=90).stdout.strip()
        copy_ok = False
        if code in ("200", "201", "204"):
            dst = dexport / obj
            copy_ok = dst.is_file() and dst.read_bytes() == (self.prefix / "tpcsrc.bin").read_bytes()
        return TpcResult(copy_ok, code)

    def drive_tpc_root(self, cred: str, sport: int, dport: int, obj: str, who: str) -> TpcResult:
        src_url = f"root://{TPC_HOST}:{sport}//tpcsrc.bin"
        dst_url = f"root://{TPC_HOST}:{dport}//{obj}"
        dexport = self.prefix / "dstroot/export"
        if cred == "gsi":
            px = self.proxy_a if who == "A" else self.proxy_b
            env = self.gsi_env(px)
            drop: tuple[str, ...] = ()
            if who == "A":
                # userA opts into delegation: the client signs the dest's
                # proxy request and the dest pulls from the source AS userA.
                env["XRDC_GSI_DELEGATE"] = "1"
            else:
                # userB does NOT opt in: XRDC_GSI_DELEGATE MUST be truly UNSET
                # (not empty — getenv()!=NULL would still enable it).
                drop = ("XRDC_GSI_DELEGATE",)
            proc = _call([BRIX_XRDCP, "-f", "--tpc", "delegate", src_url, dst_url],
                         env_add=env, env_drop=drop, timeout=90)
        else:
            env = self.token_env(self.token_a if who == "A" else self.token_b)
            proc = _call([BRIX_XRDCP, "-f", "--tpc", "delegate", src_url, dst_url],
                         env_add=env, timeout=90)
        (self.prefix / f"tpc_{who}.err").write_text(proc.stderr or "")
        copy_ok = False
        if proc.returncode == 0:
            dst = dexport / obj
            copy_ok = dst.is_file() and dst.read_bytes() == (self.prefix / "tpcsrc.bin").read_bytes()
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
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    sport, dport = free_ports(2)
    bearer_mode = "passthrough" if cred == "token" else ""

    slog = h.spawn_brix_source_root("srcroot", cred, sport)
    if slog is None:
        h.record(key, "FAIL", "brix root source start failed")
        return
    (h.prefix / "srcroot/export/tpcsrc.bin").write_bytes((h.prefix / "tpcsrc.bin").read_bytes())
    dlog = h.spawn_brix_dest_root("dstroot", cred, dport, bearer_mode)
    if dlog is None:
        h.record(key, "FAIL", "brix root dest start failed")
        return

    slog.write_text("")
    pos = h.drive_tpc_root(cred, sport, dport, "posA.bin", "A")
    if not pos.copy_ok:
        if cred == "token":
            evidence = _grep_last(dlog, r"ztn|token|tls|3028|auth|passthrough")
            h.record(key, "FAIL", f"userA passthrough token pull did not complete ({pos.deny_obs}): {evidence}")
        else:
            tail = (h.prefix / "tpc_A.err").read_text(errors="replace").splitlines()
            h.record(key, "FAIL", f"userA delegated GSI pull not byte-exact ({pos.deny_obs}): {tail[-1] if tail else ''}")
        return
    time.sleep(0.3)
    if not h.assert_source_identity("brix", cred, slog):
        who = f"userA (sub={A_SUB}) on the forwarded pull leg" if cred == "token" else f"userA (DN={A_CN}) on the pull leg"
        h.record(key, "FAIL", f"source did not authenticate {who} — check {slog}")
        return
    # negative: userB (wrong-issuer token / no delegation) → denied, no bytes
    neg = h.drive_tpc_root(cred, sport, dport, "negB.bin", "B")
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
    sport, dport = free_ports(2)
    slog = h.spawn_xrootd_node("stocksrc", "origin", sport, "", "gsi")
    if slog is None or not wait_tcp("127.0.0.1", sport, 3):
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


def tpc_fwd_root(nginx: Path | None = None) -> int:
    """Port of run_tpc_fwd_root.sh — native root:// TPC credential forwarding."""
    with TpcHarness("tpc_root", nginx) as h:
        reason = h.preflight()
        if reason:
            print(f"run_tpc_fwd_root: environment SKIP ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        (h.prefix / "tpcsrc.bin").write_bytes(os.urandom(65536))
        print("== TPC credential forwarding — native root:// flavor (PULL) ==")
        for cred in ("gsi", "token"):
            for cell_fn in (_root_cell_bb, _root_cell_sb, _root_cell_bs):
                with h.cell():
                    cell_fn(h, cred)
        return _tpc_outcome(h, "run_tpc_fwd_root")


# ===========================================================================
# run_tpc_fwd_webdav.sh — WebDAV/HTTP TPC flavor (PULL)
# ===========================================================================

def _webdav_cell_bb_gsi(h: TpcHarness, key: str, sport: int, dport: int) -> None:
    slog = h.spawn_brix_source_dav("srcdav", "gsi", sport)
    if slog is None:
        h.record(key, "FAIL", "brix dav source start failed")
        return
    (h.prefix / "srcdav/export/tpcsrc.bin").write_bytes((h.prefix / "tpcsrc.bin").read_bytes())
    # dest has NO static service cert (delegation-only) so a non-delegated pull
    # has no credential to present — the genuine negative control.
    if h.spawn_brix_dest_dav("dstdav", "gsi", dport, "nostatic") is None:
        h.record(key, "FAIL", "brix dav dest start failed")
        return
    dst_log = h.prefix / "dstdav/logs/e.log"

    slog.write_text("")
    pos = h.drive_tpc_webdav("gsi", sport, dport, "posA.bin", "A")
    if not pos.copy_ok:
        h.record(key, "FAIL", f"userA delegated-proxy pull did not complete (code={pos.deny_obs}) — "
                              f"dest: {_grep_last(dst_log, r'deleg|proxy|tpc|GSI|403')}")
        return
    if not h.assert_source_identity("brix", "gsi", slog):
        seen = re.findall(r'dn="[^"]*"', slog.read_text(errors="replace"))
        h.record(key, "FAIL", f"delegated-proxy pull landed but source authenticated "
                              f"{seen[-1] if seen else '(none)'}, not userA (CN={A_CN}) — passthrough "
                              f"not engaged; dest: {_grep_last(dst_log, r'deleg|proxy|tpc')}")
        return
    neg = h.drive_tpc_webdav("gsi", sport, dport, "negB.bin", "B")
    if h.assert_tpc_denied(neg, h.prefix / "dstdav/export/negB.bin"):
        h.record(key, "PASS", f"source authenticated userA (delegated proxy, CN={A_CN}, NOT the service "
                              "CN=localhost); userB (no delegation, no fallback) denied, no bytes")
    else:
        h.record(key, "FAIL", f"userB not denied (code={neg.deny_obs}) or bytes leaked to dest")


def _webdav_cell_bb(h: TpcHarness, cred: str) -> None:
    key = f"webdav bb {cred}"
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    sport, dport = free_ports(2)
    if cred == "gsi":
        _webdav_cell_bb_gsi(h, key, sport, dport)
        return

    slog = h.spawn_brix_source_dav("srcdav", cred, sport)
    if slog is None:
        h.record(key, "FAIL", "brix dav source start failed")
        return
    (h.prefix / "srcdav/export/tpcsrc.bin").write_bytes((h.prefix / "tpcsrc.bin").read_bytes())
    if h.spawn_brix_dest_dav("dstdav", cred, dport) is None:
        h.record(key, "FAIL", "brix dav dest start failed")
        return

    slog.write_text("")
    pos = h.drive_tpc_webdav(cred, sport, dport, "posA.bin", "A")
    if not pos.copy_ok:
        h.record(key, "FAIL", f"userA token pull not byte-exact (code={pos.deny_obs})")
        return
    time.sleep(0.3)
    if not h.assert_source_identity("brix", "token", slog):
        h.record(key, "FAIL", f"source did not authenticate userA (sub={A_SUB}) on the pull leg")
        return
    neg = h.drive_tpc_webdav("token", sport, dport, "negB.bin", "B")
    if h.assert_tpc_denied(neg, h.prefix / "dstdav/export/negB.bin"):
        h.record(key, "PASS", "source authenticated userA (forwarded bearer); userB denied, no bytes")
    else:
        h.record(key, "FAIL", f"userB not denied (code={neg.deny_obs}) or bytes leaked to dest")


def _webdav_cell_sb(h: TpcHarness, cred: str) -> None:
    key = f"webdav stock-src->brix-dest {cred}"
    if not os.access(XROOTD_BIN, os.X_OK):
        h.record(key, "SKIP", "stock xrootd absent")
        return
    if cred == "token":
        h.record(key, "SKIP", "stock XrdHttp ztn-over-http source not provisioned (GSI-only stock XrdHttp node)")
        return
    if not Path("/usr/lib64/libXrdHttp-5.so").is_file() and not Path("/usr/lib/libXrdHttp-5.so").is_file():
        h.record(key, "SKIP", "stock XrdHttp plugin (libXrdHttp) absent — no stock https source")
        return
    h.record(key, "GAP", "brix puller forwards userA's delegated proxy (see the bb gsi cell), but a stock "
                         "XrdHttp source would need http.gridmap provisioned for the forwarded "
                         "proxy-leaf DN — not stood up in this harness")


def _webdav_cell_bs(h: TpcHarness, cred: str) -> None:
    h.record(f"webdav brix-src->stock-dest {cred}", "SKIP",
             "stock XrdHttp dest is an upstream TPC coordinator, not the brix puller under test "
             "(brix forwarding proven by the brix-dest cells)")


def tpc_fwd_webdav(nginx: Path | None = None) -> int:
    """Port of run_tpc_fwd_webdav.sh — WebDAV/HTTP TPC credential forwarding."""
    with TpcHarness("tpc_webdav", nginx) as h:
        reason = h.preflight()
        if reason:
            print(f"run_tpc_fwd_webdav: environment SKIP ({reason})")
            return 0
        if not h.mint_pki():
            return 0
        if not h.mint_token():
            print("  (token authority unavailable — token cells will SKIP)")
            h.tok_jwks = None
        (h.prefix / "tpcsrc.bin").write_bytes(os.urandom(65536))
        print("== TPC credential forwarding — WebDAV/HTTP flavor (PULL) ==")
        for cred in ("token", "gsi"):
            for cell_fn in (_webdav_cell_bb, _webdav_cell_sb, _webdav_cell_bs):
                with h.cell():
                    cell_fn(h, cred)
        return _tpc_outcome(h, "run_tpc_fwd_webdav")


# ===========================================================================
# run_tpc_delegation_nginx.sh — GSI delegated TPC, nginx fileserver both ends
# ===========================================================================

def tpc_delegation_nginx(nginx: Path | None = None) -> int:
    """Port of run_tpc_delegation_nginx.sh (official + repo xrdcp clients)."""
    test_root = Path(os.environ.get("TEST_ROOT", TEST_ROOT))
    ca = test_root / "pki/ca/ca.pem"
    cadir = test_root / "pki/ca"
    sc = test_root / "pki/server/hostcert.pem"
    sk = test_root / "pki/server/hostkey.pem"
    proxy_std = test_root / "pki/user/proxy_std.pem"

    with LiveRun("ngxtpcdlg", nginx) as run:
        if not os.access(run.nginx, os.X_OK):
            print("SKIP: nginx not built")
            return 0
        # Refresh only the proxy when the CA/hostcert exist — a full blitz would
        # regenerate the CA and desync the standing fleet (05:21 CA vs new CA),
        # breaking every concurrent GSI/TLS test. See live_common.refresh_shared_pki.
        from cmdscripts.live_common import refresh_shared_pki  # noqa: PLC0415
        ok, msg = refresh_shared_pki(run.root, want_proxy=True)
        if not ok:
            print(f"SKIP: {msg}")
            return 0

        srcp, dstp = free_ports(2)
        src, dst = run.mkdir("src"), run.mkdir("dst")
        for d in (src, dst):
            (d / "root").mkdir()
            (d / "logs").mkdir()
        payload = src / "root/f.bin"
        payload.write_bytes(os.urandom(400000))

        # nginx SOURCE — GSI fileserver (read-only; still advertises TPC as a source)
        src_conf = run.write(run.root / "src.conf", f"""daemon on; error_log {src}/logs/e.log info; pid {run.root}/src.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{srcp}; brix_root on; brix_export {src}/root;
  brix_auth gsi; brix_certificate {sc}; brix_certificate_key {sk}; brix_trusted_ca {ca}; }} }}
""")
        # nginx DEST — GSI fileserver + delegation-capturing TPC pull
        dst_conf = run.write(run.root / "dst.conf", f"""daemon on; error_log {dst}/logs/e.log info; pid {run.root}/dst.pid;
thread_pool default threads=4;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{dstp}; brix_root on; brix_export {dst}/root;
  brix_auth gsi; brix_gsi_signed_dh require; brix_allow_write on;
  brix_tpc_allow_local on; brix_tpc_allow_private on; brix_tpc_delegate on;
  brix_certificate {sc}; brix_certificate_key {sk}; brix_trusted_ca {ca}; }} }}
""")
        for name, conf in (("src", src_conf), ("dst", dst_conf)):
            proc = _call([run.nginx, "-p", run.root / name, "-c", conf], env_drop=("NGINX",))
            if proc.returncode:
                print(f"{name}-fail\n{proc.stderr}")
                return 2
            run.pidfiles.append(run.root / f"{name}.pid")
        for port in (srcp, dstp):
            if not wait_tcp("127.0.0.1", port, 3):
                print(f"FAIL: port {port} never listened")
                return 2

        base_env = {"X509_USER_PROXY": str(proxy_std), "X509_CERT_DIR": str(cadir),
                    "XrdSecGSICADIR": str(cadir)}
        checks: list[tuple[bool, str]] = []
        src_log, dst_log = src / "logs/e.log", dst / "logs/e.log"

        def run_case(label: str, xrdcp: Path, env_extra: dict[str, str],
                     out: str, *tpc_args: str) -> None:
            src_log.write_text("")
            (dst / "root" / out).unlink(missing_ok=True)
            proc = _call([xrdcp, "-f", *tpc_args,
                          f"root://localhost:{srcp}//f.bin", f"root://localhost:{dstp}//{out}"],
                         env_add={**base_env, **env_extra}, timeout=120)
            copied = dst / "root" / out
            if proc.returncode == 0 and copied.is_file() and copied.read_bytes() == payload.read_bytes():
                checks.append((True, f"{label}: nginx source -> nginx dest delegated TPC byte-exact"))
            else:
                tail = "\n".join((proc.stderr or proc.stdout or "").splitlines()[-6:])
                checks.append((False, f"{label}: delegated TPC failed (rc={proc.returncode})\n{tail}"))
                return
            # the destination's pull must authenticate to the source as the
            # delegated USER — its DN carries an EXTRA proxy layer (two trailing
            # numeric CNs: the client's own proxy + the dest's delegated proxy).
            src_text = src_log.read_text(errors="replace")
            checks.append((re.search(r'GSI auth OK dn=".*CN=12345/CN=[0-9]+/CN=[0-9]+"', src_text) is not None,
                           f"{label}: source authenticated the pull as the delegated user"))
            if "signal 11" in dst_log.read_text(errors="replace"):
                checks.append((False, f"{label}: dest crashed"))

        # stock syntax: `--tpc delegate only`; this repo's xrdcp: `--tpc delegate`.
        stock_xrdcp = Path("/usr/bin/xrdcp")
        if stock_xrdcp.is_file():
            run_case("official", stock_xrdcp, {}, "out_official.bin", "--tpc", "delegate", "only")
        else:
            print("  SKIP official client (/usr/bin/xrdcp absent)")
        our_xrdcp = Path(os.environ.get("OUR_XRDCP", BRIX_XRDCP))
        if os.access(our_xrdcp, os.X_OK):
            run_case("repo", our_xrdcp, {"XRDC_GSI_DELEGATE": "1"}, "out_repo.bin", "--tpc", "delegate")
        else:
            print("  SKIP repo client (build: make -C client xrdcp)")

        for passed, message in checks:
            print(f"  {'ok  ' if passed else 'FAIL'} {message}")
        failed = any(not passed for passed, _ in checks)
        print(f"run_tpc_delegation_nginx: {'FAILURES' if failed else 'ALL PASS'}")
        return 1 if failed else 0


SCENARIOS = {
    "tpc-fwd-root": tpc_fwd_root,
    "tpc-fwd-webdav": tpc_fwd_webdav,
    "tpc-delegation-nginx": tpc_delegation_nginx,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"tpc scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
