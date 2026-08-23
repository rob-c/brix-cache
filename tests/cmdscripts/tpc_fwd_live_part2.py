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
import functools
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

def _expression_1_next(checks):
    return (
        any(not passed for passed, _ in checks)
    )


def _phase_tpc_delegation_nginx_1(src, dst):
    for d in (src, dst):
        (d / "root").mkdir()
        (d / "logs").mkdir()


def _expression_1(message, passed):
    return (
        print(f"  {'ok  ' if passed else 'FAIL'} {message}")
    )

def _expression_2(failed):
    return (
        print(f"run_tpc_delegation_nginx: {'FAILURES' if failed else 'ALL PASS'}")
    )

def _expression_3(failed):
    return (
        1 if failed else 0
    )


def _guard_tpc_delegation_nginx_1(stock_xrdcp, run_case):
    if stock_xrdcp.is_file():
        run_case("official", stock_xrdcp, {}, "out_official.bin", "--tpc", "delegate", "only")
    else:
        print("  SKIP official client (/usr/bin/xrdcp absent)")

def _guard_tpc_delegation_nginx_2(our_xrdcp, run_case):
    if os.access(our_xrdcp, os.X_OK):
        run_case("repo", our_xrdcp, {"XRDC_GSI_DELEGATE": "1"}, "out_repo.bin", "--tpc", "delegate")
    else:
        print("  SKIP repo client (build: make -C client xrdcp)")


_PORTS = cmdscript_ports("tpc_fwd_live")

# A NAME (matches the cert DNS:localhost SAN) so the GSI client does NOT fall
# back to reverse-DNS, which forbids proxy delegation.
TPC_HOST = SERVER_HOST


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
                              "CN=localhost); userB (no delegation, no fallback) denied, no bytes")  # net-literal-allow: service cert CN named in assertion message
    else:
        h.record(key, "FAIL", f"userB not denied (code={neg.deny_obs}) or bytes leaked to dest")


def _webdav_cell_bb(h: TpcHarness, cred: str) -> None:
    key = f"webdav bb {cred}"
    if cred == "token" and h.tok_jwks is None:
        h.record(key, "SKIP", "token authority unavailable")
        return
    sport, dport = _PORTS[4:6]  # was free_ports(2)
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

def _start_delegation_servers(run, servers):
    from cmdscripts import open_tree_for_worker

    for name, config in servers:
        inject_nginx_load_modules(config)
        open_tree_for_worker(run.root, config)
        proc = _call([run.nginx, "-p", run.root / name, "-c", config],
                     env_drop=("NGINX",))
        if proc.returncode:
            print(f"{name}-fail\n{proc.stderr}")
            return False
        run.pidfiles.append(run.root / f"{name}.pid")
    return True


def _delegation_ports_ready(*ports):
    for port in ports:
        if not wait_tcp(BIND_HOST, port, 3):
            print(f"FAIL: port {port} never listened")
            return False
    return True


def _run_delegation_case(label, xrdcp, env_extra, out, *tpc_args,
                         base_env, checks, src_log, dst_log, dst, payload,
                         srcp, dstp):
    src_log.write_text("")
    copied = dst / "root" / out
    copied.unlink(missing_ok=True)
    proc = _call(
        [xrdcp, "-f", *tpc_args,
         f"root://{SERVER_HOST}:{srcp}//f.bin",
         f"root://{SERVER_HOST}:{dstp}//{out}"],
        env_add={**base_env, **env_extra}, timeout=120)
    if proc.returncode != 0 or not copied.is_file() \
            or copied.read_bytes() != payload.read_bytes():
        tail = "\n".join((proc.stderr or proc.stdout or "").splitlines()[-6:])
        checks.append((False, f"{label}: delegated TPC failed (rc={proc.returncode})\n{tail}"))
        return
    checks.append((True, f"{label}: nginx source -> nginx dest delegated TPC byte-exact"))
    src_text = src_log.read_text(errors="replace")
    pattern = r'GSI auth OK dn=".*CN=12345/CN=[0-9]+/CN=[0-9]+"'
    checks.append((re.search(pattern, src_text) is not None,
                   f"{label}: source authenticated the pull as the delegated user"))
    if "signal 11" in dst_log.read_text(errors="replace"):
        checks.append((False, f"{label}: dest crashed"))


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

        srcp, dstp = _PORTS[6:8]  # was free_ports(2)
        src, dst = run.mkdir("src"), run.mkdir("dst")
        _phase_tpc_delegation_nginx_1(src, dst)
        payload = src / "root/f.bin"
        payload.write_bytes(os.urandom(400000))

        # nginx SOURCE — GSI fileserver (read-only; still advertises TPC as a source)
        src_conf = run.write(run.root / "src.conf", f"""daemon on; error_log {src}/logs/e.log info; pid {run.root}/src.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{srcp}; brix_root on; brix_export {src}/root;
  brix_auth gsi; brix_certificate {sc}; brix_certificate_key {sk}; brix_trusted_ca {ca}; }} }}
""")
        # nginx DEST — GSI fileserver + delegation-capturing TPC pull
        dst_conf = run.write(run.root / "dst.conf", f"""daemon on; error_log {dst}/logs/e.log info; pid {run.root}/dst.pid;
thread_pool default threads=4;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{dstp}; brix_root on; brix_export {dst}/root;
  brix_auth gsi; brix_gsi_signed_dh require; brix_allow_write on;
  brix_tpc_allow_local on; brix_tpc_allow_private on; brix_tpc_delegate on;
  brix_certificate {sc}; brix_certificate_key {sk}; brix_trusted_ca {ca}; }} }}
""")
        # Root harness: these configs pin no `user`, so the always-on
        # de-escalation drops workers to `nobody`, which cannot traverse the
        # 0700 mkdtemp tree — the export's confined-ops open then EACCESes, the
        # node never serves, and the delegated TPC pull to it times out. Open
        # the tree for that worker (this launch bypasses
        # ForwardHarness._start_nginx, so the opening is repeated here).
        if not _start_delegation_servers(run, (("src", src_conf), ("dst", dst_conf))):
            return 2
        if not _delegation_ports_ready(srcp, dstp):
            return 2

        base_env = {"X509_USER_PROXY": str(proxy_std), "X509_CERT_DIR": str(cadir),
                    "XrdSecGSICADIR": str(cadir)}
        checks: list[tuple[bool, str]] = []
        src_log, dst_log = src / "logs/e.log", dst / "logs/e.log"

        run_case = functools.partial(
            _run_delegation_case, base_env=base_env, checks=checks,
            src_log=src_log, dst_log=dst_log, dst=dst, payload=payload,
            srcp=srcp, dstp=dstp)

        # stock syntax: `--tpc delegate only`; this repo's xrdcp: `--tpc delegate`.
        stock_xrdcp = Path("/usr/bin/xrdcp")
        _guard_tpc_delegation_nginx_1(stock_xrdcp, run_case)
        our_xrdcp = Path(os.environ.get("OUR_XRDCP", BRIX_XRDCP))
        _guard_tpc_delegation_nginx_2(our_xrdcp, run_case)

        for passed, message in checks:
            _expression_1(message, passed)
        failed = _expression_1_next(checks)
        _expression_2(failed)
        return _expression_3(failed)


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
