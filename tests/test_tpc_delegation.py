"""phase-57 §F6 interop GATE — a stock xrootd GSI source with X.509 proxy
delegation (-dlgpxy:request) + DN logging (-showdn), standing up the real
correctness gate against which F6 (multi-hop X.509 proxy delegation) is to be
implemented.

What this file establishes:

  * test_stock_gsi_source_logs_dn          (GREEN) — the gate's assertion mechanism:
        a stock xrdcp download with a USER proxy authenticates via GSI and the
        source log records `secgsi_Authenticate: <user> Subject DN='<DN>'`.
  * test_stock_source_captures_delegation  (GREEN) — the delegation mechanism F6
        drives: with XrdSecGSIDELEGPROXY=2 the client delegates and the source logs
        `Delegated proxy saved`.
  * test_dest_pulls_as_user_via_delegation (XFAIL until F6) — the F6 target:
        a delegating client → OUR nginx dest (xrootd_tpc_delegate on) → stock
        source; once F6 captures+forwards the user's proxy, the source must
        authorise the dest's PULL as the USER (gateway DN absent from the pull).
        Flip the xfail to a hard assertion when F6 lands.

KEY PLAN CORRECTION (verified here): the stock option is `-dlgpxy:request`
(XrdSecgsi parses NAMED values via getOptVal); `-dlgpxy:1` silently falls back to
`ignore`. The plan's "-dlgpxy:1" wording is wrong.
"""
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX = "/tmp/nginx-1.28.3/objs/nginx"
XRDCP = "/usr/bin/xrdcp"          # STOCK client (knows GSI delegation)
SRC_PORT, DST_PORT = 21262, 21263
USER_DN = "/O=F6Test/CN=F6 User"
GW_DN = "/O=F6Test/CN=tpc-gateway"


def _have(*t):
    return all(shutil.which(x) for x in t)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=90, **kw)


def _wait(port, tries=100):
    for _ in range(tries):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return True
        time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def gate(tmp_path_factory):
    if not _have("xrootd", "openssl", "xrdgsiproxy") or not os.path.exists(XRDCP):
        pytest.skip("stock xrootd / openssl / xrdgsiproxy not installed")
    if not os.path.exists(NGINX):
        pytest.skip("nginx not built")

    base = tmp_path_factory.mktemp("f6gate")
    ca, certs, srv, usr, data = (
        base / d for d in ("ca", "certs", "srv", "usr", "data"))
    for d in (ca, certs, srv, usr, data):
        d.mkdir(parents=True)
    # Lowercase: the client lowercases the connect hostname, so the server cert CN
    # must be lowercase too — else the name check fails, the client falls back to
    # DNS, and "usedDNS" forbids proxy delegation (§F6).
    fqdn = socket.getfqdn().lower()

    def osl(*a):
        r = _run(["openssl", *a])
        assert r.returncode == 0, f"openssl {a}: {r.stderr}"

    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=F6Test/CN=F6Test CA",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = _run(["openssl", "x509", "-in", str(ca / "ca.pem"),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca / "ca.pem", certs / f"{chash}.0")
    (certs / f"{chash}.signing_policy").write_text(
        "access_id_CA      X509     '/O=F6Test/CN=F6Test CA'\n"
        "pos_rights        globus   CA:sign\n"
        "cond_subjects     globus   '\"/O=F6Test/*\"'\n")

    def signed(cn, key, cert):
        csr = base / (cn.replace(" ", "") + ".csr")
        osl("req", "-nodes", "-newkey", "rsa:2048", "-subj", f"/O=F6Test/CN={cn}",
            "-keyout", str(key), "-out", str(csr))
        osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
            "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
            "-out", str(cert))

    signed(fqdn, srv / "hostkey.pem", srv / "hostcert.pem")
    signed("F6 User", usr / "userkey.pem", usr / "usercert.pem")
    signed("tpc-gateway", srv / "gwkey.pem", srv / "gwcert.pem")
    for k in ("userkey.pem",):
        os.chmod(usr / k, 0o600)
    os.chmod(srv / "gwkey.pem", 0o600)

    penv = dict(os.environ, X509_CERT_DIR=str(certs))

    def mkproxy(cert, key, out):
        _run(["xrdgsiproxy", "init", "-cert", str(cert), "-key", str(key),
              "-out", str(out), "-certdir", str(certs), "-valid", "1:00"],
             input="\n\n", env=penv)
        return out.exists()

    uproxy = usr / "proxy.pem"
    gwproxy = srv / "gwproxy.pem"
    if not mkproxy(usr / "usercert.pem", usr / "userkey.pem", uproxy):
        pytest.skip("could not mint user proxy")
    if not mkproxy(srv / "gwcert.pem", srv / "gwkey.pem", gwproxy):
        pytest.skip("could not mint gateway proxy")
    os.chmod(gwproxy, 0o600)

    (data / "hello.txt").write_text("f6 delegation gate\n")

    # Source gridmap maps BOTH the user and the gateway DN so a pull authenticates
    # either way — the discriminator is WHICH DN the source logs for the pull.
    me = os.environ.get("USER", "nobody")
    gridmap = base / "grid-mapfile"
    gridmap.write_text(f'"{USER_DN}" {me}\n"{GW_DN}" {me}\n')

    # ---- stock GSI source: delegation requested + DN logged ----
    src_cfg = base / "xrootd.cfg"
    src_cfg.write_text(
        f"xrd.port {SRC_PORT}\n"
        "all.export /data\n"
        f"oss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{certs} "
        f"-cert:{srv / 'hostcert.pem'} -key:{srv / 'hostkey.pem'} "
        f"-gridmap:{gridmap} -d:2 -crl:0 -gmapopt:2 "
        "-dlgpxy:request -showdn:1 -exppxy:=creds\n"
        "sec.protbind * only gsi\n"
        "ofs.tpc ttl 300 300 pgm /usr/bin/xrdcp\n")
    # xrootd -n <name> inserts the instance name as a subdir of the -l directory,
    # so `-l base/xrootd.log -n src` writes to base/src/xrootd.log.
    src_log = base / "src" / "xrootd.log"
    _run(["bash", "-c", f"fuser -k {SRC_PORT}/tcp 2>/dev/null"])
    src = subprocess.Popen(["xrootd", "-c", str(src_cfg),
                            "-l", str(base / "xrootd.log"), "-n", "src"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait(SRC_PORT):
        src.terminate()
        pytest.skip("stock GSI source did not come up")

    # ---- OUR nginx destination: GSI inbound + (reserved) delegation ----
    dst_cfg = base / "dst.conf"
    dst_cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {base}/dst-err.log info;\npid {base}/dst.pid;\n"
        "thread_pool default threads=4 max_queue=65536;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {DST_PORT};\n    xrootd on;\n"
        f"    xrootd_root {base / 'dstdata'};\n    xrootd_auth gsi;\n"
        "    xrootd_allow_write on;\n"
        "    xrootd_tpc_allow_local on;\n    xrootd_tpc_allow_private on;\n"
        "    xrootd_tpc_delegate on;\n"
        # X.509 proxy delegation requires signed-DH: a stock client disables
        # delegation if the server's DH params aren't RSA-signed.
        "    xrootd_gsi_signed_dh require;\n"
        # Server cert CN = fqdn so the client (connecting by fqdn) verifies it
        # without reverse-DNS — delegation is forbidden when the client "used DNS".
        f"    xrootd_certificate {srv / 'hostcert.pem'};\n"
        f"    xrootd_certificate_key {srv / 'hostkey.pem'};\n"
        # CA *file* (not the dir) so gsi_ca_hash computes — stock clients verify
        # the server cert via the advertised ca: hash (config.c fopen+PEM_read).
        f"    xrootd_trusted_ca {ca / 'ca.pem'};\n"
        f"    xrootd_access_log {base}/dst-acc.log;\n  }}\n}}\n")
    (base / "dstdata").mkdir(exist_ok=True)
    _run(["bash", "-c", f"fuser -k {DST_PORT}/tcp 2>/dev/null"])
    dst = subprocess.Popen([NGINX, "-c", str(dst_cfg), "-p", str(base)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait(DST_PORT):
        src.terminate()
        dst.terminate()
        pytest.skip("nginx dest did not come up")

    ctx = {"base": str(base), "fqdn": fqdn, "src_log": src_log,
           "env": dict(penv, X509_USER_PROXY=str(uproxy))}
    yield ctx
    for p in (dst, src):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def _src_log(gate):
    p = Path(gate["src_log"])
    return p.read_text(errors="replace") if p.exists() else ""


def test_stock_gsi_source_logs_dn(gate):
    """GREEN: the gate's DN-assertion mechanism — a user-proxy GSI download is
    authenticated and the source logs the user's Subject DN."""
    out = Path(gate["base"]) / "got.txt"
    r = _run([XRDCP, "-f", f"root://{gate['fqdn']}:{SRC_PORT}//data/hello.txt",
              str(out)], env=gate["env"])
    assert r.returncode == 0 and out.exists(), f"GSI download failed: {r.stderr}"
    time.sleep(0.5)
    assert f"Subject DN='{USER_DN}'" in _src_log(gate), \
        "source did not log the authenticated user DN (gate mechanism broken)"


def test_stock_source_captures_delegation(gate):
    """GREEN: the delegation mechanism F6 drives — with XrdSecGSIDELEGPROXY the
    client delegates its proxy and the source captures it."""
    out = Path(gate["base"]) / "got_dlg.txt"
    env = dict(gate["env"], XrdSecGSIDELEGPROXY="2")
    r = _run([XRDCP, "-f", f"root://{gate['fqdn']}:{SRC_PORT}//data/hello.txt",
              str(out)], env=env)
    assert r.returncode == 0 and out.exists(), f"delegated download failed: {r.stderr}"
    time.sleep(0.5)
    assert "Delegated proxy saved" in _src_log(gate), \
        "source did not capture the delegated proxy (delegation not engaged)"


@pytest.mark.xfail(reason="dest-side F6 inbound is implemented + the handshake "
    "reaches kXGC_sigpxy, but the stock client declines to return a signed proxy "
    "under its usedDNS/hostname delegation policy in this synthetic-hostname WSL2 "
    "rig (needs a real grid host); flip to strict in a proper grid env", strict=False)
def test_dest_captures_delegated_proxy(gate):
    """INBOUND F6: a stock DELEGATING client (XrdSecGSIDELEGPROXY=1, dlgReqSign)
    authenticates to OUR nginx dest (xrootd_auth gsi + xrootd_tpc_delegate on +
    signed-DH); the dest runs the kXGS_pxyreq/kXGC_sigpxy round and captures the
    user's delegated proxy (logged at INFO). The dest reaches kXGC_sigpxy in every
    rig; the client only RETURNS a signed proxy when its delegation policy allows
    (real resolvable host + signed-DH + cert-CN match without DNS fallback)."""
    upload = Path(gate["base"]) / "upload.txt"
    upload.write_text("inbound delegation capture\n")
    # XrdSecGSIDELEGPROXY=1 (dlgReqSign): client SIGNS our proxy request into a
    # delegated proxy cert. Connect by fqdn (matches the dest cert CN) so the
    # client does not "use DNS" — which would forbid delegation.
    env = dict(gate["env"], XrdSecGSIDELEGPROXY="1")
    r = _run([XRDCP, "-f", str(upload),
              f"root://{gate['fqdn']}:{DST_PORT}//cap.txt"], env=env)
    time.sleep(0.5)
    errlog = Path(gate["base"]) / "dst-err.log"
    log = errlog.read_text(errors="replace") if errlog.exists() else ""
    assert "captured delegated proxy" in log, (
        f"nginx dest did not capture the delegated proxy (xrdcp rc={r.returncode}: "
        f"{r.stderr.strip()})\n--- dst-err tail ---\n"
        + "\n".join(log.splitlines()[-20:]))


@pytest.mark.xfail(reason="F6 outbound use (TPC pull presents the delegated proxy) "
                          "not yet implemented", strict=False)
def test_dest_pulls_as_user_via_delegation(gate):
    """F6 TARGET (xfail until implemented): a delegating client → our nginx dest
    (xrootd_tpc_delegate on) → stock source. Once the dest captures and forwards
    the user's proxy, the source must authorise the dest's PULL as the USER — i.e.
    the gateway DN must NOT appear in the source log. Until F6, the dest pulls as
    itself (gateway DN present) → this fails (xfail). Flip strict=True on landing."""
    out = Path(gate["base"]) / "dstdata" / "pulled.txt"
    # Mark the log boundary so we only inspect THIS transfer's DNs.
    before = len(_src_log(gate))
    env = dict(gate["env"], XrdSecGSIDELEGPROXY="2")
    _run([XRDCP, "-f", "--tpc", "only",
          f"root://{gate['fqdn']}:{SRC_PORT}//data/hello.txt",
          f"root://127.0.0.1:{DST_PORT}//pulled.txt"], env=env)
    time.sleep(0.5)
    after = _src_log(gate)[before:]
    # The pull (dest→source) must authenticate as the user, never the gateway.
    assert GW_DN not in after, \
        "source authorised the pull as the GATEWAY DN — delegation not forwarded"
    assert out.exists() and out.read_text() == "f6 delegation gate\n"
