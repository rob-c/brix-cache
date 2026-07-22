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
        a delegating client → OUR nginx dest (brix_tpc_delegate on) → stock
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

from server_registry import NginxInstanceSpec
from ephemeral_port import free_port

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpc")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = "/usr/bin/xrdcp"          # STOCK client (knows GSI delegation)
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


@pytest.fixture
def gate(lifecycle, tmp_path_factory):
    if not _have("xrootd", "openssl", "xrdgsiproxy") or not os.path.exists(XRDCP):
        pytest.skip("stock xrootd / openssl / xrdgsiproxy not installed")

    src_port = free_port()
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

    # GSI X.509 proxy delegation signs a proxy request against the delegator's
    # chain; XrdCrypto's X509SignProxyReq rejects a signing chain whose EEC lacks
    # a keyUsage extension ("wrong extensions in request"). A real IGTF EEC always
    # carries keyUsage(digitalSignature,keyEncipherment) — mint ours the same way,
    # otherwise every delegation attempt fails at the crypto step regardless of the
    # protocol wiring under test.
    ku_ext = base / "ku.ext"
    ku_ext.write_text(
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
    )

    def signed(cn, key, cert):
        csr = base / (cn.replace(" ", "") + ".csr")
        osl("req", "-nodes", "-newkey", "rsa:2048", "-subj", f"/O=F6Test/CN={cn}",
            "-keyout", str(key), "-out", str(csr))
        osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
            "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
            "-out", str(cert), "-extfile", str(ku_ext))

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
        f"xrd.port {src_port}\n"
        "all.export /data\n"
        f"oss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{certs} "
        f"-cert:{srv / 'hostcert.pem'} -key:{srv / 'hostkey.pem'} "
        f"-gridmap:{gridmap} -d:2 -crl:0 -gmapopt:2 "
        "-dlgpxy:request -showdn:1 -exppxy:=creds\n"
        "sec.protbind * only gsi\n"
        "ofs.tpc ttl 300 300 pgm /usr/bin/xrdcp\n"
        # Keep xrootd's runtime admin/pid dirs under the test-owned base so the
        # `-R nobody` drop (below) can create its sockets.
        f"all.adminpath {base / 'admin'}\n"
        f"all.pidpath {base / 'admin'}\n")
    # xrootd -n <name> inserts the instance name as a subdir of the -l directory,
    # so `-l base/brix.log -n src` writes to base/src/brix.log.
    src_log = base / "src" / "xrootd.log"
    _run(["bash", "-c", f"fuser -k {src_port}/tcp 2>/dev/null"])
    argv = ["xrootd", "-c", str(src_cfg),
            "-l", str(base / "xrootd.log"), "-n", "src"]
    # Root-harness privilege drop: stock xrootd refuses to run as superuser, so
    # run it via `-R nobody` and pre-open only what that user needs — traverse
    # base, read the data tree + CA certdir + hostcert + gridmap, write admin/log,
    # read the GSI key (nobody-only 0400). NOT usr/: XrdSecgsi rejects a
    # group/world-writable proxy credential, which only the root client reads.
    if os.geteuid() == 0:
        runas = os.environ.get("REF_RUNAS_USER", "nobody")
        (base / "admin").mkdir(parents=True, exist_ok=True)
        (base / "src").mkdir(parents=True, exist_ok=True)
        _run(["chmod", "a+rx", str(base)])
        for d in (data, certs):
            _run(["chmod", "-R", "a+rX", str(d)])
        for d in (base / "admin", base / "src"):
            _run(["chmod", "-R", "a+rwX", str(d)])
        for f in (srv / "hostcert.pem", gridmap):
            if f.exists():
                _run(["chmod", "a+r", str(f)])
        _run(["chmod", "a+rx", str(srv)])
        hostkey = srv / "hostkey.pem"
        if hostkey.exists():
            shutil.chown(hostkey, runas)
            os.chmod(hostkey, 0o400)
        argv += ["-R", runas]
    src = subprocess.Popen(argv,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait(src_port):
        src.terminate()
        pytest.skip("stock GSI source did not come up")

    # ---- OUR nginx destination: GSI inbound + delegation (registry-managed) ----
    dstdata = base / "dstdata"
    dstdata.mkdir(exist_ok=True)
    try:
        dst = lifecycle.start(NginxInstanceSpec(
            name="lc-tpc-delegation-dest",
            template="nginx_tpc_delegation_dest.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(dstdata),
            template_values={
                "CERT_FILE": str(srv / "hostcert.pem"),
                "KEY_FILE": str(srv / "hostkey.pem"),
                "CA_FILE": str(ca / "ca.pem"),
            },
            reason="F6 GSI TPC delegation destination (captures + forwards proxy).",
        ))
    except Exception:
        src.terminate()
        raise

    ctx = {"base": str(base), "fqdn": fqdn, "src_log": src_log,
           "src_port": src_port, "dst_port": dst.port,
           "dst_logs": os.path.join(dst.prefix, "logs"),
           "env": dict(penv, X509_USER_PROXY=str(uproxy))}
    yield ctx
    src.terminate()
    try:
        src.wait(timeout=5)
    except subprocess.TimeoutExpired:
        src.kill()


def _src_log(gate):
    p = Path(gate["src_log"])
    return p.read_text(errors="replace") if p.exists() else ""


def test_stock_gsi_source_logs_dn(gate):
    """GREEN: the gate's DN-assertion mechanism — a user-proxy GSI download is
    authenticated and the source logs the user's Subject DN."""
    out = Path(gate["base"]) / "got.txt"
    r = _run([XRDCP, "-f", f"root://{gate['fqdn']}:{gate['src_port']}//data/hello.txt",
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
    r = _run([XRDCP, "-f", f"root://{gate['fqdn']}:{gate['src_port']}//data/hello.txt",
              str(out)], env=env)
    assert r.returncode == 0 and out.exists(), f"delegated download failed: {r.stderr}"
    time.sleep(0.5)
    assert "Delegated proxy saved" in _src_log(gate), \
        "source did not capture the delegated proxy (delegation not engaged)"


def test_dest_captures_delegated_proxy(gate):
    """INBOUND F6 (GREEN): a stock DELEGATING client (`xrdcp --tpc delegate`)
    authenticates to OUR nginx dest (brix_auth gsi + brix_tpc_delegate on +
    signed-DH); the dest runs the kXGS_pxyreq/kXGC_sigpxy round and CAPTURES the
    user's signed delegated proxy (logged at INFO with the user DN).

    KEY MECHANISM (verified): the client only sets its delegation flags
    (kOptsSigReq/kOptsDlgPxy) for a real TPC-delegate operation — the plain
    `XrdSecGSIDELEGPROXY` env var leaves dlgpxy=0, so the client declines with
    "Not allowed to sign proxy requests". `--tpc delegate` sets dlgpxy=1, the
    client signs our proxy request, and the dest captures a key-bearing proxy.

    Three server-side requirements this exercises (all now met):
      * the client cert chain must VERIFY despite the AKID/SKID mismatch that
        real xrdgsiproxy proxies carry (pki_build.c proxy-tolerant check_issued);
      * the kXRS_x509_req proxy request must be sent as PEM (delegation.c), which
        is what the stock client's PEM_read_bio_X509_REQ expects;
      * the signing EEC must carry keyUsage (the test PKI mints it).

    The subsequent TPC PULL (dest->source using the captured proxy) is a distinct
    outbound-use phase covered by test_dest_pulls_as_user_via_delegation; this
    test asserts only the CAPTURE."""
    # `--tpc delegate only`: the client delegates its proxy to the dest during
    # login (setting dlgpxy=1), then the dest is asked to pull from the source.
    # Connect by fqdn (matches the dest cert CN) so the client does not fall back
    # to DNS, which would forbid delegation.
    r = _run([XRDCP, "-f", "--tpc", "delegate", "only",
              f"root://{gate['fqdn']}:{gate['src_port']}//data/hello.txt",
              f"root://{gate['fqdn']}:{gate['dst_port']}//cap.txt"], env=gate["env"])
    time.sleep(0.5)
    errlog = Path(gate["dst_logs"]) / "dst-err.log"
    log = errlog.read_text(errors="replace") if errlog.exists() else ""
    assert "captured delegated proxy" in log, (
        f"nginx dest did not capture the delegated proxy (xrdcp rc={r.returncode}: "
        f"{r.stderr.strip()})\n--- dst-err tail ---\n"
        + "\n".join(log.splitlines()[-20:]))
    assert f"dn=\"{USER_DN}" in log, \
        "captured proxy is not the delegating USER's identity"


def test_dest_pulls_as_user_via_delegation(gate):
    """F6 TARGET (GREEN): a delegating client (`xrdcp --tpc delegate`) → our nginx
    dest (brix_tpc_delegate on) → stock source. The dest captures the user's
    proxy, then pulls the source file AS THE USER and the bytes land at the dest.

    Two properties are asserted:
      * the pull authenticates to the source as the USER, never the gateway DN
        (the source's grid-mapfile maps both, so the DN it logs is the tell);
      * the file is transferred byte-for-byte.

    Mechanism: because the dest holds the delegated proxy it opens the source file
    DIRECTLY as the user — the anonymous tpc.key rendezvous (which the source
    answers with kXR_waitresp until a client-side authorization that the delegate
    flow never issues) is skipped for delegated pulls (src/tpc/outbound/source.c)."""
    out = Path(gate["base"]) / "dstdata" / "pulled.txt"
    out.unlink(missing_ok=True)
    # Mark the log boundary so we only inspect THIS transfer's DNs.
    before = len(_src_log(gate))
    r = _run([XRDCP, "-f", "--tpc", "delegate", "only",
              f"root://{gate['fqdn']}:{gate['src_port']}//data/hello.txt",
              f"root://{gate['fqdn']}:{gate['dst_port']}//pulled.txt"], env=gate["env"])
    time.sleep(0.5)
    after = _src_log(gate)[before:]
    assert out.exists() and out.read_text() == "f6 delegation gate\n", \
        f"delegated pull did not land the bytes (xrdcp rc={r.returncode}: {r.stderr.strip()})"
    # The pull (dest→source) must authenticate as the user, never the gateway.
    assert GW_DN not in after, \
        "source authorised the pull as the GATEWAY DN — delegation not forwarded"
    assert f"Subject DN='{USER_DN}'" in after, \
        "source did not authenticate the pull as the delegating USER"
