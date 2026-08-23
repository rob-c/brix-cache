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
    _require_gate_tools()
    base = tmp_path_factory.mktemp("f6gate")
    paths = _gate_paths(base)
    # Lowercase: the client lowercases the connect hostname, so the server cert CN
    # must be lowercase too — else the name check fails, the client falls back to
    # DNS, and "usedDNS" forbids proxy delegation (§F6).
    fqdn = socket.getfqdn().lower()
    _make_gate_pki(base, paths, fqdn)
    penv, uproxy = _make_gate_proxies(paths)
    paths["data"].joinpath("hello.txt").write_text("f6 delegation gate\n")
    gridmap = _write_gridmap(base)
    src_port = free_port()
    src_cfg = _write_gate_source_config(base, paths, gridmap, src_port)
    src_log = base / "src" / "xrootd.log"
    src = _start_gate_source(base, paths, gridmap, src_cfg, src_port)
    dst = _start_gate_destination(lifecycle, base, paths, src)
    ctx = {"base": str(base), "fqdn": fqdn, "src_log": src_log,
           "src_port": src_port, "dst_port": dst.port,
           "dst_logs": os.path.join(dst.prefix, "logs"),
           "env": dict(penv, X509_USER_PROXY=str(uproxy))}
    yield ctx
    _stop_source(src)


def _require_gate_tools():
    available = _have("xrootd", "openssl", "xrdgsiproxy")
    if not available or not os.path.exists(XRDCP):
        pytest.skip("stock xrootd / openssl / xrdgsiproxy not installed")


def _gate_paths(base):
    paths = {name: base / name for name in ("ca", "certs", "srv", "usr", "data")}
    for path in paths.values():
        path.mkdir(parents=True)
    return paths


def _openssl(*args):
    result = _run(["openssl", *args])
    assert result.returncode == 0, f"openssl {args}: {result.stderr}"


def _make_gate_pki(base, paths, fqdn):
    ca = paths["ca"]
    _openssl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-subj", "/O=F6Test/CN=F6Test CA", "-keyout", str(ca / "ca.key"),
             "-out", str(ca / "ca.pem"))
    _install_gate_ca(paths)
    extension = base / "ku.ext"
    extension.write_text("keyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=serverAuth,clientAuth\n")
    _sign_gate_cert(base, paths, extension, fqdn, "srv", "host")
    _sign_gate_cert(base, paths, extension, "F6 User", "usr", "user")
    _sign_gate_cert(base, paths, extension, "tpc-gateway", "srv", "gw")
    os.chmod(paths["usr"] / "userkey.pem", 0o600)
    os.chmod(paths["srv"] / "gwkey.pem", 0o600)


def _install_gate_ca(paths):
    ca_file = paths["ca"] / "ca.pem"
    chash = _run(["openssl", "x509", "-in", str(ca_file),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca_file, paths["certs"] / f"{chash}.0")
    paths["certs"].joinpath(f"{chash}.signing_policy").write_text(
        "access_id_CA      X509     '/O=F6Test/CN=F6Test CA'\n"
        "pos_rights        globus   CA:sign\n"
        "cond_subjects     globus   '\"/O=F6Test/*\"'\n")


def _sign_gate_cert(base, paths, extension, common_name, directory, stem):
    csr = base / (common_name.replace(" ", "") + ".csr")
    key = paths[directory] / f"{stem}key.pem"
    cert = paths[directory] / f"{stem}cert.pem"
    _openssl("req", "-nodes", "-newkey", "rsa:2048",
             "-subj", f"/O=F6Test/CN={common_name}", "-keyout", str(key),
             "-out", str(csr))
    ca = paths["ca"]
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
             "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
             "-out", str(cert), "-extfile", str(extension))


def _make_gate_proxies(paths):
    penv = dict(os.environ, X509_CERT_DIR=str(paths["certs"]))
    uproxy = paths["usr"] / "proxy.pem"
    gwproxy = paths["srv"] / "gwproxy.pem"
    _mint_gate_proxy(paths["usr"], "user", uproxy, paths["certs"], penv)
    _mint_gate_proxy(paths["srv"], "gw", gwproxy, paths["certs"], penv)
    os.chmod(gwproxy, 0o600)
    return penv, uproxy


def _mint_gate_proxy(directory, stem, output, cert_dir, env):
    _run(["xrdgsiproxy", "init", "-cert", str(directory / f"{stem}cert.pem"),
          "-key", str(directory / f"{stem}key.pem"), "-out", str(output),
          "-certdir", str(cert_dir), "-valid", "1:00"], input="\n\n", env=env)
    if not output.exists():
        pytest.skip(f"could not mint {stem} proxy")


def _write_gridmap(base):
    gridmap = base / "grid-mapfile"
    user = os.environ.get("USER", "nobody")
    gridmap.write_text(f'"{USER_DN}" {user}\n"{GW_DN}" {user}\n')
    return gridmap


def _write_gate_source_config(base, paths, gridmap, src_port):
    certs, srv = paths["certs"], paths["srv"]
    config = base / "xrootd.cfg"
    config.write_text(
        f"xrd.port {src_port}\nall.export /data\noss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{certs} "
        f"-cert:{srv / 'hostcert.pem'} -key:{srv / 'hostkey.pem'} "
        f"-gridmap:{gridmap} -d:2 -crl:0 -gmapopt:2 "
        "-dlgpxy:request -showdn:1 -exppxy:=creds\n"
        "sec.protbind * only gsi\nofs.tpc ttl 300 300 pgm /usr/bin/xrdcp\n"
        f"all.adminpath {base / 'admin'}\nall.pidpath {base / 'admin'}\n")
    return config


def _start_gate_source(base, paths, gridmap, config, port):
    _run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"])
    argv = ["xrootd", "-c", str(config), "-l", str(base / "xrootd.log"),
            "-n", "src"]
    argv = _gate_source_argv(base, paths, gridmap, argv)
    source = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    if not _wait(port):
        source.terminate()
        pytest.skip("stock GSI source did not come up")
    return source


def _gate_source_argv(base, paths, gridmap, argv):
    if os.geteuid() != 0:
        return argv
    runas = os.environ.get("REF_RUNAS_USER", "nobody")
    writable = (base / "admin", base / "src")
    for directory in writable:
        directory.mkdir(parents=True, exist_ok=True)
    _run(["chmod", "a+rx", str(base)])
    _chmod_trees((paths["data"], paths["certs"]), "a+rX")
    _chmod_trees(writable, "a+rwX")
    _make_readable(paths["srv"] / "hostcert.pem")
    _run(["chmod", "a+rx", str(paths["srv"])])
    _protect_for_user(paths["srv"] / "hostkey.pem", runas)
    return argv + ["-R", runas]


def _chmod_trees(paths, mode):
    for path in paths:
        _run(["chmod", "-R", mode, str(path)])


def _make_readable(path):
    if path.exists():
        _run(["chmod", "a+r", str(path)])


def _protect_for_user(path, user):
    if path.exists():
        shutil.chown(path, user)
        os.chmod(path, 0o400)


def _start_gate_destination(lifecycle, base, paths, source):
    destination_data = base / "dstdata"
    destination_data.mkdir(exist_ok=True)
    try:
        return lifecycle.start(NginxInstanceSpec(
            name="lc-tpc-delegation-dest",
            template="nginx_tpc_delegation_dest.conf", protocol="root",
            readiness="tcp", data_root=str(destination_data),
            template_values={"CERT_FILE": str(paths["srv"] / "hostcert.pem"),
                             "KEY_FILE": str(paths["srv"] / "hostkey.pem"),
                             "CA_FILE": str(paths["ca"] / "ca.pem")},
            reason="F6 GSI TPC delegation destination (captures + forwards proxy)."))
    except Exception:
        source.terminate()
        raise


def _stop_source(source):
    source.terminate()
    try:
        source.wait(timeout=5)
    except subprocess.TimeoutExpired:
        source.kill()


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
