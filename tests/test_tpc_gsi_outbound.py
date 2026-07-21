"""Local verification of the server-outbound TPC GSI handshake (src/tpc/gsi/gsi_outbound_*.c).

This is the missing behavioural coverage for the code path that authenticates to a
GSI-requiring TPC *source*: a native TPC PULL where the nginx data server (the
destination) connects to a remote XrdSecgsi server and must present its own
certificate (`brix_certificate`) — i.e. `tpc_outbound_gsi()` in
src/tpc/gsi/gsi_outbound_certreq.c + the DH/cipher exchange in gsi_outbound_exchange.c.

Topology:
    stock `xrootd` (GSI source, sec.protbind * only gsi, exports /gsidata)
        ^
        | native TPC pull (nginx dest connects + GSI-auths with its hostcert)
        |
    nginx-xrootd (TPC destination: native TPC, brix_certificate=<CA-signed cert>)
        ^
        | xrdcp -f -s --tpc <mode> <gsi-source>/hello.txt <nginx-dest>/pulled.txt
    native xrdcp client

Skips cleanly when the GSI toolchain (stock xrootd / openssl / xrdgsiproxy) or the
built binaries are absent. The baseline (current code) must PASS — this is the
regression gate for migrating tpc_outbound_gsi onto the shared gsi_core kernel.
"""
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec
from settings import free_port

pytestmark = pytest.mark.uses_lifecycle_harness

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")


def _have(*tools):
    return all(shutil.which(t) for t in tools)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def _free_port(port):
    subprocess.run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"], check=False)
    for _ in range(20):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode != 0:
            return
        time.sleep(0.1)


def _wait_listen(port, tries=60):
    for _ in range(tries):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def gsi_tpc(lifecycle, tmp_path_factory):
    if not _have("xrootd", "openssl", "xrdgsiproxy"):
        pytest.skip("stock xrootd / openssl / xrdgsiproxy not installed")
    if not os.path.exists(XRDCP):
        pytest.skip("native xrdcp not built")

    base = tmp_path_factory.mktemp("tpcgsi")
    ca, srv, certs, src_data, dst_data, logs = (
        base / d for d in ("ca", "server", "certs", "srcdata", "dstdata", "logs"))
    for d in (ca, srv, certs, src_data, dst_data, logs):
        d.mkdir(parents=True, exist_ok=True)
    fqdn = socket.getfqdn()

    # The rendezvous on the stock source is a raw strcmp (XrdOfsTPCInfo::Match):
    # the grant's org host is the source's reverse-name of the CLIENT connection
    # and must equal the nginx destination's reverse-name of that same client on
    # ITS leg.  Every leg must therefore ride the SAME address family on the
    # same loopback address: numeric 127.0.0.1 forces IPv4 everywhere, so both
    # sides derive the identical string (the "[::ffff:127.0.0.1]" literal where
    # glibc cannot name the v4-MAPPED form, "localhost" where it can).  Anything
    # else splits the horizon: getfqdn() routes via the public NIC (its PTR name
    # is unreachable from a loopback leg), and a "localhost" URL lets the client
    # reach the dual-stack source over ::1 ("localhost") while the v4-only nginx
    # dest names the same client "[::ffff:127.0.0.1]".
    loop = "127.0.0.1"

    def osl(*a):
        r = _run(["openssl", *a])
        assert r.returncode == 0, f"openssl {a}: {r.stderr}"

    # Test CA + hashed link.
    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=XrdTpcTest/CN=XrdTpcTest CA",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = _run(["openssl", "x509", "-in", str(ca / "ca.pem"),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca / "ca.pem", certs / f"{chash}.0")

    def signed(cn, key, cert):
        csr = base / (cn.replace(" ", "") + ".csr")
        osl("req", "-nodes", "-newkey", "rsa:2048",
            "-subj", f"/O=XrdTpcTest/CN={cn}", "-keyout", str(key), "-out", str(csr))
        osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
            "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
            "-out", str(cert))

    # Source host cert; the nginx dest presents its own CA-signed cert outbound;
    # the client gets a user EEC + proxy to open the GSI source for the rendezvous.
    signed(fqdn, srv / "hostkey.pem", srv / "hostcert.pem")
    signed("tpc-dest", srv / "destkey.pem", srv / "destcert.pem")
    os.chmod(srv / "destkey.pem", 0o600)
    usr = base / "user"
    usr.mkdir(parents=True, exist_ok=True)
    signed("Test User", usr / "userkey.pem", usr / "usercert.pem")
    os.chmod(usr / "userkey.pem", 0o600)
    proxy = usr / "proxy.pem"
    penv = dict(os.environ, X509_CERT_DIR=str(certs), X509_USER_PROXY=str(proxy))
    mk = _run(["xrdgsiproxy", "init", "-cert", str(usr / "usercert.pem"),
               "-key", str(usr / "userkey.pem"), "-out", str(proxy),
               "-certdir", str(certs), "-valid", "1:00"], input="\n\n", env=penv)
    if not proxy.exists():
        pytest.skip(f"could not mint a test proxy: {mk.stdout}{mk.stderr}")

    # The nginx destination authenticates to the GSI source with a PROXY chain
    # (proxy + EEC = >= 2 certs in the kXGC_cert bucket); stock XrdSecgsi rejects a
    # bare single-cert bucket ("expected: >= 2"). Mint a dest proxy from its EEC.
    dest_proxy = srv / "destproxy.pem"
    _run(["xrdgsiproxy", "init", "-cert", str(srv / "destcert.pem"),
          "-key", str(srv / "destkey.pem"), "-out", str(dest_proxy),
          "-certdir", str(certs), "-valid", "1:00"], input="\n\n", env=penv)
    if not dest_proxy.exists():
        pytest.skip("could not mint the destination proxy")
    os.chmod(dest_proxy, 0o600)

    (src_data / "hello.txt").write_text("hello-tpc-gsi\n")

    # ---- GSI source: stock xrootd, GSI required ----
    src_port = free_port()
    src_cfg = base / "xrootd.cfg"
    src_cfg.write_text(
        f"xrd.port {src_port}\n"
        "all.export /gsidata\n"
        f"oss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{certs} "
        f"-cert:{srv / 'hostcert.pem'} -key:{srv / 'hostkey.pem'} "
        "-crl:0 -gmapopt:10 -dlgpxy:0\n"
        "sec.protbind * only gsi\n"
        # Enable third-party-copy on the source so the rendezvous (tpc.dst/key)
        # and the destination's pull (tpc.org/key) are accepted; without this the
        # stock source rejects the TPC open with "tpc not supported".
        # Generous rendezvous TTL: the GSI handshake + async wait can exceed a
        # short default, yielding "tpc authorization expired".
        "ofs.tpc ttl 300 300 pgm /usr/bin/xrdcp\n"
        # Keep xrootd's runtime admin/pid dirs under the test-owned base so the
        # `-R nobody` drop (below) can create its sockets — the default location
        # is root-owned and unwritable to the dropped user.
        f"all.adminpath {base / 'admin'}\n"
        f"all.pidpath {base / 'admin'}\n")
    shutil.move(str(src_data), str(base / "gsidata"))
    _free_port(src_port)
    argv = ["xrootd", "-c", str(src_cfg), "-l", str(logs / "xrd.log"),
            "-n", "tpcgsisrc"]
    # Root-harness privilege drop: stock xrootd refuses to run as superuser, so
    # run it via `-R nobody` and pre-open every path that user must touch — the
    # test-owned tree (a+rwX), the admin dir, and the GSI key (nobody-only 0400).
    if os.geteuid() == 0:
        runas = os.environ.get("REF_RUNAS_USER", "nobody")
        (base / "admin").mkdir(parents=True, exist_ok=True)
        # Open ONLY what the dropped source needs: traverse base, read the data
        # tree + CA certdir + hostcert, write admin/log. Deliberately do NOT
        # touch usr/ — XrdSecgsi refuses a group/world-writable proxy credential
        # ("cannot load proxy credential"), and only the root client/nginx dest
        # (not the -R nobody source) ever read it.
        _run(["chmod", "a+rx", str(base)])
        for d in (base / "gsidata", certs):
            _run(["chmod", "-R", "a+rX", str(d)])
        for d in (base / "admin", logs):
            _run(["chmod", "-R", "a+rwX", str(d)])
        hostcert = srv / "hostcert.pem"
        if hostcert.exists():
            _run(["chmod", "a+r", str(hostcert)])
            _run(["chmod", "a+rx", str(srv)])
        hostkey = srv / "hostkey.pem"
        if hostkey.exists():
            shutil.chown(hostkey, runas)
            os.chmod(hostkey, 0o400)
        argv += ["-R", runas]
    src = subprocess.Popen(argv,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_listen(src_port):
        src.terminate()
        pytest.skip("stock xrootd GSI source did not come up")

    # ---- TPC destination: nginx-xrootd, native TPC + outbound GSI cert ----
    try:
        dst = lifecycle.start(NginxInstanceSpec(
            name="lc-tpc-gsi-outbound-dest",
            template="nginx_tpc_gsi_outbound_dest.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(dst_data),
            template_values={
                "CERT_FILE": str(srv / "destproxy.pem"),
                "KEY_FILE": str(srv / "destproxy.pem"),
                "CA_DIR": str(certs),
            },
            reason="TPC outbound-GSI dest; auths to stock GSI source with its proxy.",
        ))
    except Exception:
        src.terminate()
        raise

    dst_logs = os.path.join(dst.prefix, "logs")
    ctx = {"fqdn": fqdn, "src_port": src_port, "dst_port": dst.port,
           "env": penv, "certs": str(certs), "base": str(base),
           "dst_data": str(dst_data), "logs": dst_logs,
           "src_url": f"root://{loop}:{src_port}",
           "dst_url": f"root://{loop}:{dst.port}"}
    yield ctx
    src.terminate()
    try:
        src.wait(timeout=5)
    except subprocess.TimeoutExpired:
        src.kill()


def test_tpc_pull_over_gsi(gsi_tpc):
    """Native TPC PULL from a GSI-requiring source: exercises tpc_outbound_gsi.

    The nginx destination connects to the stock GSI source and authenticates with
    its own brix_certificate (the server-outbound GSI handshake). Success means
    the file content arrives at the destination.
    """
    src = f"{gsi_tpc['src_url']}//gsidata/hello.txt"
    dst = f"{gsi_tpc['dst_url']}//pulled.txt"

    # --tpc first: try a third-party copy (dest pulls from source over GSI).
    r = _run([XRDCP, "-f", "-s", "--tpc", "first", src, dst], env=gsi_tpc["env"])

    pulled = Path(gsi_tpc["dst_data"]) / "pulled.txt"
    if r.returncode != 0 or not pulled.exists():
        # Surface the dest error log to make a handshake failure diagnosable.
        err = Path(gsi_tpc["logs"]) / "nginx-err.log"
        tail = ""
        if err.exists():
            tail = "\n".join(err.read_text(errors="replace").splitlines()[-25:])
        pytest.fail(
            f"TPC pull over GSI failed (rc={r.returncode}).\n"
            f"xrdcp stdout: {r.stdout}\nxrdcp stderr: {r.stderr}\n"
            f"--- nginx dest error.log tail ---\n{tail}")

    assert pulled.read_text() == "hello-tpc-gsi\n"
