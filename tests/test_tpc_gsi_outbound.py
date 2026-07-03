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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX_BIN = "/tmp/nginx-1.28.3/objs/nginx"
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


@pytest.fixture(scope="module")
def gsi_tpc(tmp_path_factory):
    if not _have("xrootd", "openssl", "xrdgsiproxy"):
        pytest.skip("stock xrootd / openssl / xrdgsiproxy not installed")
    if not (os.path.exists(XRDCP) and os.path.exists(NGINX_BIN)):
        pytest.skip("native xrdcp / nginx binary not built")

    base = tmp_path_factory.mktemp("tpcgsi")
    ca, srv, certs, src_data, dst_data, logs = (
        base / d for d in ("ca", "server", "certs", "srcdata", "dstdata", "logs"))
    for d in (ca, srv, certs, src_data, dst_data, logs):
        d.mkdir(parents=True, exist_ok=True)
    fqdn = socket.getfqdn()

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
    src_port = 21194
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
        "ofs.tpc ttl 300 300 pgm /usr/bin/xrdcp\n")
    shutil.move(str(src_data), str(base / "gsidata"))
    _free_port(src_port)
    src = subprocess.Popen(["xrootd", "-c", str(src_cfg), "-l", str(logs / "xrd.log"),
                            "-n", "tpcgsisrc"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_listen(src_port):
        src.terminate()
        pytest.skip("stock xrootd GSI source did not come up")

    # ---- TPC destination: nginx-xrootd, native TPC + outbound GSI cert ----
    dst_port = 21195
    dst_cfg = base / "nginx.conf"
    dst_cfg.write_text(
        "daemon off;\n"
        "worker_processes 1;\n"
        f"error_log {logs}/nginx-err.log debug;\n"
        "pid " + str(base / "nginx.pid") + ";\n"
        "thread_pool default threads=4 max_queue=65536;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen 127.0.0.1:{dst_port};\n"
        "    xrootd on;\n"
        f"    brix_storage_backend posix:{dst_data};\n"
        "    brix_auth none;\n"
        "    brix_allow_write on;\n"
        "    brix_tpc_allow_local on;\n"
        "    brix_tpc_allow_private on;\n"
        f"    brix_certificate {srv / 'destproxy.pem'};\n"
        f"    brix_certificate_key {srv / 'destproxy.pem'};\n"
        f"    brix_trusted_ca {certs};\n"
        f"    brix_access_log {logs}/dst-access.log;\n"
        "  }\n"
        "}\n")
    _free_port(dst_port)
    dst = subprocess.Popen([NGINX_BIN, "-c", str(dst_cfg), "-p", str(base)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_listen(dst_port):
        dst.terminate()
        src.terminate()
        pytest.skip("nginx TPC destination did not come up")

    ctx = {"fqdn": fqdn, "src_port": src_port, "dst_port": dst_port,
           "env": penv, "certs": str(certs), "base": str(base),
           "dst_data": str(dst_data), "logs": str(logs),
           "src_url": f"root://{fqdn}:{src_port}",
           "dst_url": f"root://127.0.0.1:{dst_port}"}
    yield ctx
    for p in (dst, src):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


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
