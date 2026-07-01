"""W1 end-to-end gate: native root:// TPC PULL where the nginx DESTINATION
authenticates to an nginx GSI SOURCE with its own proxy (the server-outbound GSI
handshake, items 4-5), and the source serves the pull synchronously.

Unlike test_tpc_gsi_outbound.py (stock xrootd source, whose ofs.tpc-pgm push model
answers the TPC open asynchronously via kXR_waitresp — a separate data-plane layer
not yet handled), BOTH endpoints here are nginx, so the source serves the TPC open
synchronously. This isolates and verifies the outbound GSI handshake end-to-end.

Topology:
    nginx (GSI source, xrootd_auth gsi, exports /srcdata)
        ^  native TPC pull: dest GSI-auths with destproxy.pem
    nginx (TPC destination, native TPC, xrootd_certificate=destproxy.pem)
        ^  xrdcp --tpc only (client GSI-auths the source with the user proxy)
    native xrdcp client
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
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
SRC, DST = 21214, 21215


def _have(*t):
    return all(shutil.which(x) for x in t)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def _wait(port, tries=80):
    for _ in range(tries):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return True
        time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def gsi_nginx(tmp_path_factory):
    if not _have("openssl", "xrdgsiproxy"):
        pytest.skip("openssl / xrdgsiproxy not installed")
    if not (os.path.exists(NGINX) and os.path.exists(XRDCP)):
        pytest.skip("nginx / xrdcp not built")

    base = tmp_path_factory.mktemp("gsinginx")
    ca, certs, srv, usr, sdata, ddata = (
        base / d for d in ("ca", "certs", "srv", "usr", "srcdata", "dstdata"))
    for d in (ca, certs, srv, usr, sdata, ddata):
        d.mkdir(parents=True, exist_ok=True)
    fqdn = socket.getfqdn()

    def osl(*a):
        r = _run(["openssl", *a])
        assert r.returncode == 0, f"openssl {a}: {r.stderr}"

    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=W1Test/CN=W1Test CA",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = _run(["openssl", "x509", "-in", str(ca / "ca.pem"),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca / "ca.pem", certs / f"{chash}.0")

    def signed(cn, key, cert):
        csr = base / (cn.replace(" ", "") + ".csr")
        osl("req", "-nodes", "-newkey", "rsa:2048",
            "-subj", f"/O=W1Test/CN={cn}", "-keyout", str(key), "-out", str(csr))
        osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
            "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
            "-out", str(cert))

    signed(fqdn, srv / "hostkey.pem", srv / "hostcert.pem")
    signed("tpc-dest", srv / "destkey.pem", srv / "destcert.pem")
    os.chmod(srv / "destkey.pem", 0o600)
    signed("Test User", usr / "userkey.pem", usr / "usercert.pem")
    os.chmod(usr / "userkey.pem", 0o600)

    penv = dict(os.environ, X509_CERT_DIR=str(certs))

    def proxy(cert, key, out):
        _run(["xrdgsiproxy", "init", "-cert", str(cert), "-key", str(key),
              "-out", str(out), "-certdir", str(certs), "-valid", "1:00"],
             input="\n\n", env=penv)
        return out.exists()

    uproxy = usr / "proxy.pem"
    dproxy = srv / "destproxy.pem"
    if not proxy(usr / "usercert.pem", usr / "userkey.pem", uproxy):
        pytest.skip("could not mint user proxy")
    if not proxy(srv / "destcert.pem", srv / "destkey.pem", dproxy):
        pytest.skip("could not mint dest proxy")
    os.chmod(dproxy, 0o600)

    (sdata / "hello.txt").write_text("nginx-GSI-source native tpc pull\n")

    src_cfg = base / "src.conf"
    src_cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {base}/src-err.log info;\npid {base}/src.pid;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {SRC};\n    xrootd on;\n"   # all interfaces: GSI cert CN=fqdn
        f"    xrootd_storage_backend posix:{sdata};\n    xrootd_auth gsi;\n"
        f"    xrootd_certificate {srv / 'hostcert.pem'};\n"
        f"    xrootd_certificate_key {srv / 'hostkey.pem'};\n"
        f"    xrootd_trusted_ca {certs};\n"
        f"    xrootd_access_log {base}/src-acc.log;\n  }}\n}}\n")

    dst_cfg = base / "dst.conf"
    dst_cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {base}/dst-err.log info;\npid {base}/dst.pid;\n"
        "thread_pool default threads=4 max_queue=65536;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen 127.0.0.1:{DST};\n    xrootd on;\n"
        f"    xrootd_storage_backend posix:{ddata};\n    xrootd_auth none;\n"
        "    xrootd_allow_write on;\n"
        "    xrootd_tpc_allow_local on;\n    xrootd_tpc_allow_private on;\n"
        f"    xrootd_certificate {dproxy};\n"
        f"    xrootd_certificate_key {dproxy};\n"
        f"    xrootd_trusted_ca {certs};\n"
        f"    xrootd_access_log {base}/dst-acc.log;\n  }}\n}}\n")

    for port in (SRC, DST):
        _run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"])
    procs = [subprocess.Popen([NGINX, "-c", str(c), "-p", str(base)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
             for c in (src_cfg, dst_cfg)]
    if not _wait(SRC) or not _wait(DST):
        for p in procs:
            p.terminate()
        pytest.skip("nginx GSI src/dst did not come up")

    ctx = {"base": str(base), "ddata": str(ddata), "fqdn": fqdn,
           "env": dict(penv, X509_USER_PROXY=str(uproxy))}
    yield ctx
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def test_tpc_pull_nginx_dest_from_nginx_gsi_source(gsi_nginx):
    out = Path(gsi_nginx["ddata"]) / "pulled.txt"
    r = _run([XRDCP, "-f", "--tpc", "only",
              f"root://{gsi_nginx['fqdn']}:{SRC}//hello.txt",
              f"root://127.0.0.1:{DST}//pulled.txt"], env=gsi_nginx["env"])
    if r.returncode != 0 or not out.exists():
        tail = ""
        for log in ("dst-err.log", "src-err.log"):
            p = Path(gsi_nginx["base"]) / log
            if p.exists():
                tail += f"\n--- {log} ---\n" + "\n".join(
                    p.read_text(errors="replace").splitlines()[-15:])
        pytest.fail(f"TPC pull failed rc={r.returncode}: {r.stderr.strip()}{tail}")
    assert out.read_text() == "nginx-GSI-source native tpc pull\n"
