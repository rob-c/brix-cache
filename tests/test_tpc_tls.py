"""phase-57 §F5 gate: native root:// TPC PULL where the DESTINATION upgrades the
pull connection to TLS (kXR_gotoTLS) before authenticating and reading.

The source nginx requires in-protocol TLS (xrootd_tls on + a CA-signed host cert);
the destination nginx has xrootd_tpc_outbound_tls on, so it advertises kXR_ableTLS,
receives kXR_gotoTLS, performs a blocking SSL_connect over the pull fd, and runs the
whole login/open/read sequence over TLS. The file must arrive byte-exact.

Topology (all over TLS):
    native xrdcp --tpc only
        ├── opens TLS source (rendezvous: tpc.dst=…)
        └── opens nginx DEST → dest pulls from the TLS source over an upgraded
            (kXR_gotoTLS) connection and writes the destination file.
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
SRC, DST = 21250, 21251


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
def tls_nginx(tmp_path_factory):
    if not _have("openssl"):
        pytest.skip("openssl not installed")
    if not (os.path.exists(NGINX) and os.path.exists(XRDCP)):
        pytest.skip("nginx / xrdcp not built")

    base = tmp_path_factory.mktemp("tpctls")
    ca, certs, srv, sdata, ddata = (
        base / d for d in ("ca", "certs", "srv", "srcdata", "dstdata"))
    for d in (ca, certs, srv, sdata, ddata):
        d.mkdir(parents=True, exist_ok=True)
    fqdn = socket.getfqdn()

    def osl(*a):
        r = _run(["openssl", *a])
        assert r.returncode == 0, f"openssl {a}: {r.stderr}"

    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=TpcTlsTest/CN=TpcTlsTest CA",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = _run(["openssl", "x509", "-in", str(ca / "ca.pem"),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca / "ca.pem", certs / f"{chash}.0")

    csr = base / "host.csr"
    osl("req", "-nodes", "-newkey", "rsa:2048", "-subj", f"/O=TpcTlsTest/CN={fqdn}",
        "-keyout", str(srv / "hostkey.pem"), "-out", str(csr))
    osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
        "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
        "-out", str(srv / "hostcert.pem"))

    (sdata / "hello.txt").write_text("tpc-over-TLS gotoTLS pull works\n")

    src_cfg = base / "src.conf"
    src_cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {base}/src-err.log info;\npid {base}/src.pid;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {SRC};\n    xrootd on;\n"
        f"    xrootd_storage_backend posix:{sdata};\n    xrootd_auth none;\n"
        "    xrootd_tls on;\n"
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
        "    xrootd_tpc_outbound_tls on;\n"
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
        pytest.skip("nginx TLS src/dst did not come up")

    ctx = {"base": str(base), "ddata": str(ddata), "fqdn": fqdn,
           "env": dict(os.environ, X509_CERT_DIR=str(certs))}
    yield ctx
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def test_tpc_pull_over_tls(tls_nginx):
    out = Path(tls_nginx["ddata"]) / "pulled.txt"
    r = _run([XRDCP, "-f", "--tpc", "only",
              f"root://{tls_nginx['fqdn']}:{SRC}//hello.txt",
              f"root://127.0.0.1:{DST}//pulled.txt"], env=tls_nginx["env"])
    if r.returncode != 0 or not out.exists():
        tail = ""
        for log in ("dst-err.log", "src-err.log"):
            p = Path(tls_nginx["base"]) / log
            if p.exists():
                tail += f"\n--- {log} ---\n" + "\n".join(
                    p.read_text(errors="replace").splitlines()[-15:])
        pytest.fail(f"TPC-over-TLS pull failed rc={r.returncode}: "
                    f"{r.stderr.strip()}{tail}")
    assert out.read_text() == "tpc-over-TLS gotoTLS pull works\n"
