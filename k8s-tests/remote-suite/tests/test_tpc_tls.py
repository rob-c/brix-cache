"""phase-57 §F5 gate: native root:// TPC PULL where the DESTINATION upgrades the
pull connection to TLS (kXR_gotoTLS) before authenticating and reading.

The source nginx requires in-protocol TLS (brix_tls on + a CA-signed host cert);
the destination nginx has brix_tpc_outbound_tls on, so it advertises kXR_ableTLS,
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

def _phase_tls_nginx_1_next(ca, certs, srv, sdata, ddata):
    for d in (ca, certs, srv, sdata, ddata):
        d.mkdir(parents=True, exist_ok=True)

def _phase_tls_nginx_2():
    for port in (SRC, DST):
        _run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"])

def _phase_tls_nginx_3(procs):
    for p in procs:
        p.terminate()
        _phase_tls_nginx_1(p)


def _expression_1(src_cfg, dst_cfg, base):
    return (
        [subprocess.Popen([NGINX, "-c", str(c), "-p", str(base)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                     for c in (src_cfg, dst_cfg)]
    )

def _expression_2():
    return (
        not _wait(SRC) or not _wait(DST)
    )


def _phase_tls_nginx_1(p):
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()


def _guard_tls_nginx_1():
    if not _have("openssl"):
        pytest.skip("openssl not installed")

def _guard_tls_nginx_2():
    if not (os.path.exists(NGINX) and os.path.exists(XRDCP)):
        pytest.skip("nginx / xrdcp not built")


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
    _guard_tls_nginx_1()
    _guard_tls_nginx_2()

    base = tmp_path_factory.mktemp("tpctls")
    ca, certs, srv, sdata, ddata = (
        base / d for d in ("ca", "certs", "srv", "srcdata", "dstdata"))
    _phase_tls_nginx_1_next(ca, certs, srv, sdata, ddata)
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
        f"    listen {SRC};\n    brix_root on;\n"
        f"    brix_storage_backend posix:{sdata};\n    brix_auth none;\n"
        "    brix_tls on;\n"
        f"    brix_certificate {srv / 'hostcert.pem'};\n"
        f"    brix_certificate_key {srv / 'hostkey.pem'};\n"
        f"    brix_trusted_ca {certs};\n"
        f"    brix_access_log {base}/src-acc.log;\n  }}\n}}\n")

    dst_cfg = base / "dst.conf"
    dst_cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {base}/dst-err.log info;\npid {base}/dst.pid;\n"
        "thread_pool default threads=4 max_queue=65536;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen 127.0.0.1:{DST};\n    brix_root on;\n"
        f"    brix_storage_backend posix:{ddata};\n    brix_auth none;\n"
        "    brix_allow_write on;\n"
        "    brix_tpc_allow_local on;\n    brix_tpc_allow_private on;\n"
        "    brix_tpc_outbound_tls on;\n"
        f"    brix_trusted_ca {certs};\n"
        f"    brix_access_log {base}/dst-acc.log;\n  }}\n}}\n")

    _phase_tls_nginx_2()
    procs = _expression_1(src_cfg, dst_cfg, base)
    if _expression_2():
        for p in procs:
            p.terminate()
        pytest.skip("nginx TLS src/dst did not come up")

    ctx = {"base": str(base), "ddata": str(ddata), "fqdn": fqdn,
           "env": dict(os.environ, X509_CERT_DIR=str(certs))}
    yield ctx
    _phase_tls_nginx_3(procs)


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
