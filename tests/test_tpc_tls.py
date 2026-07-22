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
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpc")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")


def _have(*t):
    return all(shutil.which(x) for x in t)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


@pytest.fixture
def tls_nginx(lifecycle, tmp_path_factory):
    if not _have("openssl"):
        pytest.skip("openssl not installed")
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp not built")

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

    src = lifecycle.start(NginxInstanceSpec(
        name="lc-tpc-tls-source",
        template="nginx_tpc_tls_source.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(sdata),
        template_values={
            "CERT_FILE": str(srv / "hostcert.pem"),
            "KEY_FILE": str(srv / "hostkey.pem"),
            "CA_DIR": str(certs),
        },
        reason="TPC-over-TLS: TLS-required pull source.",
    ))
    dst = lifecycle.start(NginxInstanceSpec(
        name="lc-tpc-tls-dest",
        template="nginx_tpc_tls_dest.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(ddata),
        template_values={"CA_DIR": str(certs)},
        reason="TPC-over-TLS: outbound-TLS pull destination.",
    ))

    return {"ddata": str(ddata), "fqdn": fqdn, "src_port": src.port,
            "dst_port": dst.port,
            "src_logs": os.path.join(src.prefix, "logs"),
            "dst_logs": os.path.join(dst.prefix, "logs"),
            "env": dict(os.environ, X509_CERT_DIR=str(certs))}


def test_tpc_pull_over_tls(tls_nginx):
    out = Path(tls_nginx["ddata"]) / "pulled.txt"
    r = _run([XRDCP, "-f", "--tpc", "only",
              f"root://{tls_nginx['fqdn']}:{tls_nginx['src_port']}//hello.txt",
              f"root://{HOST}:{tls_nginx['dst_port']}//pulled.txt"],
             env=tls_nginx["env"])
    if r.returncode != 0 or not out.exists():
        tail = ""
        for label, logdir, log in (("dst", tls_nginx["dst_logs"], "dst-err.log"),
                                   ("src", tls_nginx["src_logs"], "src-err.log")):
            p = Path(logdir) / log
            if p.exists():
                tail += f"\n--- {log} ---\n" + "\n".join(
                    p.read_text(errors="replace").splitlines()[-15:])
        pytest.fail(f"TPC-over-TLS pull failed rc={r.returncode}: "
                    f"{r.stderr.strip()}{tail}")
    assert out.read_text() == "tpc-over-TLS gotoTLS pull works\n"
