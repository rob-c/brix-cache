"""W1 end-to-end gate: native root:// TPC PULL where the nginx DESTINATION
authenticates to an nginx GSI SOURCE with its own proxy (the server-outbound GSI
handshake, items 4-5), and the source serves the pull synchronously.

Unlike test_tpc_gsi_outbound.py (stock xrootd source, whose ofs.tpc-pgm push model
answers the TPC open asynchronously via kXR_waitresp — a separate data-plane layer
not yet handled), BOTH endpoints here are nginx, so the source serves the TPC open
synchronously. This isolates and verifies the outbound GSI handshake end-to-end.

Topology:
    nginx (GSI source, brix_auth gsi, exports /srcdata)
        ^  native TPC pull: dest GSI-auths with destproxy.pem
    nginx (TPC destination, native TPC, brix_certificate=destproxy.pem)
        ^  xrdcp --tpc only (client GSI-auths the source with the user proxy)
    native xrdcp client
"""
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")


def _have(*t):
    return all(shutil.which(x) for x in t)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


@pytest.fixture
def gsi_nginx(lifecycle, tmp_path_factory):
    if not _have("openssl", "xrdgsiproxy"):
        pytest.skip("openssl / xrdgsiproxy not installed")
    if not os.path.exists(XRDCP):
        pytest.skip("xrdcp not built")

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

    # Root-posture: the source and dest nginx workers drop to `nobody`, so they
    # cannot read the 0700-root mktemp tree nor the 0600-root private creds. Open
    # the tree for traversal, then re-restrict every private credential and hand
    # the keys a worker must READ (source hostkey, dest brix_certificate proxy) to
    # `nobody`. The broad open MUST be followed by 0600 + chown: XrdSecgsi rejects
    # a group/world-accessible proxy ("cannot load proxy credential"). Mirrors the
    # idiom in _test_gsi_handshake_helpers.py.
    if os.geteuid() == 0:
        subprocess.run(["chmod", "-R", "a+rwX", str(base)], check=False)
        for worker_key in (srv / "hostkey.pem", dproxy):
            shutil.chown(worker_key, "nobody")
            os.chmod(worker_key, 0o600)
        for cred in (uproxy, usr / "userkey.pem", srv / "destkey.pem"):
            os.chmod(cred, 0o600)   # client/root-owned — just re-close after a+rwX
        os.chmod(certs, 0o755)

    src = lifecycle.start(NginxInstanceSpec(
        name="lc-tpc-gsi-nginx-source",
        template="nginx_tpc_gsi_nginx_source_src.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(sdata),
        template_values={
            "CERT_FILE": str(srv / "hostcert.pem"),
            "KEY_FILE": str(srv / "hostkey.pem"),
            "CA_DIR": str(certs),
        },
        reason="W1: nginx GSI pull source.",
    ))
    dst = lifecycle.start(NginxInstanceSpec(
        name="lc-tpc-gsi-nginx-dest",
        template="nginx_tpc_gsi_nginx_source_dst.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(ddata),
        template_values={
            "CERT_FILE": str(dproxy),
            "KEY_FILE": str(dproxy),
            "CA_DIR": str(certs),
        },
        reason="W1: native TPC dest, GSI-auths outbound to the nginx source.",
    ))

    return {"ddata": str(ddata), "fqdn": fqdn, "src_port": src.port,
            "dst_port": dst.port,
            "src_logs": os.path.join(src.prefix, "logs"),
            "dst_logs": os.path.join(dst.prefix, "logs"),
            "env": dict(penv, X509_USER_PROXY=str(uproxy))}


def test_tpc_pull_nginx_dest_from_nginx_gsi_source(gsi_nginx):
    out = Path(gsi_nginx["ddata"]) / "pulled.txt"
    r = _run([XRDCP, "-f", "--tpc", "only",
              f"root://{gsi_nginx['fqdn']}:{gsi_nginx['src_port']}//hello.txt",
              f"root://127.0.0.1:{gsi_nginx['dst_port']}//pulled.txt"],
             env=gsi_nginx["env"])
    if r.returncode != 0 or not out.exists():
        tail = ""
        for logdir, log in ((gsi_nginx["dst_logs"], "dst-err.log"),
                            (gsi_nginx["src_logs"], "src-err.log")):
            p = Path(logdir) / log
            if p.exists():
                tail += f"\n--- {log} ---\n" + "\n".join(
                    p.read_text(errors="replace").splitlines()[-15:])
        pytest.fail(f"TPC pull failed rc={r.returncode}: {r.stderr.strip()}{tail}")
    assert out.read_text() == "nginx-GSI-source native tpc pull\n"
