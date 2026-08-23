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
from ephemeral_port import free_port

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-tpc")]

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
    _require_gsi_tools()
    base = tmp_path_factory.mktemp("tpcgsi")
    paths = _gsi_paths(base)
    fqdn = socket.getfqdn()
    _make_gsi_pki(base, paths, fqdn)
    penv = _make_gsi_proxies(paths)
    paths["srcdata"].joinpath("hello.txt").write_text("hello-tpc-gsi\n")
    src_port = free_port()
    config = _write_gsi_source_config(base, paths, src_port)
    src = _start_gsi_source(base, paths, config, src_port)
    dst = _start_gsi_destination(lifecycle, paths, src)
    ctx = {"fqdn": fqdn, "src_port": src_port, "dst_port": dst.port,
           "env": penv, "certs": str(paths["certs"]), "base": str(base),
           "dst_data": str(paths["dstdata"]),
           "logs": os.path.join(dst.prefix, "logs"),
           "src_url": f"root://127.0.0.1:{src_port}",
           "dst_url": f"root://127.0.0.1:{dst.port}"}
    yield ctx
    _stop_gsi_source(src)


def _require_gsi_tools():
    if not _have("xrootd", "openssl", "xrdgsiproxy"):
        pytest.skip("stock xrootd / openssl / xrdgsiproxy not installed")
    if not os.path.exists(XRDCP):
        pytest.skip("native xrdcp not built")


def _gsi_paths(base):
    names = ("ca", "server", "certs", "srcdata", "dstdata", "logs", "user")
    paths = {name: base / name for name in names}
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def _openssl(*args):
    result = _run(["openssl", *args])
    assert result.returncode == 0, f"openssl {args}: {result.stderr}"


def _make_gsi_pki(base, paths, fqdn):
    ca = paths["ca"]
    _openssl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-subj", "/O=XrdTpcTest/CN=XrdTpcTest CA",
             "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = _run(["openssl", "x509", "-in", str(ca / "ca.pem"),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca / "ca.pem", paths["certs"] / f"{chash}.0")
    _sign_gsi_cert(base, paths, fqdn, "server", "host")
    _sign_gsi_cert(base, paths, "tpc-dest", "server", "dest")
    _sign_gsi_cert(base, paths, "Test User", "user", "user")
    os.chmod(paths["server"] / "destkey.pem", 0o600)
    os.chmod(paths["user"] / "userkey.pem", 0o600)


def _sign_gsi_cert(base, paths, common_name, directory, stem):
    csr = base / (common_name.replace(" ", "") + ".csr")
    key = paths[directory] / f"{stem}key.pem"
    cert = paths[directory] / f"{stem}cert.pem"
    _openssl("req", "-nodes", "-newkey", "rsa:2048",
             "-subj", f"/O=XrdTpcTest/CN={common_name}", "-keyout", str(key),
             "-out", str(csr))
    ca = paths["ca"]
    _openssl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
             "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
             "-out", str(cert))


def _make_gsi_proxies(paths):
    proxy = paths["user"] / "proxy.pem"
    env = dict(os.environ, X509_CERT_DIR=str(paths["certs"]),
               X509_USER_PROXY=str(proxy))
    result = _mint_gsi_proxy(paths["user"], "user", proxy, paths["certs"], env)
    if not proxy.exists():
        pytest.skip(f"could not mint a test proxy: {result.stdout}{result.stderr}")
    destination = paths["server"] / "destproxy.pem"
    _mint_gsi_proxy(paths["server"], "dest", destination, paths["certs"], env)
    if not destination.exists():
        pytest.skip("could not mint the destination proxy")
    os.chmod(destination, 0o600)
    return env


def _mint_gsi_proxy(directory, stem, output, certs, env):
    return _run(["xrdgsiproxy", "init", "-cert", str(directory / f"{stem}cert.pem"),
                 "-key", str(directory / f"{stem}key.pem"), "-out", str(output),
                 "-certdir", str(certs), "-valid", "1:00"],
                input="\n\n", env=env)


def _write_gsi_source_config(base, paths, port):
    server = paths["server"]
    config = base / "xrootd.cfg"
    config.write_text(
        f"xrd.port {port}\nall.export /gsidata\noss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{paths['certs']} "
        f"-cert:{server / 'hostcert.pem'} -key:{server / 'hostkey.pem'} "
        "-crl:0 -gmapopt:10 -dlgpxy:0\nsec.protbind * only gsi\n"
        "ofs.tpc ttl 300 300 pgm /usr/bin/xrdcp\n"
        f"all.adminpath {base / 'admin'}\nall.pidpath {base / 'admin'}\n")
    shutil.move(str(paths["srcdata"]), str(base / "gsidata"))
    return config


def _start_gsi_source(base, paths, config, port):
    _free_port(port)
    argv = ["xrootd", "-c", str(config), "-l", str(paths["logs"] / "xrd.log"),
            "-n", "tpcgsisrc"]
    argv = _gsi_source_argv(base, paths, argv)
    source = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    if not _wait_listen(port):
        source.terminate()
        pytest.skip("stock xrootd GSI source did not come up")
    return source


def _gsi_source_argv(base, paths, argv):
    if os.geteuid() != 0:
        return argv
    runas = os.environ.get("REF_RUNAS_USER", "nobody")
    admin = base / "admin"
    admin.mkdir(parents=True, exist_ok=True)
    _run(["chmod", "a+rx", str(base)])
    _chmod_gsi_trees((base / "gsidata", paths["certs"]), "a+rX")
    _chmod_gsi_trees((admin, paths["logs"]), "a+rwX")
    _prepare_gsi_server_files(paths["server"], runas)
    _open_parent_chain(base.parent)
    _handoff_destination_proxy(paths["server"] / "destproxy.pem", runas)
    return argv + ["-R", runas]


def _chmod_gsi_trees(paths, mode):
    for path in paths:
        _run(["chmod", "-R", mode, str(path)])


def _prepare_gsi_server_files(server, runas):
    hostcert = server / "hostcert.pem"
    if hostcert.exists():
        _run(["chmod", "a+r", str(hostcert)])
        _run(["chmod", "a+rx", str(server)])
    hostkey = server / "hostkey.pem"
    if hostkey.exists():
        shutil.chown(hostkey, runas)
        os.chmod(hostkey, 0o400)


def _open_parent_chain(parent):
    while str(parent) not in ("/", ""):
        _run(["chmod", "a+rx", str(parent)])
        parent = parent.parent


def _handoff_destination_proxy(proxy, runas):
    if proxy.exists():
        shutil.chown(proxy, runas)
        os.chmod(proxy, 0o600)


def _start_gsi_destination(lifecycle, paths, source):
    server = paths["server"]
    try:
        return lifecycle.start(NginxInstanceSpec(
            name="lc-tpc-gsi-outbound-dest",
            template="nginx_tpc_gsi_outbound_dest.conf", protocol="root",
            readiness="tcp", data_root=str(paths["dstdata"]),
            template_values={"CERT_FILE": str(server / "destproxy.pem"),
                             "KEY_FILE": str(server / "destproxy.pem"),
                             "CA_DIR": str(paths["certs"])},
            reason="TPC outbound-GSI dest; auths to stock GSI source with its proxy."))
    except Exception:
        source.terminate()
        raise


def _stop_gsi_source(source):
    source.terminate()
    try:
        source.wait(timeout=5)
    except subprocess.TimeoutExpired:
        source.kill()


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
