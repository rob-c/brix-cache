"""Native-client GSI interop against a REAL XrdSecgsi server (phase-48).

WHY THIS EXISTS: the native GSI client (client/lib/sec/sec_gsi.c) was only ever
exercised against our own (equally non-standard) server, which hid that it does
not speak real XrdSecgsi — so `./client/xrdfs root://eoslhcb.cern.ch ...` fails
("unauthorized identity used") while stock xrdfs works.  This test pins the
client against a throwaway STOCK `xrootd` GSI server so the interop gap is caught
forever: the keystone assertion requires our client to authenticate via real GSI
once the XrdSecgsi port lands (docs/refactor/phase-48-*).

The fixture self-provisions a test CA + host cert + user proxy and a stock xrootd
configured for `sec.protbind * only gsi`.  It SKIPS cleanly when the stock tools
(`xrootd`, `xrdgsiproxy`, `openssl`, stock `xrdfs`) are not installed.
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

from settings import NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
STOCK_XRDFS = "/usr/bin/xrdfs"
PORT = 21094


def _have(*tools):
    return all(shutil.which(t) or os.path.exists(t) for t in tools)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=40, **kw)


def _free_port(port):
    """Kill any stale listener squatting `port`.

    These fixtures bind fixed ports (21094/21096); a leaked server from an
    earlier run (or a crashed teardown) would otherwise keep listening with a
    DIFFERENT throwaway CA, so our freshly-started server silently fails to bind
    and the client transparently talks to the stale one — surfacing as a bogus
    "certificate chain verification failed" rather than the real bind clash.
    Pre-clearing makes the interop assertions deterministic."""
    subprocess.run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"],
                   capture_output=True)
    for _ in range(20):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode != 0:
            return
        time.sleep(0.1)


@pytest.fixture(scope="module")
def gsi_server(tmp_path_factory):
    if not _have("xrootd", "xrdgsiproxy", "openssl", STOCK_XRDFS):
        pytest.skip("stock xrootd / xrdgsiproxy / openssl / xrdfs not installed")
    if not os.path.exists(NATIVE_XRDFS):
        pytest.skip("native client/xrdfs not built")

    base = tmp_path_factory.mktemp("gsi")
    ca, srv, usr, certs, data = (base / d for d in
                                 ("ca", "server", "user", "certs", "data"))
    for d in (ca, srv, usr, certs, data, data / "sub"):
        d.mkdir(parents=True, exist_ok=True)
    fqdn = socket.getfqdn()

    def osl(*a):
        assert _run(["openssl", *a]).returncode == 0, a

    # Test CA + hashed link, host cert (CN=fqdn), user EEC — all RSA, unencrypted.
    osl("req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-subj", "/O=XrdTest/CN=XrdTest CA",
        "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    chash = _run(["openssl", "x509", "-in", str(ca / "ca.pem"),
                  "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca / "ca.pem", certs / f"{chash}.0")

    def signed(cn, key, cert):
        csr = base / (cn.replace(" ", "") + ".csr")
        osl("req", "-nodes", "-newkey", "rsa:2048", "-subj", f"/O=XrdTest/CN={cn}",
            "-keyout", str(key), "-out", str(csr))
        osl("x509", "-req", "-in", str(csr), "-CA", str(ca / "ca.pem"),
            "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-days", "1",
            "-out", str(cert))

    signed(fqdn, srv / "hostkey.pem", srv / "hostcert.pem")
    signed("Test User", usr / "userkey.pem", usr / "usercert.pem")
    os.chmod(usr / "userkey.pem", 0o600)

    proxy = usr / "proxy.pem"
    env = dict(os.environ, X509_CERT_DIR=str(certs), X509_USER_PROXY=str(proxy))
    mk = _run(["xrdgsiproxy", "init", "-cert", str(usr / "usercert.pem"),
               "-key", str(usr / "userkey.pem"), "-out", str(proxy),
               "-certdir", str(certs), "-valid", "1:00"], input="\n\n", env=env)
    if not proxy.exists():
        pytest.skip(f"could not mint a test proxy: {mk.stdout}{mk.stderr}")

    (data / "hello.txt").write_text("hello-gsi\n")
    cfg = base / "xrootd.cfg"
    cfg.write_text(
        f"xrd.port {PORT}\n"
        f"all.adminpath {base / 'admin'}\n"
        f"all.pidpath {base / 'admin'}\n"
        "all.export /gsidata\n"
        f"oss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{certs} "
        f"-cert:{srv / 'hostcert.pem'} -key:{srv / 'hostkey.pem'} "
        "-crl:0 -gmapopt:10 -dlgpxy:0\n"
        "sec.protbind * only gsi\n")
    shutil.move(str(data), str(base / "gsidata"))

    _free_port(PORT)
    argv = ["xrootd", "-c", str(cfg), "-l", str(base / "x.log"), "-n", "gsitest"]
    # Stock xrootd refuses to run as superuser, so under the root test harness we
    # drop it to `nobody` via `-R` and pre-open ONLY the paths the dropped user
    # touches.  The user proxy dir (usr/) is deliberately left untouched: XrdSecgsi
    # refuses a group/world-writable proxy, and only the root client reads it.
    if os.geteuid() == 0:
        runas = os.environ.get("REF_RUNAS_USER", "nobody")
        (base / "admin").mkdir(parents=True, exist_ok=True)
        # `-n gsitest` makes xrootd create/write a <logdir>/gsitest instance dir.
        (base / "gsitest").mkdir(parents=True, exist_ok=True)
        _run(["chmod", "a+rx", str(base)])
        for d in (base / "gsidata", certs):
            _run(["chmod", "-R", "a+rX", str(d)])
        for d in (base / "admin", base / "gsitest"):
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
    proc = subprocess.Popen(argv,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Wait for the listener.
    up = False
    for _ in range(50):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{PORT}'"]).returncode == 0:
            up = True
            break
        time.sleep(0.1)
    if not up:
        proc.terminate()
        pytest.skip("stock xrootd GSI server did not come up")

    ctx = {"host": fqdn, "port": PORT, "env": env,
           "url": f"root://{fqdn}:{PORT}", "certs": str(certs),
           "ca": str(ca / "ca.pem"), "hostcert": str(srv / "hostcert.pem"),
           "hostkey": str(srv / "hostkey.pem"), "data": str(base / "gsidata"),
           "base": str(base)}
    yield ctx
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_stock_client_gsi_auth_succeeds(gsi_server):
    """Sanity: the fixture's GSI server authenticates the stock client (so a
    failure of the native test below is the native client, not the fixture)."""
    r = _run([STOCK_XRDFS, gsi_server["url"], "ls", "/gsidata"],
             env=gsi_server["env"])
    if r.returncode != 0:
        pytest.skip(f"stock xrdfs could not GSI-auth to the fixture: {r.stderr}")
    assert "/gsidata/hello.txt" in r.stdout


def test_native_client_gsi_auth_succeeds(gsi_server):
    """KEYSTONE: the native client authenticates to a real XrdSecgsi server
    (phase-48 — the port that makes `./client/xrdfs` work against stock EOS)."""
    r = _run([NATIVE_XRDFS, "--auth", "gsi", gsi_server["url"], "ls", "/gsidata"],
             env=gsi_server["env"])
    assert r.returncode == 0, f"native GSI auth failed: {r.stderr}"
    assert "/gsidata/hello.txt" in r.stdout


def test_native_gsi_failure_is_surfaced(gsi_server):
    """Forcing GSI with NO usable client credential must fail LOUDLY — the
    native client must not silently fall back to another protocol (which would
    assert a wrong identity) against this gsi-only server.  With no proxy it
    cannot present a credential, so the command must return non-zero."""
    env = dict(gsi_server["env"], X509_USER_PROXY="/nonexistent/proxy.pem")
    r = _run([NATIVE_XRDFS, "--auth", "gsi", gsi_server["url"], "ls", "/gsidata"],
             env=env)
    assert r.returncode != 0, "forced GSI with no proxy must not succeed"


# ---------------------------------------------------------------------------
# The reverse direction: a STOCK client authenticating to OUR nginx server.
# Proves official-tool compatibility of the server side (phase-48).
# ---------------------------------------------------------------------------

def _start_nginx_gsi(lifecycle, gsi_server, name, signed_dh=None):
    """Start OUR nginx GSI server on a throwaway lifecycle instance, reusing the
    fixture's test PKI.  Returns the client URL (root://fqdn:port — no trailing
    slash, matching the cert CN which is the fixture's fqdn).

    signed_dh: None (omit the directive — default off/unsigned) or one of
    "off"/"auto"/"require" to exercise the phase-48 signed-DH server path."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not built at {NGINX_BIN}")
    sdh = f"    brix_gsi_signed_dh {signed_dh};" if signed_dh else ""
    env = {"LD_LIBRARY_PATH": "/tmp/rt_libshim:/usr/lib64:"
           + os.environ.get("LD_LIBRARY_PATH", "")}
    ep = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_lc_native_gsi_interop.conf",
        protocol="root",
        env=env,
        template_values={
            "DATA_DIR": gsi_server["data"],
            "SIGNED_DH_DIRECTIVE": sdh,
            "CERT_FILE": gsi_server["hostcert"],
            "KEY_FILE": gsi_server["hostkey"],
            "CA_DIR": gsi_server["ca"],
        },
        reason="native/stock GSI interop against OUR nginx roots:// server"))
    return f"root://{gsi_server['host']}:{ep.port}"


@pytest.fixture()
def nginx_gsi_server(lifecycle, gsi_server):
    """OUR nginx GSI server, default (unsigned-DH) policy."""
    return _start_nginx_gsi(lifecycle, gsi_server, "lc-nginx-gsi")


@pytest.fixture()
def nginx_gsi_signed_server(lifecycle, gsi_server):
    """OUR nginx GSI server with `brix_gsi_signed_dh require` — the modern
    RSA-signed-DH path (phase-48).  Every client is forced onto the signed
    variant, so a successful auth proves the server's signed path interoperates."""
    return _start_nginx_gsi(lifecycle, gsi_server, "lc-nginx-gsi-signed",
                            signed_dh="require")


def test_stock_client_auths_to_our_server(gsi_server, nginx_gsi_server):
    """KEYSTONE (reverse): the official xrdfs authenticates to OUR nginx server
    over GSI and lists/reads — proving server-side official compatibility."""
    r = _run([STOCK_XRDFS, nginx_gsi_server, "ls", "/"], env=gsi_server["env"])
    assert r.returncode == 0, f"stock client → our server failed: {r.stderr}"
    assert "/hello.txt" in r.stdout


# ---------------------------------------------------------------------------
# Signed-DH (>=10400) server path: brix_gsi_signed_dh require forces every
# client onto the RSA-signed-DH variant (phase-48).  These prove the server's
# signed path interoperates with both the official client and our own.
# ---------------------------------------------------------------------------

def test_stock_client_signed_dh(gsi_server, nginx_gsi_signed_server):
    """KEYSTONE (signed server): official xrdfs completes the RSA-signed-DH
    handshake against OUR server (signed_dh=require) and lists the export."""
    r = _run([STOCK_XRDFS, nginx_gsi_signed_server, "ls", "/"],
             env=gsi_server["env"])
    assert r.returncode == 0, f"stock client → signed server failed: {r.stderr}"
    assert "/hello.txt" in r.stdout


def test_native_client_signed_dh(gsi_server, nginx_gsi_signed_server):
    """Our native client completes the signed-DH handshake against our signed
    server — the client signed path and the new server signed path agree."""
    r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_gsi_signed_server, "ls", "/"],
             env=gsi_server["env"])
    assert r.returncode == 0, f"native client → signed server failed: {r.stderr}"
    assert "/hello.txt" in r.stdout
