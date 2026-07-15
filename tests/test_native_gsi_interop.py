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

from config_templates import render_config

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
        "all.export /gsidata\n"
        f"oss.localroot {base}\n"
        "xrootd.seclib libXrdSec.so\n"
        f"sec.protocol /usr/lib64 gsi -certdir:{certs} "
        f"-cert:{srv / 'hostcert.pem'} -key:{srv / 'hostkey.pem'} "
        "-crl:0 -gmapopt:10 -dlgpxy:0\n"
        "sec.protbind * only gsi\n")
    shutil.move(str(data), str(base / "gsidata"))

    _free_port(PORT)
    proc = subprocess.Popen(["xrootd", "-c", str(cfg), "-l", str(base / "x.log"),
                             "-n", "gsitest"],
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

from settings import NGINX_BIN  # noqa: E402

NGINX_PORT = 21096
NGINX_SIGNED_PORT = 21097


def _spawn_nginx_gsi(gsi_server, port, signed_dh=None, tag="nginx_gsi"):
    """Start OUR nginx GSI server reusing the fixture's test PKI on `port`.

    signed_dh: None (omit the directive — default off/unsigned) or one of
    "off"/"auto"/"require" to exercise the phase-48 signed-DH server path.
    Returns (proc, url); the caller owns proc and must terminate it.  Skips
    (returning (None, None)) when the binary is missing or fails to bind."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not built at {NGINX_BIN}")
    base = gsi_server["base"]
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)  # nginx default pid dir
    cfg = os.path.join(base, f"{tag}.conf")
    sdh = f"    brix_gsi_signed_dh {signed_dh};\n" if signed_dh else ""
    with open(cfg, "w") as f:
        f.write(render_config("nginx_native_gsi_interop.conf",
                              BASE_DIR=base,
                              TAG=tag,
                              PORT=port,
                              DATA_DIR=gsi_server["data"],
                              SIGNED_DH_DIRECTIVE=sdh,
                              CERT_FILE=gsi_server["hostcert"],
                              KEY_FILE=gsi_server["hostkey"],
                              CA_DIR=gsi_server["ca"]))
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/tmp/rt_libshim:/usr/lib64:" + env.get("LD_LIBRARY_PATH", "")
    _free_port(port)
    proc = subprocess.Popen([NGINX_BIN, "-p", base, "-c", cfg],
                            env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    for _ in range(50):
        # Our master must be alive AND the port listening — a dead master with a
        # stale listener (different CA) would otherwise pass and corrupt the test.
        if proc.poll() is not None:
            pytest.skip("nginx GSI server exited (could not bind / config error)")
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return proc, f"root://{gsi_server['host']}:{port}"
        time.sleep(0.1)
    proc.terminate()
    pytest.skip("nginx GSI server did not come up")
    return None, None


@pytest.fixture(scope="module")
def nginx_gsi_server(gsi_server):
    """OUR nginx GSI server, default (unsigned-DH) policy."""
    proc, url = _spawn_nginx_gsi(gsi_server, NGINX_PORT)
    yield url
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def nginx_gsi_signed_server(gsi_server):
    """OUR nginx GSI server with `brix_gsi_signed_dh require` — the modern
    RSA-signed-DH path (phase-48).  Every client is forced onto the signed
    variant, so a successful auth proves the server's signed path interoperates."""
    proc, url = _spawn_nginx_gsi(gsi_server, NGINX_SIGNED_PORT,
                                 signed_dh="require", tag="nginx_gsi_signed")
    yield url
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


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
