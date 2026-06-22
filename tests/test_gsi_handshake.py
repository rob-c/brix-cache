"""Comprehensive XrdSecgsi (x509-proxy) handshake tests — root:// and HTTPS.

Exercises every observable stage of the GSI handshake against BOTH the official
tools (stock ``xrdfs``/``xrdcp``, ``curl``) and our native client
(``client/bin/xrd{fs,cp}``), across both DH variants and both transports that
consume the x509 proxy credential:

  * ``root://``  — the XrdSecgsi stream handshake (protocol advertisement,
    certreq, server cert + DH agreement, proof-of-possession, proxy-chain
    verification, identity/DN extraction, the session cipher in BOTH data
    directions via read *and* write), for every ``xrootd_gsi_signed_dh`` policy
    (``off`` = unsigned DH, ``auto``/``require`` = RSA-signed DH ≥ 10400).
  * ``https://`` — WebDAV with x509 proxy client-cert auth
    (``xrootd_webdav_proxy_certs``): PROPFIND/GET/PUT with a proxy, and the
    matching rejections.

Negative coverage (the credential must be *refused*): a proxy from an untrusted
CA, an expired credential, no credential at all, and a client that does not
trust the server's host cert.

**S3 is intentionally out of scope.** S3 — both ours (``src/s3/``) and the
official ``XrdS3`` — authenticates with AWS SigV4 exclusively; GSI does not apply
to S3.  SigV4 coverage lives in ``test_s3_*.py``.

Self-contained: provisions its own trusted CA, an untrusted CA, a host cert, a
valid proxy, an untrusted proxy and (best-effort) an expired credential, then
spawns throwaway stock-xrootd and nginx servers on a private port band.  Skips
cleanly when the stock tools are not installed.
"""

import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from settings import NGINX_BIN  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
STOCK_XRDFS = "/usr/bin/xrdfs"
STOCK_XRDCP = "/usr/bin/xrdcp"

# Private port band (kept clear of the 11xxx fleet and the 2109x interop band).
P_STOCK_ROOT = 21130
P_ROOT = {"off": 21131, "auto": 21132, "require": 21133}
P_ROOT_NEG = 21134          # a dedicated "off" server for negative/identity tests
P_TLS = 21135               # GSI + in-protocol TLS upgrade
P_SIGVER = 21136            # GSI + kXR_sigver request signing (security_level)
P_RSA4096 = 21137           # GSI with RSA-4096 host + proxy keys
P_BOTH = 21138              # xrootd_auth both (ztn + gsi advertised)
P_VOMS = 21139              # GSI + VOMS VO ACL enforcement
P_WEBDAV = 21140


# --------------------------------------------------------------------------- #
# Small process / port helpers
# --------------------------------------------------------------------------- #
def _have(*tools):
    return all(shutil.which(t) or os.path.exists(t) for t in tools)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, **kw)


def _big(path, n_bytes, seed=b"GSI-handshake-payload-"):
    """Deterministic multi-block payload (exercises the session cipher over many
    AES-CBC blocks, not just one).  Returns the bytes written."""
    blob = (seed * (n_bytes // len(seed) + 1))[:n_bytes]
    with open(path, "wb") as f:
        f.write(blob)
    return blob


# --------------------------------------------------------------------------- #
# Raw XRootD/XrdSutBuffer wire helpers — drive the GSI handshake by hand so we
# can inspect the exact bytes of each stage (the &P=gsi advertisement and the
# kXGS_cert bucket structure) without any client library in the way.
# --------------------------------------------------------------------------- #
import socket as _sock          # noqa: E402
import struct as _st            # noqa: E402

kXR_protocol, kXR_login, kXR_auth = 3006, 3007, 3000
kXR_ok, kXR_authmore = 0, 4002
kXGC_certreq = 1000
kXRS_none, kXRS_cryptomod, kXRS_main = 0, 3000, 3001
kXRS_puk, kXRS_cipher, kXRS_rtag = 3004, 3005, 3006
kXRS_version, kXRS_x509, kXRS_cipher_alg, kXRS_md_alg = 3014, 3022, 3025, 3026


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise RuntimeError(f"connection closed ({len(buf)}/{n})")
        buf += c
    return buf


def _read_frame(s):
    hdr = _recv_exact(s, 8)
    status = _st.unpack(">H", hdr[2:4])[0]
    dlen = _st.unpack(">I", hdr[4:8])[0]
    return status, (_recv_exact(s, dlen) if dlen else b"")


def _wire_login(host, port):
    """Handshake + kXR_protocol + kXR_login; return (socket, login_body)."""
    s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
    s.settimeout(20)
    s.connect((host, port))
    s.sendall(_st.pack(">IIIII", 0, 0, 0, 4, 2012))      # handshake
    _recv_exact(s, 16)
    s.sendall(_st.pack(">BB H I BB 10x I", 0, 1, kXR_protocol, 0x00000520,
                       0x02, 0x03, 0))                    # kXR_protocol
    _read_frame(s)
    s.sendall(_st.pack(">BB H I 8s BB B B I", 0, 1, kXR_login, 0,
                       b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))   # kXR_login
    _status, body = _read_frame(s)
    return s, body


def _gsi_bucket(t, data):
    return _st.pack(">II", t, len(data)) + data


def _build_certreq(version):
    """A minimal-but-valid XrdSutBuffer certreq advertising `version`."""
    inner = (b"gsi\x00" + _st.pack(">I", kXGC_certreq)
             + _gsi_bucket(kXRS_rtag, b"RTAG5678")
             + _st.pack(">I", kXRS_none))
    return (b"gsi\x00" + _st.pack(">I", kXGC_certreq)
            + _gsi_bucket(kXRS_cryptomod, b"ssl")
            + _gsi_bucket(kXRS_version, _st.pack(">I", version))
            + _gsi_bucket(kXRS_main, inner)
            + _st.pack(">I", kXRS_none))


def _send_certreq(s, version):
    """Send kXR_auth(certreq) and return (status, parsed-bucket-dict)."""
    payload = _build_certreq(version)
    s.sendall(_st.pack(">BB H 12x 4s I", 0, 1, kXR_auth, b"gsi\x00",
                       len(payload)) + payload)
    status, body = _read_frame(s)
    buckets, i = {}, 8                     # skip "gsi\0" + step
    while i + 8 <= len(body):
        t, n = _st.unpack(">II", body[i:i + 8])
        i += 8
        if t == kXRS_none:
            break
        buckets[t] = body[i:i + n]
        i += n
    return status, buckets


def _free_port(port):
    """Kill any stale listener on ``port`` and wait until it is free, so a leaked
    server from a prior run can't masquerade for the one we are about to start."""
    subprocess.run(["bash", "-c", f"fuser -k {port}/tcp 2>/dev/null"],
                   capture_output=True)
    for _ in range(20):
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode != 0:
            return
        time.sleep(0.1)


def _wait_listen(proc, port, what):
    """Wait for ``port`` to listen.  A server that fails to come up is a hard
    failure (these tests are required to pass, never skip)."""
    for _ in range(60):
        assert proc.poll() is None, f"{what} exited before binding {port}"
        if _run(["bash", "-c", f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return True
        time.sleep(0.1)
    proc.terminate()
    raise AssertionError(f"{what} did not come up on {port}")


def _terminate(proc):
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# --------------------------------------------------------------------------- #
# PKI provisioning — trusted CA, untrusted CA, host cert, proxies
# --------------------------------------------------------------------------- #
def _osl(*a):
    r = _run(["openssl", *a])
    assert r.returncode == 0, f"openssl {a[0]} failed: {r.stderr}"


def _ca_hash_link(ca_pem, certs_dir):
    h = _run(["openssl", "x509", "-in", ca_pem, "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca_pem, os.path.join(certs_dir, f"{h}.0"))


def _make_ca(path, subj, bits=2048):
    key, pem = os.path.join(path, "ca.key"), os.path.join(path, "ca.pem")
    _osl("req", "-x509", "-nodes", "-newkey", f"rsa:{bits}", "-days", "2",
         "-subj", subj, "-keyout", key, "-out", pem)
    return key, pem


def _signed(ca_key, ca_pem, cn, key, cert, base, bits=2048):
    csr = os.path.join(base, os.path.basename(key) + ".csr")
    _osl("req", "-nodes", "-newkey", f"rsa:{bits}", "-subj", f"/O=XrdTest/CN={cn}",
         "-keyout", key, "-out", csr)
    _osl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
         "-CAcreateserial", "-days", "2", "-out", cert)


def _mint_proxy(eec_cert, eec_key, out, certs, env):
    _run(["xrdgsiproxy", "init", "-cert", eec_cert, "-key", eec_key,
          "-out", out, "-certdir", certs, "-valid", "1:00"],
         input="\n\n", env=env)
    return os.path.exists(out)


def _make_expired_eec(ca_key, ca_pem, cn, base):
    """Best-effort expired End-Entity cert via ``openssl ca`` with past dates;
    returns a combined cert+key PEM path usable as X509_USER_PROXY, or None."""
    cadb = os.path.join(base, "cadb")
    newc = os.path.join(cadb, "newcerts")
    os.makedirs(newc, exist_ok=True)
    open(os.path.join(cadb, "index.txt"), "w").close()
    with open(os.path.join(cadb, "serial"), "w") as f:
        f.write("01\n")
    cnf = os.path.join(base, "ca.cnf")
    with open(cnf, "w") as f:
        f.write(
            "[ca]\ndefault_ca=d\n[d]\n"
            f"database={cadb}/index.txt\nserial={cadb}/serial\n"
            f"new_certs_dir={newc}\ndefault_md=sha256\npolicy=pol\n"
            "[pol]\ncommonName=supplied\norganizationName=optional\n")
    key = os.path.join(base, "expired.key")
    csr = os.path.join(base, "expired.csr")
    cert = os.path.join(base, "expired.cert")
    if _run(["openssl", "req", "-nodes", "-newkey", "rsa:2048",
             "-subj", f"/O=XrdTest/CN={cn}", "-keyout", key,
             "-out", csr]).returncode != 0:
        return None
    r = _run(["openssl", "ca", "-batch", "-config", cnf, "-keyfile", ca_key,
              "-cert", ca_pem, "-in", csr, "-out", cert, "-notext",
              "-startdate", "20200101000000Z", "-enddate", "20200102000000Z"])
    if r.returncode != 0 or not os.path.exists(cert):
        return None
    combined = os.path.join(base, "expired_proxy.pem")
    with open(combined, "w") as o:
        o.write(open(cert).read())
        o.write(open(key).read())
    return combined


def _split_for_curl(proxy_pem, base, tag):
    """Split a grid-proxy PEM into a cert-chain file (all certs, proxy first) and
    a key file, as curl wants them separately."""
    text = open(proxy_pem).read()
    certs = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    key = re.search(
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----",
        text, re.S)
    if not certs or not key:
        return None, None
    cf = os.path.join(base, f"{tag}_cert.pem")
    kf = os.path.join(base, f"{tag}_key.pem")
    open(cf, "w").write("\n".join(certs) + "\n")
    open(kf, "w").write(key.group(0) + "\n")
    return cf, kf


def _voms_dn(pem, field):
    r = _run(["openssl", "x509", "-in", pem, "-noout", f"-{field}",
              "-nameopt", "compat"])
    return r.stdout.strip().split("=", 1)[1].strip()


def _make_voms_signing_cert(ca_key, ca_pem, base):
    """A VOMS signing cert (signed by the trusted CA) with a SubjectKeyIdentifier
    so voms-proxy-fake can embed an AKI in the attribute certificate."""
    key = os.path.join(base, "vomscert.key")
    cert = os.path.join(base, "vomscert.pem")
    csr = os.path.join(base, "voms.csr")
    ext = os.path.join(base, "voms_ext.conf")
    _osl("genrsa", "-out", key, "2048")
    _osl("req", "-new", "-key", key,
         "-subj", "/DC=test/DC=xrootd/CN=voms.test.local", "-out", csr)
    with open(ext, "w") as f:
        f.write("[voms_ext]\nsubjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always\n"
                "basicConstraints = CA:FALSE\n")
    _osl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
         "-CAcreateserial", "-out", cert, "-days", "2",
         "-extensions", "voms_ext", "-extfile", ext)
    return cert, key


def _make_vomsdir(vomsdir, voms_cert, vo):
    subject = _voms_dn(voms_cert, "subject")
    issuer = _voms_dn(voms_cert, "issuer")
    vo_dir = os.path.join(vomsdir, vo)
    os.makedirs(vo_dir, exist_ok=True)
    with open(os.path.join(vo_dir, "voms.test.local.lsc"), "w") as f:
        f.write(f"{subject}\n{issuer}\n")


def _make_voms_proxy(usercert, userkey, certs, voms_cert, voms_key, vo, fqan, out):
    return _run(["voms-proxy-fake", "-cert", usercert, "-key", userkey,
                 "-certdir", certs, "-hostcert", voms_cert, "-hostkey", voms_key,
                 "-voms", vo, "-fqan", fqan, "-uri", "voms.test.local:15000",
                 "-out", out, "-hours", "24"]).returncode == 0


@pytest.fixture(scope="module", autouse=True)
def _native_tools():
    """Guarantee the native client is present BEFORE any test runs (building it
    once if needed), so the native-client cases never skip — and never relink
    mid-run, which would briefly hide the binary from os.path.exists()."""
    if not (os.path.exists(NATIVE_XRDFS) and os.path.exists(NATIVE_XRDCP)):
        subprocess.run(["make", "-C", os.path.join(REPO, "client"),
                        "xrdfs", "xrdcp"], capture_output=True)
    yield


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """Trusted CA + untrusted CA + host cert + valid/untrusted/expired creds.

    Every prerequisite is a hard requirement: these tests must pass, not skip."""
    assert _have("openssl", "xrdgsiproxy"), \
        "openssl and xrdgsiproxy are required for the GSI handshake tests"
    base = str(tmp_path_factory.mktemp("gsihs"))
    certs = os.path.join(base, "certs")
    data = os.path.join(base, "data")
    for d in (certs, data, os.path.join(data, "sub")):
        os.makedirs(d, exist_ok=True)
    fqdn = socket.getfqdn()

    # Trusted CA (host + valid/expired creds chain to this; it is in certs/).
    ca_key, ca_pem = _make_ca(base, "/O=XrdTest/CN=XrdTest Trusted CA")
    _ca_hash_link(ca_pem, certs)

    # Untrusted CA — its proxy must be refused (NOT linked into certs/).
    unt = os.path.join(base, "unt")
    os.makedirs(unt, exist_ok=True)
    u_key, u_pem = _make_ca(unt, "/O=XrdEvil/CN=XrdEvil Untrusted CA")

    # Host cert (trusted), user EEC (trusted) + a valid proxy.
    srv = os.path.join(base, "server")
    usr = os.path.join(base, "user")
    for d in (srv, usr):
        os.makedirs(d, exist_ok=True)
    _signed(ca_key, ca_pem, fqdn, os.path.join(srv, "hostkey.pem"),
            os.path.join(srv, "hostcert.pem"), base)
    _signed(ca_key, ca_pem, "Test User", os.path.join(usr, "userkey.pem"),
            os.path.join(usr, "usercert.pem"), base)
    os.chmod(os.path.join(usr, "userkey.pem"), 0o600)

    env = dict(os.environ, X509_CERT_DIR=certs,
               X509_USER_PROXY=os.path.join(usr, "proxy.pem"))
    assert _mint_proxy(os.path.join(usr, "usercert.pem"),
                       os.path.join(usr, "userkey.pem"),
                       os.path.join(usr, "proxy.pem"), certs, env), \
        "could not mint a valid test proxy"

    # Untrusted proxy: user EEC signed by the untrusted CA, minted to a proxy.
    _signed(u_key, u_pem, "Evil User", os.path.join(unt, "ekey.pem"),
            os.path.join(unt, "ecert.pem"), base)
    os.chmod(os.path.join(unt, "ekey.pem"), 0o600)
    ucerts = os.path.join(base, "ucerts")          # only the untrusted CA here
    os.makedirs(ucerts, exist_ok=True)
    _ca_hash_link(u_pem, ucerts)
    uenv = dict(os.environ, X509_CERT_DIR=ucerts,
                X509_USER_PROXY=os.path.join(unt, "eproxy.pem"))
    untrusted_proxy = (os.path.join(unt, "eproxy.pem")
                       if _mint_proxy(os.path.join(unt, "ecert.pem"),
                                      os.path.join(unt, "ekey.pem"),
                                      os.path.join(unt, "eproxy.pem"),
                                      ucerts, uenv) else None)

    expired_proxy = _make_expired_eec(ca_key, ca_pem, "Test User", base)

    # Required for the negative tests — these must exist, not be skipped over.
    assert untrusted_proxy, "could not mint the untrusted-CA proxy"
    assert expired_proxy, "could not build the expired credential (openssl ca)"

    with open(os.path.join(data, "hello.txt"), "w") as f:
        f.write("hello-gsi-handshake\n")

    yield {
        "fqdn": fqdn, "base": base, "certs": certs, "data": data,
        "ca": ca_pem, "ca_key": ca_key,
        "hostcert": os.path.join(srv, "hostcert.pem"),
        "hostkey": os.path.join(srv, "hostkey.pem"),
        "usercert": os.path.join(usr, "usercert.pem"),
        "userkey": os.path.join(usr, "userkey.pem"),
        "valid_proxy": os.path.join(usr, "proxy.pem"),
        "untrusted_proxy": untrusted_proxy, "expired_proxy": expired_proxy,
        "env": env,
    }


def _env_with(pki, proxy):
    return dict(os.environ, X509_CERT_DIR=pki["certs"], X509_USER_PROXY=proxy)


# --------------------------------------------------------------------------- #
# Server launchers
# --------------------------------------------------------------------------- #
def _nginx_root_conf(pki, port, policy, logpath):
    sdh = f"    xrootd_gsi_signed_dh {policy};\n" if policy != "off" else ""
    return (
        "daemon off;\n"
        f"error_log {logpath} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {port};\n"
        "    xrootd on;\n"
        f"    xrootd_root {pki['data']};\n"
        "    xrootd_auth gsi;\n"
        "    xrootd_allow_write on;\n"
        + sdh +
        f"    xrootd_certificate     {pki['hostcert']};\n"
        f"    xrootd_certificate_key {pki['hostkey']};\n"
        f"    xrootd_trusted_ca      {pki['ca']};\n"
        "  }\n}\n")


def _spawn_nginx(conf_text, base, port, tag):
    assert os.path.exists(NGINX_BIN), f"nginx binary not built at {NGINX_BIN}"
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)
    cfg = os.path.join(base, f"{tag}.conf")
    with open(cfg, "w") as f:
        f.write(conf_text)
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = "/tmp/rt_libshim:/usr/lib64:" + env.get(
        "LD_LIBRARY_PATH", "")
    _free_port(port)
    proc = subprocess.Popen([NGINX_BIN, "-p", base, "-c", cfg], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_listen(proc, port, f"nginx {tag}")
    return proc


@pytest.fixture(scope="module", params=["off", "auto", "require"])
def nginx_root(pki, request):
    """Our nginx GSI root:// server, one per signed-DH policy."""
    policy = request.param
    port = P_ROOT[policy]
    log = os.path.join(pki["base"], "logs", f"root_{policy}.log")
    proc = _spawn_nginx(_nginx_root_conf(pki, port, policy, log),
                        pki["base"], port, f"root_{policy}")
    yield {"url": f"root://{pki['fqdn']}:{port}", "policy": policy, "log": log}
    _terminate(proc)


@pytest.fixture(scope="module")
def nginx_root_off(pki):
    """A dedicated default (unsigned) server for negative + identity tests."""
    log = os.path.join(pki["base"], "logs", "root_neg.log")
    proc = _spawn_nginx(_nginx_root_conf(pki, P_ROOT_NEG, "off", log),
                        pki["base"], P_ROOT_NEG, "root_neg")
    yield {"url": f"root://{pki['fqdn']}:{P_ROOT_NEG}", "log": log}
    _terminate(proc)


@pytest.fixture(scope="module")
def nginx_root_both(pki):
    """A server advertising BOTH token and GSI (`xrootd_auth both`).  The GSI
    client must still pick gsi from the multi-protocol `&P=ztn…&P=gsi…` block and
    authenticate."""
    log = os.path.join(pki["base"], "logs", "root_both.log")
    jwks = os.path.join(pki["base"], "jwks.json")
    with open(jwks, "w") as f:           # token side is unused by the GSI client
        f.write('{"keys":[]}')
    conf = (
        "daemon off;\n"
        f"error_log {log} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {P_BOTH};\n"
        "    xrootd on;\n"
        f"    xrootd_root {pki['data']};\n"
        "    xrootd_auth both;\n"
        "    xrootd_allow_write on;\n"
        f"    xrootd_token_jwks     {jwks};\n"
        '    xrootd_token_issuer   "https://test.example.com";\n'
        '    xrootd_token_audience "nginx-xrootd";\n'
        f"    xrootd_certificate     {pki['hostcert']};\n"
        f"    xrootd_certificate_key {pki['hostkey']};\n"
        f"    xrootd_trusted_ca      {pki['ca']};\n"
        "  }\n}\n")
    proc = _spawn_nginx(conf, pki["base"], P_BOTH, "root_both")
    yield {"url": f"root://{pki['fqdn']}:{P_BOTH}", "log": log}
    _terminate(proc)


@pytest.fixture(scope="module")
def voms(pki):
    """A VOMS signing cert + vomsdir (LSC) + a fake VOMS proxy carrying the
    `testvo` VO — so the server can verify and extract the VO attribute."""
    assert shutil.which("voms-proxy-fake"), \
        "voms-proxy-fake is required for the VOMS tests"
    base = os.path.join(pki["base"], "voms")
    vomsdir = os.path.join(base, "vomsdir")
    os.makedirs(vomsdir, exist_ok=True)
    vcert, vkey = _make_voms_signing_cert(pki["ca_key"], pki["ca"], base)
    _make_vomsdir(vomsdir, vcert, "testvo")
    proxy = os.path.join(base, "voms_proxy.pem")
    assert _make_voms_proxy(pki["usercert"], pki["userkey"], pki["certs"],
                            vcert, vkey, "testvo",
                            "/testvo/Role=NULL/Capability=NULL", proxy), \
        "could not mint the fake VOMS proxy"
    yield {"vomsdir": vomsdir, "proxy": proxy,
           "env": _env_with(pki, proxy)}


@pytest.fixture(scope="module")
def nginx_voms(pki, voms):
    """A GSI server requiring the `testvo` VO under /vodata — exercises VOMS
    attribute extraction (a proxy carrying the VO is admitted; a plain proxy is
    refused)."""
    vdata = os.path.join(pki["base"], "vodata_root")
    os.makedirs(os.path.join(vdata, "vodata"), exist_ok=True)
    with open(os.path.join(vdata, "vodata", "secret.txt"), "w") as f:
        f.write("vo-only\n")
    with open(os.path.join(vdata, "open.txt"), "w") as f:
        f.write("open\n")
    log = os.path.join(pki["base"], "logs", "voms.log")
    conf = (
        "daemon off;\n"
        f"error_log {log} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {P_VOMS};\n"
        "    xrootd on;\n"
        f"    xrootd_root {vdata};\n"
        "    xrootd_auth gsi;\n"
        f"    xrootd_vomsdir       {voms['vomsdir']};\n"
        f"    xrootd_voms_cert_dir {pki['certs']};\n"
        "    xrootd_require_vo /vodata testvo;\n"
        f"    xrootd_certificate     {pki['hostcert']};\n"
        f"    xrootd_certificate_key {pki['hostkey']};\n"
        f"    xrootd_trusted_ca      {pki['ca']};\n"
        "  }\n}\n")
    proc = _spawn_nginx(conf, pki["base"], P_VOMS, "voms")
    yield {"url": f"root://{pki['fqdn']}:{P_VOMS}"}
    _terminate(proc)


@pytest.fixture(scope="module")
def nginx_root_tls(pki):
    """GSI server that also advertises in-protocol TLS (kXR_ableTLS): the client
    authenticates with GSI, then upgrades the channel to TLS."""
    log = os.path.join(pki["base"], "logs", "root_tls.log")
    conf = (
        "daemon off;\n"
        f"error_log {log} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {P_TLS};\n"
        "    xrootd on;\n"
        f"    xrootd_root {pki['data']};\n"
        "    xrootd_auth gsi;\n"
        "    xrootd_allow_write on;\n"
        "    xrootd_tls on;\n"
        f"    xrootd_certificate     {pki['hostcert']};\n"
        f"    xrootd_certificate_key {pki['hostkey']};\n"
        f"    xrootd_trusted_ca      {pki['ca']};\n"
        "  }\n}\n")
    proc = _spawn_nginx(conf, pki["base"], P_TLS, "root_tls")
    # roots:// forces the TLS upgrade after the GSI login.
    yield {"url": f"roots://{pki['fqdn']}:{P_TLS}", "log": log}
    _terminate(proc)


@pytest.fixture(scope="module")
def nginx_root_sigver(pki):
    """GSI server at security level `intense` — most opcodes must carry a valid
    kXR_sigver signature derived from the GSI session key.  A client that signs
    correctly (stock xrdfs) proceeds; this exercises the request-signing half of
    the handshake (signing_key = SHA-256(DH secret))."""
    log = os.path.join(pki["base"], "logs", "root_sigver.log")
    conf = (
        "daemon off;\n"
        f"error_log {log} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {P_SIGVER};\n"
        "    xrootd on;\n"
        f"    xrootd_root {pki['data']};\n"
        "    xrootd_auth gsi;\n"
        "    xrootd_allow_write on;\n"
        "    xrootd_security_level intense;\n"
        f"    xrootd_certificate     {pki['hostcert']};\n"
        f"    xrootd_certificate_key {pki['hostkey']};\n"
        f"    xrootd_trusted_ca      {pki['ca']};\n"
        "  }\n}\n")
    proc = _spawn_nginx(conf, pki["base"], P_SIGVER, "root_sigver")
    yield {"url": f"root://{pki['fqdn']}:{P_SIGVER}", "log": log}
    _terminate(proc)


@pytest.fixture(scope="module")
def rsa4096(pki):
    """A parallel RSA-4096 PKI (CA + host + user proxy) so the handshake's RSA
    sign/recover (chunked by key-size) is exercised at a larger modulus."""
    base = os.path.join(pki["base"], "rsa4096")
    certs = os.path.join(base, "certs")
    usr = os.path.join(base, "user")
    srv = os.path.join(base, "server")
    for d in (certs, usr, srv):
        os.makedirs(d, exist_ok=True)
    ck, cp = _make_ca(base, "/O=XrdTest/CN=XrdTest 4096 CA", bits=4096)
    _ca_hash_link(cp, certs)
    _signed(ck, cp, pki["fqdn"], os.path.join(srv, "hostkey.pem"),
            os.path.join(srv, "hostcert.pem"), base, bits=4096)
    _signed(ck, cp, "Test User 4096", os.path.join(usr, "userkey.pem"),
            os.path.join(usr, "usercert.pem"), base, bits=4096)
    os.chmod(os.path.join(usr, "userkey.pem"), 0o600)
    env = dict(os.environ, X509_CERT_DIR=certs,
               X509_USER_PROXY=os.path.join(usr, "proxy.pem"))
    assert _mint_proxy(os.path.join(usr, "usercert.pem"),
                       os.path.join(usr, "userkey.pem"),
                       os.path.join(usr, "proxy.pem"), certs, env), \
        "could not mint the RSA-4096 proxy"
    yield {"certs": certs, "ca": cp, "env": env,
           "hostcert": os.path.join(srv, "hostcert.pem"),
           "hostkey": os.path.join(srv, "hostkey.pem")}


@pytest.fixture(scope="module")
def nginx_rsa4096(pki, rsa4096):
    """A signed-DH GSI server on the RSA-4096 PKI — round 1 signs the DH public
    with the 4096-bit host key, round 2 recovers the 4096-bit-proxy-signed
    client public, so both RSA directions run at the larger size."""
    log = os.path.join(pki["base"], "logs", "rsa4096_srv.log")
    conf = (
        "daemon off;\n"
        f"error_log {log} info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {P_RSA4096};\n"
        "    xrootd on;\n"
        f"    xrootd_root {pki['data']};\n"
        "    xrootd_auth gsi;\n"
        "    xrootd_allow_write on;\n"
        "    xrootd_gsi_signed_dh require;\n"
        f"    xrootd_certificate     {rsa4096['hostcert']};\n"
        f"    xrootd_certificate_key {rsa4096['hostkey']};\n"
        f"    xrootd_trusted_ca      {rsa4096['ca']};\n"
        "  }\n}\n")
    proc = _spawn_nginx(conf, pki["base"], P_RSA4096, "rsa4096")
    yield {"url": f"root://{pki['fqdn']}:{P_RSA4096}", "env": rsa4096["env"]}
    _terminate(proc)


@pytest.fixture(scope="module")
def stock_root(pki):
    """A throwaway stock xrootd GSI server (for native-client interop)."""
    assert _have("xrootd", STOCK_XRDFS), \
        "stock xrootd / xrdfs are required for the GSI interop tests"
    base = pki["base"]
    gsidata = os.path.join(base, "gsidata")
    if not os.path.isdir(gsidata):
        shutil.copytree(pki["data"], gsidata)
    cfg = os.path.join(base, "stock.cfg")
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {P_STOCK_ROOT}\n"
            "all.export /gsidata\n"
            f"oss.localroot {base}\n"
            "xrootd.seclib libXrdSec.so\n"
            f"sec.protocol /usr/lib64 gsi -certdir:{pki['certs']} "
            f"-cert:{pki['hostcert']} -key:{pki['hostkey']} "
            "-crl:0 -gmapopt:10 -dlgpxy:0\n"
            "sec.protbind * only gsi\n")
    _free_port(P_STOCK_ROOT)
    proc = subprocess.Popen(["xrootd", "-c", cfg, "-l",
                             os.path.join(base, "stock.log"), "-n", "gsihs"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _wait_listen(proc, P_STOCK_ROOT, "stock xrootd")
    yield {"url": f"root://{pki['fqdn']}:{P_STOCK_ROOT}"}
    _terminate(proc)


@pytest.fixture(scope="module")
def nginx_webdav(pki):
    """HTTPS WebDAV server requiring x509 proxy client-cert auth."""
    base = pki["base"]
    wdata = os.path.join(base, "wdata")
    os.makedirs(wdata, exist_ok=True)
    with open(os.path.join(wdata, "hello.txt"), "w") as f:
        f.write("hello-webdav-gsi\n")
    log = os.path.join(base, "logs", "webdav.log")
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)
    conf = (
        "daemon off;\n"
        f"error_log {log} info;\n"
        "events { worker_connections 64; }\n"
        "http {\n  server {\n"
        f"    listen {P_WEBDAV} ssl;\n"
        f"    ssl_certificate     {pki['hostcert']};\n"
        f"    ssl_certificate_key {pki['hostkey']};\n"
        "    ssl_verify_client   optional_no_ca;\n"
        "    ssl_verify_depth    10;\n"
        "    xrootd_webdav_proxy_certs on;\n"
        "    client_max_body_size 64m;\n"
        "    location / {\n"
        f"      root               {wdata};\n"
        "      xrootd_webdav      on;\n"
        f"      xrootd_webdav_root {wdata};\n"
        f"      xrootd_webdav_cadir {pki['certs']};\n"
        "      xrootd_webdav_auth required;\n"
        "      xrootd_webdav_allow_write on;\n"
        "    }\n  }\n}\n")
    proc = _spawn_nginx(conf, base, P_WEBDAV, "webdav")
    yield {"url": f"https://{pki['fqdn']}:{P_WEBDAV}", "data": wdata, "log": log}
    _terminate(proc)


# --------------------------------------------------------------------------- #
# root:// — the handshake end-to-end, every policy, both clients
#
# Each op below drives the full handshake (advertisement → certreq → server
# cert + DH agreement → encrypted proxy chain → CA verification) and then a real
# operation.  read exercises the session cipher server→client; write exercises
# it client→server, so the pair proves both directions of the agreed AES key.
# --------------------------------------------------------------------------- #
class TestRootStockClient:
    def test_ls(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_stat(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "stat", "/hello.txt"],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "Size" in r.stdout or "size" in r.stdout.lower()

    def test_read(self, pki, nginx_root, tmp_path):
        out = str(tmp_path / f"dl_{nginx_root['policy']}")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_write_then_read(self, pki, nginx_root, tmp_path):
        src = str(tmp_path / "up.txt")
        payload = f"signed={nginx_root['policy']}-roundtrip\n" * 8
        open(src, "w").write(payload)
        key = f"/up_stock_{nginx_root['policy']}.txt"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "back.txt")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"download {nginx_root['policy']}: {dl.stderr}"
        assert open(back).read() == payload

    def test_large_write_then_read(self, pki, nginx_root, tmp_path):
        # 5 MiB: the session cipher must hold over thousands of AES-CBC blocks
        # in BOTH directions, not just the tiny single-block proxy-chain main.
        src = str(tmp_path / "big.bin")
        blob = _big(src, 5 * 1024 * 1024)
        key = f"/big_stock_{nginx_root['policy']}.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"big upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "bigback.bin")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"big download: {dl.stderr}"
        assert open(back, "rb").read() == blob

    def test_mkdir_stat_rmdir(self, pki, nginx_root):
        d = f"/dir_stock_{nginx_root['policy']}"
        u = pki["env"]
        assert _run([STOCK_XRDFS, nginx_root["url"], "mkdir", d],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", d],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "rmdir", d],
                    env=u).returncode == 0
        # gone now
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", d],
                    env=u).returncode != 0

    def test_mv_then_rm(self, pki, nginx_root, tmp_path):
        src = str(tmp_path / "mv.txt")
        open(src, "w").write("mv-payload\n")
        a = f"/mv_a_{nginx_root['policy']}.txt"
        b = f"/mv_b_{nginx_root['policy']}.txt"
        u = pki["env"]
        assert _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{a}"],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "mv", a, b],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", b],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", a],
                    env=u).returncode != 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "rm", b],
                    env=u).returncode == 0

    def test_query_checksum(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "query", "checksum",
                  "/hello.txt"], env=pki["env"])
        assert r.returncode == 0, f"query checksum: {r.stderr}"
        # the response is "<algo> <hexdigest>"
        assert len(r.stdout.split()) >= 2, f"unexpected checksum reply: {r.stdout!r}"


class TestRootNativeClient:
    def _skip_if_unbuilt(self):
        assert os.path.exists(NATIVE_XRDFS) and os.path.exists(NATIVE_XRDCP), \
            "native client/bin/xrd{fs,cp} must be built (make -C client)"

    def test_ls(self, pki, nginx_root):
        self._skip_if_unbuilt()
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"], "ls", "/"],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        out = str(tmp_path / f"ndl_{nginx_root['policy']}")
        r = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                  f"{nginx_root['url']}//hello.txt", out], env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_write_then_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        src = str(tmp_path / "nup.txt")
        payload = f"native={nginx_root['policy']}-roundtrip\n" * 8
        open(src, "w").write(payload)
        key = f"/up_native_{nginx_root['policy']}.txt"
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{nginx_root['url']}/{key}"], env=pki["env"])
        assert up.returncode == 0, f"upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "nback.txt")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{nginx_root['url']}/{key}", back], env=pki["env"])
        assert dl.returncode == 0, f"download {nginx_root['policy']}: {dl.stderr}"
        assert open(back).read() == payload

    def test_large_write_then_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        src = str(tmp_path / "nbig.bin")
        blob = _big(src, 5 * 1024 * 1024)
        key = f"/nbig_{nginx_root['policy']}.bin"
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{nginx_root['url']}/{key}"], env=pki["env"])
        assert up.returncode == 0, f"native big upload: {up.stderr}"
        back = str(tmp_path / "nbigback.bin")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{nginx_root['url']}/{key}", back], env=pki["env"])
        assert dl.returncode == 0, f"native big download: {dl.stderr}"
        assert open(back, "rb").read() == blob

    def test_mkdir_rmdir(self, pki, nginx_root):
        self._skip_if_unbuilt()
        d = f"/ndir_{nginx_root['policy']}"
        u = pki["env"]
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "mkdir", d], env=u).returncode == 0
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "stat", d], env=u).returncode == 0
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "rmdir", d], env=u).returncode == 0


# --------------------------------------------------------------------------- #
# root:// — GSI authentication followed by an in-protocol TLS upgrade (roots://)
# --------------------------------------------------------------------------- #
class TestRootGsiTls:
    def test_stock_read_over_tls(self, pki, nginx_root_tls, tmp_path):
        out = str(tmp_path / "tls.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_tls['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode == 0, f"GSI+TLS read: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_stock_write_then_read_over_tls(self, pki, nginx_root_tls, tmp_path):
        src = str(tmp_path / "tlsup.bin")
        blob = _big(src, 2 * 1024 * 1024)
        key = "/tls_rt.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_tls['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"GSI+TLS upload: {up.stderr}"
        back = str(tmp_path / "tlsback.bin")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root_tls['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"GSI+TLS download: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — concurrent GSI handshakes (the ephemeral-DH keypool under load)
# --------------------------------------------------------------------------- #
class TestRootConcurrency:
    def test_many_concurrent_signed_handshakes(self, pki, nginx_root):
        # Fire N independent stat handshakes at once; the per-worker DH keypool
        # must answer every certreq without head-of-line blocking, for signed and
        # unsigned alike.
        import concurrent.futures as cf

        def one(_):
            return _run([STOCK_XRDFS, nginx_root["url"], "stat", "/hello.txt"],
                        env=pki["env"]).returncode

        with cf.ThreadPoolExecutor(max_workers=12) as ex:
            rcs = list(ex.map(one, range(12)))
        assert all(rc == 0 for rc in rcs), \
            f"{nginx_root['policy']}: concurrent handshakes failed: {rcs}"


# --------------------------------------------------------------------------- #
# root:// — protocol-version advertisement (the signed-vs-unsigned switch)
# --------------------------------------------------------------------------- #
class TestVersionAdvertisement:
    # off → unsigned v:10000; auto/require → signed-capable v:10600.
    EXPECT = {"off": "v:10000", "auto": "v:10600", "require": "v:10600"}

    def test_advertised_version_matches_policy(self, pki, nginx_root):
        env = dict(pki["env"], XrdSecDEBUG="3")
        r = _run([STOCK_XRDFS, nginx_root["url"], "ls", "/"], env=env)
        m = re.search(r"token='([^']*P=gsi[^']*)'", r.stdout + r.stderr)
        assert m, ("could not capture the advertised &P=gsi token from the "
                   f"stock client debug output:\n{(r.stdout + r.stderr)[:400]}")
        want = self.EXPECT[nginx_root["policy"]]
        assert want in m.group(1), \
            f"policy {nginx_root['policy']}: expected {want}, got {m.group(1)!r}"


# --------------------------------------------------------------------------- #
# root:// — identity (DN) extraction from the verified proxy chain
# --------------------------------------------------------------------------- #
class TestIdentityExtraction:
    def test_dn_logged(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, r.stderr
        time.sleep(0.2)
        log = open(nginx_root_off["log"]).read() if os.path.exists(
            nginx_root_off["log"]) else ""
        assert "GSI auth OK" in log, "server did not log a GSI auth"
        # The log sanitizer escapes the space in "Test User" → "Test\x20User",
        # so match the stable, unescaped CN prefix instead.
        assert "CN=Test" in log, f"expected the proxy DN in the log:\n{log[-800:]}"


# --------------------------------------------------------------------------- #
# root:// — negative paths: the credential must be REFUSED
# --------------------------------------------------------------------------- #
class TestRootNegative:
    def test_no_proxy_rejected(self, pki, nginx_root_off):
        env = dict(os.environ, X509_CERT_DIR=pki["certs"],
                   X509_USER_PROXY="/nonexistent/proxy.pem")
        env.pop("BEARER_TOKEN", None)
        r = _run([STOCK_XRDFS, "--noasync", nginx_root_off["url"], "ls", "/"],
                 env=env)
        assert r.returncode != 0, "auth without a proxy must fail"

    def test_untrusted_ca_proxy_rejected(self, pki, nginx_root_off):
        assert pki["untrusted_proxy"], "untrusted proxy not provisioned"
        # Present the untrusted proxy but keep the trusted certdir so the client
        # offers gsi; the server must reject the chain (unknown CA).
        env = dict(os.environ, X509_CERT_DIR=pki["certs"],
                   X509_USER_PROXY=pki["untrusted_proxy"])
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=env)
        assert r.returncode != 0, "a proxy from an untrusted CA must be refused"

    def test_expired_proxy_rejected(self, pki, nginx_root_off):
        assert pki["expired_proxy"], "expired credential not provisioned"
        env = _env_with(pki, pki["expired_proxy"])
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=env)
        assert r.returncode != 0, "an expired credential must be refused"

    def test_wrong_server_ca_rejected(self, pki, nginx_root_off):
        # Client trusts only the untrusted CA → must reject the server host cert.
        env = dict(os.environ, X509_CERT_DIR=os.path.join(pki["base"], "ucerts"),
                   X509_USER_PROXY=pki["valid_proxy"])
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=env)
        assert r.returncode != 0, "client must reject an untrusted server cert"


# --------------------------------------------------------------------------- #
# Native client ↔ real stock xrootd server (the reverse keystone, with ops)
# --------------------------------------------------------------------------- #
class TestNativeAgainstStock:
    def _skip(self):
        assert os.path.exists(NATIVE_XRDFS) and os.path.exists(NATIVE_XRDCP), \
            "native client/bin/xrd{fs,cp} must be built (make -C client)"

    def test_native_ls_stock(self, pki, stock_root):
        self._skip()
        r = _run([NATIVE_XRDFS, "--auth", "gsi", stock_root["url"],
                  "ls", "/gsidata"], env=pki["env"])
        assert r.returncode == 0, f"native→stock ls: {r.stderr}"
        assert "/gsidata/hello.txt" in r.stdout

    def test_native_read_stock(self, pki, stock_root, tmp_path):
        self._skip()
        out = str(tmp_path / "ns.txt")
        r = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                  f"{stock_root['url']}//gsidata/hello.txt", out], env=pki["env"])
        assert r.returncode == 0, f"native→stock read: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_native_write_stock(self, pki, stock_root, tmp_path):
        self._skip()
        src = str(tmp_path / "nw.bin")
        blob = _big(src, 2 * 1024 * 1024)
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{stock_root['url']}//gsidata/nw.bin"], env=pki["env"])
        assert up.returncode == 0, f"native→stock write: {up.stderr}"
        back = str(tmp_path / "nwback.bin")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{stock_root['url']}//gsidata/nw.bin", back], env=pki["env"])
        assert dl.returncode == 0, f"native→stock readback: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# https:// WebDAV — the SAME x509 proxy credential over TLS client-cert auth
# --------------------------------------------------------------------------- #
def _rejected(http_code):
    """A WebDAV auth rejection is any non-2xx outcome — the request was refused
    by the TLS/cert layer (400), the access phase (401/403), or curl failed the
    handshake outright (000).  The only failure that matters is being *served*."""
    code = (http_code or "").strip()
    return bool(code) and not code.startswith("2")


def _curl(pki, webdav, proxy, *args, method=None, upload=None):
    cf, kf = _split_for_curl(proxy, pki["base"], "wc") if proxy else (None, None)
    cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}"]
    if cf and kf:
        cmd += ["--cert", cf, "--key", kf]
    if method:
        cmd += ["-X", method]
    if upload:
        cmd += ["-T", upload]
    cmd += list(args)
    return _run(cmd)


class TestHttpsProxyCert:
    def test_propfind_with_proxy(self, pki, nginx_webdav):
        r = _curl(pki, nginx_webdav, pki["valid_proxy"], nginx_webdav["url"] + "/",
                  method="PROPFIND")
        assert r.stdout.strip() in ("200", "207"), f"PROPFIND → {r.stdout}"

    def test_get_with_proxy(self, pki, nginx_webdav, tmp_path):
        out = str(tmp_path / "wget.txt")
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wg")
        assert cf, "could not split the proxy into cert/key for curl"
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
                  nginx_webdav["url"] + "/hello.txt"])
        assert r.returncode == 0 and open(out).read() == "hello-webdav-gsi\n", \
            f"GET body mismatch: {open(out).read()!r}"

    def test_put_then_get_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wp")
        assert cf, "could not split the proxy into cert/key for curl"
        src = str(tmp_path / "wput.txt")
        payload = "webdav-proxy-roundtrip\n" * 4
        open(src, "w").write(payload)
        put = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", "-T", src,
                    nginx_webdav["url"] + "/put.txt"])
        assert put.stdout.strip() in ("200", "201", "204"), f"PUT → {put.stdout}"
        out = str(tmp_path / "wback.txt")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
              nginx_webdav["url"] + "/put.txt"])
        assert open(out).read() == payload

    def test_head_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wh")
        r = _run(["curl", "-sk", "-I", "--cert", cf, "--key", kf, "-o",
                  "/dev/null", "-w", "%{http_code}",
                  nginx_webdav["url"] + "/hello.txt"])
        assert r.stdout.strip() == "200", f"HEAD → {r.stdout}"

    def test_propfind_depth1_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wd1")
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-X", "PROPFIND",
                  "-H", "Depth: 1", nginx_webdav["url"] + "/"])
        assert "hello.txt" in r.stdout, \
            f"Depth:1 PROPFIND should list children:\n{r.stdout[:300]}"

    def test_mkcol_then_propfind(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wmk")
        col = nginx_webdav["url"] + "/coll/"
        mk = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "MKCOL", col])
        assert mk.stdout.strip() in ("201", "200"), f"MKCOL → {mk.stdout}"
        pf = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "PROPFIND", col])
        assert pf.stdout.strip() in ("200", "207"), f"PROPFIND coll → {pf.stdout}"

    def test_put_delete_then_absent(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wdel")
        src = str(tmp_path / "del.txt")
        open(src, "w").write("to-be-deleted\n")
        url = nginx_webdav["url"] + "/todelete.txt"
        put = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", "-T", src, url])
        assert put.stdout.strip() in ("200", "201", "204"), f"PUT → {put.stdout}"
        dl = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "DELETE", url])
        assert dl.stdout.strip() in ("200", "204"), f"DELETE → {dl.stdout}"
        get = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", url])
        assert get.stdout.strip() == "404", f"deleted file should 404, got {get.stdout}"

    def test_range_get_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wr")
        # hello.txt = "hello-webdav-gsi\n"; bytes 0-4 → "hello"
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-r", "0-4",
                  nginx_webdav["url"] + "/hello.txt"])
        assert r.stdout == "hello", f"range GET → {r.stdout!r}"

    def test_large_put_get_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wl")
        src = str(tmp_path / "wbig.bin")
        blob = _big(src, 4 * 1024 * 1024)
        url = nginx_webdav["url"] + "/wbig.bin"
        put = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", "-T", src, url])
        assert put.stdout.strip() in ("200", "201", "204"), f"big PUT → {put.stdout}"
        out = str(tmp_path / "wbigback.bin")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out, url])
        assert open(out, "rb").read() == blob

    def test_options_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wo")
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                  "-w", "%{http_code}", "-X", "OPTIONS", nginx_webdav["url"] + "/"])
        assert r.stdout.strip() in ("200", "204"), f"OPTIONS → {r.stdout}"

    def test_copy_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wcp")
        base = nginx_webdav["url"]
        src = str(tmp_path / "c.txt")
        open(src, "w").write("copy-src\n")
        assert _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                     "-w", "%{http_code}", "-T", src, base + "/csrc.txt"]
                    ).stdout.strip() in ("200", "201", "204")
        cp = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "COPY",
                   "-H", f"Destination: {base}/cdst.txt", base + "/csrc.txt"])
        assert cp.stdout.strip() in ("200", "201", "204"), f"COPY → {cp.stdout}"
        out = str(tmp_path / "c.out")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
              base + "/cdst.txt"])
        assert open(out).read() == "copy-src\n"

    def test_move_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wmv")
        base = nginx_webdav["url"]
        src = str(tmp_path / "m.txt")
        open(src, "w").write("move-src\n")
        assert _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                     "-w", "%{http_code}", "-T", src, base + "/msrc.txt"]
                    ).stdout.strip() in ("200", "201", "204")
        mv = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "MOVE",
                   "-H", f"Destination: {base}/mdst.txt", base + "/msrc.txt"])
        assert mv.stdout.strip() in ("200", "201", "204"), f"MOVE → {mv.stdout}"
        gone = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                     "-w", "%{http_code}", base + "/msrc.txt"])
        assert gone.stdout.strip() == "404", f"moved source should 404: {gone.stdout}"
        out = str(tmp_path / "m.out")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
              base + "/mdst.txt"])
        assert open(out).read() == "move-src\n"

    def test_concurrent_proxy_requests(self, pki, nginx_webdav):
        import concurrent.futures as cf
        cfp, kfp = _split_for_curl(pki["valid_proxy"], pki["base"], "wcc")

        def one(_):
            return _run(["curl", "-sk", "--cert", cfp, "--key", kfp, "-o",
                         "/dev/null", "-w", "%{http_code}", "-X", "PROPFIND",
                         nginx_webdav["url"] + "/"]).stdout.strip()

        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            codes = list(ex.map(one, range(10)))
        assert all(c in ("200", "207") for c in codes), \
            f"concurrent proxy-cert PROPFINDs: {codes}"

    def test_no_client_cert_rejected(self, pki, nginx_webdav):
        r = _curl(pki, nginx_webdav, None, nginx_webdav["url"] + "/",
                  method="PROPFIND")
        assert _rejected(r.stdout), f"no-cert request must be refused, got {r.stdout}"

    def test_untrusted_proxy_rejected(self, pki, nginx_webdav):
        assert pki["untrusted_proxy"], "untrusted proxy not provisioned"
        r = _curl(pki, nginx_webdav, pki["untrusted_proxy"],
                  nginx_webdav["url"] + "/", method="PROPFIND")
        assert _rejected(r.stdout), \
            f"untrusted-CA proxy must be refused, got {r.stdout}"

    def test_expired_proxy_rejected(self, pki, nginx_webdav):
        assert pki["expired_proxy"], "expired credential not provisioned"
        r = _curl(pki, nginx_webdav, pki["expired_proxy"],
                  nginx_webdav["url"] + "/", method="PROPFIND")
        assert _rejected(r.stdout), \
            f"expired credential must be refused, got {r.stdout}"


# --------------------------------------------------------------------------- #
# root:// — GSI auth ENFORCEMENT (the server must refuse unauthenticated I/O)
# --------------------------------------------------------------------------- #
class TestRootAuthEnforcement:
    def _anon_env(self):
        env = dict(os.environ)
        env["X509_USER_PROXY"] = "/nonexistent/proxy.pem"
        env.pop("BEARER_TOKEN", None)
        return env

    def test_anon_read_refused(self, pki, nginx_root_off, tmp_path):
        out = str(tmp_path / "anon.bin")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_off['url']}//hello.txt", out],
                 env=self._anon_env())
        assert r.returncode != 0, "unauthenticated read must be refused"

    def test_anon_write_refused(self, pki, nginx_root_off, tmp_path):
        src = str(tmp_path / "anon_up.txt")
        open(src, "w").write("should-not-land\n")
        r = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_off['url']}//anon_up.txt"],
                 env=self._anon_env())
        assert r.returncode != 0, "unauthenticated write must be refused"


# --------------------------------------------------------------------------- #
# root:// — cross-server transfer (our nginx ↔ a real stock xrootd), GSI both
# ends.  The self-contained equivalent of the bridge suite.
# --------------------------------------------------------------------------- #
class TestRootCrossServer:
    def test_nginx_to_stock_and_back(self, pki, nginx_root_off, stock_root,
                                     tmp_path):
        src = str(tmp_path / "xfer.bin")
        blob = _big(src, 1024 * 1024)
        u = pki["env"]
        # local → our nginx
        assert _run([STOCK_XRDCP, "-f", src,
                     f"{nginx_root_off['url']}//xfer.bin"], env=u).returncode == 0
        # our nginx → stock xrootd (client-mediated copy, GSI on both ends)
        assert _run([STOCK_XRDCP, "-f", f"{nginx_root_off['url']}//xfer.bin",
                     f"{stock_root['url']}//gsidata/xfer.bin"],
                    env=u).returncode == 0
        # stock → local, verify byte-exact
        out = str(tmp_path / "xfer.back")
        assert _run([STOCK_XRDCP, "-f",
                     f"{stock_root['url']}//gsidata/xfer.bin", out],
                    env=u).returncode == 0
        assert open(out, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — further authenticated metadata ops over the GSI session
# --------------------------------------------------------------------------- #
class TestRootMoreOps:
    def test_truncate(self, pki, nginx_root_off, tmp_path):
        src = str(tmp_path / "t.bin")
        _big(src, 4096)
        u = pki["env"]
        assert _run([STOCK_XRDCP, "-f", src,
                     f"{nginx_root_off['url']}//trunc.bin"], env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root_off["url"], "truncate",
                     "/trunc.bin", "1024"], env=u).returncode == 0
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "stat", "/trunc.bin"], env=u)
        assert r.returncode == 0 and "1024" in r.stdout, \
            f"truncate did not resize: {r.stdout!r}"

    def test_cat(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "cat", "/hello.txt"],
                 env=pki["env"])
        assert r.returncode == 0 and "hello-gsi-handshake" in r.stdout


# --------------------------------------------------------------------------- #
# root:// — query opcodes over the authenticated GSI session
# --------------------------------------------------------------------------- #
class TestRootQueryOps:
    def test_query_config(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "query", "config",
                  "version"], env=pki["env"])
        assert r.returncode == 0 and "version=" in r.stdout, \
            f"query config: rc={r.returncode} {r.stdout!r} {r.stderr!r}"

    def test_locate(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "locate", "/"],
                 env=pki["env"])
        assert r.returncode == 0 and ":" in r.stdout, \
            f"locate: rc={r.returncode} {r.stdout!r} {r.stderr!r}"

    def test_stat_q_readable(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "stat", "-q", "IsReadable",
                  "/hello.txt"], env=pki["env"])
        assert r.returncode == 0, f"stat -q: {r.stderr}"


# --------------------------------------------------------------------------- #
# root:// — a spread of file sizes (0, 1, odd, block-spanning) over GSI, to
# exercise the session cipher / data plane at every boundary.
# --------------------------------------------------------------------------- #
class TestRootFileSizes:
    @pytest.mark.parametrize("size", [0, 1, 16, 17, 9973, 65537])
    def test_roundtrip(self, pki, nginx_root_off, tmp_path, size):
        src = str(tmp_path / f"sz{size}")
        blob = _big(src, size)
        key = f"/sz_{size}.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_off['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"upload size={size}: {up.stderr}"
        back = str(tmp_path / f"b{size}")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root_off['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"download size={size}: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — kXR_sigver request signing (security_level intense)
# --------------------------------------------------------------------------- #
class TestSigverEnforcement:
    """At `intense` the server requires a kXR_sigver signature (HMAC keyed by
    signing_key = SHA-256 of the GSI DH secret) on the protected opcodes.  GSI
    auth itself completes (it is pre-key), arming `signing_active`; the very next
    real op then fails with kXR_error 3010 ("request signing required") because
    the unsigned-by-default stock client does not sign — proving the enforcement
    is correctly wired to the GSI session key."""

    def test_unsigned_dirlist_refused(self, pki, nginx_root_sigver):
        # The 3010 (not an auth error) proves GSI auth succeeded first, then the
        # protected dirlist was rejected for lacking a signature.
        r = _run([STOCK_XRDFS, nginx_root_sigver["url"], "ls", "/"], env=pki["env"])
        assert r.returncode != 0 and "signing" in r.stderr.lower(), \
            f"intense must refuse the unsigned dirlist: {r.stderr}"

    def test_unsigned_read_refused(self, pki, nginx_root_sigver, tmp_path):
        out = str(tmp_path / "sv.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_sigver['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode != 0 and "signing" in r.stderr.lower(), \
            f"intense must refuse the unsigned open/read: {r.stderr}"

    def test_unsigned_write_refused(self, pki, nginx_root_sigver, tmp_path):
        src = str(tmp_path / "svu.bin")
        open(src, "w").write("should-be-refused\n")
        r = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_sigver['url']}//sv.bin"],
                 env=pki["env"])
        assert r.returncode != 0 and "signing" in r.stderr.lower(), \
            f"intense must refuse the unsigned write: {r.stderr}"


# --------------------------------------------------------------------------- #
# root:// — RSA-4096 host + proxy keys through the signed-DH handshake
# --------------------------------------------------------------------------- #
class TestRsa4096:
    def test_stock_auth_and_read(self, nginx_rsa4096, tmp_path):
        r = _run([STOCK_XRDFS, nginx_rsa4096["url"], "ls", "/"],
                 env=nginx_rsa4096["env"])
        assert r.returncode == 0, f"rsa4096 ls: {r.stderr}"
        assert "/hello.txt" in r.stdout
        out = str(tmp_path / "r4.txt")
        rc = _run([STOCK_XRDCP, "-f", f"{nginx_rsa4096['url']}//hello.txt", out],
                  env=nginx_rsa4096["env"])
        assert rc.returncode == 0, f"rsa4096 read: {rc.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_native_auth(self, nginx_rsa4096):
        if not os.path.exists(NATIVE_XRDFS):
            assert False, "native client must be built"
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_rsa4096["url"], "ls", "/"],
                 env=nginx_rsa4096["env"])
        assert r.returncode == 0, f"rsa4096 native ls: {r.stderr}"
        assert "/hello.txt" in r.stdout


# --------------------------------------------------------------------------- #
# root:// — VOMS attribute extraction + VO ACL enforcement
# --------------------------------------------------------------------------- #
class TestVomsExtraction:
    """The server parses the VOMS attribute certificate, extracts the VO, and
    enforces `require_vo`: a proxy carrying `testvo` reaches the VO-gated path
    while the plain (no-VO) proxy is refused — proving the VO was extracted."""

    def test_voms_proxy_allowed_on_vo_path(self, voms, nginx_voms):
        r = _run([STOCK_XRDFS, nginx_voms["url"], "ls", "/vodata"],
                 env=voms["env"])
        assert r.returncode == 0, f"VOMS proxy denied its own VO path: {r.stderr}"
        assert "secret.txt" in r.stdout

    def test_voms_proxy_can_read_vo_file(self, voms, nginx_voms, tmp_path):
        out = str(tmp_path / "vo.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_voms['url']}//vodata/secret.txt",
                  out], env=voms["env"])
        assert r.returncode == 0, f"VOMS proxy read denied: {r.stderr}"
        assert open(out).read() == "vo-only\n"

    def test_plain_proxy_denied_on_vo_path(self, pki, voms, nginx_voms):
        # Same identity/CA, but NO VO attribute → must be refused on /vodata.
        r = _run([STOCK_XRDFS, nginx_voms["url"], "ls", "/vodata"],
                 env=pki["env"])
        assert r.returncode != 0, \
            "a proxy without the required VO must be refused on /vodata"

    def test_native_voms_proxy_allowed(self, voms, nginx_voms):
        if not os.path.exists(NATIVE_XRDFS):
            assert False, "native client must be built"
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_voms["url"],
                  "ls", "/vodata"], env=voms["env"])
        assert r.returncode == 0, f"native VOMS proxy denied: {r.stderr}"
        assert "secret.txt" in r.stdout


# --------------------------------------------------------------------------- #
# root:// — xrootd_auth both: the GSI client picks gsi from a ztn+gsi offer
# --------------------------------------------------------------------------- #
class TestBothAuthMode:
    def test_gsi_client_authenticates(self, pki, nginx_root_both):
        r = _run([STOCK_XRDFS, nginx_root_both["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"both-mode GSI ls: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_advertises_both_protocols(self, pki, nginx_root_both):
        s, body = _wire_login("127.0.0.1",
                              int(nginx_root_both["url"].rsplit(":", 1)[1]))
        s.close()
        assert b"&P=ztn" in body and b"&P=gsi" in body, \
            f"both mode must advertise ztn and gsi: {body!r}"

    def test_native_client_authenticates(self, pki, nginx_root_both):
        if not os.path.exists(NATIVE_XRDFS):
            assert False, "native client must be built"
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root_both["url"],
                  "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"both-mode native GSI ls: {r.stderr}"
        assert "/hello.txt" in r.stdout


# --------------------------------------------------------------------------- #
# Wire-level — drive the handshake by hand and inspect each stage's bytes.
# --------------------------------------------------------------------------- #
class TestWireHandshake:
    EXPECT_VER = {"off": b"v:10000", "auto": b"v:10600", "require": b"v:10600"}

    @staticmethod
    def _port(url):
        return int(url.rsplit(":", 1)[1])

    def test_login_advertises_gsi(self, pki, nginx_root):
        """The kXR_login response carries the `&P=gsi,v:…,c:ssl,ca:…` block, and
        the advertised version matches the signed-DH policy — read straight off
        the wire, no client library."""
        s, body = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        s.close()
        assert b"&P=gsi" in body, f"login did not advertise gsi: {body!r}"
        assert b"c:ssl" in body and b"ca:" in body, \
            f"gsi advertisement missing crypto/CA hint: {body!r}"
        assert self.EXPECT_VER[nginx_root["policy"]] in body, \
            f"{nginx_root['policy']}: wrong advertised version in {body!r}"

    def test_certreq_response_buckets(self, pki, nginx_root):
        """A real certreq elicits kXGS_cert; assert the response carries the
        server cert, a cipher list with aes-128-cbc first, and the right
        DH-public bucket for the policy (kXRS_puk unsigned vs kXRS_cipher signed)."""
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        status, bk = _send_certreq(s, 10600)
        s.close()
        assert status == kXR_authmore, \
            f"certreq → status {status}, expected kXR_authmore"
        assert kXRS_x509 in bk, "kXGS_cert missing the server cert (kXRS_x509)"
        assert kXRS_cipher_alg in bk, "kXGS_cert missing kXRS_cipher_alg"
        assert bk[kXRS_cipher_alg].startswith(b"aes-128-cbc"), \
            f"cipher list must offer aes-128-cbc first: {bk[kXRS_cipher_alg]!r}"
        if nginx_root["policy"] == "off":
            assert kXRS_puk in bk and kXRS_cipher not in bk, \
                "unsigned policy must send a bare kXRS_puk"
        else:
            assert kXRS_cipher in bk and kXRS_puk not in bk, \
                "signed policy must send an RSA-signed kXRS_cipher"

    def test_old_client_version_negotiation(self, pki, nginx_root):
        """A pre-DHsigned (v10300) certreq: off & auto fall back to unsigned;
        require always signs — proving the per-client version gate works."""
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        _status, bk = _send_certreq(s, 10300)
        s.close()
        if nginx_root["policy"] == "require":
            assert kXRS_cipher in bk and kXRS_puk not in bk, \
                "require signs even a <10400 client"
        else:
            assert kXRS_puk in bk and kXRS_cipher not in bk, \
                f"{nginx_root['policy']}: a <10400 client must get unsigned DH"

    def test_certreq_advertises_digest(self, pki, nginx_root):
        """kXGS_cert offers a digest list including sha256."""
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        _status, bk = _send_certreq(s, 10600)
        s.close()
        assert kXRS_md_alg in bk and b"sha256" in bk[kXRS_md_alg], \
            f"kXGS_cert should offer a sha256 digest: {bk.get(kXRS_md_alg)!r}"

    def test_login_advertises_8hex_ca_hash(self, pki, nginx_root):
        """The gsi advertisement carries the server CA subject hash as 8 hex."""
        s, body = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        s.close()
        assert re.search(rb"ca:[0-9a-fA-F]{8}", body), \
            f"login must advertise an 8-hex CA hash: {body!r}"


# --------------------------------------------------------------------------- #
# S3: GSI is not applicable.  Documented here so the omission is intentional.
# --------------------------------------------------------------------------- #
def test_s3_uses_sigv4_not_gsi():
    """Guard the design invariant: S3 (ours and official XrdS3) authenticates
    with AWS SigV4, never GSI — so there is deliberately no S3 GSI test."""
    handler = os.path.join(REPO, "src", "s3", "handler.c")
    assert os.path.exists(handler), "src/s3/handler.c not present"
    text = open(handler).read().lower()
    assert "sigv4" in text, "S3 handler should authenticate via SigV4"
