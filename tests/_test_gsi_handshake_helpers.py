# _test_gsi_handshake_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_gsi_handshake.py.  `from _test_gsi_handshake_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""Comprehensive XrdSecgsi (x509-proxy) handshake tests — root:// and HTTPS.

Exercises every observable stage of the GSI handshake against BOTH the official
tools (stock ``xrdfs``/``xrdcp``, ``curl``) and our native client
(``client/bin/xrd{fs,cp}``), across both DH variants and both transports that
consume the x509 proxy credential:

  * ``root://``  — the XrdSecgsi stream handshake (protocol advertisement,
    certreq, server cert + DH agreement, proof-of-possession, proxy-chain
    verification, identity/DN extraction, the session cipher in BOTH data
    directions via read *and* write), for every ``brix_gsi_signed_dh`` policy
    (``off`` = unsigned DH, ``auto``/``require`` = RSA-signed DH ≥ 10400).
  * ``https://`` — WebDAV with x509 proxy client-cert auth
    (``brix_webdav_proxy_certs``): PROPFIND/GET/PUT with a proxy, and the
    matching rejections.

Negative coverage (the credential must be *refused*): a proxy from an untrusted
CA, an expired credential, no credential at all, and a client that does not
trust the server's host cert.

**S3 is intentionally out of scope.** S3 — both ours (``src/protocols/s3/``) and the
official ``XrdS3`` — authenticates with AWS SigV4 exclusively; GSI does not apply
to S3.  SigV4 coverage lives in ``test_s3_*.py``.

Self-contained: provisions its own trusted CA, an untrusted CA, a host cert, a
valid proxy, an untrusted proxy and (best-effort) an expired credential, then
spawns throwaway stock-xrootd and nginx servers on a private port band.  Skips
cleanly when the stock tools are not installed.
"""

import fcntl
import os
import re
import shutil
import socket
import subprocess
import time

import pytest

from server_launcher import LifecycleHarness  # noqa: E402
from server_registry import NginxInstanceSpec  # noqa: E402

# Every nginx GSI server in this module is a throwaway registry instance driven
# through the phase-81 LifecycleHarness (never a direct nginx launch), so the
# registry lint treats the file as migrated.
pytestmark = pytest.mark.uses_lifecycle_harness

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
STOCK_XRDFS = "/usr/bin/xrdfs"
STOCK_XRDCP = "/usr/bin/xrdcp"

# All nginx GSI servers here are registry LifecycleHarness instances on
# OS-assigned (free_port) ports with pid-suffixed names, so xdist workers and
# serial runs never collide on ports or registry prefixes.  The one remaining
# fixed-port server is the throwaway STOCK xrootd used for native-client interop
# (`stock_root`): it is launched directly (not through the registry) and needs a
# stable listen port, so it keeps the per-worker OFFSET scheme — under
# `pytest -n<N> --dist load` every worker imports this helper and starts its own
# stock xrootd, so the port is shifted by a per-worker stride (gw0→+20, gw1→+40,
# …; serial runs get offset 0) to keep the self-started servers collision-free.
_WK = os.environ.get("PYTEST_XDIST_WORKER", "")   # "gw0".."gwN" under xdist, "" serial
_WOFF = (int(_WK[2:]) + 1) * 20 if _WK.startswith("gw") else 0

P_STOCK_ROOT = 21130 + _WOFF


# --------------------------------------------------------------------------- #
# Small process / port helpers
# --------------------------------------------------------------------------- #
def _have(*tools):
    return all(shutil.which(t) or os.path.exists(t) for t in tools)


def _run(cmd, timeout=120, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          **kw)


# RSA keygen is an unbounded prime search: a 4096-bit `openssl req -newkey` that
# takes ~5s idle can blow well past 120s on a CPU-saturated 12-worker lane.  A
# timeout on keygen should mean "wedged", never "slow" — so every command that
# generates or consumes a fresh RSA key gets this generous ceiling instead of
# the default 120s.
_KEYGEN_TIMEOUT = 600


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
def _osl(*a, timeout=120):
    r = _run(["openssl", *a], timeout=timeout)
    assert r.returncode == 0, f"openssl {a[0]} failed: {r.stderr}"


def _ca_hash_link(ca_pem, certs_dir):
    h = _run(["openssl", "x509", "-in", ca_pem, "-noout", "-hash"]).stdout.strip()
    shutil.copy(ca_pem, os.path.join(certs_dir, f"{h}.0"))


def _make_ca(path, subj, bits=2048):
    key, pem = os.path.join(path, "ca.key"), os.path.join(path, "ca.pem")
    _osl("req", "-x509", "-nodes", "-newkey", f"rsa:{bits}", "-days", "2",
         "-subj", subj, "-keyout", key, "-out", pem,
         timeout=_KEYGEN_TIMEOUT)
    return key, pem


def _signed(ca_key, ca_pem, cn, key, cert, base, bits=2048):
    csr = os.path.join(base, os.path.basename(key) + ".csr")
    _osl("req", "-nodes", "-newkey", f"rsa:{bits}", "-subj", f"/O=XrdTest/CN={cn}",
         "-keyout", key, "-out", csr, timeout=_KEYGEN_TIMEOUT)
    _osl("x509", "-req", "-in", csr, "-CA", ca_pem, "-CAkey", ca_key,
         "-CAcreateserial", "-days", "2", "-out", cert)


def _mint_proxy(eec_cert, eec_key, out, certs, env):
    # NB: no -certdir flag — xrootd-client's xrdgsiproxy only accepts
    # -valid/-cert/-key/-out/-bits (a stray -certdir makes it print usage and
    # exit 50). It reads the CA dir from X509_CERT_DIR, which every caller has
    # already set to `certs` in `env`; the param is kept for that contract.
    _run(["xrdgsiproxy", "init", "-cert", eec_cert, "-key", eec_key,
          "-out", out, "-valid", "1:00"],
         input="\n\n", env=env, timeout=_KEYGEN_TIMEOUT)
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

    # The pytest fleet runs with umask 000, so os.makedirs(certs) above created
    # the CA dir world-WRITABLE (0777). XrdCl's TLS client init (XrdClTls.cc
    # InitTLS -> XrdOucUtils::ValPath, mask 0755) REFUSES a CA directory with
    # group/other-write bits ("has excessive access rights") and throws
    # "Failed to initialize TLS", so EVERY roots:// (GSI+TLS-upgrade) test that
    # points X509_CERT_DIR here fails — deterministically once you notice it, but
    # masked as a flake because it only surfaces on workers heavy enough to hit
    # these cases. Clamp the CA dir to 0755: still world-readable/traversable (the
    # stock server-as-`nobody` and every client can read the CA), no longer
    # "excessive" so TLS client init accepts it. (stock_root's broad `a+rwX`
    # re-loosens it to 0777; it re-clamps there too.)
    os.chmod(certs, 0o755)

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
# Server launchers — every nginx GSI server is a throwaway registry instance
# driven through the phase-81 LifecycleHarness.  The harness renders a committed
# tests/configs/nginx_gsi_handshake_*.conf template, runs `nginx -t`, launches
# the daemon (`daemon on;`), waits for its listen port, and reaps master+workers
# by pidfile on close().  The URL still uses the PKI fqdn (the host-cert CN the
# roots:// TLS upgrade verifies against); only the port is OS-assigned, read back
# from the started endpoint.
# --------------------------------------------------------------------------- #
def _gsi_nginx(name, template, data_root, protocol="root", **template_values):
    """Start a GSI nginx server via the LifecycleHarness; return (harness, endpoint).

    The custom launch env (the runtime lib shim) is passed straight through to
    the registry launcher.  Coming up is a HARD requirement — these tests must
    pass, never skip — so a start failure (bad config caught by `nginx -t`, or a
    readiness timeout) propagates after the harness is torn down so nothing leaks.
    Callers yield a fixture dict built from `endpoint` and call `harness.close()`
    on teardown."""
    ld = "/tmp/rt_libshim:/usr/lib64:" + os.environ.get("LD_LIBRARY_PATH", "")
    harness = LifecycleHarness()
    spec = NginxInstanceSpec(
        name=name,
        template=template,
        protocol=protocol,
        data_root=data_root,
        readiness="tcp",
        env={"LD_LIBRARY_PATH": ld},
        template_values=template_values,
    )
    try:
        endpoint = harness.start(spec)
    except Exception:
        harness.close()
        raise
    return harness, endpoint


def _gsi_log(endpoint):
    """The started instance's error log (registry: <prefix>/logs/error.log)."""
    return os.path.join(endpoint.prefix, "logs", "error.log")


@pytest.fixture(scope="module", params=["off", "auto", "require"])
def nginx_root(pki, request):
    """Our nginx GSI root:// server, one per signed-DH policy."""
    policy = request.param
    sdh = "" if policy == "off" else f"        brix_gsi_signed_dh {policy};"
    harness, ep = _gsi_nginx(
        f"gsihs-root-{policy}", "nginx_gsi_handshake_root.conf", pki["data"],
        CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"],
        CIPHERS_DIRECTIVE="", SIGNED_DH_DIRECTIVE=sdh)
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}", "policy": policy,
               "log": _gsi_log(ep)}
    finally:
        harness.close()


@pytest.fixture(scope="module")
def nginx_root_off(pki):
    """A dedicated default (unsigned) server for negative + identity tests."""
    harness, ep = _gsi_nginx(
        "gsihs-root-neg", "nginx_gsi_handshake_root.conf", pki["data"],
        CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"],
        CIPHERS_DIRECTIVE="", SIGNED_DH_DIRECTIVE="")
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}", "log": _gsi_log(ep)}
    finally:
        harness.close()


@pytest.fixture(scope="module")
def nginx_root_both(pki):
    """A server advertising BOTH token and GSI (`brix_auth both`).  The GSI
    client must still pick gsi from the multi-protocol `&P=ztn…&P=gsi…` block and
    authenticate."""
    jwks = os.path.join(pki["base"], "jwks.json")
    with open(jwks, "w") as f:           # token side is unused by the GSI client
        f.write('{"keys":[]}')
    harness, ep = _gsi_nginx(
        "gsihs-root-both", "nginx_gsi_handshake_both.conf", pki["data"],
        JWKS=jwks, CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"])
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}", "log": _gsi_log(ep)}
    finally:
        harness.close()


@pytest.fixture(scope="module")
def nginx_root_aes256(pki):
    """A GSI server advertising ONLY aes-256-cbc (brix_gsi_ciphers).  A
    successful handshake against it proves the client negotiated a NON-default
    session cipher (WS-A) — aes-128-cbc is not on offer, so the proven default
    path cannot be the one exercised."""
    harness, ep = _gsi_nginx(
        "gsihs-root-aes256", "nginx_gsi_handshake_root.conf", pki["data"],
        CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"],
        CIPHERS_DIRECTIVE='        brix_gsi_ciphers "aes-256-cbc";',
        SIGNED_DH_DIRECTIVE="")
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}", "log": _gsi_log(ep)}
    finally:
        harness.close()


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
    harness, ep = _gsi_nginx(
        "gsihs-voms", "nginx_gsi_handshake_voms.conf", vdata,
        VOMSDIR=voms["vomsdir"], VOMS_CERT_DIR=pki["certs"],
        CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"])
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}"}
    finally:
        harness.close()


@pytest.fixture(scope="module")
def nginx_root_tls(pki):
    """GSI server that also advertises in-protocol TLS (kXR_ableTLS): the client
    authenticates with GSI, then upgrades the channel to TLS."""
    harness, ep = _gsi_nginx(
        "gsihs-root-tls", "nginx_gsi_handshake_tls.conf", pki["data"],
        CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"])
    try:
        # roots:// forces the TLS upgrade after the GSI login.
        yield {"url": f"roots://{pki['fqdn']}:{ep.port}", "log": _gsi_log(ep)}
    finally:
        harness.close()


@pytest.fixture(scope="module")
def nginx_root_sigver(pki):
    """GSI server at security level `intense` — most opcodes must carry a valid
    kXR_sigver signature derived from the GSI session key.  A client that signs
    correctly (stock xrdfs) proceeds; this exercises the request-signing half of
    the handshake (signing_key = SHA-256(DH secret))."""
    harness, ep = _gsi_nginx(
        "gsihs-root-sigver", "nginx_gsi_handshake_sigver.conf", pki["data"],
        CERT=pki["hostcert"], KEY=pki["hostkey"], CA=pki["ca"])
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}", "log": _gsi_log(ep)}
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# RSA-4096 PKI cache — three 4096-bit keygens (~seconds idle, unbounded under a
# CPU-saturated 12-worker lane) used to run on EVERY module import, and one slow
# prime search past the subprocess timeout errored the whole TestRsa4096 class.
# The long-lived material (CA + host + user EEC, all `-days 2`) is generated
# once and cached in a stable location OUTSIDE every rotated tree (never under
# TMPDIR / pytest basetemp / /tmp/xrd-test — concurrent sessions rotate+rm those
# roots), guarded by a cross-process flock so concurrent workers generate once.
# Only the short-lived proxy (xrdgsiproxy -valid 1:00) is minted fresh per run.
# --------------------------------------------------------------------------- #
_PKI_CACHE_ROOT = "/tmp/brix-gsi-pki-cache"
_PKI_CACHE_TAG = "rsa4096-v1"          # bump on any layout/parameter change


def _pki_cache_paths(cache):
    return {
        "ca_key": os.path.join(cache, "ca.key"),
        "ca": os.path.join(cache, "ca.pem"),
        "certs": os.path.join(cache, "certs"),
        "hostkey": os.path.join(cache, "server", "hostkey.pem"),
        "hostcert": os.path.join(cache, "server", "hostcert.pem"),
        "userkey": os.path.join(cache, "user", "userkey.pem"),
        "usercert": os.path.join(cache, "user", "usercert.pem"),
    }


def _pki_cache_valid(cache, fqdn):
    """True iff the cached RSA-4096 material is safe to reuse: complete, each
    cert chains to the cached CA and is INSIDE its validity window in both
    directions (`openssl verify` rejects not-yet-valid certs — a WSL2 clock
    step backwards can leave a cached notBefore in the future), has >= 1h of
    life left (headroom for the run), each key matches its cert, and the host
    cert was issued for THIS host's fqdn."""
    p = _pki_cache_paths(cache)
    if not all(os.path.exists(v) for k, v in p.items() if k != "certs"):
        return False
    for cert in (p["ca"], p["hostcert"], p["usercert"]):
        if _run(["openssl", "x509", "-in", cert, "-noout",
                 "-checkend", "3600"]).returncode != 0:
            return False
    for cert in (p["hostcert"], p["usercert"]):
        if _run(["openssl", "verify", "-CAfile", p["ca"],
                 cert]).returncode != 0:
            return False
    for cert, key in ((p["hostcert"], p["hostkey"]),
                      (p["usercert"], p["userkey"])):
        cpub = _run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"]).stdout
        kpub = _run(["openssl", "pkey", "-in", key, "-pubout"]).stdout
        if not cpub or cpub != kpub:
            return False
    subj = _run(["openssl", "x509", "-in", p["hostcert"], "-noout",
                 "-subject"]).stdout
    return fqdn in subj


def _rsa4096_cached_pki(fqdn):
    """Return the validated RSA-4096 cache dir, (re)generating it under an
    exclusive cross-process flock so N concurrent workers pay the three
    4096-bit keygens exactly once.  Any validation failure (expired, clock-
    skewed, truncated, wrong host) regenerates from scratch — into a temp dir
    swapped in whole, so a reader never sees a half-written cache."""
    os.makedirs(_PKI_CACHE_ROOT, exist_ok=True)
    cache = os.path.join(_PKI_CACHE_ROOT, _PKI_CACHE_TAG)
    with open(os.path.join(_PKI_CACHE_ROOT,
                           f".{_PKI_CACHE_TAG}.lock"), "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        if _pki_cache_valid(cache, fqdn):
            return cache
        tmp = f"{cache}.tmp.{os.getpid()}"
        shutil.rmtree(tmp, ignore_errors=True)
        p = _pki_cache_paths(tmp)
        for d in (p["certs"], os.path.dirname(p["hostkey"]),
                  os.path.dirname(p["userkey"])):
            os.makedirs(d, exist_ok=True)
        ck, cp = _make_ca(tmp, "/O=XrdTest/CN=XrdTest 4096 CA", bits=4096)
        _ca_hash_link(cp, p["certs"])
        _signed(ck, cp, fqdn, p["hostkey"], p["hostcert"], tmp, bits=4096)
        _signed(ck, cp, "Test User 4096", p["userkey"], p["usercert"], tmp,
                bits=4096)
        os.chmod(p["userkey"], 0o600)
        # The fleet runs with umask 000; clamp the CA dir like pki() does so
        # XrdCl's TLS init never rejects it as "excessive access rights".
        os.chmod(p["certs"], 0o755)
        shutil.rmtree(cache, ignore_errors=True)
        os.rename(tmp, cache)
        return cache


@pytest.fixture(scope="module")
def rsa4096(pki, tmp_path_factory):
    """A parallel RSA-4096 PKI (CA + host + user proxy) so the handshake's RSA
    sign/recover (chunked by key-size) is exercised at a larger modulus.

    The long-lived material comes from the cross-run cache above; only the
    short-lived (1h) proxy is minted fresh, into this run's private tmp."""
    p = _pki_cache_paths(_rsa4096_cached_pki(pki["fqdn"]))
    proxy = os.path.join(str(tmp_path_factory.mktemp("rsa4096proxy")),
                         "proxy.pem")
    env = dict(os.environ, X509_CERT_DIR=p["certs"], X509_USER_PROXY=proxy)
    assert _mint_proxy(p["usercert"], p["userkey"], proxy, p["certs"], env), \
        "could not mint the RSA-4096 proxy"
    yield {"certs": p["certs"], "ca": p["ca"], "env": env,
           "hostcert": p["hostcert"], "hostkey": p["hostkey"]}


@pytest.fixture(scope="module")
def nginx_rsa4096(pki, rsa4096):
    """A signed-DH GSI server on the RSA-4096 PKI — round 1 signs the DH public
    with the 4096-bit host key, round 2 recovers the 4096-bit-proxy-signed
    client public, so both RSA directions run at the larger size."""
    harness, ep = _gsi_nginx(
        "gsihs-rsa4096", "nginx_gsi_handshake_root.conf", pki["data"],
        CERT=rsa4096["hostcert"], KEY=rsa4096["hostkey"], CA=rsa4096["ca"],
        CIPHERS_DIRECTIVE="",
        SIGNED_DH_DIRECTIVE="        brix_gsi_signed_dh require;")
    try:
        yield {"url": f"root://{pki['fqdn']}:{ep.port}", "env": rsa4096["env"]}
    finally:
        harness.close()


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
    # xrootd refuses to run as the superuser; under a root test runner drop it to
    # `nobody` (-R) and open the tree + private key it must read/write as that
    # user (mirrors the fleet's refxrootd.sh _ref_launch shim).
    xrd_cmd = ["xrootd", "-c", cfg, "-l",
               os.path.join(base, "stock.log"), "-n", "gsihs"]
    if os.geteuid() == 0:
        subprocess.run(["chmod", "-R", "a+rwX", base], check=False)
        subprocess.run(["chown", "nobody", pki["hostkey"]], check=False)
        subprocess.run(["chmod", "0400", pki["hostkey"]], check=False)
        # The broad `chmod -R a+rwX base` (so xrootd-as-`nobody` can read the
        # export tree) also loosens the user's PRIVATE proxy + key under base/user/
        # to world-accessible. The native client's credential loader
        # (brix_open_credfile secret=1) correctly refuses any proxy that is
        # group/other-accessible ("gsi: cannot load proxy credential"), so restore
        # those two files to 0600 (owned by the root test runner) — the stock
        # server never needs them.
        for cred in (pki["valid_proxy"], pki["userkey"]):
            subprocess.run(["chmod", "0600", cred], check=False)
        # The broad `a+rwX` also left the shared CA dir (certs/) world-WRITABLE
        # (0777). XrdCl's TLS client init (XrdClTls.cc InitTLS -> XrdOucUtils::
        # ValPath, mask 0755) REFUSES a CA directory with group/other-write bits
        # ("has excessive access rights") and throws "Failed to initialize TLS".
        # Every later roots:// test in this module points X509_CERT_DIR at certs/,
        # so if a stock-server test seeds this fixture first the TLS cases fail
        # (order-dependent under -n<N> --dist load -> flaky). Restore certs/ to
        # 0755: still traversable/readable by the stock server-as-`nobody`, but
        # no longer "excessive" so TLS client init accepts it.
        subprocess.run(["chmod", "0755", pki["certs"]], check=False)
        xrd_cmd += ["-R", "nobody"]
    proc = subprocess.Popen(xrd_cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    _wait_listen(proc, P_STOCK_ROOT, "stock xrootd")
    yield {"url": f"root://{pki['fqdn']}:{P_STOCK_ROOT}"}
    _terminate(proc)


@pytest.fixture(scope="module")
def nginx_webdav(pki):
    """HTTPS WebDAV server requiring x509 proxy client-cert auth."""
    wdata = os.path.join(pki["base"], "wdata")
    os.makedirs(wdata, exist_ok=True)
    with open(os.path.join(wdata, "hello.txt"), "w") as f:
        f.write("hello-webdav-gsi\n")
    harness, ep = _gsi_nginx(
        "gsihs-webdav", "nginx_gsi_handshake_webdav.conf", wdata,
        protocol="https", CERT=pki["hostcert"], KEY=pki["hostkey"],
        CADIR=pki["certs"])
    try:
        yield {"url": f"https://{pki['fqdn']}:{ep.port}", "data": wdata,
               "log": _gsi_log(ep)}
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# root:// — the handshake end-to-end, every policy, both clients
#
# Each op below drives the full handshake (advertisement → certreq → server
# cert + DH agreement → encrypted proxy chain → CA verification) and then a real
# operation.  read exercises the session cipher server→client; write exercises
# it client→server, so the pair proves both directions of the agreed AES key.
# --------------------------------------------------------------------------- #


__all__ = [n for n in dir() if not n.startswith('__')]
