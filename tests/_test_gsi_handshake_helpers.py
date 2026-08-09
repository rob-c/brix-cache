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
import sys
import time

import pytest

from server_launcher import LifecycleHarness  # noqa: E402
from server_registry import NginxInstanceSpec  # noqa: E402

# Every nginx GSI server in this module is a throwaway registry instance driven
# through the phase-81 LifecycleHarness (never a direct nginx launch), so the
# registry lint treats the file as migrated.
# Both test_gsi_handshake.py and test_gsi_handshake_b.py `import *` from here and
# share these module-scoped GSI server fixtures (same fixed-port ledger names),
# so both files must run on one worker — otherwise two workers would race the
# same fixed listen.  One xdist_group here (propagated to both files via __all__)
# serialises them; each module tears its fixtures down before the next starts, so
# the shared ledger ports are reused rather than contended.
pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("gsihs")]

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
P_STOCK_ROOT_FCA = 21131 + _WOFF   # foreign-CA stock server; +1 within the stride


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
    installed = shutil.which("voms-proxy-fake")
    command = [installed] if installed else [
        sys.executable, os.path.join(REPO, "utils", "voms_proxy_fake.py")]
    return _run([*command, "-cert", usercert, "-key", userkey,
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


# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_handshake_helpers_b")
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_handshake_helpers_c")
