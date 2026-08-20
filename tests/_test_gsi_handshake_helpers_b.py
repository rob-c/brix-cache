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
from port_ladder import PORT_LAST  # noqa: E402

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

P_STOCK_ROOT = PORT_LAST + 20 + _WOFF
P_STOCK_ROOT_FCA = PORT_LAST + 21 + _WOFF  # foreign-CA stock server


# --------------------------------------------------------------------------- #
# Small process / port helpers
# --------------------------------------------------------------------------- #
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

    # Foreign-CA server: a host cert signed by a SECOND, distinct CA (the "server
    # CA"), while the user proxy still chains to the trusted CA above. Models a
    # real grid site (e.g. UK e-Science CA 2B) whose host cert hangs off a CA
    # different from the client's proxy CA. The server trusts BOTH CAs via a
    # CApath directory (it must verify its own host cert to advertise the ca:
    # hint AND verify the client's proxy), and the client trusts both too (the
    # server CA is hash-linked into certs/ so the roots:// TLS upgrade verifies
    # the host cert). The advertised ca: is then the server CA — a client that
    # echoes it as its issuer hash makes the server anchor our proxy on the wrong
    # CA and reject the chain as "inconsistent"; a correct client sends its OWN
    # proxy CA. See gsi_client_issuer_hash in client/lib/auth/sec/sec_gsi.c.
    scb = os.path.join(base, "scb")
    os.makedirs(scb, exist_ok=True)
    scb_key, scb_pem = _make_ca(scb, "/O=XrdTest/CN=XrdTest Server CA")
    _signed(scb_key, scb_pem, fqdn, os.path.join(scb, "hostkey.pem"),
            os.path.join(scb, "hostcert.pem"), base)
    _ca_hash_link(scb_pem, certs)               # client also trusts the server CA
    both_ca = os.path.join(base, "both_ca")     # CApath the foreign server trusts
    os.makedirs(both_ca, exist_ok=True)
    _ca_hash_link(ca_pem, both_ca)              # to verify the client proxy
    _ca_hash_link(scb_pem, both_ca)             # to verify its own host cert
    os.chmod(both_ca, 0o755)

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
        "foreign_hostcert": os.path.join(scb, "hostcert.pem"),
        "foreign_hostkey": os.path.join(scb, "hostkey.pem"),
        "both_ca": both_ca,
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
    assert shutil.which("voms-proxy-fake") or os.path.isfile(
        os.path.join(REPO, "utils", "voms_proxy_fake.py")), \
        "voms-proxy-fake or the repository fallback is required for VOMS tests"
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
# Per-uid cache root: a root-run cache is unreadable/undeletable for a later
# unprivileged run (0600 keys, foreign-owned entries defeat the rmtree+rename
# swap), so users must never share one.
_PKI_CACHE_ROOT = f"/tmp/brix-gsi-pki-cache.{os.getuid()}"
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
