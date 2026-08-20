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


def _start_stock_gsi(pki, port, hostcert, hostkey, certdir, cfgname):
    """Launch a throwaway stock xrootd GSI server; return the Popen. Shared by
    the same-CA (stock_root) and foreign-CA (stock_root_foreign_ca) fixtures —
    they differ only by the host cert/key, the server's certdir and the port."""
    assert _have("xrootd", STOCK_XRDFS), \
        "stock xrootd / xrdfs are required for the GSI interop tests"
    base = pki["base"]
    gsidata = os.path.join(base, "gsidata")
    if not os.path.isdir(gsidata):
        shutil.copytree(pki["data"], gsidata)
    cfg = os.path.join(base, cfgname)
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {port}\n"
            "all.export /gsidata\n"
            f"oss.localroot {base}\n"
            # Keep the admin/pid state INSIDE the per-run tree: the default is
            # /tmp/<instance> (/tmp/gsihs), shared host-wide state that a prior
            # run under another account (root vs brixtest lanes) leaves behind
            # 0700 — the next lane's server then cannot use it and dies at boot.
            f"all.adminpath {base}\n"
            f"all.pidpath {base}\n"
            "xrootd.seclib libXrdSec.so\n"
            f"sec.protocol /usr/lib64 gsi -certdir:{certdir} "
            f"-cert:{hostcert} -key:{hostkey} "
            "-crl:0 -gmapopt:10 -dlgpxy:0\n"
            "sec.protbind * only gsi\n")
    _free_port(port)
    # xrootd refuses to run as the superuser; under a root test runner drop it to
    # `nobody` (-R) and open the tree + private key it must read/write as that
    # user (mirrors the fleet's refxrootd.sh _ref_launch shim).
    xrd_cmd = ["xrootd", "-c", cfg, "-l",
               os.path.join(base, f"stock-{port}.log"), "-n", "gsihs"]
    if os.geteuid() == 0:
        subprocess.run(["chmod", "-R", "a+rwX", base], check=False)
        # pytest's tmp_path_factory creates pytest-of-root/pytest-N as 0700, so
        # xrootd-as-`nobody` cannot even traverse DOWN to the opened base —
        # open the ancestor chain (a+rx adds nothing to /tmp and friends).
        parent = os.path.dirname(base)
        while parent not in ("/", ""):
            subprocess.run(["chmod", "a+rx", parent], check=False)
            parent = os.path.dirname(parent)
        # Both host keys may be served across the two stock fixtures; open each to
        # `nobody`. (chown-ing an absent key is a harmless no-op via check=False.)
        for key in (pki["hostkey"], pki["foreign_hostkey"]):
            subprocess.run(["chown", "nobody", key], check=False)
            subprocess.run(["chmod", "0400", key], check=False)
        # The broad `chmod -R a+rwX base` (so xrootd-as-`nobody` can read the
        # export tree) also loosens the user's PRIVATE proxy + key under base/user/
        # to world-accessible. The native client's credential loader
        # (brix_open_credfile secret=1) correctly refuses any proxy that is
        # group/other-accessible ("gsi: cannot load proxy credential"), so restore
        # those two files to 0600 (owned by the root test runner) — the stock
        # server never needs them.
        for cred in (pki["valid_proxy"], pki["userkey"]):
            subprocess.run(["chmod", "0600", cred], check=False)
        # The broad `a+rwX` also left the shared CA dirs world-WRITABLE (0777).
        # XrdCl's TLS client init (XrdClTls.cc InitTLS -> XrdOucUtils::ValPath,
        # mask 0755) REFUSES a CA directory with group/other-write bits ("has
        # excessive access rights") and throws "Failed to initialize TLS". Every
        # later roots:// test in this module points X509_CERT_DIR at certs/, so if
        # a stock-server test seeds this fixture first the TLS cases fail (order-
        # dependent under -n<N> --dist load -> flaky). Restore both CA dirs to
        # 0755: still traversable/readable by the stock server-as-`nobody`, but no
        # longer "excessive" so TLS client init accepts them.
        subprocess.run(["chmod", "0755", pki["certs"]], check=False)
        subprocess.run(["chmod", "0755", pki["both_ca"]], check=False)
        xrd_cmd += ["-R", "nobody"]
    proc = subprocess.Popen(xrd_cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    _wait_listen(proc, port, "stock xrootd")
    return proc


@pytest.fixture(scope="module")
def stock_root(pki):
    """A throwaway stock xrootd GSI server (for native-client interop)."""
    proc = _start_stock_gsi(pki, P_STOCK_ROOT, pki["hostcert"], pki["hostkey"],
                            pki["certs"], "stock.cfg")
    yield {"url": f"root://{pki['fqdn']}:{P_STOCK_ROOT}"}
    _terminate(proc)


@pytest.fixture(scope="module")
def stock_root_foreign_ca(pki):
    """A stock xrootd GSI server whose HOST cert is signed by a CA distinct from
    the client's proxy CA (it trusts BOTH via the both_ca CApath). It advertises
    its own (foreign) CA in the gsi ca: hint, so a client that echoes that hint
    as its issuer hash is rejected with 'chain is inconsistent' — the exact
    condition our native client hit at UK e-Science CA 2B grid sites."""
    proc = _start_stock_gsi(pki, P_STOCK_ROOT_FCA, pki["foreign_hostcert"],
                            pki["foreign_hostkey"], pki["both_ca"],
                            "stock_fca.cfg")
    yield {"url": f"root://{pki['fqdn']}:{P_STOCK_ROOT_FCA}"}
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
