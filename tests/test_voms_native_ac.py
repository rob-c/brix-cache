"""
tests/test_voms_native_ac.py

End-to-end pins for the native VOMS attribute-certificate verifier
(shared/voms/) behind ``brix_require_vo``: a live GSI server with a vomsdir
must admit a proxy whose AC verifies and refuse every proxy whose AC fails a
check — with no VOMS library on the host (these tests used to skip wherever
``libvomsapi.so.1`` was absent; they run everywhere now).

Topology — the registry's dedicated ``vo-acl`` member (tests/configs/
nginx_vo_acl.conf on VO_PORT), exactly as tests/test_vo_acl.py uses it:

    brix_auth gsi;  brix_vomsdir {VOMSDIR};  brix_voms_cert_dir {CA_DIR};
    brix_require_vo /cms cms;  brix_require_vo /atlas atlas;  # /public open

Credentials (utils/voms_proxy_fake.py; the session fixture from
_test_vo_acl_helpers builds the VOMS signing cert, the vomsdir LSC and the
good proxies):

  good        proxy_cms.pem — AC for cms signed by voms.test.local, named in
                              vomsdir/cms/voms.test.local.lsc
  rogue       AC signed by a DIFFERENT certificate (rogue.test.local, also
              issued by the test CA — so the chain check passes and only the
              LSC match can refuse it)
  expired     AC notAfter one hour in the past (-ac-hours -1); the proxy
              certificate itself is still valid, so GSI still authenticates
  holder      AC holder names a serial that is not the user certificate's
              (-holder-serial) — an AC lifted from someone else's proxy

Each bad proxy is a valid GSI credential: only the AC is wrong, so the server
must authenticate the user and then deny the VO-scoped path (no VO extracted).

Two more SHAPES of a good credential (utils/voms_proxy_fake.py knobs) must be
admitted exactly like proxy_cms.pem:

  delegated   -delegate: a second-level proxy signed by the VOMS proxy, with no
              VOMS extension of its own — the AC sits on chain index 1 and the
              engine collects it from there (brix_voms_retrieve walks every
              carrier; the holder binds two hops up, at the EEC)
  legacy      -legacy-proxy: a GT2-style proxy (subject = user DN + CN=proxy, no
              proxyCertInfo) — the engine's EEC walk recognises the legacy
              shape (pinned by test_voms_corner_cases.py) and, since
              brix_gsi_legacy_proxy (default on), the server's GSI chain
              check marks GT2 proxies for OpenSSL so the login succeeds

    cd tests && PYTHONPATH=$PWD:$PWD/../brixtest/src ../.venv/bin/python \\
        -m pytest test_voms_native_ac.py -q -p no:cacheprovider
"""

import os
import subprocess

import pytest

from settings import CA_DIR, PKI_DIR, PROXY_CMS, USER_CERT, USER_KEY, VOMS_CERT, VOMS_KEY
from split_continuation import reexport as _reexport

# vo_nginx (session fixture), VOMS_PROXY_FAKE, _pki_lock, _xrdfs_stat, _xrdcp_read, ...
_reexport(globals(), "_test_vo_acl_helpers")

ROGUE_CERT = os.path.join(PKI_DIR, "voms", "roguecert.pem")
ROGUE_KEY = os.path.join(PKI_DIR, "voms", "roguekey.pem")
BAD_DIR = os.path.join(PKI_DIR, "user")
# One directory per xdist worker: the module fixture runs in every worker, and
# two workers minting the same file names would race each other's reads.
BAD_DIR = os.path.join(BAD_DIR, os.environ.get("PYTEST_XDIST_WORKER", "main"))


def _run(argv):
    subprocess.run(argv, check=True, capture_output=True)


def _make_rogue_signing_cert():
    """A second VOMS signing cert from the SAME test CA under another name:
    chains fine against brix_voms_cert_dir, but no LSC names it."""
    with _pki_lock(VOMS_CERT):   # same lock as the real signer: shared ca.srl
        if not (os.path.exists(ROGUE_CERT) and os.path.exists(ROGUE_KEY)):
            _make_rogue_signing_cert_locked()


def _make_rogue_signing_cert_locked():
    csr = ROGUE_CERT.replace(".pem", ".csr")
    ext = ROGUE_CERT.replace(".pem", "_ext.conf")
    with open(ext, "w") as fh:
        fh.write("[voms_ext]\nsubjectKeyIdentifier = hash\n"
                 "authorityKeyIdentifier = keyid:always\nbasicConstraints = CA:FALSE\n")
    _run(["openssl", "genrsa", "-out", ROGUE_KEY, "2048"])
    _run(["openssl", "req", "-new", "-key", ROGUE_KEY,
          "-subj", "/DC=test/DC=xrootd/CN=rogue.test.local", "-out", csr])
    _run(["openssl", "x509", "-req", "-in", csr, "-CA", f"{CA_DIR}/ca.pem",
          "-CAkey", f"{CA_DIR}/ca.key", "-CAcreateserial", "-out", ROGUE_CERT,
          "-days", "365", "-extensions", "voms_ext", "-extfile", ext])


def _fake_proxy(out, hostcert, hostkey, *extra):
    _run(VOMS_PROXY_FAKE + [
        "-cert", USER_CERT, "-key", USER_KEY, "-certdir", CA_DIR,
        "-hostcert", hostcert, "-hostkey", hostkey,
        "-voms", "cms", "-fqan", "/cms/Role=NULL/Capability=NULL",
        "-uri", "voms.test.local:15000", "-out", out, "-hours", "24", *extra])


@pytest.fixture(scope="module")
def bad_proxies(vo_nginx):
    """The three bad credentials, minted after the session fixture has built
    the signing cert + vomsdir the good proxy is verified against."""
    os.makedirs(BAD_DIR, exist_ok=True)
    _make_rogue_signing_cert()
    rogue = os.path.join(BAD_DIR, "proxy_cms_rogue_signer.pem")
    expired = os.path.join(BAD_DIR, "proxy_cms_expired_ac.pem")
    holder = os.path.join(BAD_DIR, "proxy_cms_wrong_holder.pem")
    _fake_proxy(rogue, ROGUE_CERT, ROGUE_KEY)
    _fake_proxy(expired, VOMS_CERT, VOMS_KEY, "-ac-hours", "-1")
    _fake_proxy(holder, VOMS_CERT, VOMS_KEY, "-holder-serial", "424242")
    return {"rogue": rogue, "expired": expired, "holder": holder}


@pytest.fixture(scope="module")
def shaped_proxies(vo_nginx):
    """Good ACs on unusual proxy shapes, plus the security partner: a delegated
    proxy whose parent AC is expired."""
    os.makedirs(BAD_DIR, exist_ok=True)
    delegated = os.path.join(BAD_DIR, "proxy_cms_delegated.pem")
    legacy = os.path.join(BAD_DIR, "proxy_cms_legacy_gt2.pem")
    delegated_expired = os.path.join(BAD_DIR, "proxy_cms_delegated_expired_ac.pem")
    _fake_proxy(delegated, VOMS_CERT, VOMS_KEY, "-delegate")
    _fake_proxy(legacy, VOMS_CERT, VOMS_KEY, "-legacy-proxy")
    _fake_proxy(delegated_expired, VOMS_CERT, VOMS_KEY, "-delegate", "-ac-hours", "-1")
    return {"delegated": delegated, "legacy": legacy, "delegated_expired": delegated_expired}


# --- success: a verifying AC yields the VO -----------------------------------

@pytest.mark.registry_server("vo-acl")
def test_good_ac_is_admitted(vo_nginx):
    """The genuine credential: the AC verifies (holder, window, signature,
    chain, LSC), VO cms is extracted, /cms is served and /public too."""
    assert _xrdfs_stat("/cms", PROXY_CMS) == 0
    assert _xrdcp_read("/cms/seed.txt", PROXY_CMS) == 0
    assert _xrdfs_stat("/public", PROXY_CMS) == 0


@pytest.mark.registry_server("vo-acl")
def test_good_ac_does_not_grant_other_vos(vo_nginx):
    """Error partner: the VO comes from the AC, not from 'some AC verified' —
    the cms credential is still refused the atlas subtree."""
    assert _xrdfs_stat("/atlas", PROXY_CMS) != 0


# --- security-negative: every failed check means no VO -----------------------

@pytest.mark.registry_server("vo-acl")
@pytest.mark.parametrize("kind", ["rogue", "expired", "holder"])
def test_bad_ac_is_refused_the_vo_path(bad_proxies, kind):
    """An AC signed by a certificate no LSC names, an expired AC, and an AC
    bound to another holder each verify as NOT cms: /cms is refused."""
    assert _xrdfs_stat("/cms", bad_proxies[kind]) != 0
    assert _xrdcp_read("/cms/seed.txt", bad_proxies[kind]) != 0


@pytest.mark.registry_server("vo-acl")
@pytest.mark.parametrize("kind", ["rogue", "expired", "holder"])
def test_bad_ac_is_denied_write_too(bad_proxies, kind):
    """The denial covers writes: a bad AC never lands a file under /cms."""
    assert _xrdcp_write(b"must not land\n", f"/cms/bad_{kind}.txt",
                        bad_proxies[kind]) != 0


@pytest.mark.registry_server("vo-acl")
@pytest.mark.parametrize("kind", ["rogue", "expired", "holder"])
def test_bad_ac_is_still_a_valid_gsi_login(bad_proxies, kind):
    """Only the AC is wrong: the proxy chain itself verifies, so the user is
    authenticated with NO VO — served under /public, refused under /cms.
    This pins that the denials above are VO decisions, not a broken login."""
    assert _xrdfs_stat("/public", bad_proxies[kind]) == 0


# --- proxy shapes: the AC is found wherever it sits on the chain ------------

@pytest.mark.registry_server("vo-acl")
def test_delegated_proxy_keeps_parent_ac(shaped_proxies):
    """A delegated proxy (AC on chain index 1, holder two hops up at the EEC)
    carries the same verifying AC: VO cms is extracted and /cms is served."""
    assert _xrdfs_stat("/cms", shaped_proxies["delegated"]) == 0
    assert _xrdcp_read("/cms/seed.txt", shaped_proxies["delegated"]) == 0


@pytest.mark.registry_server("vo-acl")
def test_delegated_proxy_does_not_grant_other_vos(shaped_proxies):
    """Error partner: the shape changes nothing about WHICH VO the AC names."""
    assert _xrdfs_stat("/atlas", shaped_proxies["delegated"]) != 0


@pytest.mark.registry_server("vo-acl")
def test_delegated_proxy_of_expired_ac_is_refused(shaped_proxies):
    """Security-negative: delegating does not launder an expired parent AC —
    the login still works (/public) but /cms is refused."""
    assert _xrdfs_stat("/public", shaped_proxies["delegated_expired"]) == 0
    assert _xrdfs_stat("/cms", shaped_proxies["delegated_expired"]) != 0


@pytest.mark.registry_server("vo-acl")
def test_legacy_gt2_proxy_is_admitted(shaped_proxies):
    """A GT2-style proxy must log in (/public), be granted its VO (/cms) and
    nothing else (/atlas) — exactly like the RFC 3820 proxy."""
    assert _xrdfs_stat("/public", shaped_proxies["legacy"]) == 0
    assert _xrdfs_stat("/cms", shaped_proxies["legacy"]) == 0
    assert _xrdfs_stat("/atlas", shaped_proxies["legacy"]) != 0
