"""Phase-85 F3 — token-gated (private) CVMFS repos: brix_cvmfs_repo_authz.

Theme
-----
``brix_cvmfs_repo_authz <repo|*> <scitokens.cfg>`` requires a valid WLCG/
SciToken (READ scope, validated against the named issuer registry — the same
engine as the WebDAV/scvmfs token paths) before ANY class of request for that
repo is served: CAS, signed metadata, and geo alike. Contract:

* valid READ-scope bearer → served exactly as an open repo;
* missing / garbage / out-of-scope bearer → 401 + guard-core audit line
  ``signal=authfail proto=cvmfs`` (fail2ban [xrootd-guard-authfail] jail);
* a gated repo on a cleartext connection → 400 — bearer-on-cleartext would
  put the token on the wire (mirrors the scvmfs transport gate);
* repos NOT matched by any brix_cvmfs_repo_authz entry stay world-readable —
  the directive absent or non-matching is exactly today's open behavior;
* ``*`` gates every repo the location serves.

Port block 13280-13299 (mocks 13280-13289, nginx 13290-13299).
"""

import itertools
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import NGINX_BIN, PortBlock, srv_instance

try:                                     # cryptography is an optional test dep
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                        # noqa: BLE001
    _HAVE_TOKENFORGE = False

REPO = "test.cern.ch"

requires_openssl = pytest.mark.skipif(shutil.which("openssl") is None,
                                      reason="openssl not installed")
requires_tokens = pytest.mark.skipif(not _HAVE_TOKENFORGE,
                                     reason="tokenforge (cryptography) unavailable")

pytestmark = [
    pytest.mark.skipif(not os.path.exists(NGINX_BIN),
                       reason=f"nginx binary not found: {NGINX_BIN}"),
    requires_openssl, requires_tokens,
]


class _FixedBlock(PortBlock):
    def __init__(self, mock_port: int, nginx_port: int):
        super().__init__("srv_authz")
        self._mp, self._np = mock_port, nginx_port

    def mock(self) -> int:
        return self._mp

    def nginx(self) -> int:
        return self._np


_PAIRS = itertools.cycle([(13280 + i, 13290 + i) for i in range(10)])


@pytest.fixture(scope="module")
def tls_identity(tmp_path_factory):
    d = tmp_path_factory.mktemp("authz_tls")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", str(d / "key.pem"),
         "-out", str(d / "crt.pem")],
        check=True, capture_output=True)
    return d / "crt.pem", d / "key.pem"


@pytest.fixture(scope="module")
def mint(tmp_path_factory):
    """Local RS256 mint + the scitokens.cfg registry the server loads."""
    d = tmp_path_factory.mktemp("authz_tokens")
    forge = TokenForge(str(d))
    forge.init_keys()
    cfg = d / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "repo-authz", "issuer": forge.issuer, "audience": forge.audience,
        "base_paths": ["/"], "jwks_path": forge.jwks_path,
        "strategy": "capability",
    }])
    return forge, cfg


@contextmanager
def _srv(gate, cfg, tls=None, **kw):
    """cvmfs instance with brix_cvmfs_repo_authz `<gate> <cfg>`; TLS optional."""
    mock_port, nginx_port = next(_PAIRS)
    if gate is not None:
        kw["extra_directives"] = f"brix_cvmfs_repo_authz {gate} {cfg};"
    if tls is not None:
        kw["ssl_cert"], kw["ssl_key"] = tls
    with srv_instance(_FixedBlock(mock_port, nginx_port), objects=4, **kw) as srv:
        yield srv


def _fetch(port, path, *, https, token=None):
    scheme = "https" if https else "http"
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}{path}")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    kw = {"context": ssl._create_unverified_context()} if https else {}
    try:
        with urllib.request.urlopen(req, timeout=15, **kw) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _authfail_lines(srv):
    text = Path(srv.error_log).read_text(errors="replace")
    return [l for l in text.splitlines()
            if "signal=authfail" in l and "proto=cvmfs" in l]


# ---- success ---------------------------------------------------------------

def test_valid_token_serves(tls_identity, mint):
    forge, cfg = mint
    with _srv(REPO, cfg, tls=tls_identity) as srv:
        obj = srv.objects()[0]
        st, body = _fetch(srv.nginx_port, obj, https=True, token=forge.generate())
        assert st == 200 and body
        st, _ = _fetch(srv.nginx_port, f"/cvmfs/{REPO}/.cvmfspublished",
                       https=True, token=forge.generate())
        assert st == 200
        assert _authfail_lines(srv) == []


def test_unmatched_repo_stays_open(tls_identity, mint):
    """Gating other.repo.io leaves REPO world-readable — absent match is
    exactly the open phase-84 behavior."""
    _forge, cfg = mint
    with _srv("other.repo.io", cfg, tls=tls_identity) as srv:
        st, body = _fetch(srv.nginx_port, srv.objects()[0], https=True)
        assert st == 200 and body


# ---- error: unauthenticated access refused + audited -----------------------

def test_missing_token_401_authfail(tls_identity, mint):
    _forge, cfg = mint
    with _srv(REPO, cfg, tls=tls_identity) as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], https=True)
        assert st == 401
        assert _authfail_lines(srv), "expected a signal=authfail audit line"


def test_garbage_token_401(tls_identity, mint):
    _forge, cfg = mint
    with _srv(REPO, cfg, tls=tls_identity) as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], https=True,
                       token="not.a.token")
        assert st == 401
        assert _authfail_lines(srv)


# ---- security-negative -----------------------------------------------------

def test_scopeless_token_401(tls_identity, mint):
    """A structurally valid, correctly signed token WITHOUT a storage scope
    must not open a gated repo (capability strategy: scope is the grant)."""
    forge, cfg = mint
    with _srv(REPO, cfg, tls=tls_identity) as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], https=True,
                       token=forge.no_scope())
        assert st == 401
        assert _authfail_lines(srv)


def test_wildcard_gates_every_repo(tls_identity, mint):
    forge, cfg = mint
    with _srv("*", cfg, tls=tls_identity) as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], https=True)
        assert st == 401
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], https=True,
                       token=forge.generate())
        assert st == 200


def test_cleartext_gated_repo_refused(mint):
    """A gated repo must never accept (or solicit) a bearer over cleartext —
    the transport gate answers 400 before any token is examined."""
    forge, cfg = mint
    with _srv(REPO, cfg, tls=None) as srv:
        st, _ = _fetch(srv.nginx_port, srv.objects()[0], https=False,
                       token=forge.generate())
        assert st == 400
