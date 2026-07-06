"""WLCG token conformance — multi-issuer / base_path enforcement (ISS family).

Probes port 11251 (nginx_token_registry.conf) which loads scitokens.cfg with
two issuers:
  atlas: issuer https://atlas.example.com, base_path /atlas, jwks = jwks.json
  cms:   issuer https://cms.example.com,   base_path /cms,   jwks = jwks.json

Both issuers use the MAIN signing key so TokenForge.for_issuer(iss) tokens
verify under the matching issuer entry.  The authz model (phase-59 W1) validates
the JWT against the matched issuer's JWKS, then enforces that the request path
falls under that issuer's base_path before checking capability scope.

Cases:
  ISS-01  atlas token, path /atlas/ok.txt    → accept  (in-base, scope covers)
  ISS-02  atlas token, path /cms/ok.txt      → reject  (§3.1: not under /atlas)
  ISS-03  cms token,   path /cms/ok.txt      → accept  (in-base, scope covers)
  ISS-04  cms token,   path /atlas/ok.txt    → reject  (§3.1: not under /cms)
  ISS-05  evil issuer, path /atlas/ok.txt    → reject  (issuer absent from registry)
  ISS-06  atlas token, path /test.txt        → reject  (/test.txt not under /atlas)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data, _CONFORMANCE_FILES
from settings import NGINX_TOKEN_REGISTRY_PORT as REG, TOKENS_DIR, DATA_ROOT

# The dedicated token-registry nginx instance uses its own data root (separate
# from the shared fleet DATA_ROOT) so that its brix_storage_backend is isolated.
# Derived from DATA_ROOT following the manage_test_servers "data-<name>" convention.
_REGISTRY_DATA_ROOT = os.path.join(os.path.dirname(DATA_ROOT), "data-token-registry")


def _ensure_registry_data():
    """Create fixture files in the registry server's dedicated data root.

    WHAT: Mirrors ensure_conformance_data() but targets data-token-registry
          rather than the shared fleet data root.
    WHY:  The dedicated token-registry nginx instance uses a separate
          brix_storage_backend root so stat requests land there, not in
          the shared data tree.
    HOW:  Idempotent (skips existing files); creates parent directories.
    """
    for rel, body in _CONFORMANCE_FILES.items():
        path = os.path.join(_REGISTRY_DATA_ROOT, rel)
        if os.path.exists(path):
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)


def _forge():
    return TokenForge(TOKENS_DIR)


@pytest.fixture(autouse=True)
def _data():
    ensure_conformance_data()
    _ensure_registry_data()


@pytest.mark.tokenconf
def test_iss01_atlas_in_base():
    """Atlas token, path /atlas/ok.txt — in-base accept.

    Token iss matches the atlas registry entry; /atlas/ok.txt is under base_path
    /atlas; scope storage.read:/ covers the path.  Must accept.
    """
    token = _forge().for_issuer("https://atlas.example.com")
    assert root_ztn(token, "/atlas/ok.txt", port=REG) == "accept"


@pytest.mark.tokenconf
def test_iss02_atlas_out_of_base():
    """Atlas token, path /cms/ok.txt — §3.1 base_path enforcement rejects.

    Token iss matches the atlas entry (base_path /atlas); /cms/ok.txt is NOT
    under /atlas, so brix_token_issuer_path_ok must reject before scope check.
    """
    token = _forge().for_issuer("https://atlas.example.com")
    assert root_ztn(token, "/cms/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_iss03_cms_in_base():
    """CMS token, path /cms/ok.txt — in-base accept.

    Token iss matches the cms registry entry; /cms/ok.txt is under base_path
    /cms; scope storage.read:/ covers the path.  Must accept.
    """
    token = _forge().for_issuer("https://cms.example.com")
    assert root_ztn(token, "/cms/ok.txt", port=REG) == "accept"


@pytest.mark.tokenconf
def test_iss04_cms_out_of_base():
    """CMS token, path /atlas/ok.txt — §3.1 base_path enforcement rejects.

    Token iss matches the cms entry (base_path /cms); /atlas/ok.txt is NOT
    under /cms, so brix_token_issuer_path_ok must reject before scope check.
    """
    token = _forge().for_issuer("https://cms.example.com")
    assert root_ztn(token, "/atlas/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_iss05_unknown_issuer():
    """Unknown issuer — registry lookup fails, must reject.

    https://evil.example.com has no entry in scitokens.cfg; the registry
    returns no match so the token is rejected at lookup before any JWKS verify
    or path check.
    """
    token = _forge().for_issuer("https://evil.example.com")
    assert root_ztn(token, "/atlas/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_iss06_atlas_token_root_path():
    """Atlas token, path /test.txt — outside base_path /atlas, must reject.

    /test.txt is not under /atlas so even a validly-signed atlas token with
    broad scope must be rejected by the base_path check (§3.1).
    """
    token = _forge().for_issuer("https://atlas.example.com")
    assert root_ztn(token, "/test.txt", port=REG) == "reject"
