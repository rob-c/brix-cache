"""
test_audit15b_webdav_token_config.py — live coverage for
`brix_token_config` (audit §A1, testsuite-combinatorial-coverage-audit
2026-08-15: a genuine plane-parity hole — the stream twin `brix_token_config`
is tested via nginx_token_registry.conf, the separately named, separately
parsed WebDAV directive never was).

The directive loads a scitokens.cfg issuer registry
(src/auth/token/issuer_registry.c via the WebDAV proxy conf) and turns Bearer
JWTs into the auth decision for the location.  The three cases:

  * registered issuer, capability scope covering the path  -> 200
  * token signed for an UNREGISTERED issuer                -> rejected (an
    issuer outside the registry must never authenticate, valid signature or not)
  * no token at all under brix_webdav_auth required        -> rejected
"""

import os

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from port_ladder import PORT_LAST

try:
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                       # noqa: BLE001 — cryptography optional
    _HAVE_TOKENFORGE = False

pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group("lc-audit15b-webdav-tokcfg"),
    pytest.mark.skipif(not _HAVE_TOKENFORGE,
                       reason="tokenforge (cryptography) unavailable"),
]

SEED_BODY = "token-config-payload\n"


@pytest.fixture()
def dav(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    mint = tmp_path / "mint"
    forge = TokenForge(str(mint))
    forge.init_keys()
    cfg = mint / "scitokens.cfg"
    write_scitokens_cfg(str(cfg), [{
        "name": "dav-parity", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])

    data = tmp_path / "data"
    data.mkdir()
    (data / "test.txt").write_text(SEED_BODY)
    cadir = tmp_path / "cadir"
    cadir.mkdir()

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15b-webdav-tokcfg-reload",
        template="nginx_lc_webdav_token_config.conf",
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "CADIR": str(cadir), "TOKEN_CFG": str(cfg)},
        port=PORT_LAST + 1,
        reason="audit-15b webdav token_config plane parity"))
    return ep.port, forge


def _get(port, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(f"http://{HOST}:{port}/test.txt",
                        headers=headers, timeout=10)


def test_registered_issuer_token_authenticates(dav):
    port, forge = dav
    r = _get(port, forge.generate(sub="alice", scope="storage.read:/"))
    assert r.status_code == 200, (r.status_code, r.text[:200])
    assert r.text == SEED_BODY


def test_unregistered_issuer_rejected(dav):
    # Security-negative: same signing key, same claims shape, but an issuer
    # the registry does not list — must fail issuer lookup, not fall through
    # to a signature-only check.
    port, forge = dav
    r = _get(port, forge.for_issuer("https://evil.example.org"))
    assert r.status_code in (401, 403), \
        f"token from an unregistered issuer authenticated: {r.status_code}"


def test_missing_token_rejected(dav):
    port, _ = dav
    r = _get(port)
    assert r.status_code in (401, 403), \
        f"anonymous request served under brix_webdav_auth required: {r.status_code}"
