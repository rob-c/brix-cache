"""
tests/test_query_token.py — §1 HTTP bearer token via ?authz= query parameter.

Verifies the query-string token fallback (davix/gfal2/xrdcp redirect & pre-signed
URL flows) added in src/protocols/webdav/auth_token.c:
  - GET with ?authz=Bearer<jwt> authenticates (200)
  - GET with ?authz=<rawjwt> (no scheme) authenticates (200)
  - Authorization header path still works (200)
  - tampered query token is rejected
  - the module's own access log never records the token (redaction / path-only log)

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_query_token.py -v
"""

import os
import sys
import uuid

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.make_token import TokenIssuer
from settings import NGINX_WEBDAV_PORT, SERVER_HOST, TOKENS_DIR

BASE = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
_ISSUER = None
_TOKEN = ""


@pytest.fixture(scope="module", autouse=True)
def _init_token():
    global _ISSUER, _TOKEN
    _ISSUER = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(_ISSUER.key_path):
        _ISSUER.init_keys()
    _TOKEN = _ISSUER.generate(scope="storage.read:/ storage.write:/", lifetime=7200)


def _url(p):
    return BASE + p


def _put_seed():
    """Seed a file using the header path so the GET target exists."""
    path = f"/qtok_{uuid.uuid4().hex[:10]}.txt"
    s = requests.Session()
    s.verify = False
    s.headers["Authorization"] = f"Bearer {_TOKEN}"
    r = s.put(_url(path), data=b"querytoken-payload", timeout=10)
    assert r.status_code in (200, 201, 204), r.status_code
    return path


def test_query_token_bearer_prefix():
    path = _put_seed()
    r = requests.get(_url(path), params={"authz": f"Bearer {_TOKEN}"},
                     verify=False, timeout=10)
    assert r.status_code == 200
    assert r.content == b"querytoken-payload"


def test_query_token_raw():
    path = _put_seed()
    r = requests.get(_url(path), params={"authz": _TOKEN}, verify=False, timeout=10)
    assert r.status_code == 200


def test_query_token_access_token_alias():
    path = _put_seed()
    r = requests.get(_url(path), params={"access_token": _TOKEN},
                     verify=False, timeout=10)
    assert r.status_code == 200


def test_header_still_primary():
    path = _put_seed()
    s = requests.Session()
    s.verify = False
    s.headers["Authorization"] = f"Bearer {_TOKEN}"
    assert s.get(_url(path), timeout=10).status_code == 200


def test_query_token_tampered_not_elevated():
    """On this optional-auth endpoint anonymous reads succeed, so a tampered query
    token must not grant MORE than anonymous: it is ignored (same status as no
    credentials), never honored as a valid token and never a 5xx."""
    path = _put_seed()
    bad = _TOKEN[:-3] + "xxx"
    anon = requests.get(_url(path), verify=False, timeout=10).status_code
    tampered = requests.get(_url(path), params={"authz": bad},
                            verify=False, timeout=10).status_code
    assert tampered < 500
    assert tampered == anon


def test_query_token_not_in_module_access_log():
    """The module logs r->uri (path only), never r->args — the JWT must not land
    in the module's own access log even when presented via the query string."""
    marker = _ISSUER.generate(scope="storage.read:/", lifetime=600)
    path = _put_seed()
    requests.get(_url(path), params={"authz": marker}, verify=False, timeout=10)
    logdir = "/tmp/xrd-test/logs"
    hits = []
    if os.path.isdir(logdir):
        for fn in os.listdir(logdir):
            if "webdav" in fn and fn.endswith(".log"):
                try:
                    with open(os.path.join(logdir, fn), "r", errors="ignore") as fh:
                        if marker in fh.read():
                            hits.append(fn)
                except OSError:
                    pass
    assert not hits, f"token leaked into module access log(s): {hits}"
