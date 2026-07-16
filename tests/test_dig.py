"""
tests/test_dig.py — §3 XrdDig remote diagnostics (security-first).

Self-provisions a WebDAV server with a dig export + a principal→export allow-file
(JWT auth via a test JWKS) and asserts the security envelope BEFORE any convenience:

  * authorized principal reads a whitelisted file              -> 200 + content
  * authenticated-but-unlisted principal                       -> 403
  * anonymous (no credential)                                  -> 403  (fail-closed)
  * symlink escape out of the export (RESOLVE_BENEATH/NOFOLLOW)-> 403
  * unknown export name                                        -> 404
  * write method on a dig path                                 -> 405  (read-only)
  * dig disabled                                               -> 404  (falls through)

Throwaway nginx instances come from the registry lifecycle harness.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_dig.py -v
"""

import os
from pathlib import Path

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from utils.make_token import TokenIssuer  # noqa: E402
from settings import NGINX_BIN, HOST, BIND_HOST, TOKENS_DIR  # noqa: E402
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness


def _issuer():
    iss = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(iss.key_path) or not os.path.exists(iss.jwks_path):
        iss.init_keys()
    return iss


def _start(lifecycle, tmp_path, name, dig_on):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")
    iss = _issuer()
    cadir = tmp_path / "cadir"
    cadir.mkdir()
    # The dig export tree + a secret OUTSIDE it + a symlink escaping the export.
    exp = tmp_path / "export"
    exp.mkdir()
    (exp / "server.cfg").write_text("DIG-CONFIG-CONTENT\n")
    (tmp_path / "outside.txt").write_text("OUTSIDE-SECRET\n")
    try:
        os.symlink(str(tmp_path / "outside.txt"), str(exp / "escape"))
    except OSError:
        pass
    allow = tmp_path / "dig.allow"
    allow.write_text("# principal export\ndiguser conf\n")

    dig = (f"brix_webdav_dig on;\n"
           f"            brix_webdav_dig_export conf {exp};\n"
           f"            brix_webdav_dig_auth {allow};") if dig_on else ""
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_dig.conf",
        protocol="http",
        template_values={
            "BIND_HOST": BIND_HOST,
            "CADIR": str(cadir),
            "JWKS_PATH": iss.jwks_path,
            "ISSUER": iss.issuer,
            "AUDIENCE": iss.audience,
            "DIG_DIRECTIVES": dig,
        },
        reason="XrdDig remote-diagnostics security envelope"))
    return endpoint.port, iss


@pytest.fixture
def dig_server(lifecycle, tmp_path):
    return _start(lifecycle, tmp_path, "lc-dig", dig_on=True)


@pytest.fixture
def dig_off_server(lifecycle, tmp_path):
    return _start(lifecycle, tmp_path, "lc-dig-off", dig_on=False)


def _get(port, path, sub=None, iss=None):
    h = {}
    if sub is not None:
        h["Authorization"] = f"Bearer {iss.generate(sub=sub, scope='storage.read:/')}"
    return requests.get(f"http://{HOST}:{port}{path}", headers=h, timeout=10)


def test_authorized_principal_reads(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/conf/server.cfg", sub="diguser", iss=iss)
    assert r.status_code == 200, r.status_code
    assert r.text == "DIG-CONFIG-CONTENT\n"


def test_unlisted_principal_forbidden(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/conf/server.cfg", sub="otheruser", iss=iss)
    assert r.status_code == 403, r.status_code


def test_anonymous_forbidden(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/conf/server.cfg")
    assert r.status_code == 403, r.status_code


def test_symlink_escape_blocked(dig_server):
    port, iss = dig_server
    # 'escape' is a symlink to a file OUTSIDE the export; RESOLVE_BENEATH/NOFOLLOW
    # must refuse it even for an authorized principal.
    r = _get(port, "/.well-known/dig/conf/escape", sub="diguser", iss=iss)
    assert r.status_code in (403, 404), r.status_code
    assert "OUTSIDE-SECRET" not in r.text


def test_unknown_export_not_found(dig_server):
    port, iss = dig_server
    r = _get(port, "/.well-known/dig/nope/server.cfg", sub="diguser", iss=iss)
    assert r.status_code == 404, r.status_code


def test_write_method_rejected(dig_server):
    port, iss = dig_server
    tok = iss.generate(sub="diguser", scope="storage.read:/ storage.write:/")
    r = requests.put(f"http://{HOST}:{port}/.well-known/dig/conf/server.cfg",
                     data=b"x", headers={"Authorization": f"Bearer {tok}"},
                     timeout=10)
    assert r.status_code == 405, r.status_code


def test_dig_disabled_falls_through(dig_off_server):
    port, iss = dig_off_server
    r = _get(port, "/.well-known/dig/conf/server.cfg", sub="diguser", iss=iss)
    # dig off → not handled as dig; normal WebDAV has no such file → 404
    assert r.status_code == 404, r.status_code
