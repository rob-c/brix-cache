"""
test_audit15c_webdav_introspection.py — WebDAV bearer-token introspection
(RFC 7662) live coverage (audit §A2, testsuite-combinatorial-coverage-audit
2026-08-15: `brix_token_introspect_loc/_ttl/_fail_open` and
`brix_webdav_revoke_cache` had config-parse tests only, zero live requests).

The subject proxies its introspection subrequests (src/protocols/webdav/
introspect.c: internal location + `token=` arg, completion requires an
upstream) to a colocated mock IdP — a plain nginx server in the same process
answering `{"active": false}` only for one exact token value.  Cases:

  * success — a bearer the IdP calls active passes through to the file
  * security-negative — a revoked bearer is refused 403 twice, the second
    refusal served from the revoke cache (negative-result caching, log pin)
  * gate — a request with no bearer never consults the introspector
  * policy — a dead introspector refuses (fail-closed) or admits (fail-open)
    per brix_token_introspect_fail_open
"""

from pathlib import Path

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15c-introspect")]

PAYLOAD = b"introspected-file-body\n"
REVOKED = "revoked-tok-audit15c"


@pytest.fixture()
def isp(lifecycle, tmp_path):
    data = tmp_path / "data"
    (data / "fc").mkdir(parents=True)
    (data / "fo").mkdir()
    for rel in ("hello.txt", "fc/hello.txt", "fo/hello.txt"):
        (data / rel).write_bytes(PAYLOAD)
    return lifecycle.start(NginxInstanceSpec(
        name="lc-audit15c-introspect",
        template="nginx_audit15c_introspect.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": HOST, "DATA_DIR": str(data),
                         "REVOKED_TOKEN": REVOKED},
        reason="audit-15c webdav token introspection live coverage"))


def _get(port, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.get(f"http://{HOST}:{port}{path}",
                        headers=headers, timeout=10)


def test_active_token_admitted(isp):
    r = _get(isp.port, "/hello.txt", "active-tok-audit15c")
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.content == PAYLOAD


def test_revoked_token_refused_then_cache_hit(isp):
    assert _get(isp.port, "/hello.txt", REVOKED).status_code == 403
    # Within introspect_ttl the negative result must come from the revoke
    # cache, not a second IdP roundtrip.
    assert _get(isp.port, "/hello.txt", REVOKED).status_code == 403
    log = (Path(isp.prefix) / "logs" / "error.log").read_text()
    assert "revocation cache hit" in log, log[-2000:]


def test_no_bearer_skips_introspection(isp):
    # The handler gates on an Authorization: Bearer header; a bare request on
    # an auth-none location must not be routed through the introspector.
    r = _get(isp.port, "/hello.txt")
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.content == PAYLOAD


def test_dead_introspector_fail_closed(isp):
    r = _get(isp.port, "/fc/hello.txt", "any-tok")
    assert r.status_code == 403, (r.status_code, r.text)


def test_dead_introspector_fail_open(isp):
    r = _get(isp.port, "/fo/hello.txt", "any-tok")
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.content == PAYLOAD
