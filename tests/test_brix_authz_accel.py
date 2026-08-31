"""brix as an authorization brain for locations it does not serve
(phase-106 W4 auth_request, W3 X-Accel-Redirect).

Before this, brix's authz corpus — WLCG tokens, VOMS FQANs, macaroons, GSI
chains, ZTN — was unreachable unless brix also served the bytes: adoption was
all-or-nothing. These two seams let an operator keep their data path and put
brix's authorization in front of it.

Neither seam performs an authorization check of its own. nginx runs the ACCESS
phase before CONTENT, and webdav's access handler has by then already run
`access_authenticate()` plus the write-method / token-scope / XrdAcc gates,
answering 401/403 itself on refusal. Reaching the content phase IS the verdict.
The tests below are written to hold that property to account.

  * success   — brix admits, and the plain nginx location serves the bytes
                (W4); brix decides and hands off to an `internal` location
                which serves the bytes (W3)
  * error     — a refusing authz target denies the outer location, and the
                refusal is the ACCESS phase's own status
  * security  — the internal targets are unreachable from outside; a client
                cannot forge the handoff by sending X-Accel-Redirect itself;
                and no credential material is echoed in any response header

Run:
    PYTHONPATH=tests pytest tests/test_brix_authz_accel.py -v
"""

from __future__ import annotations

import http.client
import os
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-brix-authz-accel")]

TEMPLATE = "nginx_lc_brix_authz_accel.conf"
BODY = b"phase-106 authz/accel probe\n"

# Anything that would mean a credential reached a response header. An
# auth_request consumer copies these onward with auth_request_set, so a leak
# here is a leak into somebody's upstream.
CREDENTIAL_MARKERS = ("authorization", "bearer", "token", "macaroon",
                      "secret", "password", "private")


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path_factory.mktemp("authzaccel-data")
    (data / "probe.txt").write_bytes(BODY)
    # The accel seam redirects /gated/<path> to <prefix>/gated/<path>, and the
    # internal location aliases <prefix>/ onto the data root — so the handed-off
    # request resolves to data/gated/<path>. Stage it there too.
    (data / "gated").mkdir()
    (data / "gated" / "probe.txt").write_bytes(BODY)

    harness = LifecycleHarness()
    try:
        inst = harness.start(NginxInstanceSpec(
            name="lc-brix-authz-accel",
            template=TEMPLATE,
            protocol="webdav",
            readiness="tcp",
            data_root=str(data),
            template_values={"DATA_DIR": str(data),
                             "SECRET_HEX": "00" * 32},
            reason="phase-106 W3/W4 authz + accel seams"))
    except Exception as exc:                      # noqa: BLE001 — clean skip
        harness.close()
        pytest.skip(f"authz/accel node did not start: {str(exc)[-300:]}")
    try:
        yield inst
    finally:
        harness.close()


def _get(inst, path, headers=None):
    conn = http.client.HTTPConnection(inst.host, inst.port, timeout=30)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read(), dict(resp.getheaders())
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# success
# ---------------------------------------------------------------------------

def test_w4_brix_authorizes_a_location_it_does_not_serve(node):
    """(success) A plain nginx location delegates authz to brix via
    auth_request; brix admits, and nginx serves its own bytes."""
    status, body, _ = _get(node, "/protected/probe.txt")
    assert status == 200, f"auth_request-gated location returned {status}"
    assert body == BODY


def test_w3_brix_decides_and_nginx_serves_via_accel_redirect(node):
    """(success) brix gates /gated/, serves nothing itself, and hands off to an
    `internal` location which delivers the bytes."""
    status, body, headers = _get(node, "/gated/probe.txt")
    assert status == 200, f"accel-redirect handoff returned {status}"
    assert body == BODY
    # The handoff is internal to nginx: the client must never see the header.
    assert "X-Accel-Redirect" not in headers, headers


def test_w3_outbound_handoff_delivers_nginx_range_serving(node):
    """(success) The W3 'outbound half': a file handed off to a static
    `internal` location is served by ngx_http_static_module, so brix inherits
    nginx's range serving for free after making the authorization decision.

    This is what the plan meant by 'hand a staged file to nginx's static path':
    brix_webdav_accel_redirect IS that mechanism — the target here is a plain
    `alias` location with no brix directive, i.e. the static module. Proving a
    Range request comes back 206 with a correct Content-Range shows the value
    (sendfile-capable, range-capable serving) actually lands.
    """
    import http.client

    conn = http.client.HTTPConnection(node.host, node.port, timeout=30)
    try:
        conn.request("GET", "/gated/probe.txt", headers={"Range": "bytes=5-9"})
        resp = conn.getresponse()
        body = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()

    assert resp.status == 206, f"static handoff did not honour Range: {resp.status}"
    assert body == BODY[5:10], body
    assert headers.get("content-range") == f"bytes 5-9/{len(BODY)}", headers
    # Still no leak of the internal mechanism to the client.
    assert "x-accel-redirect" not in headers, headers


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------

def test_w4_refusing_authz_target_denies_the_outer_location(node):
    """(error) When the brix authz target refuses, the outer location is denied
    and serves nothing — even though nginx, not brix, owns those bytes.

    This is the non-vacuity half of the success case: without it, a handler
    that admitted everything would pass the test above.
    """
    status, body, _ = _get(node, "/denied/probe.txt")
    assert status in (401, 403), f"refusing target let the request through: {status}"
    assert BODY not in body, "denied request still received the file contents"


# ---------------------------------------------------------------------------
# security-negative — the load-bearing cells
# ---------------------------------------------------------------------------

def test_internal_targets_are_unreachable_from_outside(node):
    """(security-neg) The authz target and the accel target are `internal`.

    If either were reachable directly, the accel target would serve every byte
    with no authorization at all, and the authz endpoint would become an
    identity oracle.
    """
    for path in ("/_authz", "/_authz_deny", "/internal/probe.txt"):
        status, body, _ = _get(node, path)
        assert status == 404, f"{path} is externally reachable ({status})"
        assert BODY not in body, f"{path} served the file to an outside client"


def test_client_cannot_forge_the_handoff(node):
    """(security-neg) A client sending X-Accel-Redirect itself must not be able
    to steer the handoff.

    Request headers do not become response headers, and the handler builds the
    value from a CONFIGURED prefix plus nginx's already-normalised r->uri — but
    that is exactly the kind of property that must be tested rather than
    asserted in a comment.
    """
    status, body, _ = _get(node, "/denied/probe.txt",
                           headers={"X-Accel-Redirect": "/internal/probe.txt"})
    assert status in (401, 403), (
        f"a client-supplied X-Accel-Redirect turned a denial into {status}")
    assert BODY not in body, "client-forged handoff served the file"


def test_authz_bypass_regression_subrequest_gets_real_enforcement(node):
    """(security-neg, named regression) The specific bug this workstream found:
    nginx SKIPS the ACCESS phase for subrequests, and auth_request issues a
    subrequest, so an authz endpoint that assumed 'reaching the content phase
    means I was authorized' admitted EVERYTHING.

    The property is pinned in both directions on the SAME endpoint:
      - the refusing target (/denied/ -> /_authz_deny) must DENY
      - the admitting target (/protected/ -> /_authz) must ADMIT
    A stubbed-out enforcer that always returned 204 would pass the admit half
    and fail the deny half; a broken one that always 403'd would fail admit.
    Only real per-subrequest enforcement passes both.
    """
    denied, _, _ = _get(node, "/denied/probe.txt")
    admitted, body, _ = _get(node, "/protected/probe.txt")
    assert denied in (401, 403), (
        f"auth_request subrequest was NOT enforced (bypass): /denied/ -> {denied}")
    assert admitted == 200, f"/protected/ -> {admitted}"
    assert body == BODY


def test_no_credential_material_in_any_response_header(node):
    """(security-neg) The seams publish the SUBJECT of an identity, never the
    credential that proved it — an auth_request consumer forwards these
    headers to an upstream that has no business seeing a token."""
    probes = [
        ("/protected/probe.txt", {}),
        ("/gated/probe.txt", {}),
        ("/protected/probe.txt", {"Authorization": "Bearer not-a-real-token"}),
    ]
    for path, hdrs in probes:
        _status, _body, headers = _get(node, path, headers=hdrs)
        for name, value in headers.items():
            low = f"{name} {value}".lower()
            assert "not-a-real-token" not in low, (
                f"{path}: the presented credential was echoed in {name}")
            if name.lower().startswith("x-brix-"):
                assert not any(m in name.lower() for m in CREDENTIAL_MARKERS), (
                    f"{path}: credential-shaped response header {name}")
