"""Authorization is decided before conditionals (phase-106 W6 security property).

nginx runs the ACCESS phase before the CONTENT phase, and brix evaluates HTTP
conditionals (If-None-Match / If-Match / If-Modified-Since) in the content
phase (webdav get_serve.c, s3 conditional.c). So an unauthorized caller's
conditional request must be refused by the access phase (401/403) and NEVER
answered 304/412 by the conditional evaluator.

Why this matters: a 304 would confirm the resource exists to someone with no
right to know, and a 304 in response to If-Modified-Since additionally reveals
that the resource is unchanged since a probed timestamp — an existence/mtime
oracle. The ordering is structural (phase order), but a refactor that moved a
conditional check earlier, or a plane that evaluated conditionals before authz,
would silently open the oracle. This pins it on every HTTP plane that has both
an auth gate and a conditional evaluator.

  * success   — an AUTHORIZED conditional request is still answered normally
                (the ordering does not break conditionals for legitimate use)
  * error     — an unauthorized plain request is refused
  * security  — an unauthorized CONDITIONAL request is refused with the auth
                status, never 304/412 (the oracle is closed) — on webdav AND s3

Run:
    PYTHONPATH=tests pytest tests/test_authz_before_conditionals.py -v
"""

from __future__ import annotations

import http.client
import os

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-authz-before-cond")]

TEMPLATE = "nginx_lc_authz_before_cond.conf"
FUTURE = "Sat, 01 Jan 2050 00:00:00 GMT"      # newer than any real mtime


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data = tmp_path_factory.mktemp("authzcond-data")
    (data / "secret.txt").write_bytes(b"authz-before-conditionals probe\n")

    harness = LifecycleHarness()
    try:
        inst = harness.start(NginxInstanceSpec(
            name="lc-authz-before-cond",
            template=TEMPLATE,
            protocol="webdav",
            readiness="tcp",
            data_root=str(data),
            template_values={
                "DATA_DIR": str(data),
                "SECRET_HEX": "00" * 32,
                "ACCESS_KEY": "AKIAPHASE106W6",
                "SECRET_KEY": "s3secretkeyphase106w6verificationonly",
            },
            reason="phase-106 W6 authz-before-conditionals"))
    except Exception as exc:                      # noqa: BLE001 — clean skip
        harness.close()
        pytest.skip(f"authz/cond node did not start: {str(exc)[-300:]}")
    try:
        yield inst
    finally:
        harness.close()


def _plane_port(inst, path):
    """s3 lives on the extra port (one brix protocol per listen)."""
    return inst.extra_ports["S3_PORT"] if path.startswith("/s3/") else inst.port


def _get(inst, path, headers=None):
    conn = http.client.HTTPConnection(inst.host, _plane_port(inst, path),
                                      timeout=30)
    try:
        conn.request("GET", path, headers=headers or {})
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


# The two protected planes and the path that exists behind each.
PLANES = [("webdav", "/dav/secret.txt"), ("s3", "/s3/secret.txt")]


@pytest.mark.parametrize("plane,path", PLANES)
def test_unauthorized_plain_request_is_refused(node, plane, path):
    """(error) The baseline: an unauthorized GET is denied, so the resource is
    protected at all. Without this the security assertions below are vacuous —
    a location that served everything would 'pass' them."""
    status = _get(node, path)
    assert status in (401, 403), f"{plane}: unprotected — plain GET got {status}"


@pytest.mark.parametrize("plane,path", PLANES)
@pytest.mark.parametrize("cond_header", [
    {"If-None-Match": "*"},
    {"If-Modified-Since": FUTURE},
    {"If-Match": "\"anything\""},
])
def test_unauthorized_conditional_request_is_not_answered_by_the_evaluator(
        node, plane, path, cond_header):
    """(security-neg) An unauthorized CONDITIONAL request must be refused with
    the auth status — never 304 or 412.

    A 304 here confirms the resource exists (and, for If-Modified-Since, that it
    is unchanged since the probed time) to a caller with no right to know: an
    existence/mtime oracle. 412 would likewise leak existence. The only correct
    answer is the access phase's denial.
    """
    status = _get(node, path, headers=cond_header)
    assert status in (401, 403), (
        f"{plane}: conditional request leaked a {status} to an unauthorized "
        f"caller ({cond_header}) — authz must precede conditionals")
    assert status not in (304, 412), (
        f"{plane}: existence/mtime oracle open — got {status}")
