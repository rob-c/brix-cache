"""test_impersonate_config.py — config-time validation of the phase-40
`brix_impersonation` directives via `nginx -t`.

Unlike the end-to-end userns test, this needs NO root, NO user namespace, and NO
running broker — only the built nginx binary.  It drives `nginx -t` with each
operating mode and asserts the directive surface + mode validation:

  * `off` (and no directive)            -> config OK
  * `single` without a user             -> rejected, clear message
  * `single` with a user                -> config OK
  * `map` as a non-root master          -> rejected (broker needs root)
  * an invalid mode token               -> rejected, lists off|single|map

It lives in tests/userns/ so it shares that folder's standalone pytest root and
is never gated on the main server fleet.  The config is rendered from the
committed `nginx_userns_impersonate.conf` template and driven through the
phase-81 registry (LifecycleHarness), which owns the `nginx -t` primitive.
"""

import itertools
import os
import sys

import pytest

# tests/userns/ is a standalone pytest root, so the parent tests/ dir is not on
# sys.path when invoked as `pytest tests/userns/` — add it so the phase-81
# registry (server_launcher / server_registry / config_templates) imports.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server_launcher import LifecycleHarness  # noqa: E402
from server_registry import NginxInstanceSpec  # noqa: E402
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT  # noqa: E402

pytestmark = pytest.mark.uses_lifecycle_harness

_SEQ = itertools.count()


def _check(harness, stream_body):
    """Render the impersonation template with the given per-server directive
    lines and run `nginx -t`, returning (returncode, combined stdout+stderr)."""
    name = f"lc-imp-config-{next(_SEQ)}"
    harness.register(NginxInstanceSpec(
        name=name, template="nginx_userns_impersonate.conf",
        port=SHARED_PARSE_PLACEHOLDER_PORT,
        protocol="root", readiness="tcp",
        template_values={"STREAM_BODY": stream_body}))
    harness.launcher.render_nginx(harness.spec(name))
    r = harness.nginx_test(name, check=False)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


@pytest.fixture()
def imp(tmp_path):
    harness = LifecycleHarness()
    try:
        yield lambda body: _check(harness, body)
    finally:
        harness.close()


def test_off_is_accepted(imp):
    rc, out = imp("    brix_impersonation off;")
    assert rc == 0, out
    assert "successful" in out


def test_no_directive_is_accepted(imp):
    rc, out = imp("    # no impersonation directive")
    assert rc == 0, out


def test_single_without_user_is_rejected(imp):
    rc, out = imp("    brix_impersonation single;")
    assert rc != 0
    assert "brix_impersonation_user" in out


def test_single_with_user_is_accepted(imp):
    rc, out = imp(
        "    brix_impersonation single;\n"
        "    brix_impersonation_user nobody;")
    assert rc == 0, out
    assert "successful" in out


def test_map_requires_root(imp, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root: map would be accepted")
    rc, out = imp(
        "    brix_impersonation map;\n"
        f"    brix_impersonation_socket {tmp_path}/b.sock;")
    assert rc != 0
    assert "root" in out.lower()


def test_invalid_mode_is_rejected(imp):
    rc, out = imp("    brix_impersonation bogus;")
    assert rc != 0
    assert "off|single|map" in out
