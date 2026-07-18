"""P80.5 — config-time guardrail for origin-scheme backends without a runtime export.

A server whose mode skips brix_export setup (manager/supervisor/proxy) keeps
root_canon at "/", so the authz gate compares "//<wire-path>" against rules
canonicalized to "/<path>" — nothing matches and every request dies 3010 with
no hint at the cause. brix_server_guard_remote_authz() turns that silent
everything-denied server into a loud `nginx -t` failure.

Pins three legs against the real binary:
  - guard fires: manager mode + s3:// backend + brix_authdb (xrdacc)
  - guard fires: manager mode + s3:// backend + brix_require_vo (vo_rules branch)
  - guard silent: same server without rules, and a normal exported server with rules
"""

import itertools

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

GUARD_NEEDLE = "requires a runtime export"
DENY_NEEDLE = "denied 3010"

_SEQ = itertools.count()


@pytest.fixture()
def guard(tmp_path):
    """A one-server config-test harness: each call renders a server body into
    the committed template and returns the `nginx -t` result (stderr carries
    the [emerg] guard message)."""
    harness = LifecycleHarness()

    def run(server_body):
        name = f"lc-p805-guard-{next(_SEQ)}"
        harness.register(NginxInstanceSpec(
            name=name, template="nginx_p805_authz_guard.conf",
            protocol="root", readiness="tcp",
            template_values={"SERVER_BODY": server_body}))
        harness.launcher.render_nginx(harness.spec(name))
        return harness.nginx_test(name, check=False)

    try:
        yield run
    finally:
        harness.close()


@pytest.fixture()
def authdb(tmp_path):
    path = tmp_path / "authdb"
    path.write_text("u * /atlas lr\n")
    return path


def test_guard_fires_authdb_no_export(guard, authdb):
    """s3 backend + xrdacc authdb + manager mode (no runtime export) → EMERG."""
    r = guard(f"""\
        brix_manager_mode on;
        brix_storage_backend s3://127.0.0.1:29000/brixfwd;
        brix_authdb_format xrdacc;
        brix_authdb {authdb};
""")
    assert r.returncode != 0, f"-t unexpectedly passed:\n{r.stderr}"
    assert GUARD_NEEDLE in r.stderr, f"guard message missing:\n{r.stderr}"
    assert DENY_NEEDLE in r.stderr, f"3010 mechanics missing:\n{r.stderr}"


def test_guard_fires_vo_rules_no_export(guard):
    """Same trap via the vo_rules branch: the guard runs at server prepare,
    before finalize_policy's own brix_require_vo auth-mode validation, so it
    must win even with brix_auth none."""
    r = guard("""\
        brix_manager_mode on;
        brix_storage_backend s3://127.0.0.1:29000/brixfwd;
        brix_require_vo /atlas atlas;
""")
    assert r.returncode != 0, f"-t unexpectedly passed:\n{r.stderr}"
    assert GUARD_NEEDLE in r.stderr, f"guard message missing:\n{r.stderr}"


def test_no_rules_and_exported_server_pass(guard, tmp_path, authdb):
    """Security-scoped negative controls: the guard must NOT reject
    (a) the same rule-less manager server — remote backends without authz
        rules are the supported forwarding topology, and
    (b) a normal server with a runtime export + the same rules — the export
        aligns the gate and rule canonicalizations, which is the remediation
        the guard message prescribes."""
    r = guard("""\
        brix_manager_mode on;
        brix_storage_backend s3://127.0.0.1:29000/brixfwd;
""")
    assert r.returncode == 0, f"rule-less manager server rejected:\n{r.stderr}"
    assert GUARD_NEEDLE not in r.stderr

    export = tmp_path / "export"
    export.mkdir()
    r = guard(f"""\
        brix_export {export};
        brix_storage_backend s3://127.0.0.1:29000/brixfwd;
        brix_authdb_format xrdacc;
        brix_authdb {authdb};
""")
    assert r.returncode == 0, f"exported server with rules rejected:\n{r.stderr}"
    assert GUARD_NEEDLE not in r.stderr
