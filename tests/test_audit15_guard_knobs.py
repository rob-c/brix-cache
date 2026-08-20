"""
test_audit15_guard_knobs.py — live coverage for the httpguard signature-engine
knobs (audit §A1, testsuite-combinatorial-coverage-audit 2026-08-15: the four
operator knobs `brix_guard_signature`, `brix_guard_default_signatures`,
`brix_guard_bounce_status` and `brix_guard_valid_method` had ZERO coverage —
the existing guard suites only drive the profile defaults).

The guard fronts a LOCAL static root (template nginx_guard_knobs.conf), so a
request that PASSES the guard is observable as 200 (seeded file) or 404
(absent file, audited signal=notfound), while a bounce carries the configured
bounce status — no stub-backend shared state, hence no serial marker.

Subject instance (all four knobs at once — they must compose):
    brix_guard_bounce_status 403         bounce is a real 403, not a 444 drop
    brix_guard_default_signatures off    built-in scanner set disabled
    brix_guard_signature /custom-probe   operator blocklist substring
    brix_guard_valid_method GET HEAD     op grammar narrowed

Control instance: same profile/prefix/bounce but default signatures LEFT ON —
the same /.git probe that sails through the subject is signature-bounced there,
pinning the knob (not the profile) as the cause.
"""

import os

import pytest

from guard_http_lib import AuditLog, GuardServer
from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from port_ladder import PORT_LAST
from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15-guard")]

SEED_BODY = "guarded-payload\n"

KNOBS = ("            brix_guard_bounce_status 403;\n"
         "            brix_guard_default_signatures off;\n"
         "            brix_guard_signature /custom-probe;\n"
         "            brix_guard_valid_method GET HEAD;\n")

CONTROL_KNOBS = "            brix_guard_bounce_status 403;\n"


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")


def _boot(lifecycle, tmp_path, name, knobs, reason):
    data = tmp_path / "data"
    (data / "store" / "data").mkdir(parents=True, exist_ok=True)
    (data / "store" / "data" / "file.txt").write_text(SEED_BODY)
    audit_path = tmp_path / f"{name}-audit.log"
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_guard_knobs.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "AUDIT_LOG": str(audit_path),
                         "GUARD_KNOBS": knobs},
        # These are private control/subject instances.  Their historical
        # names also exist in the shared fleet ledger, so give each throwaway
        # process a private port beyond the managed ladder.
        port=(PORT_LAST + 1 if name.endswith("guard-knobs-reload")
              else PORT_LAST + 2),
        reason=reason))
    server = GuardServer(HOST, endpoint.port)
    server.wait_ready("/store/data/file.txt")
    return server, AuditLog(str(audit_path))


@pytest.fixture()
def knob_server(lifecycle, tmp_path):
    return _boot(lifecycle, tmp_path, "lc-audit15-guard-knobs-reload", KNOBS,
                 "audit-15 guard operator-knob matrix")


def test_clean_get_and_head_pass(knob_server):
    """Success path: an in-prefix, allowed-method, non-signature request is
    served by the local root — the four knobs together leave good traffic alone."""
    server, _ = knob_server
    r = server.get("/store/data/file.txt")
    assert r.status == 200, r.status
    assert r.body.decode() == SEED_BODY
    r = server.request("HEAD", "/store/data/file.txt")
    assert r.status == 200, r.status


def test_operator_signature_bounced_with_custom_status(knob_server):
    """brix_guard_signature + brix_guard_bounce_status: the operator substring
    is bounced with a real 403 response (not the default 444 drop), audited as
    signal=signature."""
    server, audit = knob_server
    baseline = audit.line_count()
    r = server.get("/store/custom-probe/x")
    assert r.status == 403, f"expected configured bounce 403, got {r.status}"
    assert audit.wait_for_count(baseline + 1), "no audit line written"
    assert audit.last_line_has(signal="signature")


def test_default_signatures_off_admits_builtin_probe(knob_server, lifecycle,
                                                     tmp_path):
    """brix_guard_default_signatures off: a probe from the BUILT-IN scanner set
    (the "/.env" SUBSTR signature — the ".git" one is a PREFIX rule and can
    never fire under /store) passes the guard and reaches the content phase
    (404 + audited signal=notfound), while the control instance with defaults
    ON signature-bounces the identical request — so the built-ins, and only
    the built-ins, were disabled."""
    server, audit = knob_server
    baseline = audit.line_count()
    r = server.get("/store/.env")
    assert r.status == 404, \
        f"built-in signature fired despite default_signatures off: {r.status}"
    assert audit.wait_for_count(baseline + 1)
    assert audit.last_line_has(signal="notfound")

    ctl_server, ctl_audit = _boot(lifecycle, tmp_path,
                                  "lc-audit15-guard-defaults-reload", CONTROL_KNOBS,
                                  "audit-15 guard default-signature control")
    ctl_baseline = ctl_audit.line_count()
    r = ctl_server.get("/store/.env")
    assert r.status == 403, \
        f"default signature set inactive on the control: {r.status}"
    assert ctl_audit.wait_for_count(ctl_baseline + 1)
    assert ctl_audit.last_line_has(signal="signature")


def test_valid_method_grammar_bounces_write_methods(knob_server):
    """Security-negative: with the grammar narrowed to GET/HEAD, mutating
    methods on an otherwise-valid path are grammar-bounced before any handler
    (403 here — bounce_status applies to grammar too), audited signal=grammar."""
    server, audit = knob_server
    for method in ("PUT", "DELETE"):
        baseline = audit.line_count()
        r = server.request(method, "/store/data/file.txt", body=b"x")
        assert r.status == 403, (method, r.status)
        assert audit.wait_for_count(baseline + 1), method
        assert audit.last_line_has(signal="grammar"), method


def _parse(tmp_path, knobs):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return nginx_t("nginx_guard_knobs.conf", tmp_path,
                   PORT=PARSE_PLACEHOLDER_PORT, BIND_HOST=BIND_HOST,
                   DATA_ROOT=str(data), LOG_DIR=str(tmp_path),
                   TMP_DIR=str(tmp_path),
                   AUDIT_LOG=str(tmp_path / "audit.log"),
                   GUARD_KNOBS=knobs)


def test_unknown_valid_method_rejected_at_parse(tmp_path):
    """Config-parse negative: a typoed method name must fail nginx -t — a
    silently ignored entry would widen the allowed grammar."""
    result = _parse(tmp_path, "            brix_guard_valid_method GET BOGUS;\n")
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0, out
    assert 'unknown method "BOGUS"' in out, out


def test_bounce_status_restricted_to_403_or_444(tmp_path):
    """Config-parse negative: any bounce code other than 403/444 is refused."""
    result = _parse(tmp_path, "            brix_guard_bounce_status 418;\n")
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0, out
    assert "must be 403 or 444" in out, out
