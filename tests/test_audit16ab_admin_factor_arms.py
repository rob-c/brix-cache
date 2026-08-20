"""The two arm-gaps of `src/observability/dashboard/module.c`, one port apart.

The dashboard module declares nineteen directives and the census finds exactly
two whose `off` arm is written nowhere in `tests/` `conf/` `client/`
`k8s-tests/`: `brix_admin_require_both`, which combines the two factors the
admin write API authenticates with, and `brix_dashboard_vfs_browse`, which
decides whether the monitoring UI may read stored user data at all.  They are
one subject rather than two — between them they are the whole of what the
dashboard exposes and to whom — and they share a shape that decides the layout
below: both endpoints live at a FIXED uri (`/brix/api/v1/admin/...` and
`/brix/api/v1/vfs...`, matched against `r->uri` in
`dashboard/module_dispatch.c`), and `brix_admin_require_both` is declared
`NGX_HTTP_LOC_CONF` alone.  A plane therefore cannot be a path.  It is a
`server_name` vhost, and fourteen of them share one `listen`.

`brix_admin_check_auth` (`dashboard/api_admin.c:196`) computes two independent
predicates — the peer inside `brix_admin_allow`, and a constant-time bearer
compare against `brix_admin_secret` — and then combines them:

    require_both on   every CONFIGURED factor must pass   (AND)
    require_both off  either configured factor passing is enough  (OR)
    neither configured -> denied, the API is not open but closed

The corpus had only ever written the first line, and only ever with ONE factor
configured (`test_phase23_admin_api.py` sets a secret and no allowlist), so the
combiner itself had never been entered: no test had a plane where one factor
passes and the other fails, which is the only shape in which AND and OR differ.
Ten planes below supply it, using RFC 5737 TEST-NET-1 for an allowlist that is
configured and can never match.

The browser flag is the table's only `MAIN|SRV|LOC` directive, which changes
what its missing arm even is — as in file 15, `off` in a bare location is the
merge default under another name, so the arm worth writing is the per-location
opt-out under a server that wrote `on`.  Four planes take that, the inheritance
it opts out of, the bare-location spelling, and the same feature on a dashboard
with no password.

The combiner's verdict is read off the pair 403/405 rather than 403/200: see
ADMITTED below.

Covered (success + error + security-negative):
  success       — AND with both factors satisfied, OR with either, and a real
                  registration through the admitted arm;
  arm           — `require_both off` admits a request the `on` arm refuses, and
                  absence is byte-identical to the written `off`;
  arm           — a location takes the server's `vfs_browse on` away again;
  error         — an unconfigured admin API refuses every caller, credentialed
                  or not; a disabled browser 404s before it authenticates;
  security-neg  — a bearer that is a prefix of the secret, a forged session
                  cookie, and a `..` traversal are each refused;
  finding       — with one factor configured the two arms are indistinguishable,
                  and a passwordless dashboard serves the export browser to
                  anyone who asks.

Run:
    cd tests && PYTHONPATH=. python3 -m pytest test_audit16ab_admin_factor_arms.py -q
"""

import hashlib
import hmac
import http.client
import json
import time
from pathlib import Path

import pytest

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

NAME = "lc-audit16ab-admin"
SECRET = "audit16ab-admin-bearer-secret-value"
PASSWORD = "audit16ab-dash-password"
SEEDED = b"the bytes the export browser hands out\n"

ADMIN = "/brix/api/v1/admin/cluster/servers"
CENSUS = "/brix/api/v1/vfs"

# What a combiner verdict looks like from outside.  `brix_admin_dispatch`
# (`api_admin_routing.c:233`) authenticates FIRST and answers 403
# `{"error":"forbidden"}` when the combiner refuses; only then does it route,
# and `cluster/servers` is a POST route (`api_admin_routing.c:109`), so a GET
# that cleared the gate is refused by the method check one line later.  The two
# statuses are therefore a discriminator for exactly the thing under test — and
# a read-only one, which is why every combiner cell below is a GET.  That 405
# really is post-auth is not assumed: `test_the_admitted_arm_reaches_the_handler`
# posts a registration through the same plane and gets the handler's own 200.
ADMITTED = 405   # auth passed, then routing refused the method
DENIED = 403     # the combiner said no; routing never ran

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


def _request(port, host, path, bearer=None, cookie=None, method="GET",
             payload=None):
    """One request to one vhost.  http.client rather than urllib because the
    plane IS the Host header here, and only a hand-built request can be sure
    which one went out."""
    headers = {"Host": host}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    if cookie is not None:
        headers["Cookie"] = cookie
    if payload is not None:
        headers["Content-Type"] = "application/json"
    conn = http.client.HTTPConnection(HOST, port, timeout=10)
    try:
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def _cookie(password=PASSWORD, stamp=None):
    """The dashboard session cookie: HMAC-SHA256(password, "<ts>") . "<ts>"."""
    stamp = int(time.time()) if stamp is None else int(stamp)
    digest = hmac.new(password.encode(), str(stamp).encode(),
                      hashlib.sha256).hexdigest()
    return f"xrd_dashboard={digest}.{stamp}"


@pytest.fixture(scope="module")
def planes(tmp_path_factory):
    """One instance, fourteen vhosts, one registered export.

    MODULE-scoped with its own harness for the reason file 27 gives: the port
    is fixed, so a per-test start/stop races the OS releasing it.  One cell
    below writes (a cluster registration, to prove the 405 discriminator is
    post-auth); every other cell is a read, and the registration it adds is
    scoped to this instance's own registry.
    """
    harness = LifecycleHarness()
    secret_dir = tmp_path_factory.mktemp("audit16ab")
    secret_file = secret_dir / "admin.secret"
    secret_file.write_text(SECRET + "\n", encoding="utf-8")
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16ab_admin_factor_arms.conf",
            protocol="http",
            template_values={"BIND_HOST": BIND_HOST,
                             "ALLOW_CIDR": f"{BIND_HOST}/32",
                             "SECRET_FILE": str(secret_file),
                             "PASSWORD": PASSWORD},
            reason="dashboard admin-factor and export-browser arm census.",
        ))
        data = Path(instance.data_root)
        (data / "sub").mkdir(parents=True, exist_ok=True)
        (data / "seeded.bin").write_bytes(SEEDED)
        yield {"port": instance.port, "data": data}
    finally:
        harness.close()


def _census(planes, host, cookie):
    status, body = _request(planes["port"], host, CENSUS, cookie=cookie)
    return status, body


def _export_index(planes):
    """The registry index of the one export this config registers."""
    status, body = _request(planes["port"], "vfs-inherit.arm", CENSUS,
                            cookie=_cookie())
    assert status == 200, body
    exports = json.loads(body)["exports"]
    assert exports, "no export registered — every browser cell would be empty"
    return exports[0]["index"]


# --------------------------------------------------------------------------- #
# 1. The combiner with both factors configured and both satisfiable            #
# --------------------------------------------------------------------------- #

class TestBothFactorsConfigured:

    def test_and_admits_the_caller_that_passes_both(self, planes):
        status, body = _request(planes["port"], "both-on.arm", ADMIN,
                                bearer=SECRET)
        assert status == ADMITTED, body

    def test_the_admitted_arm_reaches_the_handler(self, planes):
        """405 is worth nothing as a signal unless it is genuinely downstream
        of the gate, so one cell spends the write: the same plane, the same
        credentials, the method the route does accept, and the registration
        handler's own answer comes back."""
        payload = json.dumps({"host": "audit16ab-ds.example.org",
                              "port": 1094,
                              "paths": "/store"})
        status, body = _request(planes["port"], "both-on.arm", ADMIN,
                                bearer=SECRET, method="POST", payload=payload)
        assert status == 200, body
        assert json.loads(body)["result"] == "registered", body

    def test_the_denied_arm_never_reaches_the_handler(self, planes):
        """And the mirror: the same write, refused before the body is read, so
        403 is the gate rather than anything the route did."""
        payload = json.dumps({"host": "audit16ab-denied.example.org",
                              "port": 1094,
                              "paths": "/store"})
        status, body = _request(planes["port"], "deny-on.arm", ADMIN,
                                bearer=SECRET, method="POST", payload=payload)
        assert status == DENIED
        assert json.loads(body)["error"] == "forbidden", body

    def test_and_refuses_a_matching_peer_with_no_bearer(self, planes):
        """The whole point of the armed flag: an allowlisted address is not
        enough once a secret is also configured."""
        status, _ = _request(planes["port"], "both-on.arm", ADMIN)
        assert status == DENIED

    def test_and_refuses_a_matching_peer_with_a_wrong_bearer(self, planes):
        status, _ = _request(planes["port"], "both-on.arm", ADMIN,
                             bearer="not-the-secret-value-at-all")
        assert status == DENIED

    def test_or_admits_the_matching_peer_alone(self, planes):
        """The arm nothing had written: with `off`, the allowlist by itself
        authenticates a caller who presents no credential at all."""
        status, body = _request(planes["port"], "both-off.arm", ADMIN)
        assert status == ADMITTED, body

    def test_or_admits_a_matching_peer_carrying_a_wrong_bearer(self, planes):
        status, body = _request(planes["port"], "both-off.arm", ADMIN,
                                bearer="not-the-secret-value-at-all")
        assert status == ADMITTED, body

    def test_the_unwritten_directive_is_the_written_off(self, planes):
        """Absence and `off` answer identically to all three request shapes."""
        for bearer in (None, SECRET, "not-the-secret-value-at-all"):
            written, _ = _request(planes["port"], "both-off.arm", ADMIN,
                                  bearer=bearer)
            omitted, _ = _request(planes["port"], "both-absent.arm", ADMIN,
                                  bearer=bearer)
            assert written == omitted == ADMITTED, (bearer, written, omitted)


# --------------------------------------------------------------------------- #
# 2. The combiner when one configured factor cannot pass                       #
# --------------------------------------------------------------------------- #

class TestOneFactorCannotPass:
    """TEST-NET-1 as the allowlist: the factor is configured and always fails,
    which is the only shape in which AND and OR are different functions."""

    def test_and_refuses_a_correct_bearer_from_outside_the_allowlist(self, planes):
        status, _ = _request(planes["port"], "deny-on.arm", ADMIN, bearer=SECRET)
        assert status == DENIED

    def test_and_refuses_the_uncredentialed_caller_too(self, planes):
        status, _ = _request(planes["port"], "deny-on.arm", ADMIN)
        assert status == DENIED

    def test_or_admits_the_bearer_the_and_arm_refused(self, planes):
        """One directive, one token, and the same request changes verdict."""
        status, body = _request(planes["port"], "deny-off.arm", ADMIN,
                                bearer=SECRET)
        assert status == ADMITTED, body

    def test_or_still_refuses_a_caller_that_passes_neither(self, planes):
        status, _ = _request(planes["port"], "deny-off.arm", ADMIN)
        assert status == DENIED

    def test_or_still_refuses_a_wrong_bearer(self, planes):
        status, _ = _request(planes["port"], "deny-off.arm", ADMIN,
                             bearer="not-the-secret-value-at-all")
        assert status == DENIED


# --------------------------------------------------------------------------- #
# 3. One configured factor: the two arms stop being two arms                   #
# --------------------------------------------------------------------------- #

class TestOneConfiguredFactorMakesTheArmsEqual:

    def test_and_admits_a_caller_that_passed_only_the_cidr(self, planes):
        """`require_both on` with only an allowlist configured requires only
        the allowlist — an unconfigured factor is not a required one."""
        status, body = _request(planes["port"], "allow-on.arm", ADMIN)
        assert status == ADMITTED, body

    def test_or_admits_the_same_caller(self, planes):
        status, body = _request(planes["port"], "allow-off.arm", ADMIN)
        assert status == ADMITTED, body

    def test_the_cidr_only_arms_are_indistinguishable(self, planes):
        for bearer in (None, SECRET, "not-the-secret-value-at-all"):
            armed, _ = _request(planes["port"], "allow-on.arm", ADMIN,
                                bearer=bearer)
            disarmed, _ = _request(planes["port"], "allow-off.arm", ADMIN,
                                   bearer=bearer)
            assert armed == disarmed == ADMITTED, (bearer, armed, disarmed)

    def test_and_admits_a_caller_that_passed_only_the_secret(self, planes):
        status, body = _request(planes["port"], "secret-on.arm", ADMIN,
                                bearer=SECRET)
        assert status == ADMITTED, body

    def test_and_refuses_the_secret_only_plane_without_the_secret(self, planes):
        status, _ = _request(planes["port"], "secret-on.arm", ADMIN)
        assert status == DENIED

    def test_the_secret_only_arms_are_indistinguishable(self, planes):
        for bearer, expected in ((None, DENIED),
                                 (SECRET, ADMITTED),
                                 ("not-the-secret-value-at-all", DENIED)):
            armed, _ = _request(planes["port"], "secret-on.arm", ADMIN,
                                bearer=bearer)
            disarmed, _ = _request(planes["port"], "secret-off.arm", ADMIN,
                                   bearer=bearer)
            assert armed == disarmed == expected, (bearer, armed, disarmed)


# --------------------------------------------------------------------------- #
# 4. An unconfigured admin API, and the bearer compare's length gate           #
# --------------------------------------------------------------------------- #

class TestTheUnconfiguredApiAndTheBearerGate:

    def test_neither_factor_configured_refuses_everyone(self, planes):
        status, _ = _request(planes["port"], "none.arm", ADMIN)
        assert status == DENIED

    def test_neither_factor_configured_refuses_the_real_secret(self, planes):
        """`brix_dashboard on` alone does not open the write API — with no
        factor configured the API is disabled, not unauthenticated."""
        status, _ = _request(planes["port"], "none.arm", ADMIN, bearer=SECRET)
        assert status == DENIED

    def test_the_refusal_is_the_structured_admin_error(self, planes):
        status, body = _request(planes["port"], "none.arm", ADMIN)
        assert status == DENIED
        assert json.loads(body)["error"] == "forbidden", body

    def test_a_prefix_of_the_secret_is_not_the_secret(self, planes):
        """The compare is length-gated before CRYPTO_memcmp, so a truncated
        credential cannot walk the comparison."""
        status, _ = _request(planes["port"], "secret-on.arm", ADMIN,
                             bearer=SECRET[:-1])
        assert status == DENIED

    def test_an_empty_bearer_is_not_the_secret(self, planes):
        status, _ = _request(planes["port"], "secret-on.arm", ADMIN, bearer="")
        assert status == DENIED


# --------------------------------------------------------------------------- #
# 5. The export browser's arms                                                 #
# --------------------------------------------------------------------------- #

class TestTheExportBrowserArms:

    def test_the_server_arm_reaches_a_silent_location(self, planes):
        status, body = _census(planes, "vfs-inherit.arm", _cookie())
        assert status == 200, body
        assert json.loads(body)["exports"], body

    def test_the_location_takes_the_server_arm_away(self, planes):
        """The arm the corpus never wrote: `off` inside a server that wrote
        `on` is the only spelling that disables the browser for one location."""
        status, _ = _census(planes, "vfs-locoff.arm", _cookie())
        assert status == 404

    def test_a_bare_location_off_is_the_merge_default(self, planes):
        status, _ = _census(planes, "vfs-bareoff.arm", _cookie())
        assert status == 404

    def test_the_two_disabled_spellings_answer_identically(self, planes):
        opted_out, first = _census(planes, "vfs-locoff.arm", _cookie())
        defaulted, second = _census(planes, "vfs-bareoff.arm", _cookie())
        assert (opted_out, first) == (defaulted, second)

    def test_the_listing_reports_the_seeded_file(self, planes):
        index = _export_index(planes)
        status, body = _request(
            planes["port"], "vfs-inherit.arm",
            f"/brix/api/v1/vfs/files?export={index}&path=/", cookie=_cookie())
        assert status == 200, body
        entries = {e["name"]: e for e in json.loads(body)["entries"]}
        assert entries["seeded.bin"]["type"] == "file"
        assert entries["seeded.bin"]["size"] == len(SEEDED)
        assert entries["sub"]["type"] == "dir"

    def test_the_download_is_byte_exact(self, planes):
        index = _export_index(planes)
        status, body = _request(
            planes["port"], "vfs-inherit.arm",
            f"/brix/api/v1/vfs/download?export={index}&path=/seeded.bin",
            cookie=_cookie())
        assert status == 200
        assert body == SEEDED

    def test_no_cookie_is_refused(self, planes):
        status, _ = _census(planes, "vfs-inherit.arm", None)
        assert status == 401

    def test_a_forged_cookie_is_refused(self, planes):
        status, _ = _census(planes, "vfs-inherit.arm",
                            _cookie(password="not-the-dashboard-password"))
        assert status == 401

    def test_a_traversal_path_is_refused(self, planes):
        index = _export_index(planes)
        status, _ = _request(
            planes["port"], "vfs-inherit.arm",
            f"/brix/api/v1/vfs/files?export={index}&path=/../",
            cookie=_cookie())
        assert status == 400

    def test_the_disabled_browser_404s_before_it_authenticates(self, planes):
        """The feature gate is the preamble's first line, so a disabled
        location never distinguishes an authorized caller from any other."""
        status, _ = _census(planes, "vfs-locoff.arm", None)
        assert status == 404


# --------------------------------------------------------------------------- #
# 6. The browser on a dashboard with no password                               #
# --------------------------------------------------------------------------- #

class TestThePasswordlessDashboardOpensTheBrowser:
    """`vfs_browse.c`'s header says the endpoints are "Always admin-auth ...
    never the anonymous tier: this surface exposes stored user data".  The call
    it makes is `ngx_http_brix_dashboard_check_auth`, which returns NGX_OK
    before looking at the request when no password and no user list are
    configured.  These three cells are what that costs."""

    def test_the_census_answers_an_anonymous_caller(self, planes):
        status, body = _census(planes, "vfs-nopw.arm", None)
        assert status == 200, body
        assert json.loads(body)["exports"], body

    def test_the_download_answers_an_anonymous_caller(self, planes):
        index = _export_index(planes)
        status, body = _request(
            planes["port"], "vfs-nopw.arm",
            f"/brix/api/v1/vfs/download?export={index}&path=/seeded.bin")
        assert status == 200
        assert body == SEEDED, "stored export data served with no credential"

    def test_the_only_difference_is_the_password_directive(self, planes):
        """Same flag, same endpoint, same anonymous request: the plane that
        configured a password refuses it and the plane that did not serves it."""
        guarded, _ = _census(planes, "vfs-inherit.arm", None)
        open_plane, _ = _census(planes, "vfs-nopw.arm", None)
        assert (guarded, open_plane) == (401, 200)
