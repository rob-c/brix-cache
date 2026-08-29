"""§6.1 `brix_webdav_redirect_dataserver`, both arms, one directive apart.

`test_webdav_redirect_ds.py` claims the negative in its own docstring —
"off-path — with the feature off the manager serves locally (no 307)" — and
then never writes it: its only manager location has the flag ON, and no config
in the corpus sets it off or leaves it out.  The claim is the kind that looks
safe and is not, because DECLINED has three producers.  `webdav_redirect_
dataserver` (src/protocols/webdav/redirect.c) serves locally when the flag is
off, when the method is outside GET/HEAD/PUT, when the request already carries
a `brixrdr.mac`, AND when `brix_srv_select` has no node to hand it to — four
paths that are byte-identical on the wire.  Attributing a 200 to the directive
means holding the other three still, which is why everything below runs against
ONE instance whose locations differ by exactly one line and whose registry is
proven populated before any assertion is made.

The layout (nginx_audit16aa_webdav_redirect_arms.conf):
    /on/          flag on, key set        — the arm the corpus already had
    /off/         flag off, key set       — the arm nothing had written
    /absent/      unwritten               — the merge default, measured
    /off-authed/  flag off, auth required — the ACCEPTING half of §6.1
    /on-nokey/    flag on, no key         — an unsigned handoff

Covered (success + error + security-negative):
  success       — GET/HEAD/PUT on the armed location 307 to the data server;
  success       — the same URIs on the off location are served locally, and
                  the recording data server never hears of them;
  default       — the unwritten directive behaves exactly like `off`;
  wire          — the Location's CGI verifies against the shared key under the
                  documented canon, inside the configured window;
  loop-guard    — a request already carrying brixrdr.mac is never re-redirected;
  security-neg  — tampered, expired, foreign-key and path-replayed handoffs are
                  refused 403 at a location whose redirect arm is OFF.

Run:
    cd tests && PYTHONPATH=. python3 -m pytest test_audit16aa_webdav_redirect_arms.py -q
"""

import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from _test_audit16aa_helpers import CmsNode, mac_hex, signed_cgi
from _test_audit16z_helpers import RecordingShadow
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST

NAME = "lc-audit16aa-rdr"
SECRET = "audit16aa-shared-hmac-key-0123456789"

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None          # surface the 307 rather than chasing it


_OPENER = urllib.request.build_opener(_NoRedirect)


def _http(port, method, path, query="", body=None):
    """Status, headers and body for one request; a 4xx is an answer, not an
    exception, because half the cells here are refusals."""
    url = f"http://{HOST}:{port}{path}"
    if query:
        url += "?" + query
    request = urllib.request.Request(url, method=method, data=body)
    try:
        with _OPENER.open(request, timeout=10) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


@pytest.fixture(scope="module")
def arms():
    """One manager with five locations, one registered data node, and a
    recording server listening where the Location points.

    MODULE-scoped with its own harness for the reason `test_webdav_redirect_ds`
    gives: the ports are fixed, so a per-test start/stop races the OS releasing
    them.  Every test here is read-only against the running instance except the
    PUT cells, which use their own URIs.
    """
    harness = LifecycleHarness()
    shadow = None
    node = None
    try:
        instance = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16aa_webdav_redirect_arms.conf",
            protocol="root",
            readiness="tcp",
            template_values={"BIND_HOST": BIND_HOST, "SECRET": SECRET},
            reason="§6.1 redirect-to-dataserver arm census (on/off/unwritten).",
        ))
        cms_port = instance.extra_ports["CMS_PORT"]
        http_port = instance.extra_ports["HTTP_PORT"]
        ds_port = instance.extra_ports["DS_HTTP_PORT"]

        # Where the Location is built to point.  Nothing in nginx listens
        # there, so "the handoff arrives" is this process seeing the bytes.
        shadow = RecordingShadow(BIND_HOST, ds_port, status=200)

        node = CmsNode(HOST, cms_port, instance.port)
        assert node.wait_registered(), \
            "the data node never registered — every arm would DECLINE alike"

        # The export is rooted at the data dir and the FULL uri is the path
        # under it, so a file for /off/held.txt lives in data/off/, not at the
        # top: the five locations are five directories.
        data = Path(instance.data_root)
        for uri, body in (("/on/armed.txt", b"body-of-armed"),
                          ("/on/shared.txt", b"body-of-shared"),
                          ("/off/held.txt", b"body-of-held"),
                          ("/off/shared.txt", b"body-of-shared"),
                          ("/absent/held.txt", b"body-of-held"),
                          ("/absent/shared.txt", b"body-of-shared"),
                          ("/off-authed/authed.txt", b"body-of-authed"),
                          ("/on-nokey/nokey.txt", b"body-of-nokey")):
            target = data / uri.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)

        yield {"http": http_port, "ds": ds_port, "shadow": shadow,
               "data": data}
    finally:
        if node is not None:
            node.close()
        if shadow is not None:
            shadow.close()
        harness.close()


def _location(headers):
    return headers.get("Location", "")


def _wait_for_path(shadow, path, timeout=6.0):
    """The shadow's first record whose PATH is `path`, ignoring the query — the
    handoff CGI rides in the same string, so an exact match never fires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for entry in shadow.seen():
            if entry["path"].split("?", 1)[0] == path:
                return entry
        time.sleep(0.02)
    return None


def _cgi(location):
    """The query of a Location, as a plain dict."""
    parsed = urllib.parse.urlparse(location)
    return dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))


# ── the arm the corpus already had ─────────────────────────────────────────

class TestTheArmThatWasAlreadyWritten:
    """`on` — kept here as the control the negative is read against."""

    def test_get_is_handed_off(self, arms):
        """success: the armed location answers a GET with a 307."""
        status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        assert status == 307, (status, headers)

    def test_the_location_names_the_data_server(self, arms):
        """success: scheme, the configured port and the path, in one value."""
        _status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        location = _location(headers)
        assert location.startswith("http://"), location
        assert f":{arms['ds']}/on/armed.txt" in location, location

    def test_head_is_handed_off_too(self, arms):
        """success: HEAD is one of the three body-bearing methods."""
        status, _headers, _body = _http(arms["http"], "HEAD", "/on/armed.txt")
        assert status == 307, status

    def test_put_is_handed_off(self, arms):
        """success: a PUT is redirected before any body is stored — the
        manager does not become the writer by accident."""
        status, headers, _body = _http(arms["http"], "PUT", "/on/fresh.txt",
                                       body=b"never-lands-here")
        assert status == 307, (status, headers)
        assert not (arms["data"] / "on" / "fresh.txt").exists(), \
            "the manager stored a body it had already redirected"

    def test_a_fourth_method_is_served_locally(self, arms):
        """error: PROPFIND is outside GET/HEAD/PUT, so the same location with
        the same flag serves it here — the method filter, not the flag."""
        status, headers, _body = _http(arms["http"], "PROPFIND",
                                       "/on/armed.txt")
        assert status != 307, (status, headers)

    def test_a_missing_file_is_still_handed_off(self, arms):
        """success: selection is registry-driven, not file-driven — the
        manager never stats the path before handing it over."""
        status, _headers, _body = _http(arms["http"], "GET",
                                        "/on/no-such-file.txt")
        assert status == 307, status


# ── the arm nothing had written ────────────────────────────────────────────

class TestTheArmNothingHadWritten:
    """`off` — the claim `test_webdav_redirect_ds.py` makes in prose."""

    def test_get_is_served_locally(self, arms):
        """success: the file's own bytes come back, not a 307."""
        status, _headers, body = _http(arms["http"], "GET", "/off/held.txt")
        assert status == 200, status
        assert body == b"body-of-held", body

    def test_no_location_is_offered(self, arms):
        """success: not merely a different status — no handoff is proposed."""
        _status, headers, _body = _http(arms["http"], "GET", "/off/held.txt")
        assert "Location" not in headers, headers

    def test_head_is_served_locally(self, arms):
        """success: the method that would have been redirected is answered."""
        status, headers, _body = _http(arms["http"], "HEAD", "/off/held.txt")
        assert status == 200, status
        assert "Location" not in headers, headers

    def test_put_is_stored_here(self, arms):
        """success: with the arm off this node IS the writer — the body lands
        in the export instead of being pushed to a data server."""
        status, _headers, _body = _http(arms["http"], "PUT", "/off/kept.txt",
                                        body=b"stored-locally")
        assert status in (200, 201, 204), status
        assert (arms["data"] / "off" / "kept.txt").read_bytes() \
            == b"stored-locally"

    def test_the_data_server_never_hears_of_it(self, arms):
        """success: the negative on the far side of the wire — nothing was
        sent anywhere, as opposed to sent and refused."""
        arms["shadow"].reset()
        _http(arms["http"], "GET", "/off/held.txt")
        _http(arms["http"], "HEAD", "/off/held.txt")
        assert arms["shadow"].settle(0.4) == [], arms["shadow"].paths()

    def test_the_same_uri_differs_only_by_the_directive(self, arms):
        """success: the A/B — one path, two locations, one line of config
        between a 307 and a 200."""
        off_status, _oh, off_body = _http(arms["http"], "GET",
                                          "/off/shared.txt")
        on_status, _nh, _on_body = _http(arms["http"], "GET",
                                         "/on/shared.txt")
        assert (off_status, on_status) == (200, 307), (off_status, on_status)
        assert off_body == b"body-of-shared", off_body


# ── the merge default, measured rather than read ───────────────────────────

class TestTheUnwrittenDirective:
    """`ngx_conf_merge_value(..., 0)` — asserted from outside the process."""

    def test_the_default_serves_locally(self, arms):
        """success: never writing the directive is never redirecting."""
        status, _headers, body = _http(arms["http"], "GET", "/absent/held.txt")
        assert status == 200, status
        assert body == b"body-of-held", body

    def test_the_default_offers_no_location(self, arms):
        """success: the default is off, not on-with-nowhere-to-go."""
        _status, headers, _body = _http(arms["http"], "GET", "/absent/held.txt")
        assert "Location" not in headers, headers

    def test_the_default_and_the_written_off_agree(self, arms):
        """success: the two arms are indistinguishable at the response, which
        is the only honest way to claim a default without reading the C."""
        absent = _http(arms["http"], "GET", "/absent/shared.txt")
        written = _http(arms["http"], "GET", "/off/shared.txt")
        assert absent[0] == written[0], (absent[0], written[0])
        assert absent[2] == written[2], (absent[2], written[2])
        assert sorted(absent[1]) == sorted(written[1]), \
            (sorted(absent[1]), sorted(written[1]))

    def test_the_default_writes_here_too(self, arms):
        """success: a PUT under the unwritten directive is stored locally."""
        status, _headers, _body = _http(arms["http"], "PUT",
                                        "/absent/default.txt",
                                        body=b"default-writer")
        assert status in (200, 201, 204), status
        assert (arms["data"] / "absent" / "default.txt").exists()


# ── what the armed location actually puts on the wire ──────────────────────

class TestTheSignedHandoffOnTheWire:
    """The Location is a credential; these cells read it as one."""

    def test_the_handoff_arrives_where_it_points(self, arms):
        """success: following the Location reaches a listener that is not
        nginx — the port in the header is a port something can be reached on."""
        arms["shadow"].reset()
        _status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        location = _location(headers)
        with urllib.request.urlopen(location, timeout=10) as response:
            assert response.status == 200, response.status
        assert _wait_for_path(arms["shadow"], "/on/armed.txt"), \
            arms["shadow"].paths()

    def test_the_cgi_reaches_the_data_server_intact(self, arms):
        """success: the four handoff parameters survive the round trip, so
        the data server verifies what the manager signed."""
        arms["shadow"].reset()
        _status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        location = _location(headers)
        with urllib.request.urlopen(location, timeout=10):
            pass
        entry = _wait_for_path(arms["shadow"], "/on/armed.txt")
        assert entry is not None, arms["shadow"].paths()
        received = _cgi(entry["path"])
        assert set(received) == {"brixrdr.exp", "brixrdr.usr", "brixrdr.vo",
                                 "brixrdr.mac"}, received

    def test_the_mac_verifies_under_the_documented_canon(self, arms):
        """success: the signature is HMAC over METHOD\\npath\\nexp\\nusr\\nvo —
        recomputed here from the shared key, not compared to itself."""
        _status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        cgi = _cgi(_location(headers))
        expected = mac_hex(SECRET, "GET", "/on/armed.txt", cgi["brixrdr.exp"],
                           cgi["brixrdr.usr"], cgi["brixrdr.vo"])
        assert cgi["brixrdr.mac"] == expected, (cgi["brixrdr.mac"], expected)

    def test_the_expiry_sits_inside_the_configured_window(self, arms):
        """success: brix_webdav_redirect_window 120 is what bounds it."""
        now = int(time.time())
        _status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        exp = int(_cgi(_location(headers))["brixrdr.exp"])
        assert now < exp <= now + 121, (now, exp)

    def test_an_anonymous_client_is_vouched_for_as_anonymous(self, arms):
        """success: the location authenticates nobody, so the manager signs an
        empty principal rather than inventing one."""
        _status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt")
        cgi = _cgi(_location(headers))
        assert cgi["brixrdr.usr"] == "", cgi
        assert cgi["brixrdr.vo"] == "", cgi


# ── the accepting half, on a location whose arm is off ─────────────────────

class TestTheAcceptingHalfIgnoresTheFlag:
    """`webdav_redirect_signed_auth` is gated on `brix_webdav_secretkey` alone
    (access_auth.c), so opting out of EMITTING handoffs does not opt out of
    honouring them.  Every cell below runs against `redirect_dataserver off`."""

    def test_without_a_handoff_the_location_refuses(self, arms):
        """error: auth required, no credential — the baseline the acceptance
        below is measured against."""
        status, _headers, _body = _http(arms["http"], "GET",
                                        "/off-authed/authed.txt")
        assert status in (401, 403), status

    def test_a_valid_handoff_is_accepted_with_the_arm_off(self, arms):
        """success (and the observation): the file is served to a client whose
        only credential is a MAC, at a location that emits no handoffs."""
        path = "/off-authed/authed.txt"
        status, _headers, body = _http(
            arms["http"], "GET", path,
            signed_cgi(SECRET, "GET", path, usr="/DC=test/CN=alice"))
        assert status == 200, status
        assert body == b"body-of-authed", body

    def test_a_tampered_mac_is_refused(self, arms):
        """security-neg: fail-closed — a flipped MAC is 403, never a
        fall-through to anonymous."""
        path = "/off-authed/authed.txt"
        cgi = signed_cgi(SECRET, "GET", path, usr="/DC=test/CN=alice")
        tampered = cgi[:-1] + ("0" if cgi[-1] != "0" else "1")
        status, _headers, _body = _http(arms["http"], "GET", path, tampered)
        assert status == 403, status

    def test_an_expired_handoff_is_refused(self, arms):
        """security-neg: the window is enforced even when the MAC is valid
        over the expired timestamp."""
        path = "/off-authed/authed.txt"
        cgi = signed_cgi(SECRET, "GET", path, usr="/DC=test/CN=alice",
                         exp=int(time.time()) - 10)
        status, _headers, _body = _http(arms["http"], "GET", path, cgi)
        assert status == 403, status

    def test_a_foreign_key_is_refused(self, arms):
        """security-neg: the shared secret is what authorises the handoff, so
        a well-formed CGI from a stranger is 403."""
        path = "/off-authed/authed.txt"
        cgi = signed_cgi("a-totally-different-key", "GET", path,
                         usr="/DC=test/CN=mallory")
        status, _headers, _body = _http(arms["http"], "GET", path, cgi)
        assert status == 403, status

    def test_a_handoff_cannot_be_replayed_onto_another_path(self, arms):
        """security-neg: method and path are bound into the signature."""
        cgi = signed_cgi(SECRET, "GET", "/off-authed/authed.txt",
                         usr="/DC=test/CN=alice")
        status, _headers, _body = _http(arms["http"], "GET",
                                        "/off-authed/other.txt", cgi)
        assert status == 403, status


# ── the loop guard, and an armed location with no key ──────────────────────

class TestTheGuardAndTheKeylessArm:

    def test_a_signed_request_is_not_re_redirected(self, arms):
        """loop-guard: a node configured as BOTH roles serves a request that
        already carries a handoff rather than bouncing the client."""
        path = "/on/armed.txt"
        status, headers, _body = _http(arms["http"], "GET", path,
                                       signed_cgi(SECRET, "GET", path))
        assert status != 307, (status, headers)

    def test_the_guard_fires_on_presence_not_validity(self, arms):
        """security-neg: a garbage MAC still stops the redirect — and is then
        refused rather than served, because the key is configured."""
        status, headers, _body = _http(arms["http"], "GET", "/on/armed.txt",
                                       "brixrdr.exp=1&brixrdr.usr=&"
                                       "brixrdr.vo=&brixrdr.mac=" + "0" * 64)
        assert status != 307, (status, headers)
        assert status == 403, status

    def test_the_keyless_arm_still_hands_off(self, arms):
        """success: the redirect leg does not depend on the shared key."""
        status, headers, _body = _http(arms["http"], "GET",
                                       "/on-nokey/nokey.txt")
        assert status == 307, (status, headers)
        assert f":{arms['ds']}/on-nokey/nokey.txt" in _location(headers), \
            _location(headers)

    def test_the_keyless_handoff_is_unsigned(self, arms):
        """error: with no key there is nothing to sign with, so the Location
        carries no identity at all — the data server gets an anonymous
        referral, not a forged one."""
        _status, headers, _body = _http(arms["http"], "GET",
                                        "/on-nokey/nokey.txt")
        assert "brixrdr." not in _location(headers), _location(headers)

    def test_a_keyless_node_ignores_an_unverifiable_handoff(self, arms):
        """security-neg: a server with no key cannot verify a CGI, so it
        treats it as opaque noise and applies its own policy — it must not
        adopt the named principal."""
        path = "/on-nokey/nokey.txt"
        status, _headers, body = _http(
            arms["http"], "GET", path,
            signed_cgi("some-key-this-node-never-had", "GET", path,
                       usr="/DC=test/CN=mallory"))
        assert status == 200, status
        assert body == b"body-of-nokey", body
