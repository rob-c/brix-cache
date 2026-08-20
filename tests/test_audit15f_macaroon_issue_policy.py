"""
test_audit15f_macaroon_issue_policy.py — macaroon issuance policy
(testsuite-combinatorial-coverage-audit 2026-08-15, §B1 zero-coverage
appendix): brix_webdav_macaroon_location and brix_webdav_macaroon_max_validity
appear in no test configuration, so neither the location a site stamps into the
macaroons it mints nor the ceiling it puts on a requested lifetime has ever
been driven.

Both knobs are loc-conf, so one server with two locations is the whole cross:
/open/ is the untouched default face and /tight/ carries a foreign issuer URI
and a 120s maximum.  Every assertion reads the ISSUED token rather than the
JSON envelope — a macaroon is a stream of `[4-hex len]<label> <value>\\n`
packets under a base64url wrapper (macaroon_issue.c write_packet), so the
`location` packet and the `before:` expiry caveat are plain bytes once decoded.

Cases:
  * success       — the configured location is stamped verbatim, and the
    request's own Host never appears;
  * negative      — the default face, same request, derives the location from
    scheme + Host, so the stamp above is the directive's doing;
  * success       — a request with no `validity` at all is issued at exactly
    the configured maximum, not the 86400s merge default;
  * security-neg  — a requested PT1H is CLAMPED to the 120s maximum: a caller
    cannot mint itself a longer-lived credential than the site allows;
  * negative      — the same PT1H on the default face is honoured in full, so
    the clamp is the ceiling and not some unrelated floor;
  * security-note — the stamped location is ADVISORY: the token still
    validates here, because only brix_webdav_token_issuer pins validation
    (validate.c token_validate_macaroon).  A site that expects
    brix_webdav_macaroon_location to fence its macaroons is mistaken;
  * defect pin    — a macaroon issued with a SUBTREE path: caveat authorises
    nothing at all (defect candidate #17, found by this file): the caveat is
    measured against the token's own root scope with 1-byte prefix arithmetic
    and comes out DISJOINT, so every permission is revoked and the read 403s.
    It fails closed, so it is a broken feature rather than a hole.

Run:
    PYTHONPATH=tests pytest tests/test_audit15f_macaroon_issue_policy.py -v
"""

import base64
import calendar
import json
import os
import re
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, HOST, BIND_HOST
from test_token_macaroon import make_macaroon

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                                    # pragma: no cover
    _HAVE_REQUESTS = False

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15f-macpol")]

SECRET_HEX = "5eeded1c" * 8
SECRET = bytes.fromhex(SECRET_HEX)
ISSUER_URI = "https://issuer.example.org/brix"      # a host this server is not
TIGHT_MAX = 120                                     # brix_webdav_macaroon_max_validity
DEFAULT_MAX = 86400                                 # the merged default
SLACK = 5                                           # clock slack (issue vs assert)


@pytest.fixture()
def macpol(lifecycle, tmp_path):
    """One WebDAV server whose two locations differ only in the two knobs."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    data = tmp_path / "data"
    for face in ("open", "tight"):
        (data / face).mkdir(parents=True)
        (data / face / "f.txt").write_text(f"{face}-payload\n")
    cadir = tmp_path / "cadir"
    cadir.mkdir()

    return lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-macpol",
        template="nginx_audit15f_macpolicy.conf",
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "CADIR": str(cadir), "SECRET_HEX": SECRET_HEX,
                         "ISSUER_URI": ISSUER_URI},
        reason="audit-15f macaroon issuance policy"))


def _auth_header(port):
    """A macaroon that authenticates the issuance request itself.  Its own
    location is the Host face: validation applies no pin here (no
    brix_webdav_token_issuer), which is exactly what lets the two faces be
    compared through one credential."""
    caveats = ["activity:DOWNLOAD,LIST,MANAGE", "path:/",
               "before:2099-12-31T23:59:59Z"]
    token = make_macaroon(SECRET, "issuer-subject", caveats,
                          location=f"http://{HOST}:{port}")
    return {"Authorization": f"Bearer {token}",
            "Content-Type": "application/macaroon-request"}


def _issue(port, face, body):
    """POST a dCache macaroon-request at `face`; returns (token, issued_at)."""
    issued_at = time.time()
    resp = requests.post(f"http://{HOST}:{port}/{face}/f.txt",
                         headers=_auth_header(port), data=json.dumps(body),
                         timeout=10)
    assert resp.status_code == 200, resp.text
    return resp.json()["macaroon"], issued_at


def _read(port, face, token):
    """GET the face's file with the issued macaroon as the query credential
    (brix_webdav_http_query_token is on by default)."""
    return requests.get(f"http://{HOST}:{port}/{face}/f.txt",
                        params={"authz": token}, timeout=10)


def _decode(token):
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))

def _location_packet(raw):
    """The one `location <value>` packet, or None when the macaroon carries
    none (emit_location skips an empty location entirely)."""
    match = re.search(rb"location ([^\n]+)\n", raw)
    return match.group(1).decode() if match else None


def _expiry(raw):
    """The `before:` caveat as a unix timestamp (the caveat is UTC ISO-8601)."""
    match = re.search(rb"before:(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)Z", raw)
    assert match is not None, f"no before: caveat in {raw!r}"
    return calendar.timegm(time.strptime(match.group(1).decode(),
                                         "%Y-%m-%dT%H:%M:%S"))


def _assert_lifetime(raw, issued_at, want):
    """The issued lifetime is `want` seconds, within the clock slack."""
    lifetime = _expiry(raw) - issued_at
    assert abs(lifetime - want) <= SLACK, (
        f"lifetime {lifetime:.0f}s, expected {want}s: {raw!r}")


# ── brix_webdav_macaroon_location: the stamped issuer ─────────────────────

def test_the_configured_location_is_stamped_into_the_macaroon(macpol):
    """success: mac_build_location prefers the configured location (the dCache
    endpoint passes allow_conf_location=1), so the issued macaroon names the
    site's issuer URI and never the address the request happened to reach."""
    token, _ = _issue(macpol.port, "tight",
                      {"caveats": ["activity:DOWNLOAD", "path:/tight"]})
    raw = _decode(token)
    assert _location_packet(raw) == ISSUER_URI, raw
    assert f"{HOST}:{macpol.port}".encode() not in raw, raw


def test_the_default_face_derives_the_location_from_the_request(macpol):
    """negative control: the identical request on the face without the
    directive falls through to scheme + Host — so the stamp above is the
    directive and not some fixed build-time issuer."""
    token, _ = _issue(macpol.port, "open",
                      {"caveats": ["activity:DOWNLOAD", "path:/open"]})
    raw = _decode(token)
    assert _location_packet(raw) == f"http://{HOST}:{macpol.port}", raw
    assert ISSUER_URI.encode() not in raw, raw


def test_the_stamped_location_does_not_pin_validation(macpol):
    """security-note: the stamped location is ADVISORY.  This server does not
    serve ISSUER_URI, yet the macaroon it just minted still authenticates a
    read here — only brix_webdav_token_issuer makes validation reject a
    location mismatch (validate.c).  Pinned so that a site cannot mistake this
    directive for a fence."""
    token, _ = _issue(macpol.port, "tight",
                      {"caveats": ["activity:DOWNLOAD", "path:/"],
                       "validity": "PT1M"})
    assert _location_packet(_decode(token)) == ISSUER_URI
    resp = _read(macpol.port, "tight", token)
    assert resp.status_code in (200, 206), resp.text
    assert resp.text == "tight-payload\n"


def test_a_subtree_path_caveat_revokes_the_macaroon_defect_pin(macpol):
    """defect pin (#17): a macaroon confined to a SUBTREE cannot read anything.

    The issued token's own scope comes from its activity: caveat and is rooted
    at "/", and macaroon_apply_path_to_scope compares the caveat against that
    root as a 1-byte prefix: it then demands caveat_path[1] be '/' or NUL to
    call the caveat "deeper".  For "/tight" that byte is 't', so neither the
    narrow branch nor the already-narrower branch matches and the scope is
    revoked as DISJOINT — every permission cleared, scopes=0, 403.  Confining
    a delegation to a subtree is the entire point of the dCache caveats[] API,
    so this makes the feature unusable while failing closed (a denial, not a
    leak).  The path:/ control beside it proves the round trip is otherwise
    sound."""
    subtree, _ = _issue(macpol.port, "tight",
                        {"caveats": ["activity:DOWNLOAD", "path:/tight"]})
    assert b"cid path:/tight\n" in _decode(subtree)      # it IS in the token
    assert _read(macpol.port, "tight", subtree).status_code == 403, (
        "the subtree caveat now narrows instead of revoking — the parser was "
        "fixed; retire this pin")
    whole, _ = _issue(macpol.port, "tight",
                      {"caveats": ["activity:DOWNLOAD", "path:/"]})
    assert _read(macpol.port, "tight", whole).status_code in (200, 206)


# ── brix_webdav_macaroon_max_validity: the ceiling on a lifetime ──────────

def test_an_absent_validity_issues_at_the_configured_maximum(macpol):
    """success: with no `validity` field the handler falls back to the
    configured maximum, so the knob sets the DEFAULT lifetime as well as the
    ceiling — 120s here rather than the 86400s merge default."""
    token, issued_at = _issue(macpol.port, "tight",
                              {"caveats": ["activity:DOWNLOAD",
                                           "path:/tight"]})
    _assert_lifetime(_decode(token), issued_at, TIGHT_MAX)


def test_a_requested_validity_over_the_maximum_is_clamped(macpol):
    """security-negative: a caller asking for an hour on the policed face gets
    two minutes.  mac_iso8601_secs clamps to conf->macaroon_max_validity before
    the expiry is computed, so a client cannot mint itself a longer-lived
    delegation than the site permits."""
    token, issued_at = _issue(macpol.port, "tight",
                              {"caveats": ["activity:DOWNLOAD", "path:/tight"],
                               "validity": "PT1H"})
    raw = _decode(token)
    _assert_lifetime(raw, issued_at, TIGHT_MAX)
    assert _expiry(raw) - issued_at < 3600, raw


def test_the_default_face_honours_the_same_hour_in_full(macpol):
    """negative control: the identical PT1H on the default face is issued at
    the full 3600s — well under its own 86400s ceiling.  The clamp above is
    therefore the configured maximum, not a hard cap somewhere in the parser."""
    token, issued_at = _issue(macpol.port, "open",
                              {"caveats": ["activity:DOWNLOAD", "path:/open"],
                               "validity": "PT1H"})
    raw = _decode(token)
    _assert_lifetime(raw, issued_at, 3600)
    assert _expiry(raw) - issued_at < DEFAULT_MAX, raw
