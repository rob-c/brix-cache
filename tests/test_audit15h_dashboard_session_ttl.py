"""
test_audit15h_dashboard_session_ttl.py — dashboard session expiry
(audit §A1: `brix_dashboard_session_ttl` was *configured* by the 15c users
file, but nothing anywhere asserted that a session ever expires).

The directive is a security control — it is the only thing that stops a leaked
dashboard cookie from being valid forever — and it was the last of the
dashboard hardening knobs with no behavioural coverage.  It stayed uncovered
because the obvious test is "log in, wait out the TTL, try again", and this
suite bans wall-clock waits: the WSL host clock steps backwards, so a sleeping
test is both slow and flaky.

WHAT MAKES IT TESTABLE WITHOUT WAITING.  The session cookie is not opaque — it
is `HMAC.<ts>` (single-password) or `HMAC.<ts>.<user>` (users file), where the
HMAC key is the configured password / the user's stored credential and the
signed message is `"<ts>"` / `"<ts>.<user>"` (dashboard_auth_creds.c:167-191).
A test that knows the password knows the key, so it can MINT a cookie at any
timestamp it likes and ask the server what it thinks of it.  Age becomes a
parameter instead of a wait.

Two things keep that honest rather than circular:

  * the first test proves a minted cookie dated *now* is accepted, and that the
    product's own login cookie is byte-identical to a mint at the same ts — if
    the minting drifted from the server's construction, every rejection below
    would be a signature failure wearing an expiry's clothes;
  * "now" is read off the SERVER, out of the timestamp field of a real login
    cookie, never off the test host's clock.  Nothing here depends on the two
    clocks agreeing, which is exactly the hazard that kept this row open.

Cases:
  * success       — a mint at the server's own `now` opens the API, and the
                    product's login cookie for that ts is the same bytes
  * success       — an age just inside the window is still accepted
  * error         — an age just past `brix_dashboard_session_ttl` is refused
                    with 401, on both cookie shapes
  * success       — the same over-age cookie IS accepted by the plane that
                    leaves the TTL at its 28800s default, which is what proves
                    the refusal came from the directive
  * sec-negative  — a forged FUTURE timestamp beyond the 60s skew allowance is
                    refused even though its signature is perfect
  * sec-negative  — a cookie whose username tail is swapped for another
                    configured user is refused: the username is inside the
                    signed message, so a fresh session cannot be re-aimed
  * sec-negative  — a users-file cookie stripped to the single-password shape
                    is refused rather than falling back to the other mode
"""

import hashlib
import hmac
import re
import subprocess

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-dashttl")]

NAME = "lc-audit15h-dashttl"
PASSWORD = "a15h-dash-ttl-secret"
ALICE_PW = "alice-ttl-15h"
BOB_PW = "bob-ttl-15h"
TTL = 120                 # what the template configures on PORT and MU_PORT
DEFAULT_TTL = 28800       # module.c:136 — what DEF_PORT gets by not saying
SKEW = 60                 # auth.c:177 — the future-dated allowance

# The one authed JSON endpoint every dashboard plane serves regardless of what
# else is configured; the subject here is the cookie, not the payload.
API = "/brix/api/v1/ratelimit"


def _crypt_hash(password):
    """`openssl passwd -6` rather than crypt(3): Python 3.13 removed the crypt
    module, and the suite already standardised on this in 15c."""
    return subprocess.run(
        ["openssl", "passwd", "-6", "-salt", "aud15hsalt", password],
        capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture(scope="module")
def _alice_hash():
    return _crypt_hash(ALICE_PW)


@pytest.fixture
def dash(lifecycle, tmp_path, _alice_hash):
    """The three planes plus the two credential keys the test signs with.

    alice is a crypt(3) entry and bob a legacy-plaintext one, because the HMAC
    key is the STORED credential in both cases (dashboard_auth_creds.c:244) —
    the hash for alice, the bare password for bob — and a mint that assumed one
    shape would silently only ever test the other."""
    data = tmp_path / "data"
    data.mkdir()
    users = tmp_path / "users.txt"
    users.write_text(f"alice:{_alice_hash}\nbob:{BOB_PW}\n")

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_dashttl.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "PASSWORD": PASSWORD,
                         "USERS_FILE": str(users),
                         "TTL_SECONDS": str(TTL)},
        reason="audit-15h dashboard session TTL"))
    keys = {"alice": _alice_hash, "bob": BOB_PW}
    return endpoint, keys


# --------------------------------------------------------------------------- #
# minting and presenting cookies
# --------------------------------------------------------------------------- #

def _mint(key, ts, username=None):
    """The server's own cookie construction, in Python.

    Single-password mode signs the bare timestamp and emits "<hmac>.<ts>";
    users mode signs "<ts>.<user>" and appends the username
    (dashboard_auth_creds.c:167-191, dashboard_auth_login.c:287-299)."""
    msg = f"{ts}" if username is None else f"{ts}.{username}"
    digest = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{digest}.{ts}" if username is None else f"{digest}.{ts}.{username}"


def _login(port, password, username=None):
    data = {"password": password}
    if username is not None:
        data["username"] = username
    return requests.post(f"http://{HOST}:{port}/brix/login", data=data,
                         allow_redirects=False, timeout=10)


def _cookie_of(resp):
    m = re.search(r"xrd_dashboard=([^;]+)", resp.headers.get("Set-Cookie", ""))
    return m.group(1) if m else None


def _server_now(port, password, username=None):
    """The server's `time(NULL)`, read out of a freshly issued cookie.

    Every age below is computed from this rather than from the test host's
    clock: the cookie's timestamp IS the server's clock, so a login is the one
    measurement that cannot be wrong about it."""
    cookie = _cookie_of(_login(port, password, username))
    assert cookie, "no session cookie was issued — the credentials are wrong"
    return int(cookie.split(".")[1]), cookie


def _get(port, cookie):
    headers = {"Cookie": f"xrd_dashboard={cookie}"} if cookie else {}
    return requests.get(f"http://{HOST}:{port}{API}", headers=headers,
                        timeout=10)


# --------------------------------------------------------------------------- #

def test_a_minted_cookie_matches_the_product_and_is_accepted(dash):
    """success, and the load-bearing control: the mint reproduces the server's
    construction byte for byte, so every 401 below is about the timestamp and
    not about a signature the test got wrong."""
    endpoint, _keys = dash
    assert _get(endpoint.port, None).status_code == 401, \
        "the API answered without a cookie; nothing here would mean anything"

    now, issued = _server_now(endpoint.port, PASSWORD)
    assert _mint(PASSWORD, now) == issued, (issued, _mint(PASSWORD, now))
    assert _get(endpoint.port, _mint(PASSWORD, now)).status_code == 200


def test_an_age_inside_the_window_is_accepted(dash):
    """success: the window is at least as long as configured.  Without this the
    expiry test below would also pass against a TTL of zero."""
    endpoint, _keys = dash
    now, _ = _server_now(endpoint.port, PASSWORD)

    fresh = _mint(PASSWORD, now - (TTL - 5))
    assert _get(endpoint.port, fresh).status_code == 200, \
        f"a cookie {TTL - 5}s old was refused under a {TTL}s TTL"


def test_an_age_past_the_ttl_is_refused(dash):
    """error: the directive doing its job.  `now - ts > ttl` (auth.c:177), so
    the first refused age is ttl + 1; the +5 is slack for the second that may
    tick between the login that read `now` and the request that spends it."""
    endpoint, _keys = dash
    now, _ = _server_now(endpoint.port, PASSWORD)

    stale = _mint(PASSWORD, now - (TTL + 5))
    resp = _get(endpoint.port, stale)
    assert resp.status_code == 401, (resp.status_code, resp.text[:200])


def test_the_users_file_cookie_expires_too(dash):
    """error, on the other cookie shape: the users-file message is
    "<ts>.<user>" signed under the stored credential, and the freshness check
    runs before the HMAC check — a crypt-hash user and a plaintext user must
    both age out."""
    endpoint, keys = dash
    mu = endpoint.extra_ports["MU_PORT"]

    for user in ("alice", "bob"):
        password = ALICE_PW if user == "alice" else BOB_PW
        now, _ = _server_now(mu, password, username=user)
        assert _get(mu, _mint(keys[user], now, user)).status_code == 200, \
            f"the mint for {user} is wrong; the expiry result would be a lie"
        stale = _mint(keys[user], now - (TTL + 5), user)
        assert _get(mu, stale).status_code == 401, f"{user} did not expire"


def test_the_same_stale_cookie_is_accepted_under_the_default_ttl(dash):
    """success, and the pairing that makes the refusals attributable: the
    identical age against the plane that never mentions the directive.  The
    28800s default has to accept what the 120s setting rejects — otherwise
    "expired" is indistinguishable from "the cookie was bad for some other
    reason"."""
    endpoint, _keys = dash
    default_port = endpoint.extra_ports["DEF_PORT"]
    now, _ = _server_now(default_port, PASSWORD)

    age = TTL + 5
    assert age < DEFAULT_TTL, "the age has to be stale on one plane and fresh here"
    stale = _mint(PASSWORD, now - age)

    assert _get(default_port, stale).status_code == 200, \
        "the default TTL rejected a cookie well inside 8 hours"
    assert _get(endpoint.port, stale).status_code == 401, \
        "the same cookie was accepted by the 120s plane"


def test_a_future_dated_cookie_beyond_the_skew_is_refused(dash):
    """security-negative: the other half of the freshness check.  A cookie
    dated in the future would otherwise outlive its TTL by however far ahead it
    was dated, so `ts > now + 60` is refused (auth.c:177) — and the signature
    here is perfect, which is the point: the bound is on the timestamp, not on
    the attacker's ability to sign."""
    endpoint, _keys = dash
    now, _ = _server_now(endpoint.port, PASSWORD)

    # Just inside the documented skew allowance: still valid.
    assert _get(endpoint.port, _mint(PASSWORD, now + SKEW - 20)).status_code == 200

    forged = _mint(PASSWORD, now + DEFAULT_TTL)
    assert _get(endpoint.port, forged).status_code == 401, \
        "a cookie dated 8 hours into the future was honoured"


def test_a_cookie_cannot_be_re_aimed_at_another_user(dash):
    """security-negative: the username is inside the signed message, so a valid
    session for one user must not become a session for another by editing the
    tail — which is what would happen if the cookie signed only the timestamp
    and carried the username as an unauthenticated hint."""
    endpoint, keys = dash
    mu = endpoint.extra_ports["MU_PORT"]
    now, _ = _server_now(mu, ALICE_PW, username="alice")

    alice = _mint(keys["alice"], now, "alice")
    assert _get(mu, alice).status_code == 200

    hmac_hex, ts, _user = alice.split(".")
    assert _get(mu, f"{hmac_hex}.{ts}.bob").status_code == 401, \
        "alice's cookie was accepted as bob"


def test_a_users_mode_cookie_stripped_of_its_username_is_refused(dash):
    """security-negative: the two modes must not be interchangeable.  Dropping
    the username tail turns the cookie into the single-password shape, and a
    plane in users mode has to refuse it rather than fall back to verifying it
    against some other key."""
    endpoint, keys = dash
    mu = endpoint.extra_ports["MU_PORT"]
    now, _ = _server_now(mu, ALICE_PW, username="alice")

    hmac_hex, ts, _user = _mint(keys["alice"], now, "alice").split(".")
    assert _get(mu, f"{hmac_hex}.{ts}").status_code == 401, \
        "a users-mode plane accepted a cookie with no username"
