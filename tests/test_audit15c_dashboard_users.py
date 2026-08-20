"""
test_audit15c_dashboard_users.py — dashboard multi-user auth
(audit §A2, testsuite-combinatorial-coverage-audit 2026-08-15:
`brix_dashboard_users` / `brix_dashboard_cookie_path` /
`brix_dashboard_session_ttl` had zero coverage; every dashboard test used the
single-password mode).

The users file exercises both hash branches of module_config.c: a crypt(3)
SHA-512 entry (generated with `openssl passwd -6`; Python 3.13 removed the
crypt module) and a legacy-plaintext entry.  Session TTL is configured but
expiry is pinned via cookie tampering, not sleeping — the WSL host clock steps
backwards, so wall-clock waits are banned in this suite.  Cases:

  * success — crypt-hash login sets the HMAC session cookie on the
    non-default cookie_path and the cookie opens the authed JSON API
  * success — legacy-plaintext login works (the compat branch)
  * error / security-negative — wrong password and unknown user get no
    cookie; a bit-flipped cookie is refused by the HMAC check
  * parse-negatives — a malformed users line and the users+password conflict
    are refused at nginx -t with their documented messages
"""

import re
import subprocess

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST
from test_phase25_ratelimit import _http_values, _parse_fail

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15c-dash-users")]

COOKIE_PATH = "/dash15c"
ALICE_PW = "alice-secret-15c"
BOB_PW = "bob-plain-15c"


def _crypt_hash(password):
    return subprocess.run(
        ["openssl", "passwd", "-6", "-salt", "aud15csalt", password],
        capture_output=True, text=True, check=True).stdout.strip()


def _write_users(tmp_path):
    users = tmp_path / "users.txt"
    users.write_text(
        "# audit-15c users file: crypt(3) and legacy-plaintext branches\n"
        "\n"
        f"alice:{_crypt_hash(ALICE_PW)}\n"
        f"bob:{BOB_PW}\n")
    return users


@pytest.fixture()
def dash(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    return lifecycle.start(NginxInstanceSpec(
        name="lc-audit15c-dash-users",
        template="nginx_audit15c_dash_users.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": HOST,
                         "USERS_FILE": str(_write_users(tmp_path)),
                         "COOKIE_PATH": COOKIE_PATH},
        reason="audit-15c dashboard users-file auth")).port


def _login(port, username, password):
    return requests.post(f"http://{HOST}:{port}/brix/login",
                         data={"username": username, "password": password},
                         allow_redirects=False, timeout=10)


def _session_cookie(resp):
    m = re.search(r"xrd_dashboard=([^;]+)",
                  resp.headers.get("Set-Cookie", ""))
    return m.group(1) if m else None


def _api_get(port, cookie):
    headers = {"Cookie": f"xrd_dashboard={cookie}"} if cookie else {}
    return requests.get(f"http://{HOST}:{port}/brix/api/v1/ratelimit",
                        headers=headers, timeout=10)


def test_crypt_user_login_and_session(dash):
    resp = _login(dash, "alice", ALICE_PW)
    cookie = _session_cookie(resp)
    assert cookie, resp.headers.get("Set-Cookie")
    set_cookie = resp.headers["Set-Cookie"]
    assert f"Path={COOKIE_PATH}" in set_cookie, set_cookie
    assert "HttpOnly" in set_cookie, set_cookie
    r = _api_get(dash, cookie)
    assert r.status_code == 200, (r.status_code, r.text)


def test_plaintext_legacy_user_login(dash):
    cookie = _session_cookie(_login(dash, "bob", BOB_PW))
    assert cookie
    assert _api_get(dash, cookie).status_code == 200


def test_wrong_password_gets_no_cookie(dash):
    resp = _login(dash, "alice", "not-the-password")
    assert _session_cookie(resp) is None, resp.headers.get("Set-Cookie")


def test_unknown_user_gets_no_cookie(dash):
    resp = _login(dash, "mallory", ALICE_PW)
    assert _session_cookie(resp) is None, resp.headers.get("Set-Cookie")


def test_tampered_cookie_rejected(dash):
    cookie = _session_cookie(_login(dash, "alice", ALICE_PW))
    assert cookie
    # Flip one hex digit of the HMAC half; the constant-time verify must fail.
    hmac_hex, _, ts = cookie.partition(".")
    flipped = ("0" if hmac_hex[0] != "0" else "1") + hmac_hex[1:]
    r = _api_get(dash, f"{flipped}.{ts}")
    assert r.status_code != 200, (r.status_code, r.text)


def _dash_parse(tmp_path, knobs):
    return _parse_fail(tmp_path, "nginx_rl_http.conf", _http_values(knobs))


def test_malformed_users_line_refused_at_parse(tmp_path):
    bad = tmp_path / "bad-users.txt"
    bad.write_text("line-without-a-colon\n")
    rc, out = _dash_parse(tmp_path,
                          "            brix_dashboard on;\n"
                          f"            brix_dashboard_users {bad};\n")
    assert rc != 0
    assert "malformed user entry" in out, out


def test_users_and_password_conflict_refused_at_parse(tmp_path):
    users = _write_users(tmp_path)
    rc, out = _dash_parse(tmp_path,
                          "            brix_dashboard on;\n"
                          f"            brix_dashboard_users {users};\n"
                          "            brix_dashboard_password sesame;\n")
    assert rc != 0
    # The refusal names whichever directive arrives second; with users first
    # the emerg reads "brix_dashboard_password ... cannot be used with
    # brix_dashboard_users".
    assert "cannot be used with brix_dashboard_users" in out, out
