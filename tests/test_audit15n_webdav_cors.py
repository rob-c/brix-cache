"""
test_audit15n_webdav_cors.py — the WebDAV response surface, and the first of
the tranche-14 parse-only directives
(docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

§Method step 2 defines coverage as "the directive's name appears somewhere in
the test/deploy corpus".  That is deliberately weak, and tranche 13 exhausted
everything the strong steps could still find, so tranche 14 sharpens step 2
instead: a name that appears ONLY inside a .conf a test launches is covered by
`nginx -t` and by nothing else.  The directive parses, it merges, and no
assertion anywhere says what it does.  Thirteen directives are in that state.
Four of them are this file's subject, and they all shape the response:

    brix_webdav_cors_origin · brix_webdav_cors_credentials
    brix_webdav_cors_max_age · brix_webdav_redirect_window

`nginx_audit15n_cors.conf` puts them on one listener because they interact.
CORS headers are emitted in the ACCESS phase (`ngx_http_brix_webdav_access_
handler`, access.c:426) and the redirect is built in the CONTENT phase
(`webdav_dispatch_request`, dispatch.c:579), so a 307 inherits whatever the
access phase already put in `headers_out` — which is the difference between a
redirect a browser can follow and one `fetch()` rejects before it ever sees the
Location.  No file in the tree had run the two together.

WHAT THE BLOCK ESTABLISHES

- CORS is opt-in.  `origin_allowed()` (cors.c:31) returns 0 for an empty or
  absent allowlist, so a WebDAV export with no `brix_webdav_cors_origin` emits
  no Access-Control-* header for any Origin whatsoever.
- The allowlist is an exact byte match over a repeatable directive: both
  configured origins match, and a value that merely CONTAINS one does not.
- CORS is not access control.  A denied origin still gets 200 and the bytes —
  the enforcement is the browser's, and the server's job is only to withhold
  the permission slip.  Anything that reads a CORS denial as a security control
  is reading it wrong.
- `brix_webdav_cors_max_age` is what the header says, and its absence is 86400
  (`ngx_conf_merge_uint_value`, config_merge.c:96) — the two locations differ
  in exactly that directive and the responses differ in exactly that header.
- `brix_webdav_redirect_window` is the absolute expiry the manager signs into
  `brixrdr.exp`, and it is enforced: a handoff replayed after its window has
  lapsed is 403 at the data-server half, before `brix_webdav_auth none` ever
  gets a say (`access_authenticate` runs `webdav_redirect_signed_auth` first
  and fail-closed, access_auth.c:380).

DEFECT CANDIDATE #48 (security, config that disarms the same-origin policy) —
`brix_webdav_cors_origin *` together with `brix_webdav_cors_credentials on` is
accepted by `nginx -t` and grants every origin on the internet credentialed
cross-origin access to the export.  `cors_emit_allow_origin()` (cors.c:72)
keeps the letter of the CORS rule — with credentials on it never emits the
literal `*`, it echoes the request origin — and that echo is exactly what makes
the pair dangerous: a literal `*` is INERT for a credentialed request (browsers
refuse it), whereas the echo is honoured, so the safe-looking spelling is the
one browsers reject and the reflected one is the one they obey.  Every origin
that asks receives `Access-Control-Allow-Origin: <itself>` plus
`Access-Control-Allow-Credentials: true`, which is the textbook reflected-origin
misconfiguration: any page the user visits can read this storage element with
the user's cookies attached.  The test below shows two unrelated origins both
being admitted.  The fix is a parse-time refusal of the pair (what most CORS
middleware does), not a change to the emitter — the emitter is correct.

NOT A DEFECT, PINNED AS A FACT.  The signed-redirect handoff authenticates
BEFORE the export's own auth mode is consulted, so an export configured
`brix_webdav_auth none` still 403s a lapsed or forged handoff.  That reads
backwards — an anonymous export refusing a request an anonymous client could
have made unadorned — but it is the fail-closed rule stated in access_auth.c's
comment: a bad MAC must never fall through to a weaker source, and "no auth at
all" is the weakest source there is.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_audit15n_webdav_cors.py -v
"""

import os
import re
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

def _check_test_every_cors_decision_lands_in_its_own_counter_1(base, now):
    assert now["preflight"] == base["preflight"] + 1, (base, now)


pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15n-cors")]

REPO = Path(__file__).resolve().parents[1]

SECRET = "audit15n-redirect-hmac-key-0123456789"
SEED = b"audit15n response-surface payload\n"

# The two origins the /cors/ location admits, and one it does not.
GOOD = "https://portal.example.org"
GOOD2 = "https://notebook.example.org"
EVIL = "https://evil.example.net"
# A value that CONTAINS an allowed origin without being it.  origin_allowed()
# compares lengths first (cors.c:41), so this is the assertion that the match
# is not a prefix/substring test.
SUFFIX = GOOD + ".evil.example.net"

MAX_AGE = "900"          # /cors/ says so
MAX_AGE_DEFAULT = "86400"   # /wild/ says nothing, so the merge default speaks

WINDOW_LONG = 45
WINDOW_SHORT = 2

DEFECT48 = (
    "DEFECT CANDIDATE #48 has been FIXED: brix_webdav_cors_origin * together "
    "with brix_webdav_cors_credentials on no longer admits every origin. If "
    "the fix is a parse-time refusal, move this to the guard-negative section "
    "and assert `nginx -t` rejects the pair; if the emitter now withholds the "
    "echo, assert the absent header instead.")


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def cors(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    # WebDAV maps export root + the WHOLE request URI, so the tree on disk
    # mirrors the URI space rather than stripping the location prefix.
    for uri_dir in ("nocors", "cors", "wild", "wildcred", "rdr45", "rdr2"):
        (data / uri_dir).mkdir(parents=True)
        (data / uri_dir / "seed.txt").write_bytes(SEED)

    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15n-cors",
        template="nginx_audit15n_cors.conf",
        protocol="http",
        data_root=str(data),
        template_values={"SECRET": SECRET,
                         "TMP_DIR": str(tmp)},
        reason="audit-15n: the WebDAV response surface — CORS and the "
               "redirect signing window on one listener"))
    return endpoint, data


# --------------------------------------------------------------------------- #
# Helpers.                                                                     #
# --------------------------------------------------------------------------- #

def _url(endpoint, path):
    return f"http://{HOST}:{endpoint.port}{path}"


def _get(endpoint, path, origin=None, method="GET", **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if origin is not None:
        headers["Origin"] = origin
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("allow_redirects", False)
    return requests.request(method, _url(endpoint, path), headers=headers,
                            **kwargs)


def _acao(response):
    """Access-Control-Allow-Origin, or None when the server withheld it."""
    return response.headers.get("Access-Control-Allow-Origin")


def _metrics(endpoint):
    return _get(endpoint, "/metrics").text


def _cors_count(text, event):
    m = re.search(r'^brix_webdav_cors_total\{event="%s"\}\s+(\d+)' % event,
                  text, re.M)
    return int(m.group(1)) if m else None


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        return (Path(endpoint.prefix) / "logs" / "error.log").read_text(
            errors="replace")
    except FileNotFoundError:
        return ""


def _wait_for_redirect(endpoint, path, origin=None, tries=40, pause=0.5):
    """GET until the manager answers 307 — registration takes a heartbeat.

    webdav_redirect_dataserver() DECLINES to a local serve while the CMS
    registry is empty (redirect.c:299), and a local serve is a 200 with the
    file's bytes.  So "200" here is not a failure of the redirect, it is the
    member not having checked in yet, and the two are only distinguishable by
    waiting.
    """
    for _ in range(tries):
        response = _get(endpoint, path, origin=origin)
        if response.status_code == 307:
            return response
        time.sleep(pause)
    pytest.fail(f"{path} never answered 307 — the CMS member never registered; "
                f"last status {response.status_code}\n{_errlog(endpoint)[-3000:]}")


def _handoff(response):
    """Pull brixrdr.exp out of a 307's Location."""
    location = response.headers["Location"]
    query = parse_qs(urlparse(location).query)
    assert "brixrdr.mac" in query, location
    return location, int(query["brixrdr.exp"][0])


def _nginx_t(conf_text, tmp_path, name):
    """`nginx -t` a DAMAGED COPY under tmp_path — never the tracked template."""
    prefix = tmp_path / name
    (prefix / "logs").mkdir(parents=True)
    (prefix / "data").mkdir()
    conf = prefix / "nginx.conf"
    conf.write_bytes(conf_text)
    proc = subprocess.run([NGINX_BIN, "-t", "-p", str(prefix), "-c", str(conf)],
                          capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stderr


def _guard_conf(prefix, cors_lines):
    """The smallest config that reaches webdav_validate_cors_origins()."""
    return (
        "daemon off;\n"
        f"error_log {prefix}/logs/error.log crit;\n"
        f"pid {prefix}/logs/nginx.pid;\n"
        "events { worker_connections 32; }\n"
        "http {\n"
        f"    client_body_temp_path {prefix}/cb;\n"
        "    server {\n"
        "        listen 127.0.0.1:1;\n"   # net-literal-allow: never bound, -t only
        "        location / {\n"
        "            brix_webdav on;\n"
        f"            brix_storage_backend posix:{prefix}/data;\n"
        "            brix_webdav_auth none;\n"
        f"{cors_lines}"
        "        }\n"
        "    }\n"
        "}\n").encode()


# --------------------------------------------------------------------------- #
# §A — brix_webdav_cors_origin: the allowlist is the whole gate.               #
# --------------------------------------------------------------------------- #

def test_an_export_without_the_directive_emits_no_cors_headers(cors):
    """The control.  CORS is opt-in: origin_allowed() (cors.c:31) returns 0 for
    a NULL or empty allowlist, so an Origin on a location that never wrote
    brix_webdav_cors_origin gets nothing back — which is what makes every
    header in the tests below attributable to the directive rather than to
    nginx."""
    endpoint, _ = cors

    response = _get(endpoint, "/nocors/seed.txt", origin=GOOD)

    assert response.status_code == 200, response.text[:400]
    assert response.content == SEED
    assert _acao(response) is None, dict(response.headers)
    assert "Access-Control-Allow-Credentials" not in response.headers
    assert "Access-Control-Max-Age" not in response.headers
    assert "Origin" not in response.headers.get("Vary", "")


def test_a_configured_origin_is_echoed_with_vary(cors):
    """The success case: an allowed origin comes back verbatim, and Vary:
    Origin comes with it unconditionally (cors_emit_allow_origin, cors.c:86) so
    a shared cache cannot hand one origin's response to another."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=GOOD)

    assert response.status_code == 200
    assert _acao(response) == GOOD, dict(response.headers)
    assert "Origin" in response.headers.get("Vary", ""), \
        response.headers.get("Vary")
    assert "ETag" in response.headers.get("Access-Control-Expose-Headers", "")


def test_the_directive_is_repeatable_and_both_entries_match(cors):
    """brix_webdav_cors_origin appends (webdav_conf_add_cors_origin,
    module_directives.c:117), so the SECOND entry is a live allowlist member
    and not a value the first one overwrote."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=GOOD2)

    assert _acao(response) == GOOD2, dict(response.headers)


def test_an_unlisted_origin_gets_no_headers_but_still_gets_the_bytes(cors):
    """Security-negative, and the fact that goes with it: a denied origin is
    denied the PERMISSION, not the data.  The server answers 200 with the file
    because CORS enforcement lives in the browser; an operator who writes an
    allowlist expecting it to keep other origins away from the storage has
    configured nothing of the sort."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=EVIL)

    assert _acao(response) is None, dict(response.headers)
    assert response.status_code == 200
    assert response.content == SEED, \
        "CORS became an access control — if that is now intended, this file's " \
        "premise changed and the docstring needs rewriting"


def test_an_origin_that_merely_contains_an_allowed_one_is_denied(cors):
    """Security-negative for the match itself.  origin_allowed() compares the
    lengths before the bytes (cors.c:41), so `https://portal.example.org.evil.
    example.net` — a domain the attacker owns, and a substring match away from
    being trusted — is not a match."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=SUFFIX)

    assert _acao(response) is None, \
        f"a suffix-extended origin was admitted: {dict(response.headers)}"


def test_a_request_with_no_origin_header_gets_no_cors_headers(cors):
    """A same-origin request is not a CORS request: brix_http_add_cors_headers
    returns NGX_DECLINED before it ever consults the allowlist (cors.c:237)."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt")

    assert response.status_code == 200
    assert _acao(response) is None, dict(response.headers)


# --------------------------------------------------------------------------- #
# §B — brix_webdav_cors_credentials: the rule, and what obeying it costs.      #
# --------------------------------------------------------------------------- #

def test_a_wildcard_without_credentials_answers_the_literal_star(cors):
    """The one shape allowed to emit `*`: a wildcard match with credentials off
    (cors_emit_allow_origin, cors.c:72).  The star is what lets a cache serve
    one stored response to every origin, which is the whole point of it."""
    endpoint, _ = cors

    response = _get(endpoint, "/wild/seed.txt", origin=EVIL)

    assert _acao(response) == "*", dict(response.headers)
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_a_wildcard_with_credentials_never_answers_the_literal_star(cors):
    """The CORS security rule, kept: `*` and credentials cannot be combined, so
    when credentials are on the concrete origin is echoed instead.  Asserting
    the ABSENCE of the star is the point — a browser would reject the
    combination outright, so emitting it would be a self-disabling response."""
    endpoint, _ = cors

    response = _get(endpoint, "/wildcred/seed.txt", origin=GOOD)

    assert _acao(response) == GOOD, dict(response.headers)
    assert _acao(response) != "*"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_the_wildcard_credentialed_export_admits_every_origin(cors):
    """DEFECT CANDIDATE #48.  The echo that keeps the rule is also what breaks
    the export: two origins with nothing in common — neither of them named
    anywhere in the config — are each handed themselves plus
    Allow-Credentials: true.  That is reflected-origin CORS, and it means any
    page the user has open can read this storage element with the user's
    cookies.  `nginx -t` accepts the pair without a word."""
    endpoint, _ = cors

    # A developer's own page and the opaque "null" a sandboxed iframe sends
    # are the two origins an operator would least expect to be admitted.
    for origin in (EVIL, "http://localhost:8080", "null"):  # net-literal-allow: an Origin header value the server must string-match, never an endpoint this test dials
        response = _get(endpoint, "/wildcred/seed.txt", origin=origin)
        assert _acao(response) == origin, DEFECT48 + f" ({origin})"
        assert response.headers.get(
            "Access-Control-Allow-Credentials") == "true", DEFECT48


def test_credentials_stay_off_where_the_directive_is_absent(cors):
    """The merge default is 0 (config_merge.c:95), so the /cors/ location —
    which writes an allowlist and nothing else — must not advertise
    credentials.  Without this the test above proves only that the header
    exists somewhere."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=GOOD)

    assert "Access-Control-Allow-Credentials" not in response.headers, \
        dict(response.headers)


# --------------------------------------------------------------------------- #
# §C — brix_webdav_cors_max_age: the value, and the value of its absence.      #
# --------------------------------------------------------------------------- #

def test_the_configured_max_age_is_the_one_on_the_wire(cors):
    """cors_emit_max_age() renders conf->cors_max_age into the header
    (cors.c:210).  900 is not a round number the code could plausibly hold as a
    constant, which is what makes this an assertion about the directive."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=GOOD)

    assert response.headers.get("Access-Control-Max-Age") == MAX_AGE, \
        dict(response.headers)


def test_an_unset_max_age_falls_back_to_the_merge_default(cors):
    """/wild/ differs from /cors/ in exactly this directive's absence, so the
    86400 it reports is ngx_conf_merge_uint_value's default (config_merge.c:96)
    and not a second configured value."""
    endpoint, _ = cors

    response = _get(endpoint, "/wild/seed.txt", origin=EVIL)

    assert response.headers.get("Access-Control-Max-Age") == MAX_AGE_DEFAULT, \
        dict(response.headers)


# --------------------------------------------------------------------------- #
# §D — the preflight, and the header the server is asked to reflect.           #
# --------------------------------------------------------------------------- #

def test_the_preflight_echoes_the_requested_headers(cors):
    """cors_emit_allow_headers() reflects Access-Control-Request-Headers when
    it is clean (cors.c:161).  A WebDAV client preflighting Depth/Destination
    needs exactly that — the fixed fallback list cannot know the verbs a
    particular client will send."""
    endpoint, _ = cors

    response = _get(endpoint, "/cors/seed.txt", origin=GOOD, method="OPTIONS",
                    headers={"Access-Control-Request-Method": "PROPFIND",
                             "Access-Control-Request-Headers":
                                 "X-Audit15n, Depth"})

    assert response.status_code in (200, 204), response.text[:400]
    assert response.headers.get("Access-Control-Allow-Headers") == \
        "X-Audit15n, Depth", dict(response.headers)
    assert "PROPFIND" in response.headers.get("Access-Control-Allow-Methods",
                                              "")


def test_a_control_byte_in_the_requested_headers_is_not_reflected(cors):
    """Security-negative for the reflection.  The echo is gated on
    brix_http_str_has_ctl() (cors.c:162) because the value is attacker-supplied
    and lands in a RESPONSE header: a CR/LF or other control byte reflected
    verbatim is response-header injection.  requests() will not send such a
    value, so this goes over a raw socket, and the assertion is that the server
    fell back to its fixed list rather than echoing."""
    endpoint, _ = cors

    request = (
        f"OPTIONS /cors/seed.txt HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Origin: {GOOD}\r\n"
        "Access-Control-Request-Method: GET\r\n"
        "Access-Control-Request-Headers: X-Bad\x01Injected\r\n"
        "Connection: close\r\n\r\n").encode()

    sock = socket.create_connection((HOST, endpoint.port), timeout=30)
    try:
        sock.sendall(request)
        raw = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    finally:
        sock.close()

    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    # nginx may refuse the request outright; either answer is safe, and the one
    # thing neither may do is put the control byte in a response header.
    assert "\x01" not in head, f"a control byte was reflected:\n{head}"
    if " 400 " not in head.split("\r\n", 1)[0]:
        assert "Authorization, Content-Type" in head, \
            f"the tainted value was neither refused nor replaced:\n{head}"


# --------------------------------------------------------------------------- #
# §E — the decisions are counted.                                             #
# --------------------------------------------------------------------------- #

def test_every_cors_decision_lands_in_its_own_counter(cors):
    """brix_webdav_cors_total is labelled allowed/denied/no_origin/preflight
    (metrics/webdav.c:71).  Driving one of each and diffing is what shows the
    label is chosen by the outcome and not by the request shape — an OPTIONS
    with an allowed origin counts BOTH preflight and allowed, because
    access_options_preflight() (access.c:229) runs after the emitter."""
    endpoint, _ = cors

    before = _metrics(endpoint)
    base = {ev: _cors_count(before, ev) or 0
            for ev in ("allowed", "denied", "preflight")}

    _get(endpoint, "/cors/seed.txt", origin=GOOD)
    _get(endpoint, "/cors/seed.txt", origin=EVIL)
    _get(endpoint, "/cors/seed.txt", origin=GOOD, method="OPTIONS",
         headers={"Access-Control-Request-Method": "GET"})

    after = _metrics(endpoint)
    now = {ev: _cors_count(after, ev) or 0
           for ev in ("allowed", "denied", "preflight")}

    def _assert_test_every_cors_decision_lands_in_its_own_counter_1():
        assert now["allowed"] >= base["allowed"] + 2, (base, now)
        assert now["denied"] >= base["denied"] + 1, (base, now)

    _assert_test_every_cors_decision_lands_in_its_own_counter_1()
    _check_test_every_cors_decision_lands_in_its_own_counter_1(base, now)


# --------------------------------------------------------------------------- #
# §F — brix_webdav_redirect_window, and the pair the file exists to run.       #
# --------------------------------------------------------------------------- #

def test_the_signed_expiry_is_the_configured_window(cors):
    """rdr_append_signed_cgi() formats `ngx_time() + conf->redirect_window`
    into brixrdr.exp (redirect.c:118).  Two locations differing only in that
    directive must produce two different absolute expiries, each one its own
    window ahead of now — which is the assertion no existing test makes: the
    tree checks that brixrdr.exp is PRESENT, never that it is the configured
    number of seconds away."""
    endpoint, _ = cors

    long_response = _wait_for_redirect(endpoint, "/rdr45/seed.txt")
    sent_at = int(time.time())
    _location, long_exp = _handoff(long_response)

    short_response = _wait_for_redirect(endpoint, "/rdr2/seed.txt")
    _location, short_exp = _handoff(short_response)

    # A second of slack each way: exp is stamped from nginx's cached clock.
    assert WINDOW_LONG - 2 <= long_exp - sent_at <= WINDOW_LONG + 2, \
        f"/rdr45/ signed {long_exp - sent_at}s ahead, expected {WINDOW_LONG}"
    assert short_exp - sent_at <= WINDOW_SHORT + 2, \
        f"/rdr2/ signed {short_exp - sent_at}s ahead, expected {WINDOW_SHORT}"
    assert long_exp > short_exp, (long_exp, short_exp)


def test_a_handoff_used_inside_its_window_is_served(cors):
    """The positive control for the negative below: the same Location, followed
    at once, is 200 with the file's bytes.  The second visit is a LOCAL serve —
    rdr_eligible() (redirect.c:206) declines to redirect a request that already
    carries brixrdr.mac — so a 200 here proves the MAC verified, not that the
    redirect was skipped."""
    endpoint, _ = cors

    response = _wait_for_redirect(endpoint, "/rdr45/seed.txt")
    location, _exp = _handoff(response)

    followed = requests.get(location, timeout=30, allow_redirects=False)

    assert followed.status_code == 200, \
        f"{followed.status_code} for {location}\n{_errlog(endpoint)[-2000:]}"
    assert followed.content == SEED


def test_a_handoff_replayed_after_its_window_is_refused(cors):
    """Security-negative, and the directive's actual purpose.  The 2-second
    window is a replay bound: once the wall clock passes brixrdr.exp the
    data-server half refuses the handoff 403 (redirect.c:421), and it does so
    on an export whose brix_webdav_auth is `none` — the signed-redirect gate
    runs BEFORE the auth mode is consulted and is fail-closed
    (access_auth.c:380), so a bad handoff cannot degrade into an anonymous
    request that would have been allowed anyway."""
    endpoint, _ = cors

    response = _wait_for_redirect(endpoint, "/rdr2/seed.txt")
    location, exp = _handoff(response)

    # Outlive the window the directive set, then replay the manager's own URL.
    time.sleep(max(0.0, exp - time.time()) + 1.5)
    replayed = requests.get(location, timeout=30, allow_redirects=False)

    assert replayed.status_code == 403, (
        f"a handoff {int(time.time()) - exp}s past its expiry was answered "
        f"{replayed.status_code}\n{_errlog(endpoint)[-2000:]}")
    assert "signed redirect expired" in _errlog(endpoint), \
        "403 for some other reason than the lapsed window"


def test_the_redirect_carries_the_cors_headers_a_browser_needs(cors):
    """The pair this file exists to run.  CORS is set in the access phase and
    the 307 is built in the content phase, so the redirect inherits the
    headers — and it must, because a cross-origin fetch() rejects a redirect
    response that lacks Access-Control-Allow-Origin without ever reading its
    Location.  A redirecting storage element with a CORS allowlist and no
    header on the 307 is a storage element no browser can use."""
    endpoint, _ = cors

    response = _wait_for_redirect(endpoint, "/rdr45/seed.txt", origin=GOOD)

    assert response.status_code == 307
    assert _acao(response) == GOOD, (
        "the 307 carries no Access-Control-Allow-Origin — a browser cannot "
        f"follow it: {dict(response.headers)}")
    assert "Origin" in response.headers.get("Vary", "")
    assert "Location" in response.headers


# --------------------------------------------------------------------------- #
# §G — guard-negatives.  Every one damages a COPY under tmp_path.             #
# --------------------------------------------------------------------------- #

def test_an_empty_cors_origin_fails_nginx_t(cors, tmp_path):
    """webdav_validate_cors_origins() (config.c:76) refuses a zero-length
    entry, because an empty allowlist member would be a silent no-op the
    operator believes is a rule."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    prefix = tmp_path / "empty"

    rc, err = _nginx_t(
        _guard_conf(prefix, '            brix_webdav_cors_origin "";\n'),
        tmp_path, "empty")

    assert rc != 0, f"an empty CORS origin was accepted:\n{err}"
    assert "invalid CORS origin" in err, err


def test_a_control_byte_in_a_cors_origin_fails_nginx_t(cors, tmp_path):
    """The config-time half of the injection guard.  A configured origin is
    reflected into Access-Control-Allow-Origin, so a control byte in one would
    be header injection every operator could reach — validated at parse time so
    it fails `nginx -t` instead of poisoning responses (config.c:59)."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    prefix = tmp_path / "ctl"

    rc, err = _nginx_t(
        _guard_conf(prefix,
                    '            brix_webdav_cors_origin "https://a\x01b";\n'),
        tmp_path, "ctl")

    assert rc != 0, f"a control byte in a CORS origin was accepted:\n{err}"
    assert "invalid CORS origin" in err, err
