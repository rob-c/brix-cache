"""Auth-result accounting edges and identity-tracking hygiene.

WHAT: WebDAV auth-result rows under degenerate credentials (garbage /
      empty / missing bearer, withheld client cert), the uncovered S3
      bad_access_key row, auth-row linearity per mechanism, and the
      user-session identity tracker: a GSI session must materialize
      brix_user_sessions_total with a QUOTED 8-hex hash label (the
      unquoted-value exposition bug pinned here), never a plaintext DN,
      and anonymous traffic must add no identity row at all.

WHY:  Auth counters drive security dashboards — a fallback booked as a
      success (or a rejection dropped) hides credential problems.  The
      session tracker labels rows by user identity: an unquoted label
      breaks strict Prometheus parsers, and a raw DN would be both a
      privacy leak and an unbounded-cardinality label value.
"""

import re

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

IO = {"proto": "webdav"}

SESSION_ROW = re.compile(
    r'^brix_user_sessions_total\{hash="([0-9a-f]{8})"\} \d+$', re.M)


def snap(mx):
    return cx.Snap(mx.metrics)


def bearer_headers():
    import os
    if not os.path.exists(cx.TOKEN_FILE):
        pytest.skip("bearer token fixture missing")
    tok = open(cx.TOKEN_FILE).read().strip()
    return {"Authorization": f"Bearer {tok}"}


def cached(mx, tag, size=350):
    name = cx.unique_name(tag)
    payload = mx.seed_local(name, size)
    assert mx.dav_request("dav", f"/{name}")[0] == 200
    cx.settle()
    return name, payload


# --------------------------------------------------------------------------
# WebDAV auth-result rows
# --------------------------------------------------------------------------

def test_davs_valid_bearer_get_books_token_ok(mx):
    """A valid bearer GET books token_ok exactly once and NO fallback."""
    name, payload = cached(mx, "amtok")
    s = snap(mx)
    st, body, _ = mx.dav_request("davs", f"/{name}",
                                 headers=bearer_headers())
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_webdav_auth_total", {"result": "token_ok"},
                   after) == 1
    assert s.delta("brix_webdav_auth_total",
                   {"result": "anonymous_fallback"}, after) == 0


@pytest.mark.parametrize("auth_hdr", ["Bearer this-is-not-a-token", ""])
def test_davs_bad_bearer_falls_back_anonymous(mx, auth_hdr):
    """A garbage (or empty) Authorization value on the optional-auth plane
    serves anonymously: token_ok NEVER books, the fallback row does, and
    the object is still served (optional auth = degrade, not deny)."""
    name, payload = cached(mx, "ambad")
    s = snap(mx)
    st, body, _ = mx.dav_request("davs", f"/{name}",
                                 headers={"Authorization": auth_hdr})
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_webdav_auth_total", {"result": "token_ok"},
                   after) == 0
    assert s.delta("brix_webdav_auth_total",
                   {"result": "anonymous_fallback"}, after) == 1


def test_davs_fallback_linearity(mx):
    """Three anonymous GETs on the optional-auth plane book EXACTLY three
    fallback rows — one per request, no coalescing."""
    name, _ = cached(mx, "amlin")
    s = snap(mx)
    for _ in range(3):
        assert mx.dav_request("davs", f"/{name}")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_webdav_auth_total",
                   {"result": "anonymous_fallback"}, after) == 3


def test_token_ok_linearity(mx):
    """Three bearer GETs book exactly three token_ok rows."""
    name, _ = cached(mx, "amtok3")
    hdrs = bearer_headers()
    s = snap(mx)
    for _ in range(3):
        assert mx.dav_request("davs", f"/{name}", headers=hdrs)[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_webdav_auth_total", {"result": "token_ok"},
                   after) == 3


def test_davsg_cert_get_books_cert_ok(mx):
    """A client-cert GET books cert_ok exactly once."""
    name, payload = cached(mx, "amcrt")
    s = snap(mx)
    st, body, _ = mx.dav_request("davsg", f"/{name}")
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st == 200 and body == payload
    assert s.delta("brix_webdav_auth_total", {"result": "cert_ok"},
                   after) == 1


def test_cert_ok_linearity(mx):
    """Three cert GETs book exactly three cert_ok rows."""
    name, _ = cached(mx, "amcrt3")
    s = snap(mx)
    for _ in range(3):
        assert mx.dav_request("davsg", f"/{name}")[0] == 200
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_webdav_auth_total", {"result": "cert_ok"},
                   after) == 3


def test_davsg_without_cert_serves_no_bytes(mx):
    """Withholding the client cert on the cert plane: cert_ok NEVER books,
    no read-ok op, ZERO bytes leave."""
    name, _ = cached(mx, "amnocrt")
    s = snap(mx)
    st, _, _ = mx.dav_request("davsg", f"/{name}", cert=False)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st >= 400
    assert s.delta("brix_webdav_auth_total", {"result": "cert_ok"},
                   after) == 0
    assert s.delta("brix_io_ops_total",
                   {**IO, "op": "read", "status": "ok"}, after) == 0
    assert s.delta("brix_io_bytes_read", IO, after) == 0


# --------------------------------------------------------------------------
# S3: the one auth-result row the base suite leaves uncovered
# --------------------------------------------------------------------------

def test_s3sig_bad_access_key_books_exactly_that(mx):
    """A signature built on an UNKNOWN access key books bad_access_key
    only — not signature_mismatch, not malformed — and serves nothing."""
    name = cx.unique_name("ambadak")
    mx.seed_local(name, 200)
    good = cx.S3_ACCESS_KEY
    cx.S3_ACCESS_KEY = "no-such-access-key"
    try:
        hdrs = cx.sigv4_headers("GET", cx.HOST, mx.port("S3_SIG_PORT"),
                                f"/{cx.S3_BUCKET}/{name}")
    finally:
        cx.S3_ACCESS_KEY = good
    s = snap(mx)
    st, _, _ = mx.s3_request("s3sig", name, headers=hdrs, signed=False)
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert st in (401, 403)
    assert s.delta("brix_s3_auth_total", {"result": "bad_access_key"},
                   after) == 1
    for other in ("sigv4_ok", "signature_mismatch", "malformed"):
        assert s.delta("brix_s3_auth_total", {"result": other}, after) == 0
    assert s.delta("brix_io_ops_total",
                   {"proto": "s3", "op": "read", "status": "ok"}, after) == 0


# --------------------------------------------------------------------------
# User-session identity tracking (stream planes)
# --------------------------------------------------------------------------

def test_gsi_session_materializes_quoted_hash_row(mx):
    """After a GSI session, brix_user_sessions_total exports at least one
    row whose hash label is QUOTED 8-hex — the strict-exposition form
    (regression pin: the label used to be emitted unquoted, which strict
    Prometheus parsers reject)."""
    name = cx.unique_name("amsess")
    mx.seed_origin(name, 120)
    r = mx.xrdfs("gsi", "stat", f"/{name}")
    assert r.returncode == 0, r.stderr
    cx.settle()
    text = cx.mfetch(mx.metrics)
    assert SESSION_ROW.search(text), "no quoted session row exported"
    assert not re.search(r'brix_user_sessions_total\{hash=[^"]', text), \
        "unquoted hash label on the wire"


def test_session_rows_never_leak_identity(mx):
    """Every session row's label value is EXACTLY an 8-hex hash — never a
    DN fragment, username, or any other identity-shaped string."""
    name = cx.unique_name("amleak")
    mx.seed_origin(name, 120)
    assert mx.xrdfs("gsi", "stat", f"/{name}").returncode == 0
    cx.settle()
    text = cx.mfetch(mx.metrics)
    for line in text.splitlines():
        if line.startswith("brix_user_sessions_total{"):
            assert re.fullmatch(
                r'brix_user_sessions_total\{hash="[0-9a-f]{8}"\} \d+',
                line), f"identity-shaped session row: {line}"


def test_anonymous_traffic_adds_no_session_row(mx):
    """Anonymous stream ops carry no identity: the session-row COUNT must
    not grow when only the anon plane is exercised."""
    name = cx.unique_name("amanon")
    mx.seed_origin(name, 120)
    before = len(SESSION_ROW.findall(cx.mfetch(mx.metrics)))
    for _ in range(2):
        assert mx.xrdfs("none", "stat", f"/{name}").returncode == 0
    cx.settle()
    after = len(SESSION_ROW.findall(cx.mfetch(mx.metrics)))
    assert after == before


def test_repeat_identity_deduplicates_unique_users(mx):
    """A second session from the SAME identity adds no new unique user:
    brix_unique_users_total is a per-identity counter, not per-session."""
    name = cx.unique_name("amdedup")
    mx.seed_origin(name, 120)
    assert mx.xrdfs("gsi", "stat", f"/{name}").returncode == 0
    cx.settle()
    s = snap(mx)
    assert mx.xrdfs("gsi", "stat", f"/{name}").returncode == 0
    cx.settle()
    after = cx.mfetch(mx.metrics)
    assert s.delta("brix_unique_users_total", after=after) == 0
