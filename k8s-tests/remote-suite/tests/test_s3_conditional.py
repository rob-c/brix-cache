"""S3 conditional requests + response-header overrides (phase-43 W3).

Covers:
  - If-Match / If-None-Match / If-Modified-Since / If-Unmodified-Since on
    GET and HEAD, with S3 semantics (304 Not Modified, 412 PreconditionFailed).
  - response-content-type / -content-disposition / -cache-control overrides on
    GET, including the response-splitting (CRLF injection) guard.

Uses the pre-started nginx_shared instance (port 9001), anonymous + write.
"""

import uuid

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET
PAST = "Wed, 21 Oct 2000 07:28:00 GMT"
FUTURE = "Wed, 21 Oct 2099 07:28:00 GMT"


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


@pytest.fixture
def obj(s3_url):
    """Create a unique object; yield (url, etag); clean up afterwards."""
    key = f"cond_{uuid.uuid4().hex}"
    url = f"{s3_url}/{BUCKET}/{key}"
    assert requests.put(url, data=b"hello", timeout=10).status_code == 200
    etag = requests.head(url, timeout=10).headers["ETag"]
    yield url, etag
    requests.delete(url, timeout=10)


# ---------------------------------------------------------------------------
# If-None-Match
# ---------------------------------------------------------------------------


def test_if_none_match_etag_get_304(obj):
    url, etag = obj
    r = requests.get(url, headers={"If-None-Match": etag}, timeout=10)
    assert r.status_code == 304
    assert r.headers.get("ETag") == etag


def test_if_none_match_star_get_304(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-None-Match": "*"}, timeout=10)
    assert r.status_code == 304


def test_if_none_match_miss_get_200(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-None-Match": '"nomatch-1"'}, timeout=10)
    assert r.status_code == 200
    assert r.content == b"hello"


def test_if_none_match_head_304(obj):
    url, etag = obj
    r = requests.head(url, headers={"If-None-Match": etag}, timeout=10)
    assert r.status_code == 304


# ---------------------------------------------------------------------------
# If-Match
# ---------------------------------------------------------------------------


def test_if_match_ok_200(obj):
    url, etag = obj
    r = requests.get(url, headers={"If-Match": etag}, timeout=10)
    assert r.status_code == 200


def test_if_match_mismatch_412(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-Match": '"deadbeef-9"'}, timeout=10)
    assert r.status_code == 412
    assert "PreconditionFailed" in r.text


def test_if_match_star_ok(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-Match": "*"}, timeout=10)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# If-Modified-Since / If-Unmodified-Since  (S3 "before" semantics)
# ---------------------------------------------------------------------------


def test_if_modified_since_future_304(obj):
    # Not modified since a future date → 304 (nginx's default `exact` would 200;
    # this is the S3-correctness fix this workstream adds).
    url, _ = obj
    r = requests.get(url, headers={"If-Modified-Since": FUTURE}, timeout=10)
    assert r.status_code == 304


def test_if_modified_since_past_200(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-Modified-Since": PAST}, timeout=10)
    assert r.status_code == 200


def test_if_unmodified_since_past_412(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-Unmodified-Since": PAST}, timeout=10)
    assert r.status_code == 412


def test_if_unmodified_since_future_200(obj):
    url, _ = obj
    r = requests.get(url, headers={"If-Unmodified-Since": FUTURE}, timeout=10)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Precedence: If-Match wins over If-Unmodified-Since; If-None-Match over I-M-S
# ---------------------------------------------------------------------------


def test_precedence_if_match_over_unmodified(obj):
    # If-Match fails → 412 regardless of a satisfiable If-Unmodified-Since.
    url, _ = obj
    r = requests.get(
        url,
        headers={"If-Match": '"deadbeef-9"', "If-Unmodified-Since": FUTURE},
        timeout=10,
    )
    assert r.status_code == 412


# ---------------------------------------------------------------------------
# response-* header overrides
# ---------------------------------------------------------------------------


def test_response_content_type_override(obj):
    url, _ = obj
    r = requests.get(url, params={"response-content-type": "application/x-custom"}, timeout=10)
    assert r.status_code == 200
    assert r.headers.get("Content-Type") == "application/x-custom"


def test_response_content_disposition_override(obj):
    url, _ = obj
    r = requests.get(
        url,
        params={"response-content-disposition": "attachment;filename=foo.txt"},
        timeout=10,
    )
    assert r.headers.get("Content-Disposition") == "attachment;filename=foo.txt"


def test_response_cache_control_override(obj):
    url, _ = obj
    r = requests.get(url, params={"response-cache-control": "no-cache"}, timeout=10)
    assert r.headers.get("Cache-Control") == "no-cache"


def test_response_override_crlf_injection_rejected(obj):
    # A CRLF-laden override value must not inject a new header (response split).
    url, _ = obj
    r = requests.get(
        url,
        params={"response-content-type": "evil\r\nX-Injected: yes"},
        timeout=10,
    )
    assert "X-Injected" not in r.headers
    assert r.headers.get("x-injected") is None


# ---------------------------------------------------------------------------
# Conditional PUT (phase-43 W4): create-if-absent / overwrite-if-match
# ---------------------------------------------------------------------------


def test_put_if_none_match_star_creates(s3_url):
    url = f"{s3_url}/{BUCKET}/cput_{uuid.uuid4().hex}"
    r = requests.put(url, data=b"v1", headers={"If-None-Match": "*"}, timeout=10)
    assert r.status_code == 200
    requests.delete(url, timeout=10)


def test_put_if_none_match_star_conflict_on_existing(obj):
    url, _ = obj
    r = requests.put(url, data=b"overwrite", headers={"If-None-Match": "*"}, timeout=10)
    assert r.status_code == 412
    assert "PreconditionFailed" in r.text
    assert requests.get(url, timeout=10).content == b"hello"  # original preserved


def test_put_if_match_overwrites_when_matching(obj):
    url, etag = obj
    r = requests.put(url, data=b"v2", headers={"If-Match": etag}, timeout=10)
    assert r.status_code == 200
    assert requests.get(url, timeout=10).content == b"v2"


def test_put_if_match_stale_rejected(obj):
    url, _ = obj
    r = requests.put(url, data=b"v2", headers={"If-Match": '"deadbeef-9"'}, timeout=10)
    assert r.status_code == 412
    assert requests.get(url, timeout=10).content == b"hello"


def test_put_if_match_missing_object_rejected(s3_url):
    url = f"{s3_url}/{BUCKET}/cput_{uuid.uuid4().hex}"
    r = requests.put(url, data=b"x", headers={"If-Match": '"deadbeef-1"'}, timeout=10)
    assert r.status_code == 412
    assert requests.head(url, timeout=10).status_code == 404  # not created
