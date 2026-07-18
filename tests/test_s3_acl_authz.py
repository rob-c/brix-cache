"""A-3/T3 — GetObjectAcl runs behind the object gate.

SigV4 authenticates the *requester*; it does not prove the named object exists
or is readable.  The canned owner-FULL_CONTROL ACL document must therefore be
produced only for an object key that actually resolves to a readable object —
otherwise a probe of any name mints a FULL_CONTROL grant and, worse, turns
GetObjectAcl into an existence oracle (200 vs 404) for keys the caller was never
authorized to see.

Contract (mirrors the tagging/HEAD NoSuchKey model):
  * success           — ?acl on an existing object → 200 with FULL_CONTROL.
  * error             — ?acl on an absent key      → 404 NoSuchKey.
  * security-negative — ?acl must not leak existence: an absent key and a
    directory-target key both answer 404 (never a 200 canned ACL), while the
    bucket-level ?acl (no per-object target) stays a canned 200 so SDK probes
    keep working.

Uses the pre-started nginx_shared instance (anonymous + write).
"""

import uuid

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


@pytest.fixture
def obj(s3_url):
    key = f"{s3_url}/{BUCKET}/acl_{uuid.uuid4().hex}"
    assert requests.put(key, data=b"payload", timeout=10).status_code == 200
    yield key
    requests.delete(key, timeout=10)


# -- success: an existing object still yields the canned FULL_CONTROL doc ----- #
def test_object_acl_existing_object_ok(obj):
    r = requests.get(obj + "?acl", timeout=10)
    assert r.status_code == 200
    assert "AccessControlPolicy" in r.text
    assert "FULL_CONTROL" in r.text


# -- error: ?acl on a never-created key is NoSuchKey, not a canned 200 -------- #
def test_object_acl_absent_key_not_found(s3_url):
    missing = f"{s3_url}/{BUCKET}/acl_missing_{uuid.uuid4().hex}"
    r = requests.get(missing + "?acl", timeout=10)
    assert r.status_code == 404
    assert "NoSuchKey" in r.text
    # The gate must fire BEFORE the canned document is produced.
    assert "FULL_CONTROL" not in r.text


# -- security-negative: no existence oracle, directory target also 404 ------- #
def test_object_acl_is_not_an_existence_oracle(s3_url):
    """An absent key and a present key must be distinguishable ONLY through the
    honest NoSuchKey path — the ACL responder must never confirm a key by
    returning its FULL_CONTROL document before the object gate."""
    absent = f"{s3_url}/{BUCKET}/acl_probe_{uuid.uuid4().hex}"
    r = requests.get(absent + "?acl", timeout=10)
    assert r.status_code == 404, "absent object ?acl must 404, not canned 200"
    assert "FULL_CONTROL" not in r.text


def test_object_acl_directory_target_not_found(s3_url):
    prefix = f"acl_dir_{uuid.uuid4().hex}"
    child = f"{s3_url}/{BUCKET}/{prefix}/child"
    assert requests.put(child, data=b"d", timeout=10).status_code == 200
    try:
        # The prefix resolves to a directory, not an object → NoSuchKey.
        r = requests.get(f"{s3_url}/{BUCKET}/{prefix}?acl", timeout=10)
        assert r.status_code == 404
        assert "FULL_CONTROL" not in r.text
    finally:
        requests.delete(child, timeout=10)


def test_bucket_acl_still_canned(s3_url):
    """Bucket ?acl has no per-object target and must remain a canned 200 so the
    object-gate change does not regress SDK bucket probes."""
    r = requests.get(f"{s3_url}/{BUCKET}/?acl", timeout=10)
    assert r.status_code == 200
    assert "FULL_CONTROL" in r.text
    assert "AccessControlPolicy" in r.text
