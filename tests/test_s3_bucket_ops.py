"""S3 bucket-level operations (phase-43 W2).

Covers the SDK probe-satisfier endpoints added in phase-43:
  - HeadBucket          (HEAD /bucket)
  - GetBucketLocation   (GET  /bucket?location)
  - ListObjects V1      (GET  /bucket  with no list-type=2)

Uses the pre-started nginx_shared instance (port 9001), anonymous + write.
"""

import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


def _obj_url(s3_url, key):
    return f"{s3_url}/{BUCKET}/{key}"


def _tag(name):
    return f"{{{S3_NS}}}{name}"


# ---------------------------------------------------------------------------
# HeadBucket
# ---------------------------------------------------------------------------


def test_head_bucket_exists(s3_url):
    r = requests.head(f"{s3_url}/{BUCKET}", timeout=10)
    assert r.status_code == 200
    assert r.headers.get("x-amz-bucket-region")  # region advertised for SDKs


def test_head_bucket_trailing_slash(s3_url):
    # HEAD /bucket/ (empty key after the slash) is equally a bucket probe.
    r = requests.head(f"{s3_url}/{BUCKET}/", timeout=10)
    assert r.status_code == 200


def test_head_wrong_bucket_404(s3_url):
    # A bucket name that does not match the configured export → not our bucket.
    r = requests.head(f"{s3_url}/nope-{uuid.uuid4().hex}", timeout=10)
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GetBucketLocation
# ---------------------------------------------------------------------------


def test_get_bucket_location(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?location", timeout=10)
    assert r.status_code == 200
    root = ET.fromstring(r.text)
    assert root.tag == _tag("LocationConstraint")
    # us-east-1 (the test default) is represented by an empty constraint.
    assert (root.text or "") in ("", "us-east-1")


# ---------------------------------------------------------------------------
# ListObjects V1
# ---------------------------------------------------------------------------


def _parse_v1(xml_text):
    root = ET.fromstring(xml_text)
    keys = [el.text for el in root.findall(f".//{_tag('Key')}")]
    truncated = root.findtext(_tag("IsTruncated")) == "true"
    next_marker = root.findtext(_tag("NextMarker"))
    marker = root.findtext(_tag("Marker"))
    return root, keys, truncated, next_marker, marker


def test_list_v1_basic(s3_url):
    uid = uuid.uuid4().hex
    prefix = f"v1_basic_{uid}/"
    keys = [f"{prefix}a", f"{prefix}b", f"{prefix}c"]
    for k in keys:
        assert requests.put(_obj_url(s3_url, k), data=b"x", timeout=10).status_code == 200

    r = requests.get(f"{s3_url}/{BUCKET}/?prefix={prefix}", timeout=10)
    root, listed, truncated, _, marker = _parse_v1(r.text)
    assert r.status_code == 200
    # V1 dialect: ListBucketResult with a Marker element and NO KeyCount.
    assert root.tag == _tag("ListBucketResult")
    assert root.find(_tag("KeyCount")) is None
    assert marker == "" or marker is None
    for k in keys:
        assert k in listed
    assert not truncated


def test_list_v1_marker_pagination(s3_url):
    uid = uuid.uuid4().hex
    prefix = f"v1_page_{uid}/"
    keys = [f"{prefix}{i:02d}" for i in range(5)]
    for k in keys:
        assert requests.put(_obj_url(s3_url, k), data=b"x", timeout=10).status_code == 200

    # First page: max-keys=2 → truncated, NextMarker set.
    r1 = requests.get(
        f"{s3_url}/{BUCKET}/?prefix={prefix}&max-keys=2", timeout=10
    )
    _, page1, trunc1, next_marker, _ = _parse_v1(r1.text)
    assert r1.status_code == 200
    assert trunc1 is True
    assert len(page1) == 2
    assert next_marker

    # Second page: marker=NextMarker → the remaining keys, exclusive of marker.
    r2 = requests.get(
        f"{s3_url}/{BUCKET}/?prefix={prefix}&max-keys=2&marker={next_marker}",
        timeout=10,
    )
    _, page2, _, _, echoed_marker = _parse_v1(r2.text)
    assert r2.status_code == 200
    assert echoed_marker == next_marker
    assert all(k > next_marker for k in page2)        # marker is exclusive
    assert set(page1).isdisjoint(page2)               # no overlap across pages
