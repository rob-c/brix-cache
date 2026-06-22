"""S3 object tagging + canned subresources (phase-43 W5).

Covers:
  - x-amz-tagging header on PutObject, GET/PUT/DELETE /<key>?tagging (xattr-backed)
  - canned probe-satisfiers: GetBucketVersioning, GetBucketAcl/GetObjectAcl,
    GET ?cors (NoSuchCORSConfiguration), and PUT ?acl → 501 NotImplemented

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


@pytest.fixture
def obj(s3_url):
    key = f"{s3_url}/{BUCKET}/tag_{uuid.uuid4().hex}"
    assert requests.put(key, data=b"data", timeout=10).status_code == 200
    yield key
    requests.delete(key, timeout=10)


def _tags(xml_text):
    root = ET.fromstring(xml_text)
    out = {}
    for tag in root.iter(f"{{{S3_NS}}}Tag"):
        k = tag.findtext(f"{{{S3_NS}}}Key")
        v = tag.findtext(f"{{{S3_NS}}}Value")
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# Object tagging
# ---------------------------------------------------------------------------


def test_put_tagging_header_then_get(s3_url):
    key = f"{s3_url}/{BUCKET}/tag_{uuid.uuid4().hex}"
    requests.put(key, data=b"d", headers={"x-amz-tagging": "team=hep&project=atlas"}, timeout=10)
    r = requests.get(key + "?tagging", timeout=10)
    assert r.status_code == 200
    assert _tags(r.text) == {"team": "hep", "project": "atlas"}
    requests.delete(key, timeout=10)


def test_put_tagging_xml_replaces(obj):
    requests.put(obj, data=b"d", headers={"x-amz-tagging": "old=1"}, timeout=10)
    xml = (
        '<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>'
        "<Tag><Key>env</Key><Value>prod</Value></Tag>"
        "<Tag><Key>tier</Key><Value>gold</Value></Tag>"
        "</TagSet></Tagging>"
    )
    r = requests.put(obj + "?tagging", data=xml, timeout=10)
    assert r.status_code == 200
    got = _tags(requests.get(obj + "?tagging", timeout=10).text)
    assert got == {"env": "prod", "tier": "gold"}  # replaced, old gone


def test_delete_tagging(obj):
    requests.put(obj, data=b"d", headers={"x-amz-tagging": "a=b"}, timeout=10)
    assert requests.delete(obj + "?tagging", timeout=10).status_code == 204
    r = requests.get(obj + "?tagging", timeout=10)
    assert r.status_code == 200
    assert _tags(r.text) == {}  # empty tag set


def test_tagging_special_chars_roundtrip(s3_url):
    key = f"{s3_url}/{BUCKET}/tag_{uuid.uuid4().hex}"
    requests.put(key, data=b"d", timeout=10)
    xml = (
        '<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>'
        "<Tag><Key>k space</Key><Value>a&amp;b=c</Value></Tag>"
        "</TagSet></Tagging>"
    )
    assert requests.put(key + "?tagging", data=xml, timeout=10).status_code == 200
    got = _tags(requests.get(key + "?tagging", timeout=10).text)
    assert got == {"k space": "a&b=c"}
    requests.delete(key, timeout=10)


# ---------------------------------------------------------------------------
# Canned subresources
# ---------------------------------------------------------------------------


def test_get_bucket_versioning_disabled(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?versioning", timeout=10)
    assert r.status_code == 200
    root = ET.fromstring(r.text)
    assert root.tag == f"{{{S3_NS}}}VersioningConfiguration"
    assert root.find(f"{{{S3_NS}}}Status") is None  # never enabled


def test_get_bucket_acl(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?acl", timeout=10)
    assert r.status_code == 200
    assert "FULL_CONTROL" in r.text
    assert "AccessControlPolicy" in r.text


def test_get_object_acl(obj):
    r = requests.get(obj + "?acl", timeout=10)
    assert r.status_code == 200
    assert "FULL_CONTROL" in r.text


def test_get_cors_absent(s3_url):
    r = requests.get(f"{s3_url}/{BUCKET}/?cors", timeout=10)
    assert r.status_code == 404
    assert "NoSuchCORSConfiguration" in r.text


def test_put_object_acl_not_implemented(obj):
    r = requests.put(obj + "?acl", data="<x/>", timeout=10)
    assert r.status_code == 501
    assert "NotImplemented" in r.text
