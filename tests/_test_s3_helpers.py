"""S3-compatible object storage tests.

Tests the nginx brix_s3 module against the S3 REST API subset used by
XrdClS3: GetObject, HeadObject, PutObject, DeleteObject, ListObjectsV2.

Uses the pre-started nginx_shared instance (port 9001), anonymous mode.
"""

import os
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

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


def _list_url(s3_url, **params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    base = f"{s3_url}/{BUCKET}/?list-type=2"
    return f"{base}&{qs}" if qs else base


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------


def _parse_list(xml_text):
    root = ET.fromstring(xml_text)

    def _tag(name):
        return f"{{{S3_NS}}}{name}"

    keys = [el.text for el in root.findall(f".//{_tag('Key')}")]
    prefixes = [
        el.find(_tag("Prefix")).text
        for el in root.findall(f".//{_tag('CommonPrefixes')}")
    ]
    truncated = root.findtext(_tag("IsTruncated")) == "true"
    next_token = root.findtext(_tag("NextContinuationToken"))
    return keys, prefixes, truncated, next_token


# ---------------------------------------------------------------------------
# OPTIONS / CORS preflight
# ---------------------------------------------------------------------------

def _assert_v1_listing(r):
    assert r.status_code == 200
    assert "ListBucketResult" in r.text
    assert "<KeyCount>" not in r.text   # KeyCount is ListObjectsV2-only
    assert "<Marker>" in r.text          # Marker is the V1 pagination element



def _delete_objects_url(s3_url):
    return f"{s3_url}/{BUCKET}/?delete"


def _delete_objects_body(*keys):
    objects_xml = "".join(
        f"<Object><Key>{escape(k)}</Key></Object>" for k in keys
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"{objects_xml}"
        "</Delete>"
    ).encode()
