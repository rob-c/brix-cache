# brix-remote-skip
"""Phase-36 §7.2.5 — S3 object storage over IPv6 (HTTP client).

Exercises the S3 REST subset (PUT/GET/HEAD/list/delete/range/copy/multipart +
CORS preflight) against the dedicated "ipv6-s3" nginx instance bound to the IPv6
loopback ``[::1]`` and pre-started by ``manage_test_servers.sh start-all``
(``start_dedicated_nginx "ipv6-s3" "nginx_ipv6_s3.conf" "${IPV6_S3_PORT}"``),
serving ``IPV6_S3_DATA_ROOT`` as an anonymous, writable bucket.

The Python ``requests`` / ``http.client`` stack handles the ``[::1]`` bracket
form correctly (unlike the PyXRootD root:// client), so every request simply
targets ``http://[::1]:IPV6_S3_PORT``.  These cases are REGRESSION / SMOKE: they
prove S3 functions identically over IPv6 as over IPv4.  The §3 S3 bracket-on-emit
gates (dual-stack cross-family redirect, SigV4 canonical-Host) live in the
broader plan; this file covers the anonymous data-plane surface end-to-end.

Skip discipline (never fail on instance-absent):
  * every test depends on the session fixture ``requires_ipv6_loopback`` (auto,
    via the module-scoped autouse ``_ipv6_s3`` fixture);
  * ``reachable6(IPV6_S3_PORT)`` probes the dedicated instance and skips cleanly
    if it is down.

Run with ``TEST_SKIP_SERVER_SETUP=1`` against an already-running start-all.
"""

import os
import socket
import uuid
import xml.etree.ElementTree as ET

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

from settings import HOST6, IPV6_S3_DATA_ROOT, IPV6_S3_PORT, url_host

BUCKET = "testbucket"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"

# IPv6 literal must be bracketed in a URL authority; requests/http.client handle
# this correctly.  This is the whole point of the IPv6 S3 suite.
BASE_URL = f"http://{url_host(HOST6)}:{IPV6_S3_PORT}"


# ---------------------------------------------------------------------------
# Reachability probe (AF_INET6 loopback) — mirrors the _reachable() pattern in
# tests/test_open_flags_lifecycle.py / test_s3_upload_part_copy_traversal.py but
# forced onto the IPv6 family so a same-port IPv4 listener can never mask a down
# IPv6 instance.
# ---------------------------------------------------------------------------
def reachable6(port: int, timeout: float = 3.0) -> bool:
    """True if [::1]:port accepts an IPv6 TCP connection."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((HOST6, port, 0, 0))
            return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _ipv6_s3(requires_ipv6_loopback):
    """Gate the whole module on IPv6 loopback + a live ipv6-s3 instance, and
    seed the (shared-filesystem) data root.

    Depending on the session-scoped ``requires_ipv6_loopback`` makes every test
    a clean no-op on hosts without usable ``::1``.  We then probe the dedicated
    instance and skip if it is down — instance-absent never reddens the suite.
    """
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    # The dedicated instance shares this local filesystem; ensure the data root
    # (== the bucket root; objects land directly under it) exists.  start-all
    # creates it, but a TEST_SKIP_SERVER_SETUP run may target a freshly wiped
    # tree, so be defensive.
    os.makedirs(IPV6_S3_DATA_ROOT, exist_ok=True)

    if not reachable6(IPV6_S3_PORT):
        pytest.skip(
            f"dedicated ipv6-s3 nginx not reachable on [::1]:{IPV6_S3_PORT} — "
            f"run tests/manage_test_servers.sh start-all"
        )


# ---------------------------------------------------------------------------
# URL + XML helpers (mirrors tests/test_s3.py)
# ---------------------------------------------------------------------------
def _obj_url(key):
    return f"{BASE_URL}/{BUCKET}/{key}"


def _list_url(**params):
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    base = f"{BASE_URL}/{BUCKET}/?list-type=2"
    return f"{base}&{qs}" if qs else base


def _parse_list(xml_text):
    root = ET.fromstring(xml_text)

    def _tag(name):
        return f"{{{S3_NS}}}{name}"

    keys = [el.text for el in root.findall(f".//{_tag('Key')}")]
    truncated = root.findtext(_tag("IsTruncated")) == "true"
    next_token = root.findtext(_tag("NextContinuationToken"))
    return keys, truncated, next_token


# ---------------------------------------------------------------------------
# Multipart helpers (mirrors tests/test_s3_multipart.py)
# ---------------------------------------------------------------------------
def _initiate(key):
    r = requests.post(f"{_obj_url(key)}?uploads", timeout=10)
    assert r.status_code == 200, f"Initiate failed: {r.status_code} {r.text}"
    root = ET.fromstring(r.text)
    upload_id = root.find(f"{{{S3_NS}}}UploadId").text
    assert upload_id, "UploadId must not be empty"
    return upload_id


def _upload_part(key, part_number, data, upload_id):
    url = f"{_obj_url(key)}?partNumber={part_number}&uploadId={upload_id}"
    return requests.put(url, data=data, timeout=10)


def _complete(key, upload_id, parts):
    parts_xml = "".join(
        f"<Part><PartNumber>{n}</PartNumber></Part>" for n in parts
    )
    body = f"<CompleteMultipartUpload>{parts_xml}</CompleteMultipartUpload>"
    url = f"{_obj_url(key)}?uploadId={upload_id}"
    return requests.post(url, data=body, timeout=10)


# ---------------------------------------------------------------------------
# PUT / GET / HEAD — byte-exact object round-trip over IPv6  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_anonymous_put_and_get():
    """REGRESSION: anonymous PUT then GET over [::1] is byte-exact."""
    uid = uuid.uuid4().hex
    key = f"ipv6_put_{uid}.bin"
    content = f"ipv6 s3 payload {uid}".encode()

    r = requests.put(_obj_url(key), data=content, timeout=10)
    assert r.status_code == 200, f"PUT failed: {r.status_code} {r.text}"

    r = requests.get(_obj_url(key), timeout=10)
    assert r.status_code == 200
    assert r.content == content


def test_s3_ipv6_head_object():
    """REGRESSION: HEAD returns the correct Content-Length and an ETag."""
    uid = uuid.uuid4().hex
    key = f"ipv6_head_{uid}.bin"
    content = b"ipv6 head object content"

    r = requests.put(_obj_url(key), data=content, timeout=10)
    assert r.status_code == 200

    r = requests.head(_obj_url(key), timeout=10)
    assert r.status_code == 200
    assert int(r.headers.get("Content-Length", -1)) == len(content)
    assert "ETag" in r.headers


def test_s3_ipv6_put_zero_byte_object():
    """REGRESSION: a zero-byte object round-trips over IPv6."""
    uid = uuid.uuid4().hex
    key = f"ipv6_zero_{uid}.bin"

    r = requests.put(_obj_url(key), data=b"", timeout=10)
    assert r.status_code == 200

    r = requests.get(_obj_url(key), timeout=10)
    assert r.status_code == 200
    assert r.content == b""


# ---------------------------------------------------------------------------
# Range GET  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_range_get():
    """REGRESSION: a partial (Range) GET returns 206 with the exact slice."""
    uid = uuid.uuid4().hex
    key = f"ipv6_range_{uid}.bin"
    content = b"0123456789abcdef"

    r = requests.put(_obj_url(key), data=content, timeout=10)
    assert r.status_code == 200

    r = requests.get(_obj_url(key), headers={"Range": "bytes=4-7"}, timeout=10)
    assert r.status_code == 206
    assert r.content == b"4567"
    # Content-Range must reflect the requested slice over the full object.
    assert r.headers.get("Content-Range", "").startswith("bytes 4-7/")


# ---------------------------------------------------------------------------
# DeleteObject  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_delete_object():
    """REGRESSION: DELETE removes the object; a subsequent GET is 404."""
    uid = uuid.uuid4().hex
    key = f"ipv6_del_{uid}.bin"

    r = requests.put(_obj_url(key), data=b"to delete", timeout=10)
    assert r.status_code == 200

    r = requests.delete(_obj_url(key), timeout=10)
    assert r.status_code in (200, 204), f"DELETE failed: {r.status_code}"

    r = requests.get(_obj_url(key), timeout=10)
    assert r.status_code == 404


def test_s3_ipv6_get_missing_404_xml():
    """REGRESSION: GET of a missing key returns 404 with NoSuchKey XML."""
    r = requests.get(_obj_url(f"ipv6_no_such_{uuid.uuid4().hex}"), timeout=10)
    assert r.status_code == 404
    assert "NoSuchKey" in r.text


# ---------------------------------------------------------------------------
# ListObjectsV2  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_list_objects_v2():
    """REGRESSION: ListObjectsV2 parses and returns the seeded keys."""
    uid = uuid.uuid4().hex
    keys = [f"ipv6_list_{uid}_{i}.txt" for i in range(3)]
    for k in keys:
        r = requests.put(_obj_url(k), data=b"x", timeout=10)
        assert r.status_code == 200

    r = requests.get(_list_url(prefix=f"ipv6_list_{uid}"), timeout=10)
    assert r.status_code == 200
    listed, truncated, _ = _parse_list(r.text)
    for k in keys:
        assert k in listed, f"{k} not in listing {listed}"
    assert not truncated


# ---------------------------------------------------------------------------
# CopyObject (PUT + x-amz-copy-source)  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_copy_object():
    """REGRESSION: CopyObject duplicates an existing object byte-exact."""
    uid = uuid.uuid4().hex
    src_key = f"ipv6_copy_src_{uid}.txt"
    dst_key = f"ipv6_copy_dst_{uid}.txt"
    content = f"ipv6 copy content {uid}".encode()

    r = requests.put(_obj_url(src_key), data=content, timeout=10)
    assert r.status_code == 200, f"source PUT failed: {r.status_code}"

    r = requests.put(
        _obj_url(dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/{src_key}"},
        timeout=10,
    )
    assert r.status_code == 200, f"CopyObject failed: {r.status_code} {r.text}"
    assert "CopyObjectResult" in r.text
    assert "ETag" in r.text

    r = requests.get(_obj_url(dst_key), timeout=10)
    assert r.status_code == 200
    assert r.content == content


# ---------------------------------------------------------------------------
# DeleteObjects batch (POST /?delete)  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_delete_objects_batch():
    """REGRESSION: batch DeleteObjects removes every listed key over IPv6."""
    uid = uuid.uuid4().hex
    keys = [f"ipv6_delmulti_{uid}_{i}.txt" for i in range(3)]
    for k in keys:
        r = requests.put(_obj_url(k), data=b"x", timeout=10)
        assert r.status_code == 200

    objects_xml = "".join(f"<Object><Key>{k}</Key></Object>" for k in keys)
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f"{objects_xml}"
        "</Delete>"
    ).encode()

    r = requests.post(
        f"{BASE_URL}/{BUCKET}/?delete",
        data=body,
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200, f"DeleteObjects failed: {r.status_code} {r.text}"
    assert "DeleteResult" in r.text
    for k in keys:
        assert k in r.text, f"key {k} not in DeleteResult"

    for k in keys:
        r2 = requests.get(_obj_url(k), timeout=10)
        assert r2.status_code == 404, f"key {k} should be deleted"


# ---------------------------------------------------------------------------
# Multipart upload — full cycle (Initiate / UploadPart x3 / Complete)
# (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_multipart_upload_full_cycle():
    """REGRESSION: Initiate → UploadPart×3 → Complete concatenates in order."""
    uid = uuid.uuid4().hex
    key = f"ipv6_mpu_{uid}.bin"

    upload_id = _initiate(key)

    # Upload out of order to prove ordering is by part number, not arrival.
    r = _upload_part(key, 3, b"third", upload_id)
    assert r.status_code == 200, f"part 3 failed: {r.status_code} {r.text}"
    r = _upload_part(key, 1, b"first", upload_id)
    assert r.status_code == 200, f"part 1 failed: {r.status_code} {r.text}"
    r = _upload_part(key, 2, b"second", upload_id)
    assert r.status_code == 200, f"part 2 failed: {r.status_code} {r.text}"

    r = _complete(key, upload_id, [1, 2, 3])
    assert r.status_code == 200, f"Complete failed: {r.status_code} {r.text}"
    root = ET.fromstring(r.text)
    assert root.find(f"{{{S3_NS}}}Bucket") is not None
    assert root.find(f"{{{S3_NS}}}Key") is not None
    assert root.find(f"{{{S3_NS}}}ETag") is not None

    r = requests.get(_obj_url(key), timeout=10)
    assert r.status_code == 200
    assert r.content == b"firstsecondthird"


# ---------------------------------------------------------------------------
# OPTIONS / CORS preflight  (REGRESSION/SMOKE)
# ---------------------------------------------------------------------------
def test_s3_ipv6_options_cors_preflight():
    """REGRESSION: OPTIONS advertises the full S3 method set over IPv6."""
    r = requests.options(f"{BASE_URL}/{BUCKET}/", timeout=10)
    assert r.status_code == 200
    allow = r.headers.get("Allow", "")
    for method in ("GET", "HEAD", "PUT", "DELETE", "POST", "OPTIONS"):
        assert method in allow, f"{method} missing from Allow: {allow!r}"


# ---------------------------------------------------------------------------
# Security-negative: path traversal must not bypass confinement over IPv6
# ---------------------------------------------------------------------------
def test_s3_ipv6_path_traversal_rejected():
    """SECURITY-NEG: a ``../`` key is rejected (never 200/500); IPv6 does not
    bypass the confined-resolver contract enforced for every other transport."""
    uid = uuid.uuid4().hex
    r = requests.put(
        f"{BASE_URL}/{BUCKET}/../../../etc/ipv6_escape_{uid}",
        data=b"blocked",
        timeout=10,
    )
    assert r.status_code in (400, 403, 404), (
        f"path-traversal PUT must be rejected, got {r.status_code}"
    )
    assert r.status_code not in (200, 500)
