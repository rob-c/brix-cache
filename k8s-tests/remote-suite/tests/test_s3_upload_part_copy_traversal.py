# brix-remote-skip
"""
tests/test_s3_upload_part_copy_traversal.py

Coverage gap #15 (test-coverage-gap-audit): S3 UploadPartCopy
(PUT /bucket/key?partNumber=N&uploadId=ID + x-amz-copy-source) confinement.

UploadPartCopy validated its copy-source with an ad-hoc string check
(strstr("/../") + a trivially-true strncmp against root_canon) and then used a
RAW stat()/open() on the source path — NOT the module's confined
openat2(RESOLVE_BENEATH) resolver that every other read path uses.  So a symlink
inside the bucket that points OUT of the export root is silently FOLLOWED,
copying host-file content into the part — a confinement breach this one op
allows while the rest of the module (test_evil_paths) forbids it for all others.

These assert UploadPartCopy obeys the same contract as every other op:
  * copy-source = a real in-bucket object         → 200 (control)
  * copy-source = a symlink pointing OUT of root   → must NOT copy host content
  * copy-source = a "../" traversal                → 400
"""

import os
import socket
import uuid
import xml.etree.ElementTree as ET

import pytest

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:                                # pragma: no cover
    _HAVE_REQUESTS = False

from settings import HOST, S3_MPU_DATA_ROOT, S3_MPU_PORT

PORT = S3_MPU_PORT
BUCKET = "testbucket"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"
HOST_SECRET = b"root:x:0:0:"


def _reachable(host, port, timeout=1.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def s3_mpu_server():
    """Connect to the dedicated WRITABLE S3 server pre-started by
    manage_test_servers.sh start-all (the "s3-mpu" instance, brix_s3 on +
    brix_allow_write on, bucket "testbucket", serving S3_MPU_DATA_ROOT).
    Skips cleanly if that dedicated instance is not running.  The server and this
    test share the local filesystem, so the in-bucket source objects this suite
    relies on are seeded directly into the data root: a real "legit.txt" object
    and an "evil" symlink planted INSIDE the bucket that points OUT of the export
    root (the symlink-escape the confined resolver must refuse to follow)."""
    if not _HAVE_REQUESTS:
        pytest.skip("requests not available")

    data = S3_MPU_DATA_ROOT
    os.makedirs(data, exist_ok=True)
    with open(os.path.join(data, "legit.txt"), "w") as f:
        f.write("legit-source-object\n")
    # A symlink planted INSIDE the bucket that points OUT of the export root.
    evil = os.path.join(data, "evil")
    if not os.path.islink(evil):
        if os.path.exists(evil):
            os.unlink(evil)
        os.symlink("/etc/passwd", evil)

    if not _reachable(HOST, PORT, 3):
        pytest.skip(
            f"dedicated S3 MPU nginx not reachable on {HOST}:{PORT} — "
            f"run tests/manage_test_servers.sh start-all")
    yield


def _objurl(key):
    return f"http://{HOST}:{PORT}/{BUCKET}/{key}"


def _initiate(key):
    r = requests.post(f"{_objurl(key)}?uploads", timeout=10)
    assert r.status_code == 200, f"initiate MPU failed: {r.status_code} {r.text[:200]}"
    return ET.fromstring(r.text).find(f"{{{S3_NS}}}UploadId").text


def _upload_part_copy(key, upload_id, copy_source, part=1):
    return requests.put(
        f"{_objurl(key)}?partNumber={part}&uploadId={upload_id}",
        headers={"x-amz-copy-source": copy_source}, timeout=10)


def _complete(key, upload_id, parts):
    body = "<CompleteMultipartUpload>" + "".join(
        f"<Part><PartNumber>{n}</PartNumber></Part>" for n in parts
    ) + "</CompleteMultipartUpload>"
    return requests.post(f"{_objurl(key)}?uploadId={upload_id}", data=body, timeout=10)


def _upload_part(key, upload_id, data, part=1):
    return requests.put(
        f"{_objurl(key)}?partNumber={part}&uploadId={upload_id}",
        data=data, timeout=10)


def test_regular_multipart_roundtrip_still_works(s3_mpu_server):
    # Guards the dispatcher reorder (UploadPartCopy branch moved before the
    # fs_path overwrite): a normal initiate → 2 parts → complete → GET must
    # still return the concatenated body.
    key = f"reg_{uuid.uuid4().hex}"
    uid = _initiate(key)
    assert _upload_part(key, uid, b"AAAApart1", 1).status_code == 200
    assert _upload_part(key, uid, b"BBBBpart2", 2).status_code == 200
    assert _complete(key, uid, [1, 2]).status_code == 200
    g = requests.get(_objurl(key), timeout=10)
    assert g.status_code == 200 and g.content == b"AAAApart1BBBBpart2", \
        f"regular MPU round-trip broke: {g.status_code} {g.content!r}"


def test_upload_part_copy_legit_source_works(s3_mpu_server):
    # Control: copying a real in-bucket object must succeed, else the negative
    # tests prove nothing.
    key = f"dst_{uuid.uuid4().hex}"
    uid = _initiate(key)
    r = _upload_part_copy(key, uid, f"/{BUCKET}/legit.txt")
    assert r.status_code == 200, \
        f"UploadPartCopy of a legit source must succeed: {r.status_code} {r.text[:200]}"
    assert "CopyPartResult" in r.text


def test_upload_part_copy_symlink_escape_blocked(s3_mpu_server):
    key = f"dst_{uuid.uuid4().hex}"
    uid = _initiate(key)
    r = _upload_part_copy(key, uid, f"/{BUCKET}/evil")     # evil -> /etc/passwd
    # The symlink points OUT of the export root — UploadPartCopy must refuse it
    # (every other op does), so it must NOT report a successful copy.
    assert r.status_code != 200, (
        f"UploadPartCopy FOLLOWED a symlink out of the export root "
        f"(status={r.status_code}) — confinement breach")
    # And even if it somehow returned non-200, the completed object must never
    # expose host content.
    if r.status_code == 200:
        _complete(key, uid, [1])
        g = requests.get(_objurl(key), timeout=10)
        assert HOST_SECRET not in g.content, "host /etc/passwd content leaked via UploadPartCopy"


def test_upload_part_copy_dotdot_traversal_blocked(s3_mpu_server):
    key = f"dst_{uuid.uuid4().hex}"
    uid = _initiate(key)
    r = _upload_part_copy(key, uid, f"/{BUCKET}/../../etc/passwd")
    assert r.status_code in (400, 403, 404), \
        f"'../' copy-source traversal must be rejected, got {r.status_code}"
    if r.status_code == 200:
        _complete(key, uid, [1])
        g = requests.get(_objurl(key), timeout=10)
        assert HOST_SECRET not in g.content, "host content leaked via '../' copy-source"
