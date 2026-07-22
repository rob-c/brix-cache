"""S3 Multipart Upload integration tests.

Covers the full MPU lifecycle (Initiate → UploadPart → Complete) plus abort,
error cases, and security invariants.

All tests are deterministic and use unique keys based on uuid4 to avoid
cross-test interference.
"""

import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

BUCKET = "testbucket"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _obj_url(s3_url, key):
    return f"{s3_url}/{BUCKET}/{key}"


def _initiate(s3_url, key):
    """POST ?uploads and return the UploadId from the XML response."""
    r = requests.post(f"{_obj_url(s3_url, key)}?uploads", timeout=10)
    assert r.status_code == 200, f"Initiate failed: {r.status_code} {r.text}"
    root = ET.fromstring(r.text)
    upload_id = root.find(f"{{{S3_NS}}}UploadId").text
    assert upload_id, "UploadId must not be empty"
    return upload_id


def _upload_part(s3_url, key, part_number, data, upload_id):
    url = f"{_obj_url(s3_url, key)}?partNumber={part_number}&uploadId={upload_id}"
    r = requests.put(url, data=data, timeout=10)
    return r


def _complete(s3_url, key, upload_id, parts):
    """POST ?uploadId=... with the part-number list and return the response."""
    parts_xml = "".join(
        f"<Part><PartNumber>{n}</PartNumber></Part>" for n in parts
    )
    body = (
        "<CompleteMultipartUpload>"
        f"{parts_xml}"
        "</CompleteMultipartUpload>"
    )
    url = f"{_obj_url(s3_url, key)}?uploadId={upload_id}"
    return requests.post(url, data=body, timeout=10)


def _abort(s3_url, key, upload_id):
    url = f"{_obj_url(s3_url, key)}?uploadId={upload_id}"
    return requests.delete(url, timeout=10)


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

class TestMultipartUploadLifecycle:

    def test_basic_two_part_upload(self, s3_url):
        """Full lifecycle: initiate → 2 parts → complete → GET verifies content."""
        key = f"mpu_basic_{uuid.uuid4().hex}.bin"

        upload_id = _initiate(s3_url, key)

        r = _upload_part(s3_url, key, 1, b"Hello, ", upload_id)
        assert r.status_code == 200, f"Part 1 upload failed: {r.status_code}"

        r = _upload_part(s3_url, key, 2, b"World!", upload_id)
        assert r.status_code == 200, f"Part 2 upload failed: {r.status_code}"

        r = _complete(s3_url, key, upload_id, [1, 2])
        assert r.status_code == 200, f"Complete failed: {r.status_code} {r.text}"

        # CompleteMultipartUploadResult must include Bucket, Key, ETag
        root = ET.fromstring(r.text)
        assert root.find(f"{{{S3_NS}}}Bucket") is not None
        assert root.find(f"{{{S3_NS}}}Key") is not None
        assert root.find(f"{{{S3_NS}}}ETag") is not None

        # Content must be the exact concatenation of the two parts
        r = requests.get(_obj_url(s3_url, key), timeout=10)
        assert r.status_code == 200
        assert r.content == b"Hello, World!"

    def test_single_part_upload(self, s3_url):
        """A single-part MPU is a valid degenerate case."""
        key = f"mpu_single_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        data = b"x" * 1024
        r = _upload_part(s3_url, key, 1, data, upload_id)
        assert r.status_code == 200

        r = _complete(s3_url, key, upload_id, [1])
        assert r.status_code == 200

        r = requests.get(_obj_url(s3_url, key), timeout=10)
        assert r.status_code == 200
        assert r.content == data

    def test_overwrite_existing_object(self, s3_url):
        """CompleteMultipartUpload must atomically replace an existing object."""
        key = f"mpu_overwrite_{uuid.uuid4().hex}.bin"

        # Create the object via a plain PUT first
        r = requests.put(_obj_url(s3_url, key), data=b"original", timeout=10)
        assert r.status_code == 200

        # Now overwrite via MPU
        upload_id = _initiate(s3_url, key)
        r = _upload_part(s3_url, key, 1, b"replaced", upload_id)
        assert r.status_code == 200
        r = _complete(s3_url, key, upload_id, [1])
        assert r.status_code == 200

        r = requests.get(_obj_url(s3_url, key), timeout=10)
        assert r.status_code == 200
        assert r.content == b"replaced"

    def test_large_part_ordering(self, s3_url):
        """Parts must be concatenated in ascending part-number order."""
        key = f"mpu_order_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        # Upload in reverse order to verify ordering is by part number, not
        # upload order.
        r = _upload_part(s3_url, key, 3, b"third", upload_id)
        assert r.status_code == 200
        r = _upload_part(s3_url, key, 1, b"first", upload_id)
        assert r.status_code == 200
        r = _upload_part(s3_url, key, 2, b"second", upload_id)
        assert r.status_code == 200

        r = _complete(s3_url, key, upload_id, [1, 2, 3])
        assert r.status_code == 200

        r = requests.get(_obj_url(s3_url, key), timeout=10)
        assert r.status_code == 200
        assert r.content == b"firstsecondthird"


# ---------------------------------------------------------------------------
# Abort tests
# ---------------------------------------------------------------------------

class TestMultipartUploadAbort:

    def test_abort_cleans_staging_dir(self, s3_url):
        """AbortMultipartUpload must remove the staging directory and return 204."""
        key = f"mpu_abort_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        r = _upload_part(s3_url, key, 1, b"partial data", upload_id)
        assert r.status_code == 200

        r = _abort(s3_url, key, upload_id)
        assert r.status_code == 204

        # The object must not exist (no complete was called)
        r = requests.get(_obj_url(s3_url, key), timeout=10)
        assert r.status_code == 404

    def test_abort_idempotent_returns_404(self, s3_url):
        """Aborting an already-aborted (or non-existent) upload returns 404."""
        key = f"mpu_abort_idem_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        r = _abort(s3_url, key, upload_id)
        assert r.status_code == 204

        # Second abort must return 404 NoSuchUpload
        r = _abort(s3_url, key, upload_id)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Negative / security tests
# ---------------------------------------------------------------------------

class TestMultipartUploadNegative:

    def test_part_number_zero_rejected(self, s3_url):
        """partNumber=0 is out of the 1–10000 range and must return 400."""
        key = f"mpu_neg_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        r = _upload_part(s3_url, key, 0, b"data", upload_id)
        assert r.status_code == 400

    def test_part_number_too_large_rejected(self, s3_url):
        """partNumber=10001 exceeds the AWS limit and must return 400."""
        key = f"mpu_neg_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        r = _upload_part(s3_url, key, 10001, b"data", upload_id)
        assert r.status_code == 400

    def test_part_number_non_numeric_rejected(self, s3_url):
        """A non-integer partNumber (path traversal attempt) must return 400."""
        key = f"mpu_neg_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        url = (f"{_obj_url(s3_url, key)}"
               f"?partNumber=../../etc/passwd&uploadId={upload_id}")
        r = requests.put(url, data=b"data", timeout=10)
        assert r.status_code == 400

    def test_invalid_upload_id_rejected_on_abort(self, s3_url):
        """An uploadId containing non-hex characters must return 400."""
        key = f"mpu_neg_{uuid.uuid4().hex}.bin"
        url = f"{_obj_url(s3_url, key)}?uploadId=../../etc/passwd"
        r = requests.delete(url, timeout=10)
        assert r.status_code == 400

    def test_invalid_upload_id_rejected_on_complete(self, s3_url):
        """An invalid uploadId on CompleteMultipartUpload must return 400."""
        key = f"mpu_neg_{uuid.uuid4().hex}.bin"
        url = f"{_obj_url(s3_url, key)}?uploadId=../../../evil"
        r = requests.post(url, data="<CompleteMultipartUpload/>", timeout=10)
        assert r.status_code == 400

    def test_complete_nonexistent_upload_returns_404(self, s3_url):
        """Completing a non-existent upload must return 404 NoSuchUpload."""
        key = f"mpu_neg_{uuid.uuid4().hex}.bin"
        # A well-formed but non-existent upload ID
        upload_id = "deadbeefdeadbeefdeadbeef"
        url = f"{_obj_url(s3_url, key)}?uploadId={upload_id}"
        r = requests.post(url, data="<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part></CompleteMultipartUpload>", timeout=10)
        assert r.status_code == 404

    def test_initiate_returns_xml_with_correct_namespace(self, s3_url):
        """InitiateMultipartUploadResult must use the S3 XML namespace."""
        key = f"mpu_ns_{uuid.uuid4().hex}.bin"
        r = requests.post(f"{_obj_url(s3_url, key)}?uploads", timeout=10)
        assert r.status_code == 200

        root = ET.fromstring(r.text)
        assert root.tag == f"{{{S3_NS}}}InitiateMultipartUploadResult", (
            f"Unexpected root element: {root.tag}"
        )
        upload_id = root.find(f"{{{S3_NS}}}UploadId").text
        assert upload_id

        # Clean up — abort the initiated upload
        _abort(s3_url, key, upload_id)


# ---------------------------------------------------------------------------
# ListParts (GET /bucket/key?uploadId=...) and
# ListMultipartUploads (GET /bucket/?uploads)
# ---------------------------------------------------------------------------

def _list_parts(s3_url, key, upload_id, extra=""):
    url = f"{_obj_url(s3_url, key)}?uploadId={upload_id}"
    if extra:
        url += f"&{extra}"
    return requests.get(url, timeout=10)


def _parse_parts(xml_text):
    """Return (root, [(part_number, size), ...]) from a ListPartsResult."""
    root = ET.fromstring(xml_text)
    parts = [
        (int(p.findtext(f"{{{S3_NS}}}PartNumber")),
         int(p.findtext(f"{{{S3_NS}}}Size")))
        for p in root.findall(f"{{{S3_NS}}}Part")
    ]
    return root, parts


class TestListParts:

    def test_lists_uploaded_parts_sorted_with_sizes(self, s3_url):
        """Parts uploaded out of order come back sorted by number, sizes exact."""
        key = f"mpu_lp_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)
        for n, size in ((3, 300), (1, 100), (2, 200)):
            r = _upload_part(s3_url, key, n, b"x" * size, upload_id)
            assert r.status_code == 200, f"Part {n} upload failed: {r.status_code}"

        r = _list_parts(s3_url, key, upload_id)
        assert r.status_code == 200, f"ListParts failed: {r.status_code} {r.text}"
        root, parts = _parse_parts(r.text)
        assert root.tag == f"{{{S3_NS}}}ListPartsResult"
        assert parts == [(1, 100), (2, 200), (3, 300)]
        assert root.findtext(f"{{{S3_NS}}}Bucket") == BUCKET
        assert root.findtext(f"{{{S3_NS}}}Key") == key
        assert root.findtext(f"{{{S3_NS}}}UploadId") == upload_id
        assert root.findtext(f"{{{S3_NS}}}IsTruncated") == "false"
        for part in root.findall(f"{{{S3_NS}}}Part"):
            assert part.findtext(f"{{{S3_NS}}}ETag")
            assert part.findtext(f"{{{S3_NS}}}LastModified")

        _abort(s3_url, key, upload_id)

    def test_pagination_max_parts_and_marker(self, s3_url):
        """max-parts truncates with NextPartNumberMarker; the marker resumes."""
        key = f"mpu_lp_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)
        for n in (1, 2, 3, 4):
            r = _upload_part(s3_url, key, n, b"p", upload_id)
            assert r.status_code == 200

        r = _list_parts(s3_url, key, upload_id, "max-parts=2")
        assert r.status_code == 200
        root, parts = _parse_parts(r.text)
        assert [n for n, _ in parts] == [1, 2]
        assert root.findtext(f"{{{S3_NS}}}IsTruncated") == "true"
        assert root.findtext(f"{{{S3_NS}}}NextPartNumberMarker") == "2"

        r = _list_parts(s3_url, key, upload_id, "part-number-marker=2")
        assert r.status_code == 200
        root, parts = _parse_parts(r.text)
        assert [n for n, _ in parts] == [3, 4]
        assert root.findtext(f"{{{S3_NS}}}IsTruncated") == "false"

        _abort(s3_url, key, upload_id)

    def test_unknown_upload_returns_404(self, s3_url):
        """A well-formed uploadId with no staging dir must 404 NoSuchUpload."""
        key = f"mpu_lp_{uuid.uuid4().hex}.bin"
        r = _list_parts(s3_url, key, "deadbeefdeadbeefdeadbeef")
        assert r.status_code == 404
        assert "NoSuchUpload" in r.text

    def test_traversal_upload_id_rejected(self, s3_url):
        """A path-traversal uploadId must be rejected 400, never probed on disk."""
        key = f"mpu_lp_{uuid.uuid4().hex}.bin"
        r = _list_parts(s3_url, key, "../../etc")
        assert r.status_code == 400
        assert "InvalidArgument" in r.text


class TestListMultipartUploads:

    @staticmethod
    def _list_uploads(s3_url, extra=""):
        url = f"{s3_url}/{BUCKET}/?uploads"
        if extra:
            url += f"&{extra}"
        return requests.get(url, timeout=10)

    @staticmethod
    def _upload_pairs(xml_text):
        """Return (root, [(key, upload_id), ...]) from a ListMultipartUploadsResult."""
        root = ET.fromstring(xml_text)
        return root, [
            (u.findtext(f"{{{S3_NS}}}Key"), u.findtext(f"{{{S3_NS}}}UploadId"))
            for u in root.findall(f"{{{S3_NS}}}Upload")
        ]

    def test_lists_active_uploads(self, s3_url):
        """Both in-flight uploads appear with their key and uploadId, key-sorted."""
        prefix = f"mpu_lu_{uuid.uuid4().hex}"
        keys = [f"{prefix}_a.bin", f"{prefix}_b.bin"]
        ids = {k: _initiate(s3_url, k) for k in keys}

        r = self._list_uploads(s3_url)
        assert r.status_code == 200, (
            f"ListMultipartUploads failed: {r.status_code} {r.text}"
        )
        root, pairs = self._upload_pairs(r.text)
        assert root.tag == f"{{{S3_NS}}}ListMultipartUploadsResult"
        for k in keys:
            assert (k, ids[k]) in pairs, f"{k} missing from listing"
        # The shared bucket may hold other tests' uploads, so assert only the
        # relative order of our two keys within the key-sorted listing.
        ours = [p for p in pairs if p[0] in keys]
        assert ours == sorted(ours)

        for k in keys:
            _abort(s3_url, k, ids[k])

    def test_aborted_upload_disappears(self, s3_url):
        """An upload is listed while in flight and gone after abort."""
        key = f"mpu_lu_{uuid.uuid4().hex}.bin"
        upload_id = _initiate(s3_url, key)

        r = self._list_uploads(s3_url)
        assert r.status_code == 200
        assert (key, upload_id) in self._upload_pairs(r.text)[1]

        r = _abort(s3_url, key, upload_id)
        assert r.status_code == 204

        r = self._list_uploads(s3_url)
        assert r.status_code == 200
        assert (key, upload_id) not in self._upload_pairs(r.text)[1]

    def test_key_marker_skips_earlier_keys(self, s3_url):
        """key-marker excludes keys that sort <= the marker."""
        prefix = f"mpu_lu_{uuid.uuid4().hex}"
        keys = [f"{prefix}_a.bin", f"{prefix}_b.bin"]
        ids = {k: _initiate(s3_url, k) for k in keys}

        r = self._list_uploads(s3_url, f"key-marker={keys[0]}")
        assert r.status_code == 200
        listed = [p[0] for p in self._upload_pairs(r.text)[1]]
        assert keys[0] not in listed
        assert keys[1] in listed

        for k in keys:
            _abort(s3_url, k, ids[k])
