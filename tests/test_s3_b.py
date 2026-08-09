from split_continuation import reexport as _reexport
_reexport(globals(), "_test_s3_helpers")

def test_copy_object(s3_url):
    uid = uuid.uuid4().hex
    src_key = f"copy_src_{uid}.txt"
    dst_key = f"copy_dst_{uid}.txt"
    content = f"copy object content {uid}".encode()

    r = requests.put(_obj_url(s3_url, src_key), data=content, timeout=10)
    assert r.status_code == 200, f"source PUT failed: {r.status_code}"

    r = requests.put(
        _obj_url(s3_url, dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/{src_key}"},
        timeout=10,
    )
    assert r.status_code == 200, f"CopyObject failed: {r.status_code} {r.text}"
    assert "CopyObjectResult" in r.text
    assert "ETag" in r.text

    r = requests.get(_obj_url(s3_url, dst_key), timeout=10)
    assert r.status_code == 200
    assert r.content == content


def test_copy_object_missing_source(s3_url):
    uid = uuid.uuid4().hex
    dst_key = f"copy_dst_nosrc_{uid}.txt"

    r = requests.put(
        _obj_url(s3_url, dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/no_such_src_{uid}"},
        timeout=10,
    )
    assert r.status_code == 404, f"expected 404 for missing source, got {r.status_code}"
    assert "NoSuchKey" in r.text


def test_copy_object_path_traversal(s3_url):
    uid = uuid.uuid4().hex
    dst_key = f"copy_dst_trav_{uid}.txt"

    r = requests.put(
        _obj_url(s3_url, dst_key),
        headers={"x-amz-copy-source": f"/{BUCKET}/../../../etc/passwd"},
        timeout=10,
    )
    assert r.status_code in (400, 403), (
        f"path traversal source should be rejected, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# DeleteObjects (POST /?delete)
# ---------------------------------------------------------------------------



def test_delete_objects_success(s3_url):
    uid = uuid.uuid4().hex
    keys = [f"del_multi_{uid}_{i}.txt" for i in range(3)]
    for k in keys:
        requests.put(_obj_url(s3_url, k), data=b"x", timeout=10)

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(*keys),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200, f"DeleteObjects failed: {r.status_code} {r.text}"
    assert "DeleteResult" in r.text
    for k in keys:
        assert k in r.text, f"key {k} not in DeleteResult"
        assert "Deleted" in r.text

    for k in keys:
        r2 = requests.get(_obj_url(s3_url, k), timeout=10)
        assert r2.status_code == 404, f"key {k} should be deleted"


def test_delete_objects_xml_entity_key(s3_url):
    uid = uuid.uuid4().hex
    key = f"del_multi_entity_{uid}_a&b.txt"
    requests.put(_obj_url(s3_url, key), data=b"x", timeout=10)

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(key),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200, f"DeleteObjects failed: {r.status_code} {r.text}"
    ET.fromstring(r.text)

    r2 = requests.get(_obj_url(s3_url, key), timeout=10)
    assert r2.status_code == 404, "XML-escaped key should delete original object"


def test_delete_objects_nonexistent_is_ok(s3_url):
    uid = uuid.uuid4().hex
    key = f"never_existed_del_{uid}.txt"

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(key),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200
    assert "DeleteResult" in r.text
    assert "Deleted" in r.text
    assert "Error" not in r.text or "AccessDenied" not in r.text


def test_delete_objects_path_traversal(s3_url):
    """Keys with path traversal must be rejected with AccessDenied, not deleted."""
    uid = uuid.uuid4().hex
    traversal_key = f"../../../etc/hosts_del_{uid}"

    r = requests.post(
        _delete_objects_url(s3_url),
        data=_delete_objects_body(traversal_key),
        headers={"Content-Type": "application/xml"},
        timeout=10,
    )
    assert r.status_code == 200
    assert "DeleteResult" in r.text
    assert "AccessDenied" in r.text
    assert "Deleted" not in r.text
