from split_continuation import reexport as _reexport
_reexport(globals(), "_test_s3_status_codes_helpers")

class TestErrorResponses:
    def test_get_404_xml_has_error_element(self):
        r = _get(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        root = ET.fromstring(r.content)
        assert root.tag in ("Error", f"{{{S3_NS}}}Error"), (
            f"unexpected root tag: {root.tag}"
        )

    def test_get_404_xml_has_code_element(self):
        r = _get(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        assert _s3_error_code(r.text) == "NoSuchKey"

    def test_get_404_xml_has_message_element(self):
        r = _get(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        root = ET.fromstring(r.content)
        msg = (
            root.findtext("Message")
            or root.findtext(f"{{{S3_NS}}}Message")
            or ""
        )
        assert msg, "404 error body should include <Message>"

    def test_head_404_no_xml_body(self):
        """HEAD responses must have no body (even error responses)."""
        r = _head(f"{_PFX}err_{_uid()}.bin")
        assert r.status_code == 404
        assert r.content == b""

    def test_post_object_method_not_allowed(self):
        key = f"{_PFX}post_{_uid()}.bin"
        _put(key, b"exists")
        r = requests.post(_obj_url(key), data=b"body", timeout=10)
        assert r.status_code == 405

    def test_get_range_416_body_or_empty(self):
        key, content, _ = _existing_object()
        beyond = len(content) + 1000
        r = _get(key, headers={"Range": f"bytes={beyond}-{beyond+100}"})
        assert r.status_code == 416

    def test_list_bad_bucket_nosuchbucket_404(self):
        r = requests.get(
            f"{BASE}/no_such_bucket_ever/?list-type=2", timeout=10
        )
        assert r.status_code == 404
        assert _s3_error_code(r.text) == "NoSuchBucket"

    def test_list_content_type_is_xml(self):
        r = _list(prefix=f"{_PFX}ct_{_uid()}")
        assert r.status_code == 200
        ct = r.headers.get("Content-Type", "")
        assert "xml" in ct.lower(), f"expected XML content-type, got: {ct!r}"


# ---------------------------------------------------------------------------
# Path traversal / confinement security (Phase C of shared-code-plan-2)
# ---------------------------------------------------------------------------


class TestPathTraversal:
    """S3 key resolution must reject dot-dot traversal with 403 or 404."""

    def test_s3_path_traversal_dotdot_get_403(self):
        # Key containing ".." should be rejected (403 or 404 — never 200/500)
        r = requests.get(f"{BASE}/{BUCKET}/../../etc/passwd", timeout=10)
        assert r.status_code in (403, 404), (
            f"dot-dot traversal key should be rejected, got {r.status_code}"
        )

    def test_s3_path_traversal_dotdot_put_403(self):
        r = requests.put(
            f"{BASE}/{BUCKET}/../../tmp/evil.txt",
            data=b"should not land outside root",
            timeout=10,
        )
        assert r.status_code in (403, 404), (
            f"dot-dot traversal PUT should be rejected, got {r.status_code}"
        )

    def test_s3_path_traversal_dotdot_delete_403(self):
        r = requests.delete(f"{BASE}/{BUCKET}/../../etc/shadow", timeout=10)
        assert r.status_code in (403, 404), (
            f"dot-dot traversal DELETE should be rejected, got {r.status_code}"
        )


class TestSymlinkConfinement:
    """A symlink inside the S3 bucket pointing outside root must be blocked."""

    @pytest.fixture(autouse=True)
    def _setup_symlink(self):
        from tests.settings import DATA_ROOT
        # S3 keys map directly to DATA_ROOT — a key "foo" resolves to DATA_ROOT/foo.
        os.makedirs(DATA_ROOT, exist_ok=True)

        self._outside = tempfile.TemporaryDirectory()
        outside_file = os.path.join(self._outside.name, "secret.txt")
        with open(outside_file, "wb") as fh:
            fh.write(b"outside-root secret\n")

        link_name = f"sym_{uuid.uuid4().hex[:8]}"
        self._link_path = os.path.join(DATA_ROOT, link_name)
        self._link_key = link_name
        os.symlink(outside_file, self._link_path)

        yield

        if os.path.lexists(self._link_path):
            os.unlink(self._link_path)
        self._outside.cleanup()

    def test_s3_symlink_escape_get_403(self):
        r = _get(self._link_key)
        assert r.status_code in (403, 404), (
            f"symlink escape GET should be blocked, got {r.status_code}"
        )
