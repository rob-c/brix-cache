from split_continuation import reexport as _reexport
def _guard_test_mkcol_rejects_double_encoded_traversal_segments_1(parent_path):
    if os.path.exists(parent_path):
        shutil.rmtree(parent_path)

def _guard_test_mkcol_rejects_double_encoded_traversal_segments_2(target_path):
    if os.path.exists(target_path):
        shutil.rmtree(target_path)

def _guard_test_mkcol_rejects_double_encoded_traversal_segments_3(parent_path):
    if os.path.exists(parent_path):
        shutil.rmtree(parent_path)

def _guard_test_mkcol_rejects_double_encoded_traversal_segments_4(target_path):
    if os.path.exists(target_path):
        shutil.rmtree(target_path)


_reexport(globals(), "_test_webdav_helpers")

# The split helper owns the autouse fixture, so the static declaration scanner
# cannot infer that these tests need the shared WebDAV-bearing fleet server.
pytestmark = pytest.mark.registry_server("main")

class TestOptions:

    def test_returns_200(self):
        code = _http_code("-X", "OPTIONS", f"{BASE_URL}/")
        assert code == 200

    def test_allow_header_contains_propfind(self):
        """xrdcp uses PROPFIND for stat; it must appear in the Allow header."""
        rc, _, err = _curl("-X", "OPTIONS", f"{BASE_URL}/",
                           "-D", "-", "-o", "/dev/null")
        # curl -D - writes headers to stdout when -o /dev/null
        rc, out, _ = _curl("-X", "OPTIONS", f"{BASE_URL}/", "-D", "/dev/stderr",
                           "-o", "/dev/null")
        # Try a different approach: capture headers with -I
        rc2, head_out, _ = _curl("-I", f"{BASE_URL}/",
                                 "-X", "OPTIONS")
        headers = head_out.decode(errors="replace").lower()
        assert "propfind" in headers, (
            f"PROPFIND not found in OPTIONS response headers:\n{head_out.decode()}"
        )

    def test_dav_header_present(self):
        rc, head_out, _ = _curl("-I", f"{BASE_URL}/", "-X", "OPTIONS")
        headers = head_out.decode(errors="replace").lower()
        assert "dav:" in headers, (
            f"DAV: header missing from OPTIONS response:\n{head_out.decode()}"
        )


# ---------------------------------------------------------------------------
# PUT
# ---------------------------------------------------------------------------

class TestPut:

    def test_put_new_file_returns_201(self):
        name = f"{_PFX}put_new.txt"
        dst  = _data_path(name)
        if os.path.exists(dst):
            os.unlink(dst)
        try:
            code = _put(f"/{name}", b"new file\n")
            assert code == 201
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_overwrite_returns_200_or_204(self):
        name = f"{_PFX}put_overwrite.txt"
        dst  = _data_path(name)
        try:
            _put(f"/{name}", b"original\n")
            code = _put(f"/{name}", b"overwritten\n")
            assert code in (200, 204), f"Overwrite PUT returned HTTP {code}"
            with open(dst, "rb") as f:
                assert f.read() == b"overwritten\n"
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_content_reaches_disk(self):
        name    = f"{_PFX}put_disk.txt"
        content = b"disk verification content\n" * 100
        dst     = _data_path(name)
        try:
            code = _put(f"/{name}", content)
            assert code in (200, 201)
            with open(dst, "rb") as f:
                assert f.read() == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_binary_content(self):
        name    = f"{_PFX}put_binary.bin"
        content = bytes(range(256)) * 256  # 64 KiB, all byte values
        dst     = _data_path(name)
        try:
            code = _put(f"/{name}", content)
            assert code in (200, 201)
            with open(dst, "rb") as f:
                assert f.read() == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    @pytest.mark.timeout(60)
    def test_put_large_file(self):
        """2 MB upload — exercises chunked body buffering."""
        name    = f"{_PFX}put_large.bin"
        content = os.urandom(2 * 1024 * 1024)
        dst     = _data_path(name)
        try:
            code = _put(f"/{name}", content)
            assert code in (200, 201)
            with open(dst, "rb") as f:
                assert f.read() == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)


# ---------------------------------------------------------------------------
# HEAD
# ---------------------------------------------------------------------------

class TestHead:
    """
    HEAD tests use -I (implicit --head) rather than -X HEAD with -w/%{http_code}.
    With -I, curl stops after receiving the response headers, avoiding a hang
    where curl waits for connection close after a HEAD response.
    """

    def _head_code(self, url: str) -> int:
        """Issue a HEAD request and return the HTTP status code."""
        rc, out, _ = _curl("-I", url)
        assert rc == 0, f"curl -I failed (exit {rc})"
        # First line is "HTTP/1.x NNN reason"
        first = out.split(b"\n", 1)[0].decode(errors="replace").strip()
        parts = first.split(None, 2)
        assert len(parts) >= 2, f"Unexpected HEAD status line: {first!r}"
        return int(parts[1])

    def test_head_existing_file(self, scratch_file):
        url_path, _ = scratch_file
        assert self._head_code(f"{BASE_URL}{url_path}") == 200

    def test_head_returns_content_length(self, scratch_file):
        url_path, content = scratch_file
        rc, out, _ = _curl("-I", f"{BASE_URL}{url_path}")
        headers = out.decode(errors="replace").lower()
        assert "content-length:" in headers
        for line in headers.splitlines():
            if line.startswith("content-length:"):
                cl = int(line.split(":", 1)[1].strip())
                assert cl == len(content), (
                    f"Content-Length {cl} != expected {len(content)}"
                )
                break

    def test_head_missing_file_returns_404(self):
        assert self._head_code(f"{BASE_URL}/{_PFX}no_such_file.txt") == 404


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------

class TestGet:

    def test_get_existing_file(self, scratch_file):
        url_path, content = scratch_file
        body = _get(url_path)
        assert body == content

    def test_get_missing_file_returns_404(self):
        code = _http_code(f"{BASE_URL}/{_PFX}no_such_file.txt")
        assert code == 404

    def test_range_get_partial(self, scratch_file):
        """Range: bytes=2-5 should return 206 with 4 bytes."""
        url_path, content = scratch_file
        rc, out, _ = _curl(
            "-H", "Range: bytes=2-5",
            "-w", "\n%{http_code}",
            f"{BASE_URL}{url_path}",
        )
        lines = out.rsplit(b"\n", 1)
        body, code = lines[0], int(lines[1].strip())
        assert code == 206, f"Expected 206, got {code}"
        assert body == content[2:6], (
            f"Range body mismatch: got {body!r}, expected {content[2:6]!r}"
        )

    def test_range_get_suffix(self, scratch_file):
        """Range: bytes=-5 should return the last 5 bytes."""
        url_path, content = scratch_file
        rc, out, _ = _curl(
            "-H", "Range: bytes=-5",
            "-w", "\n%{http_code}",
            f"{BASE_URL}{url_path}",
        )
        lines = out.rsplit(b"\n", 1)
        body, code = lines[0], int(lines[1].strip())
        assert code == 206
        assert body == content[-5:]

    def test_range_get_from_offset(self, scratch_file):
        """Range: bytes=4- should return content from byte 4 to end."""
        url_path, content = scratch_file
        rc, out, _ = _curl(
            "-H", "Range: bytes=4-",
            "-w", "\n%{http_code}",
            f"{BASE_URL}{url_path}",
        )
        lines = out.rsplit(b"\n", 1)
        body, code = lines[0], int(lines[1].strip())
        assert code == 206
        assert body == content[4:]

    def test_range_beyond_eof_returns_416(self, scratch_file):
        """Range starting past EOF should return 416."""
        url_path, content = scratch_file
        beyond = len(content) + 100
        code = _http_code(
            "-H", f"Range: bytes={beyond}-{beyond + 10}",
            f"{BASE_URL}{url_path}",
        )
        assert code == 416


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------

class TestDelete:

    def test_delete_existing_file(self):
        name = f"{_PFX}delete_me.txt"
        dst  = _data_path(name)
        _put(f"/{name}", b"to be deleted\n")
        assert os.path.exists(dst)

        code = _http_code("-X", "DELETE", f"{BASE_URL}/{name}")
        assert code == 204
        assert not os.path.exists(dst), "File should be gone after DELETE"

    def test_delete_missing_returns_404(self):
        code = _http_code("-X", "DELETE",
                          f"{BASE_URL}/{_PFX}no_such_delete.txt")
        assert code == 404

    def test_delete_empty_directory(self):
        name = f"{_PFX}del_dir"
        dst  = _data_path(name)
        os.makedirs(dst, exist_ok=True)
        try:
            # RFC 4918 §9.6: collection DELETE URI should end with '/'.
            # nginx DAV (and many strict servers) require the trailing slash.
            code = _http_code("-X", "DELETE", f"{BASE_URL}/{name}/")
            assert code == 204
            assert not os.path.exists(dst)
        finally:
            if os.path.exists(dst):
                shutil.rmtree(dst)


# ---------------------------------------------------------------------------
# MKCOL
# ---------------------------------------------------------------------------

class TestMkcol:

    def test_mkcol_creates_directory(self):
        name = f"{_PFX}mkcol_plain"
        dst  = _data_path(name)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        try:
            code = _http_code("-X", "MKCOL", f"{BASE_URL}/{name}")
            assert code == 201
            assert os.path.isdir(dst), "MKCOL should have created a directory"
        finally:
            if os.path.exists(dst):
                shutil.rmtree(dst)

    def test_mkcol_with_trailing_slash(self):
        """MKCOL /dir/ (trailing slash) must work identically to MKCOL /dir."""
        name = f"{_PFX}mkcol_slash"
        dst  = _data_path(name)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        try:
            code = _http_code("-X", "MKCOL", f"{BASE_URL}/{name}/")
            assert code == 201
            assert os.path.isdir(dst)
        finally:
            if os.path.exists(dst):
                shutil.rmtree(dst)

    def test_mkcol_conflict_returns_405(self):
        """MKCOL on an already-existing path must return 405 Method Not Allowed."""
        name = f"{_PFX}mkcol_conflict"
        dst  = _data_path(name)
        os.makedirs(dst, exist_ok=True)
        try:
            code = _http_code("-X", "MKCOL", f"{BASE_URL}/{name}")
            assert code == 405, f"Expected 405 for existing dir, got {code}"
        finally:
            shutil.rmtree(dst)

    def test_mkcol_nested_missing_parent_returns_409(self):
        """MKCOL /missing_parent/child must return 409 Conflict."""
        parent = _data_path(f"{_PFX}no_parent")
        if os.path.exists(parent):
            shutil.rmtree(parent)
        code = _http_code(
            "-X", "MKCOL",
            f"{BASE_URL}/{_PFX}no_parent/{_PFX}child",
        )
        assert code == 409, f"Expected 409 for missing parent, got {code}"


# ---------------------------------------------------------------------------
# Path hardening
# ---------------------------------------------------------------------------

class TestPathHardening:

    def test_delete_rejects_double_encoded_nul_path(self):
        """
        nginx normalizes the URI once before it reaches the module. A second
        decode inside the handler must not turn `%2500` into an in-band NUL.
        """
        name = f"{_PFX}delete_nul.txt"
        dst = _data_path(name)
        with open(dst, "wb") as fh:
            fh.write(b"webdav nul hardening\n")

        try:
            code = _http_code(
                "--path-as-is",
                "-X", "DELETE",
                f"{BASE_URL}/{name}%2500tail",
            )
            assert code == 400, f"Expected 400 for decoded-NUL path, got {code}"
            assert os.path.exists(dst), "double-encoded NUL unexpectedly deleted the file"
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_mkcol_rejects_double_encoded_traversal_segments(self):
        """
        A second decode must not reinterpret `%252F..%252F` as `/../` and create
        a sibling directory outside the requested lexical path.
        """
        parent = f"{_PFX}mkcol_parent"
        target = f"{_PFX}mkcol_escape"
        parent_path = _data_path(parent)
        target_path = _data_path(target)

        _guard_test_mkcol_rejects_double_encoded_traversal_segments_1(parent_path)
        _guard_test_mkcol_rejects_double_encoded_traversal_segments_2(target_path)

        os.makedirs(parent_path, exist_ok=True)

        try:
            code = _http_code(
                "--path-as-is",
                "-X", "MKCOL",
                f"{BASE_URL}/{parent}%252F..%252F{target}",
            )
            def _assert_test_mkcol_rejects_double_encoded_traversal_segments_1():
                assert code == 403, f"Expected 403 for traversal path, got {code}"
                assert not os.path.exists(target_path), (
                    "double-encoded traversal unexpectedly created a sibling directory"
                )

            _assert_test_mkcol_rejects_double_encoded_traversal_segments_1()
        finally:
            _guard_test_mkcol_rejects_double_encoded_traversal_segments_3(parent_path)
            _guard_test_mkcol_rejects_double_encoded_traversal_segments_4(target_path)


# ---------------------------------------------------------------------------
# PROPFIND
# ---------------------------------------------------------------------------
