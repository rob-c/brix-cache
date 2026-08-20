from split_continuation import reexport as _reexport
_reexport(globals(), "_test_webdav_helpers")

pytestmark = pytest.mark.registry_server("main")

class TestAuth:

    def test_anonymous_get_matches_endpoint_auth_policy(self, scratch_file):
        """
        The token endpoint is optional-auth; the dedicated GSI endpoint is
        required-auth and must reject a request without the proxy cert.

        The GSI endpoint also carries a JWKS, so it is bearer-protected and owes
        a missing credential 401 + `WWW-Authenticate: Bearer` (RFC 6750 §3), not
        403 — 403 is reserved for insufficient_scope on a *valid* token, and is
        what a cert-only export (no JWKS) still returns.
        """
        url_path, content = scratch_file
        code = _http_code_no_cert(f"{BASE_URL}{url_path}")
        if AUTH_MODE == "gsi":
            assert code == 401, f"Anonymous GET should fail on GSI, got {code}"
            rc, hdrs, _ = _curl_no_cert("-D", "-", "-o", "/dev/null",
                                        f"{BASE_URL}{url_path}")
            assert rc == 0
            if isinstance(hdrs, bytes):
                hdrs = hdrs.decode("utf-8", "replace")
            assert "www-authenticate: bearer" in hdrs.lower(), (
                f"401 without a Bearer challenge violates RFC 6750 §3: {hdrs!r}"
            )
        else:
            assert code == 200, (
                f"Anonymous GET should succeed with optional token auth, got {code}"
            )

    def test_authenticated_put_accepted(self):
        """PUT with the endpoint's configured HTTPS credential must succeed."""
        name = f"{_PFX}auth_put.txt"
        dst  = _data_path(name)
        try:
            code = _put(f"/{name}", b"auth test\n")
            assert code in (200, 201), f"Authenticated PUT failed with {code}"
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_content_type_not_required(self, scratch_file):
        """
        GET without Accept header (bare curl) should return content.
        Verifies the module doesn't gate on Content-Type negotiation.
        """
        url_path, content = scratch_file
        rc, out, _ = _curl(f"{BASE_URL}{url_path}")
        assert rc == 0
        assert out == content


# ---------------------------------------------------------------------------
# Integrity: PUT then GET round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_put_get_round_trip_text(self):
        name    = f"{_PFX}rt_text.txt"
        content = b"Hello, WebDAV round-trip!\n" * 50
        dst     = _data_path(name)
        try:
            assert _put(f"/{name}", content) in (200, 201)
            assert _get(f"/{name}") == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_get_round_trip_binary(self):
        name    = f"{_PFX}rt_binary.bin"
        content = os.urandom(128 * 1024)  # 128 KiB random bytes
        dst     = _data_path(name)
        try:
            assert _put(f"/{name}", content) in (200, 201)
            assert _get(f"/{name}") == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    @pytest.mark.timeout(60)
    def test_put_get_round_trip_large(self):
        """4 MB round-trip to exercise chunked PUT + GET."""
        name    = f"{_PFX}rt_large.bin"
        content = os.urandom(4 * 1024 * 1024)
        dst     = _data_path(name)
        try:
            assert _put(f"/{name}", content) in (200, 201)
            assert _get(f"/{name}") == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_mkcol_put_get_in_subdirectory(self):
        """Create a directory, upload a file into it, and read it back."""
        dirname  = f"{_PFX}subdir"
        filename = "sub_file.txt"
        content  = b"file inside a WebDAV sub-directory\n"
        dst_dir  = _data_path(dirname)
        dst_file = os.path.join(dst_dir, filename)
        try:
            assert _http_code("-X", "MKCOL",
                               f"{BASE_URL}/{dirname}") == 201
            assert _put(f"/{dirname}/{filename}", content) in (200, 201)
            assert _get(f"/{dirname}/{filename}") == content
        finally:
            if os.path.exists(dst_dir):
                shutil.rmtree(dst_dir)


# ---------------------------------------------------------------------------
# WebDAV path traversal hardening
# ---------------------------------------------------------------------------

class TestWebdavTraversal:
    """Path traversal attempts via WebDAV must be blocked."""

    def test_get_dot_dot_traversal(self):
        """GET /../etc/passwd must be blocked (403 or 400)."""
        code = _http_code("--path-as-is", f"{BASE_URL}/../etc/passwd")
        assert code in (400, 403, 404), f"expected rejection, got {code}"

    def test_propfind_dot_dot_traversal(self):
        """PROPFIND /../ must not leak the parent directory listing."""
        code = _http_code(
            "--path-as-is",
            "-X", "PROPFIND", "-H", "Depth: 1",
            f"{BASE_URL}/../",
        )
        assert code in (400, 403, 404), f"expected rejection, got {code}"

    def test_put_dot_dot_escape(self):
        """PUT /../escape.txt must not create a file outside the root."""
        escaped = os.path.join(os.environ["TMPDIR"], "_webdav_escaped_file.txt")
        try:
            code = _http_code(
                "--path-as-is",
                "-X", "PUT",
                "--data-binary", "escaped",
                f"{BASE_URL}/../_webdav_escaped_file.txt",
            )
            assert code in (400, 403, 404), f"expected rejection, got {code}"
            assert not os.path.exists(escaped), "file created outside root"
        finally:
            if os.path.exists(escaped):
                os.unlink(escaped)

    def test_delete_dot_dot_escape(self):
        """DELETE /../ must not remove anything outside the root."""
        code = _http_code(
            "--path-as-is",
            "-X", "DELETE",
            f"{BASE_URL}/../",
        )
        assert code in (400, 403, 404), f"expected rejection, got {code}"

    def test_symlink_traversal_via_get(self):
        """A symlink under the root pointing outside must not be followed."""
        link_name = f"{_PFX}symlink_escape"
        link_path = _data_path(link_name)

        with tempfile.TemporaryDirectory(prefix="webdav_escape_") as outside:
            secret_file = os.path.join(outside, "secret.txt")
            with open(secret_file, "w") as f:
                f.write("leaked data\n")
            os.symlink(outside, link_path)
            try:
                code = _http_code(f"{BASE_URL}/{link_name}/secret.txt")
                # Server may follow the symlink (acceptable if within root)
                # but the file is outside root so it should fail
                if code == 200:
                    body = _get(f"/{link_name}/secret.txt")
                    assert body != b"leaked data\n", "symlink traversal leaked data"
            finally:
                if os.path.islink(link_path):
                    os.unlink(link_path)

    def test_propfind_depth1_symlink_escape(self):
        """PROPFIND Depth:1 on a symlink-to-outside must not list external dirs."""
        link_name = f"{_PFX}symlink_propfind"
        link_path = _data_path(link_name)

        with tempfile.TemporaryDirectory(prefix="webdav_pf_escape_") as outside:
            with open(os.path.join(outside, "hidden.txt"), "w") as f:
                f.write("hidden\n")
            os.symlink(outside, link_path)
            try:
                code = _http_code(
                    "-X", "PROPFIND", "-H", "Depth: 1",
                    f"{BASE_URL}/{link_name}",
                )
                # If it succeeds, verify no outside content leaked
                if code == 207:
                    rc, out, _ = _curl(
                        "-X", "PROPFIND", "-H", "Depth: 1",
                        f"{BASE_URL}/{link_name}",
                    )
                    assert b"hidden.txt" not in out, "symlink PROPFIND leaked external file"
            finally:
                if os.path.islink(link_path):
                    os.unlink(link_path)


# ---------------------------------------------------------------------------
# HTTP method restrictions
# ---------------------------------------------------------------------------

class TestMethodRestrictions:
    """Unsupported HTTP methods must be cleanly rejected."""

    def test_post_returns_405(self):
        """POST is not a WebDAV method we support."""
        code = _http_code(
            "-X", "POST",
            "--data-binary", "body",
            f"{BASE_URL}/{_PFX}post_test.txt",
        )
        assert code == 405, f"POST should return 405, got {code}"

    def test_patch_returns_405(self):
        """PATCH is not supported."""
        code = _http_code(
            "-X", "PATCH",
            "--data-binary", "body",
            f"{BASE_URL}/{_PFX}patch_test.txt",
        )
        assert code == 405, f"PATCH should return 405, got {code}"

    def test_propfind_invalid_depth_handled(self):
        """PROPFIND with Depth: infinity may be rejected or limited."""
        code = _http_code(
            "-X", "PROPFIND",
            "-H", "Depth: infinity",
            f"{BASE_URL}/",
        )
        # RFC 4918: servers SHOULD reject Depth: infinity with 403
        # but treating it as Depth:1 (207) is also acceptable
        assert code in (207, 403), f"Depth:infinity got unexpected {code}"
