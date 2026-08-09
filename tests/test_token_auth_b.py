from split_continuation import reexport as _reexport
_reexport(globals(), "_test_token_auth_helpers")

class TestScopeEnforcement:
    """Verify that token scopes are properly enforced for path-based access."""

    def test_read_allowed_within_scope(self, issuer):
        """Token scoped to storage.read:/ can read any path."""
        token = issuer.generate(scope="storage.read:/")
        sock, status, body = _token_session(token)
        assert status == kXR_ok
        try:
            status, body = _send_stat(sock, "/test.txt")
            assert status == kXR_ok
        finally:
            sock.close()

    def test_write_scope_root(self, issuer):
        """Token with storage.write:/ should allow write to any path via
        WebDAV PUT."""
        token = issuer.generate(scope="storage.read:/ storage.write:/")
        test_path = "/scope_test_write.txt"
        try:
            resp = requests.put(
                f"{WEBDAV_BASE}{test_path}",
                data=b"scope test\n",
                headers={"Authorization": f"Bearer {token}"},
                verify=False,
            )
            assert resp.status_code in (200, 201, 204)
        finally:
            try:
                os.unlink(os.path.join(DATA_ROOT, "scope_test_write.txt"))
            except FileNotFoundError:
                pass

    def test_write_scope_subpath(self, issuer):
        """Token with storage.write:/subdir should allow write under /subdir."""
        # Create the subdirectory
        subdir = os.path.join(DATA_ROOT, "token_subdir")
        os.makedirs(subdir, exist_ok=True)

        token = issuer.generate(scope="storage.read:/ storage.write:/token_subdir")
        try:
            resp = requests.put(
                f"{WEBDAV_BASE}/token_subdir/write_ok.txt",
                data=b"allowed write\n",
                headers={"Authorization": f"Bearer {token}"},
                verify=False,
            )
            assert resp.status_code in (200, 201, 204), \
                f"expected 2xx, got {resp.status_code}"
        finally:
            try:
                os.unlink(os.path.join(subdir, "write_ok.txt"))
            except FileNotFoundError:
                pass
            try:
                os.rmdir(subdir)
            except OSError:
                pass

    def test_write_denied_outside_scope(self, issuer):
        """Token with storage.write:/subdir should NOT allow write to /."""
        token = issuer.generate(scope="storage.read:/ storage.write:/subdir")
        resp = requests.put(
            f"{WEBDAV_BASE}/scope_test_outside.txt",
            data=b"should be denied\n",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        assert resp.status_code == 403, \
            f"expected 403, got {resp.status_code}"


# =========================================================================
# 5. WLCG GROUP CLAIMS
# =========================================================================

class TestWLCGGroupClaims:
    """Verify that wlcg.groups are extracted and available."""

    def test_token_with_groups_authenticates(self, issuer):
        """Token with wlcg.groups should authenticate successfully."""
        token = issuer.generate(
            scope="storage.read:/",
            groups=["/cms", "/atlas"],
        )
        sock, status, body = _token_session(token)
        try:
            assert status == kXR_ok, f"auth with groups failed: body={body!r}"
            # Verify we can still do operations
            status, body = _send_stat(sock, "/test.txt")
            assert status == kXR_ok
        finally:
            sock.close()
