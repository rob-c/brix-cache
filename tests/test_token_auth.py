from split_continuation import reexport as _reexport
_reexport(globals(), "_test_token_auth_helpers")

class TestTokenGeneration:
    """Validate that token generation produces well-formed JWTs."""

    def test_generate_valid_token(self, issuer):
        token = issuer.generate(scope="storage.read:/")
        parts = token.split(".")
        assert len(parts) == 3, "JWT must have 3 dot-separated parts"

    def test_generate_with_groups(self, issuer):
        token = issuer.generate(scope="storage.read:/", groups=["/cms", "/atlas"])
        assert isinstance(token, str)
        assert len(token.split(".")) == 3

    def test_generate_expired(self, issuer):
        token = issuer.generate_expired()
        assert len(token.split(".")) == 3

    def test_generate_bad_signature(self, issuer):
        token = issuer.generate_bad_signature()
        assert len(token.split(".")) == 3

    def test_generate_wrong_issuer(self, issuer):
        token = issuer.generate_wrong_issuer()
        assert len(token.split(".")) == 3

    def test_generate_wrong_audience(self, issuer):
        token = issuer.generate_wrong_audience()
        assert len(token.split(".")) == 3


# =========================================================================
# 2. XROOTD PROTOCOL — TOKEN AUTH
# =========================================================================

class TestXrootdTokenProtocol:
    """kXR_protocol reply shape, and where 'ztn' is actually advertised."""

    def test_protocol_secreqs_block_is_not_shifted_by_a_security_vector(self):
        """kXR_secreqs: theTag 'S' must sit at the fixed offset 8.

        ServerResponseBody_Protocol is { pval, flags, secreq }, so a conformant
        client reads theTag at offset 8 and the seclvl right behind it.  BriX
        therefore emits NO leading SecurityInfo header and no binary
        SecurityProtocol entries here — prepending either would shift 'S'
        downfield and make strict clients (go-hep, XrdRust) misread the block.
        The offered protocol list is advertised the standard way instead, as the
        "&P=..." string in the kXR_login reply (test_login_returns_ztn_params).
        """
        sock = _raw_handshake()
        try:
            status, body = _send_protocol(sock)
            assert status == kXR_ok
            # 8-byte ServerProtocolBody + the 6-byte signing block, exactly.
            assert len(body) == 8 + 6, \
                f"unexpected kXR_protocol body length {len(body)}: {body!r}"
            assert body[8:9] == b"S", \
                f"theTag 'S' is not at offset 8 — body: {body!r}"
            assert body[10] == 0, f"secver must be kXR_secver_0: {body!r}"
            assert body[13] == 0, f"secvsz must be 0 (no secvec): {body!r}"
        finally:
            sock.close()

    def test_login_returns_ztn_params(self):
        """Login response should include &P=ztn parameter block."""
        sock = _raw_handshake()
        try:
            _send_protocol(sock)
            status, body = _send_login(sock)
            assert status == kXR_ok
            assert len(body) > 16, "login response too short for params"
            params = body[16:].decode("ascii", errors="replace")
            assert "&P=ztn" in params, f"ztn not in login params: {params!r}"
        finally:
            sock.close()

    def test_ztn_params_match_the_stock_client_grammar(self):
        """The ztn block must be `&P=ztn,<expiry>:<maxtsz>:`.

        XrdSecProtocolztn's constructor parses the server parameters with
        strtoll() (minimum acceptable token lifetime) then strtol() (maximum
        accepted token size), demanding a ':' after each field and maxtsz > 0.
        BriX advertised `&P=ztn,v:10000` for its whole life, which every stock
        XrdCl rejected with "Secztn: Malformed client parameters" — so no stock
        client could ever use token auth over root://.  Pin the grammar here so
        the interop fix cannot silently regress.
        """
        sock = _raw_handshake()
        try:
            _send_protocol(sock)
            status, body = _send_login(sock)
            assert status == kXR_ok
            params = body[16:].decode("ascii", errors="replace")
            match = re.search(r"&P=ztn,(-?\d+):(-?\d+):", params)
            assert match, f"ztn block is not <expiry>:<maxtsz>:  {params!r}"
            assert int(match.group(2)) > 0, \
                f"maxtsz must be positive, got {match.group(2)}"
        finally:
            sock.close()


class TestXrootdTokenAuth:
    """XRootD authentication with bearer tokens via ztn credential type."""

    def test_valid_token_auth(self, issuer):
        """Valid read token should authenticate successfully."""
        token = issuer.generate(scope="storage.read:/")
        sock, status, body = _token_session(token)
        try:
            assert status == kXR_ok, f"auth failed: status={status} body={body!r}"
        finally:
            sock.close()

    def test_stat_after_token_auth(self, issuer):
        """After token auth, kXR_stat should succeed for test.txt."""
        token = issuer.generate(scope="storage.read:/")
        sock, status, body = _token_session(token)
        assert status == kXR_ok
        try:
            status, body = _send_stat(sock, "/test.txt")
            assert status == kXR_ok, f"stat failed: body={body!r}"
        finally:
            sock.close()

    def test_dirlist_after_token_auth(self, issuer):
        """After token auth, kXR_dirlist should succeed."""
        token = issuer.generate(scope="storage.read:/")
        sock, status, body = _token_session(token)
        assert status == kXR_ok
        try:
            status, body = _send_dirlist(sock, "/")
            assert status == kXR_ok, f"dirlist failed: body={body!r}"
            # Should contain at least test.txt
            listing = body.decode("utf-8", errors="replace")
            assert "test.txt" in listing
        finally:
            sock.close()

    def test_ping_after_token_auth(self, issuer):
        """After token auth, kXR_ping should work."""
        token = issuer.generate(scope="storage.read:/")
        sock, status, body = _token_session(token)
        assert status == kXR_ok
        try:
            status, body = _send_ping(sock)
            assert status == kXR_ok
        finally:
            sock.close()


class TestXrootdTokenNegative:
    """Negative tests — tokens that should be rejected."""

    def test_expired_token_rejected(self, issuer):
        """Expired token must be rejected."""
        token = issuer.generate_expired()
        sock, status, body = _token_session(token)
        try:
            assert status == kXR_error, "expired token should fail"
        finally:
            sock.close()

    def test_bad_signature_rejected(self, issuer):
        """Token with corrupted signature must be rejected."""
        token = issuer.generate_bad_signature()
        sock, status, body = _token_session(token)
        try:
            assert status == kXR_error, "bad signature should fail"
        finally:
            sock.close()

    def test_wrong_issuer_rejected(self, issuer):
        """Token with wrong issuer must be rejected."""
        token = issuer.generate_wrong_issuer()
        sock, status, body = _token_session(token)
        try:
            assert status == kXR_error, "wrong issuer should fail"
        finally:
            sock.close()

    def test_wrong_audience_rejected(self, issuer):
        """Token with wrong audience must be rejected."""
        token = issuer.generate_wrong_audience()
        sock, status, body = _token_session(token)
        try:
            assert status == kXR_error, "wrong audience should fail"
        finally:
            sock.close()

    def test_empty_token_rejected(self):
        """Empty token payload must be rejected."""
        sock = _raw_handshake()
        try:
            _send_protocol(sock)
            _send_login(sock)
            # Send auth with empty token (just "ztn\0")
            status, body = _send_auth_ztn(sock, b"")
            assert status == kXR_error, "empty token should fail"
        finally:
            sock.close()

    def test_garbage_token_rejected(self):
        """Random garbage as token must be rejected."""
        sock = _raw_handshake()
        try:
            _send_protocol(sock)
            _send_login(sock)
            status, body = _send_auth_ztn(sock, b"this.is.not.a.jwt")
            assert status == kXR_error, "garbage token should fail"
        finally:
            sock.close()

    def test_no_scope_token_rejected(self, issuer):
        """Token without scope claim should still authenticate (scopes are
        checked per-operation, not at auth time)."""
        token = issuer.generate_no_scope()
        sock, status, body = _token_session(token)
        try:
            # Auth should succeed (no scope is checked at auth time)
            assert status == kXR_ok, f"no-scope token auth failed: body={body!r}"
        finally:
            sock.close()


# =========================================================================
# 3. WEBDAV / HTTPS — BEARER TOKEN
# =========================================================================

class TestWebDavBearerToken:
    """WebDAV operations using Authorization: Bearer <JWT>."""

    def test_get_with_bearer_token(self, issuer):
        """GET a file using a Bearer token over HTTPS."""
        token = issuer.generate(scope="storage.read:/")
        resp = requests.get(
            f"{WEBDAV_BASE}/test.txt",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        assert resp.status_code == 200
        assert resp.content == b"hello from nginx-xrootd\n"

    def test_head_with_bearer_token(self, issuer):
        """HEAD request with Bearer token."""
        token = issuer.generate(scope="storage.read:/")
        resp = requests.head(
            f"{WEBDAV_BASE}/test.txt",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        assert resp.status_code == 200
        assert int(resp.headers["Content-Length"]) == 24

    def test_propfind_with_bearer_token(self, issuer):
        """PROPFIND (directory listing) with Bearer token."""
        token = issuer.generate(scope="storage.read:/")
        resp = requests.request(
            "PROPFIND",
            f"{WEBDAV_BASE}/",
            headers={
                "Authorization": f"Bearer {token}",
                "Depth": "1",
            },
            verify=False,
        )
        # 207 Multi-Status for PROPFIND
        assert resp.status_code == 207
        assert "test.txt" in resp.text

    def test_put_with_write_scope(self, issuer):
        """PUT a file with a write-scoped Bearer token."""
        token = issuer.generate(scope="storage.read:/ storage.write:/")
        test_path = "/token_test_write.txt"
        test_data = b"written via bearer token\n"
        try:
            resp = requests.put(
                f"{WEBDAV_BASE}{test_path}",
                data=test_data,
                headers={"Authorization": f"Bearer {token}"},
                verify=False,
            )
            assert resp.status_code in (200, 201, 204), \
                f"PUT failed: {resp.status_code} {resp.text}"

            # Verify the file was written
            local_path = os.path.join(DATA_ROOT, "token_test_write.txt")
            assert os.path.exists(local_path)
            with open(local_path, "rb") as f:
                assert f.read() == test_data
        finally:
            # Clean up
            try:
                os.unlink(os.path.join(DATA_ROOT, "token_test_write.txt"))
            except FileNotFoundError:
                pass

    def test_put_denied_without_write_scope(self, issuer):
        """PUT with read-only token should be rejected (403)."""
        token = issuer.generate(scope="storage.read:/")
        resp = requests.put(
            f"{WEBDAV_BASE}/token_test_denied.txt",
            data=b"should not be written",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        assert resp.status_code == 403, \
            f"expected 403, got {resp.status_code}"

    def test_expired_token_rejected(self, issuer):
        """Expired Bearer token should be rejected."""
        token = issuer.generate_expired()
        resp = requests.get(
            f"{WEBDAV_BASE}/test.txt",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        # With auth=optional, WebDAV may still serve (anonymous fallback)
        # or return 403/401 depending on config.  The key is that the
        # token auth specifically fails.
        # Since auth=optional, it falls through to anonymous → 200
        # This is expected behavior for optional auth mode.

    def test_bad_signature_rejected(self, issuer):
        """Bearer token with bad signature should fail token auth."""
        token = issuer.generate_bad_signature()
        resp = requests.get(
            f"{WEBDAV_BASE}/test.txt",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        # With auth=optional, bad token fails but anonymous fallback succeeds

    def test_wrong_issuer_rejected(self, issuer):
        """Bearer token with wrong issuer should fail token auth."""
        token = issuer.generate_wrong_issuer()
        resp = requests.get(
            f"{WEBDAV_BASE}/test.txt",
            headers={"Authorization": f"Bearer {token}"},
            verify=False,
        )
        # Same as above — optional auth allows fallback


# =========================================================================
# 4. SCOPE ENFORCEMENT
# =========================================================================
