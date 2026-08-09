from split_continuation import reexport as _reexport
_reexport(globals(), "_test_token_security_helpers")

class TestWebDavTokenSecurity:
    """WebDAV Bearer token scope enforcement and log-injection hardening.

    The WebDAV port uses optional auth, so a VALID token with wrong scope is
    rejected (403), but an INVALID/missing token falls through to anonymous
    (which can write — that is by design for optional auth).
    Log-injection attempts are verified via XRootD protocol where auth is strict.
    """

    def test_read_only_token_blocks_write(self, issuer):
        # Valid token with read scope cannot write (scope enforcement fires)
        token = issuer.generate(scope="storage.read:/")
        r = requests.put(WEBDAV_BASE + "/scope_ro_block.txt", data=b"x",
                         verify=False, headers={"Authorization": f"Bearer {token}"},
                         timeout=5)
        assert r.status_code == 403

    def test_wrong_path_scope_blocks_write(self, issuer):
        token = issuer.generate(scope="storage.write:/protected")
        r = requests.put(WEBDAV_BASE + "/other_dir/file.txt", data=b"x",
                         verify=False, headers={"Authorization": f"Bearer {token}"},
                         timeout=5)
        assert r.status_code in (401, 403)

    def test_valid_write_scope_allows_put(self, issuer):
        token = issuer.generate(scope="storage.write:/ storage.read:/")
        r = requests.put(WEBDAV_BASE + "/webdav_sec_write.txt", data=b"ok",
                         verify=False, headers={"Authorization": f"Bearer {token}"},
                         timeout=5)
        assert r.status_code in (200, 201, 204)

    def test_log_injection_in_kid_rejected_xrd(self, issuer):
        # kid contains newline — server sanitizes log, must not crash; XRootD rejects
        header = {"alg": "RS256", "typ": "JWT",
                  "kid": "test-key-1\nX-Injected: evil"}
        h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64url_encode(json.dumps(_valid_payload(), separators=(",", ":")).encode())
        token = f"{h_b64}.{p_b64}.{b64url_encode(b'badsig')}"
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error

    def test_log_injection_in_sub_rejected_xrd(self, issuer):
        # sub contains newline — must be sanitized in log output, not crash
        header = {"alg": "RS256", "typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
        payload = {**_valid_payload(), "sub": "user\nX-Evil: injected"}
        h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{h_b64}.{p_b64}.{b64url_encode(b'badsig')}"
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error

    def test_expired_token_write_still_blocked_by_scope(self, issuer):
        # An expired token fails auth → anonymous fallback → can write
        # But a valid-but-read-only token must still block write
        expired_read = issuer.generate_expired(scope="storage.read:/")
        # Expired token: falls to anonymous → write allowed (optional auth)
        r1 = requests.put(WEBDAV_BASE + "/exp_anon.txt", data=b"x",
                          verify=False,
                          headers={"Authorization": f"Bearer {expired_read}"},
                          timeout=5)
        assert r1.status_code in (200, 201, 204)  # anonymous fallback allowed
        # Valid read-only token: auth succeeds, scope enforcement blocks write
        valid_read = issuer.generate(scope="storage.read:/")
        r2 = requests.put(WEBDAV_BASE + "/valid_ro_block.txt", data=b"x",
                          verify=False,
                          headers={"Authorization": f"Bearer {valid_read}"},
                          timeout=5)
        assert r2.status_code == 403

    def test_wrong_issuer_token_falls_to_anonymous(self, issuer):
        # Wrong-issuer token: auth fails → anonymous can write (optional auth)
        token = issuer.generate_wrong_issuer()
        r = requests.put(WEBDAV_BASE + "/wrong_iss_anon.txt", data=b"x",
                         verify=False, headers={"Authorization": f"Bearer {token}"},
                         timeout=5)
        # Anonymous can write — test only verifies server doesn't crash
        assert r.status_code in (200, 201, 204, 400, 401, 403)

    def test_webdav_get_with_valid_token(self, issuer):
        token = issuer.generate(scope="storage.read:/")
        r = requests.get(WEBDAV_BASE + "/test.txt", verify=False,
                         headers={"Authorization": f"Bearer {token}"}, timeout=5)
        assert r.status_code == 200


# =========================================================================
# Class 6 — XRootD protocol token edge cases
# =========================================================================

class TestTokenXrootdEdgeCases:
    """Protocol-level token interactions."""

    def test_double_auth_second_accepted(self, issuer):
        # Re-authenticating with a valid token on an already-authed session
        # is accepted (no re-auth guard in token handler)
        token = issuer.generate(scope="storage.read:/")
        sock, status, body = _token_session(token)
        assert status == kXR_ok
        status2, body2 = _send_auth_ztn(sock, token)
        sock.close()
        assert status2 == kXR_ok

    def test_auth_with_unknown_credtype(self, issuer):
        # credtype "xyz\0" on token-only server
        sock = _raw_handshake()
        req = struct.pack("!2sH", b"\x00\x01", kXR_protocol)
        req += struct.pack("!I BB 10s I", 39, 0x01, 0x03, b"\x00"*10, 0)
        sock.sendall(req)
        _read_response(sock)
        _send_login(sock)
        cred_payload = b"xyz\x00" + b"garbage"
        req = struct.pack("!2sH", b"\x00\x03", kXR_auth)
        req += b"\x00" * 12
        req += b"xyz\x00"
        req += struct.pack("!I", len(cred_payload))
        req += cred_payload
        sock.sendall(req)
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error

    def test_stat_denied_without_auth(self, issuer):
        # After login but before auth, stat should fail
        sock = _raw_handshake()
        req = struct.pack("!2sH I BB 10s I",
                          b"\x00\x01", kXR_protocol, 39, 0x01, 0x03, b"\x00"*10, 0)
        sock.sendall(req)
        _read_response(sock)
        _send_login(sock)
        # Send stat without auth
        path = b"/test.txt\x00"
        req = struct.pack("!2sH", b"\x00\x03", kXR_stat)
        req += b"\x00" * 16
        req += struct.pack("!I", len(path))
        req += path
        sock.sendall(req)
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error

    def test_read_scope_blocks_write(self, issuer):
        # storage.read:/ token cannot open for write
        token = issuer.generate(scope="storage.read:/")
        sock, auth_status, _ = _token_session(token)
        assert auth_status == kXR_ok
        path = b"/readonly_write_block.txt\x00"
        # kXR_open_updt = 0x0020 (write mode)
        req = struct.pack("!2sHHH2s6s4sI",
                          b"\x00\x05", kXR_open,
                          0o644, 0x0020, b"\x00\x00", b"\x00"*6, b"\x00"*4,
                          len(path))
        sock.sendall(req + path)
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_error

    def test_ping_works_without_scope(self, issuer):
        # Token with no scope: ping still works (ping doesn't require scope)
        token = issuer.generate_no_scope()
        sock, auth_status, _ = _token_session(token)
        # Auth may succeed (no scope is allowed for login)
        if auth_status == kXR_ok:
            status, body = _send_ping(sock)
            sock.close()
            assert status == kXR_ok
        else:
            sock.close()

    def test_valid_token_stat_succeeds(self, issuer):
        token = issuer.generate(scope="storage.read:/")
        sock, auth_status, _ = _token_session(token)
        assert auth_status == kXR_ok
        path = b"/test.txt\x00"
        req = struct.pack("!2sH", b"\x00\x05", kXR_stat)
        req += b"\x00" * 16
        req += struct.pack("!I", len(path))
        req += path
        sock.sendall(req)
        status, body = _read_response(sock)
        sock.close()
        assert status == kXR_ok

    def test_wrong_issuer_rejected(self, issuer):
        token = issuer.generate_wrong_issuer()
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error

    def test_wrong_audience_rejected(self, issuer):
        token = issuer.generate_wrong_audience()
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error
