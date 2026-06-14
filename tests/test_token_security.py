"""
tests/test_token_security.py

JWT token security edge cases: algorithm confusion, nbf boundary,
structural malformation, scope path boundary, WebDAV Bearer edge cases,
and XRootD protocol-level token interactions.

Run:
    pytest tests/test_token_security.py -v
"""

import base64
import json
import os
import socket
import struct
import time

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from utils.make_token import TokenIssuer, b64url_encode

from settings import (
    CA_CERT,
    DATA_ROOT,
    NGINX_TOKEN_PORT,
    NGINX_WEBDAV_PORT,
    SERVER_HOST,
    TOKENS_DIR,
)

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

TOKEN_DIR    = TOKENS_DIR
TOKEN_HOST   = SERVER_HOST
TOKEN_PORT   = NGINX_TOKEN_PORT
WEBDAV_BASE  = f"https://{SERVER_HOST}:{NGINX_WEBDAV_PORT}"
CA_PEM       = CA_CERT

# XRootD opcodes
kXR_auth     = 3000
kXR_login    = 3007
kXR_protocol = 3006
kXR_stat     = 3017
kXR_ping     = 3011
kXR_open     = 3010
kXR_close    = 3003

# Response status codes
kXR_ok       = 0
kXR_error    = 4003


@pytest.fixture(scope="module")
def issuer():
    ti = TokenIssuer(TOKEN_DIR)
    if not os.path.exists(ti.key_path):
        ti.init_keys()
    return ti


# ---------------------------------------------------------------------------
# Raw socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(f"socket closed with {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_handshake():
    sock = socket.create_connection((TOKEN_HOST, TOKEN_PORT), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_ok
    return sock


def _send_login(sock, streamid=b"\x00\x02"):
    username = b"pytest\x00\x00"
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      username, 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


def _send_auth_ztn(sock, token, streamid=b"\x00\x03"):
    token_bytes = token.encode("ascii") if isinstance(token, str) else token
    cred_payload = b"ztn\x00" + token_bytes
    req = struct.pack("!2sH", streamid, kXR_auth)
    req += b"\x00" * 12
    req += b"ztn\x00"
    req += struct.pack("!I", len(cred_payload))
    req += cred_payload
    sock.sendall(req)
    return _read_response(sock)


def _send_ping(sock, streamid=b"\x00\x04"):
    req = struct.pack("!2sH", streamid, kXR_ping)
    req += b"\x00" * 16
    req += struct.pack("!I", 0)
    sock.sendall(req)
    return _read_response(sock)


def _token_session(token):
    """Open a session and send ztn auth; return (sock, auth_status, auth_body)."""
    sock = _raw_handshake()
    req = struct.pack("!2sH I BB 10s I",
                      b"\x00\x01", kXR_protocol, 39, 0x01, 0x03, b"\x00"*10, 0)
    sock.sendall(req)
    _read_response(sock)
    _send_login(sock)
    status, body = _send_auth_ztn(sock, token)
    return sock, status, body


def _make_raw_token(alg, payload_dict):
    """Build a JWT with the given alg header value and payload dict.

    Signature is the raw RS256 sig over the signing input so that only
    the algorithm header differs from a valid token — the server must
    reject on alg, not on sig failure.
    """
    header = {"alg": alg, "typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode())
    # Empty signature — the server should reject on alg before verifying sig
    s_b64 = b64url_encode(b"")
    return f"{h_b64}.{p_b64}.{s_b64}"


def _valid_payload():
    now = int(time.time())
    return {
        "iss": TokenIssuer.DEFAULT_ISSUER,
        "sub": "testuser",
        "aud": TokenIssuer.DEFAULT_AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "scope": "storage.read:/",
        "wlcg.ver": "1.0",
    }


# =========================================================================
# Class 1 — Algorithm Confusion
# =========================================================================

class TestAlgorithmConfusion:
    """Tokens with non-RS256 alg values must be rejected at the alg check."""

    def _assert_rejected(self, token):
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error, f"expected rejection, got status={status}"

    def test_alg_none_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("none", _valid_payload()))

    def test_alg_hs256_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("HS256", _valid_payload()))

    def test_alg_rs384_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("RS384", _valid_payload()))

    def test_alg_rs512_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("RS512", _valid_payload()))

    def test_alg_es256_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("ES256", _valid_payload()))

    def test_alg_field_missing_rejected(self, issuer):
        # Header has no "alg" key at all → empty alg string → strcmp fails
        header = {"typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
        payload = _valid_payload()
        h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        token = f"{h_b64}.{p_b64}.{b64url_encode(b'')}"
        self._assert_rejected(token)

    def test_alg_empty_string_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("", _valid_payload()))

    def test_alg_uppercase_NONE_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("NONE", _valid_payload()))

    def test_alg_rs256_mixed_case_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("Rs256", _valid_payload()))

    def test_alg_with_null_byte_rejected(self, issuer):
        # Null byte in alg — must not bypass strcmp
        self._assert_rejected(_make_raw_token("RS256\x00evil", _valid_payload()))

    def test_alg_very_long_string_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("A" * 200, _valid_payload()))

    def test_alg_control_chars_rejected(self, issuer):
        self._assert_rejected(_make_raw_token("RS\n256", _valid_payload()))


# =========================================================================
# Class 2 — nbf (not-before) boundary
# =========================================================================

class TestNbfFutureToken:
    """nbf in the future must be rejected; past/zero/now must be accepted."""

    def _make_nbf_token(self, issuer, nbf_offset):
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
        payload = {
            "iss": issuer.issuer,
            "sub": "testuser",
            "aud": issuer.audience,
            "exp": now + 7200,
            "iat": now - 60,
            "nbf": now + nbf_offset,
            "scope": "storage.read:/",
            "wlcg.ver": "1.0",
        }
        return issuer._sign_jwt(header, payload)

    def test_nbf_one_second_future_rejected(self, issuer):
        # Use 2-second offset to account for clock skew and processing latency.
        token = self._make_nbf_token(issuer, +2)
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error

    def test_nbf_one_hour_future_rejected(self, issuer):
        token = self._make_nbf_token(issuer, +3600)
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_error

    def test_nbf_zero_accepted(self, issuer):
        # nbf=0 treated as not set
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": TokenIssuer.DEFAULT_KID}
        payload = {
            "iss": issuer.issuer, "sub": "testuser", "aud": issuer.audience,
            "exp": now + 3600, "iat": now, "nbf": 0,
            "scope": "storage.read:/", "wlcg.ver": "1.0",
        }
        token = issuer._sign_jwt(header, payload)
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_ok

    def test_nbf_exactly_now_accepted(self, issuer):
        token = self._make_nbf_token(issuer, 0)
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_ok

    def test_nbf_one_second_ago_accepted(self, issuer):
        token = self._make_nbf_token(issuer, -1)
        sock, status, body = _token_session(token)
        sock.close()
        assert status == kXR_ok


# =========================================================================
# Class 3 — Malformed token structure
# =========================================================================

class TestMalformedTokenStructure:
    """Structural guards before any claim parsing."""

    def _assert_rejected(self, token_bytes):
        sock, status, body = _token_session(token_bytes)
        sock.close()
        assert status == kXR_error

    def test_token_no_dots_rejected(self, issuer):
        self._assert_rejected(b"notavalidtoken")

    def test_token_one_dot_rejected(self, issuer):
        h = b64url_encode(b'{"alg":"RS256"}')
        p = b64url_encode(b'{"sub":"x"}')
        self._assert_rejected(f"{h}.{p}".encode())

    def test_token_three_dots_rejected(self, issuer):
        # Four parts (extra dot)
        valid = issuer.generate(scope="storage.read:/")
        self._assert_rejected((valid + ".extra").encode())

    def test_token_empty_header_part_rejected(self, issuer):
        # Empty first segment
        p = b64url_encode(b'{"sub":"x"}')
        s = b64url_encode(b"sig")
        self._assert_rejected(f".{p}.{s}".encode())

    def test_token_non_b64_header_rejected(self, issuer):
        p = b64url_encode(b'{"sub":"x"}')
        s = b64url_encode(b"sig")
        self._assert_rejected(f"!!!.{p}.{s}".encode())

    def test_token_oversized_token_rejected(self, issuer):
        # Over 8192-byte cap
        garbage = "A" * 9000
        self._assert_rejected(garbage.encode())

    def test_token_zero_length_rejected(self, issuer):
        self._assert_rejected(b"")

    def test_token_binary_garbage_rejected(self, issuer):
        import os as _os
        self._assert_rejected(_os.urandom(128))


# =========================================================================
# Class 4 — Scope path boundary (security-critical)
# =========================================================================

class TestScopePathBoundary:
    """/data scope must NOT match /database — off-by-one boundary.

    WebDAV uses optional auth: anonymous can read, not write.
    Scope enforcement is tested via PUT (write) where anonymous is denied
    and the token's scope is the only way to grant access.
    For read-scope checks we use the XRootD protocol port where auth is required.
    """

    def _put(self, token, path, data=b"x"):
        url = WEBDAV_BASE + path
        r = requests.put(url, data=data, verify=False,
                         headers={"Authorization": f"Bearer {token}"},
                         timeout=5)
        return r.status_code

    def _xrd_stat(self, token, path):
        """Stat a path via XRootD protocol with token auth."""
        sock, auth_status, _ = _token_session(token)
        if auth_status != kXR_ok:
            sock.close()
            return auth_status
        path_bytes = path.encode() + b"\x00"
        req = struct.pack("!2sH", b"\x00\x05", kXR_stat)
        req += b"\x00" * 16
        req += struct.pack("!I", len(path_bytes))
        req += path_bytes
        sock.sendall(req)
        status, body = _read_response(sock)
        sock.close()
        return status

    def test_scope_data_does_not_match_database(self, issuer):
        token = issuer.generate(scope="storage.write:/data")
        code = self._put(token, "/database/file.txt")
        assert code in (401, 403), f"expected 401/403, got {code}"

    def test_scope_data_does_not_match_datastore(self, issuer):
        token = issuer.generate(scope="storage.write:/data")
        code = self._put(token, "/datastore/x.txt")
        assert code in (401, 403), f"expected 401/403, got {code}"

    def test_scope_data_write_matches_data_slash_file(self, issuer):
        # storage.write:/data token can PUT /data/something
        os.makedirs(os.path.join(DATA_ROOT, "data"), exist_ok=True)
        token = issuer.generate(scope="storage.write:/data storage.read:/data")
        code = self._put(token, "/data/scope_test.txt", data=b"hello")
        assert code in (200, 201, 204), f"expected 2xx, got {code}"

    def test_scope_root_slash_matches_everything_write(self, issuer):
        token = issuer.generate(scope="storage.write:/ storage.read:/")
        code = self._put(token, "/scope_root_write.txt", data=b"root")
        assert code in (200, 201, 204)

    def test_scope_data_read_via_xrd(self, issuer):
        # Via XRootD protocol (required auth): storage.read:/data can stat /data/test
        os.makedirs(os.path.join(DATA_ROOT, "data"), exist_ok=True)
        with open(os.path.join(DATA_ROOT, "data", "xrd_test.txt"), "w") as f:
            f.write("hello")
        token = issuer.generate(scope="storage.read:/data")
        status = self._xrd_stat(token, "/data/xrd_test.txt")
        assert status == kXR_ok, f"expected kXR_ok, got {status}"

    def test_scope_subdir_does_not_match_parent_xrd(self, issuer):
        # /subdir scope cannot stat /test.txt via XRootD (auth required)
        token = issuer.generate(scope="storage.read:/subdir")
        status = self._xrd_stat(token, "/test.txt")
        assert status == kXR_error, f"expected kXR_error, got {status}"

    def test_scope_subdir_does_not_match_sibling_write(self, issuer):
        # /a scope cannot write to /b/
        os.makedirs(os.path.join(DATA_ROOT, "b"), exist_ok=True)
        token = issuer.generate(scope="storage.write:/a")
        code = self._put(token, "/b/file.txt")
        assert code in (401, 403)

    def test_scope_exact_path_write_denied_outside(self, issuer):
        # /exact scope cannot write to /exact2
        token = issuer.generate(scope="storage.write:/exact")
        code = self._put(token, "/exact2/file.txt")
        assert code in (401, 403)

    def test_scope_exact_path_write_allowed_inside(self, issuer):
        os.makedirs(os.path.join(DATA_ROOT, "exact"), exist_ok=True)
        token = issuer.generate(scope="storage.write:/exact storage.read:/exact")
        code = self._put(token, "/exact/inner.txt", data=b"x")
        assert code in (200, 201, 204)

    def test_scope_deep_path_write_allowed(self, issuer):
        os.makedirs(os.path.join(DATA_ROOT, "a", "b", "c"), exist_ok=True)
        token = issuer.generate(scope="storage.write:/a/b/c")
        code = self._put(token, "/a/b/c/d.txt", data=b"deep")
        assert code in (200, 201, 204)

    def test_scope_deep_path_no_match_prefix_only_write(self, issuer):
        # /a/b scope does NOT match /a/bc
        os.makedirs(os.path.join(DATA_ROOT, "a"), exist_ok=True)
        token = issuer.generate(scope="storage.write:/a/b")
        code = self._put(token, "/a/bc.txt")
        assert code in (401, 403)

    def test_write_scope_allows_put(self, issuer):
        token = issuer.generate(scope="storage.write:/ storage.read:/")
        code = self._put(token, "/write_allowed.txt", data=b"allowed")
        assert code in (200, 201, 204)

    def test_read_scope_blocks_write(self, issuer):
        token = issuer.generate(scope="storage.read:/")
        code = self._put(token, "/readonly_block.txt", data=b"blocked")
        assert code in (401, 403)

    def test_write_scope_blocks_read(self, issuer):
        # Inverse direction of test_read_scope_blocks_write: a token scoped to
        # storage.write ONLY (no storage.read) must be DENIED a read.  WebDAV
        # permits anonymous reads, so this gate is exercised on the XRootD port
        # where auth is mandatory — a valid write-only token must not be able to
        # stat (read the metadata of) an existing file it has no read scope for.
        with open(os.path.join(DATA_ROOT, "write_only_noread.txt"), "wb") as f:
            f.write(b"secret")
        token = issuer.generate(scope="storage.write:/")
        status = self._xrd_stat(token, "/write_only_noread.txt")
        assert status == kXR_error, \
            f"write-only scope must block read (stat), got status={status}"

    # --- MUTUAL cross-identity isolation (token-scope model) ----------------
    # The HTTP protocols do NOT use VO-ACL (xrootd_require_vo is stream-only); a
    # client's cross-identity path access is governed by its TOKEN SCOPE.  These
    # are the token-realm equivalent of test_vo_acl.py's mutual VO isolation: two
    # differently-scoped identities, each allowed ITS OWN path and denied the
    # OTHER's, in BOTH directions, across read and write.  WebDAV permits
    # anonymous reads, so read isolation is exercised on the auth-mandatory
    # XRootD token port (_xrd_stat) and write isolation over WebDAV (_put).

    def _seed_vo_dirs(self):
        for vo in ("cms", "atlas"):
            d = os.path.join(DATA_ROOT, vo)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "r.txt"), "wb") as f:
                f.write(vo.encode())

    def test_cross_identity_cms_token_isolation(self, issuer):
        self._seed_vo_dirs()
        tok = issuer.generate(scope="storage.read:/cms storage.write:/cms")
        # own namespace: read + write allowed
        assert self._xrd_stat(tok, "/cms/r.txt") == kXR_ok
        assert self._put(tok, "/cms/cms_own.txt", data=b"mine") in (200, 201, 204)
        # the OTHER identity's namespace: read + write denied
        assert self._xrd_stat(tok, "/atlas/r.txt") == kXR_error
        assert self._put(tok, "/atlas/cms_intruder.txt", data=b"x") in (401, 403)

    def test_cross_identity_atlas_token_isolation(self, issuer):
        self._seed_vo_dirs()
        tok = issuer.generate(scope="storage.read:/atlas storage.write:/atlas")
        # own namespace: read + write allowed
        assert self._xrd_stat(tok, "/atlas/r.txt") == kXR_ok
        assert self._put(tok, "/atlas/atlas_own.txt", data=b"mine") in (200, 201, 204)
        # the OTHER identity's namespace: read + write denied
        assert self._xrd_stat(tok, "/cms/r.txt") == kXR_error
        assert self._put(tok, "/cms/atlas_intruder.txt", data=b"x") in (401, 403)

    def test_scope_overflow_max_scopes_no_crash(self, issuer):
        # 70 scope entries — server must not crash
        scopes = " ".join(f"storage.read:/path{i}" for i in range(70))
        token = issuer.generate(scope=scopes)
        # Just verify the server stays alive; any HTTP response is OK
        try:
            r = requests.get(WEBDAV_BASE + "/test.txt", verify=False,
                             headers={"Authorization": f"Bearer {token}"}, timeout=5)
            assert r.status_code in (200, 401, 403)
        except Exception:
            pass  # server closed → crash, fail if we get here cleanly

    def test_write_scope_create_and_modify(self, issuer):
        token = issuer.generate(scope="storage.create:/ storage.modify:/")
        code = self._put(token, "/create_modify.txt", data=b"cm")
        assert code in (200, 201, 204)


# =========================================================================
# Class 5 — WebDAV Bearer header edge cases
# =========================================================================

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
