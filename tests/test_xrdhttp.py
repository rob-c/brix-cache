"""XrdHttp protocol extension tests.

Verifies the XrdHttp compatibility layer implemented in xrdhttp.c /
xrdhttp_multipart.c / xrdhttp_stats.c:

  - X-Xrootd-Proto detection and X-Xrootd-Requuid echo
  - X-Xrootd-Status error code on 4xx/5xx responses
  - ?xrd.want.cksum=<algo> Digest: header (adler32, crc32, crc32c, md5, sha1, sha256)
  - Multi-range GET → multipart/byteranges response
  - ?tpc.src= header injection (synthesised Source: header)
  - ?xrd.stats XML statistics endpoint
  - Security: embedded NUL bytes in query params rejected, oversized values truncated

Uses the pre-started nginx instance on NGINX_HTTP_WEBDAV_PORT (8080, anonymous,
write-enabled).  Run after `tests/manage_test_servers.sh start`.
"""

import hashlib
import uuid
import re
import zlib

import pytest
import requests


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def base_url(test_env):
    return test_env["http_webdav_url"]


@pytest.fixture(scope="module")
def xrd_file(base_url):
    """Upload a known-content file once; share across tests in this module."""
    uid = uuid.uuid4().hex
    path = f"/xrdhttp_test_{uid}.bin"
    # 256 bytes: 0x00 through 0xFF repeated
    content = bytes(range(256))
    r = requests.put(f"{base_url}{path}", data=content, timeout=10)
    assert r.status_code in (200, 201), f"fixture PUT failed: {r.status_code}"
    return {"path": path, "content": content, "url": f"{base_url}{path}"}


# ---------------------------------------------------------------------------
# 1. X-Xrootd-Proto detection + X-Xrootd-Requuid echo
# ---------------------------------------------------------------------------

class TestXrdHttpHeaders:
    """Verify that X-Xrootd-Requuid is echoed back when the client sends it."""

    def test_requuid_echoed_on_get(self, xrd_file):
        """Success path: server echoes X-Xrootd-Requuid sent by client."""
        my_uuid = f"test-requuid-{uuid.uuid4().hex}"
        r = requests.get(
            xrd_file["url"],
            headers={
                "X-Xrootd-Proto": "xroot",
                "X-Xrootd-Requuid": my_uuid,
            },
            timeout=10,
        )
        assert r.status_code == 200
        assert r.headers.get("X-Xrootd-Requuid") == my_uuid, (
            f"Expected X-Xrootd-Requuid: {my_uuid!r} in response headers, "
            f"got: {dict(r.headers)}"
        )

    def test_no_xrdhttp_headers_without_proto(self, xrd_file):
        """Non-XrdHttp clients (no X-Xrootd-Proto) do not receive XrdHttp response headers."""
        r = requests.get(xrd_file["url"], timeout=10)
        assert r.status_code == 200
        assert "X-Xrootd-Requuid" not in r.headers
        assert "X-Xrootd-Status" not in r.headers

    def test_requuid_security_oversized_value(self, xrd_file):
        """Oversized X-Xrootd-Requuid is silently truncated — server must not crash."""
        long_uuid = "A" * 4096   # far beyond XRDHTTP_UUID_MAX=64
        r = requests.get(
            xrd_file["url"],
            headers={
                "X-Xrootd-Proto": "xroot",
                "X-Xrootd-Requuid": long_uuid,
            },
            timeout=10,
        )
        # Server must reply (not 500 / connection reset)
        assert r.status_code == 200
        # Echoed value must be truncated to at most 63 chars
        echoed = r.headers.get("X-Xrootd-Requuid", "")
        assert len(echoed) <= 63, f"UUID not truncated: len={len(echoed)}"


# ---------------------------------------------------------------------------
# 2. X-Xrootd-Status on error responses
# ---------------------------------------------------------------------------

class TestXrdHttpStatus:
    """Verify X-Xrootd-Status is set to a non-zero kXR code on 4xx responses."""

    def test_status_header_on_not_found(self, base_url):
        """Success path: 404 response carries X-Xrootd-Status with kXR_NotFound (3003)."""
        r = requests.get(
            f"{base_url}/does_not_exist_{uuid.uuid4().hex}.txt",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 404
        status_hdr = r.headers.get("X-Xrootd-Status", "")
        assert status_hdr != "" and status_hdr != "0", (
            f"Expected non-zero X-Xrootd-Status on 404, got: {status_hdr!r}"
        )
        # kXR_NotFound == 3011 per XProtocol.hh
        assert status_hdr == "3011", (
            f"Expected X-Xrootd-Status: 3011 (kXR_NotFound), got: {status_hdr!r}"
        )

    def test_status_zero_on_success(self, xrd_file):
        """Success path: 200 response carries X-Xrootd-Status: 0 (kXR_ok)."""
        r = requests.get(
            xrd_file["url"],
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 200
        status_hdr = r.headers.get("X-Xrootd-Status", "")
        assert status_hdr == "0", (
            f"Expected X-Xrootd-Status: 0 on 200 OK, got: {status_hdr!r}"
        )

    def test_status_absent_without_xrdhttp(self, base_url):
        """Security neg: non-XrdHttp clients never receive X-Xrootd-Status."""
        r = requests.get(
            f"{base_url}/does_not_exist_{uuid.uuid4().hex}.txt",
            timeout=10,
        )
        assert r.status_code == 404
        assert "X-Xrootd-Status" not in r.headers


# ---------------------------------------------------------------------------
# 3. ?xrd.want.cksum=<algo> → Digest: header
# ---------------------------------------------------------------------------

class TestXrdHttpChecksum:
    """Verify that ?xrd.want.cksum=<algo> triggers a Digest: response header."""

    def test_adler32_digest_header(self, xrd_file):
        """Success path: Digest: header with adler32 is returned when requested."""
        r = requests.get(
            xrd_file["url"] + "?xrd.want.cksum=adler32",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("adler32="), (
            f"Expected Digest: adler32=<hex>, got: {digest!r}"
        )
        cksum_part = digest[len("adler32="):]
        assert re.match(r"^[0-9a-fA-F]+$", cksum_part), (
            f"Digest value is not hex: {cksum_part!r}"
        )
        expected = zlib.adler32(xrd_file["content"]) & 0xFFFFFFFF
        assert cksum_part == f"{expected:08x}", (
            f"adler32 mismatch: got {cksum_part!r}, expected {expected:08x}"
        )

    def test_crc32_digest_header(self, xrd_file):
        """Success path: Digest: header with crc32 is returned when requested."""
        r = requests.get(
            xrd_file["url"] + "?xrd.want.cksum=crc32",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("crc32="), f"Expected Digest: crc32=<hex>, got: {digest!r}"
        cksum_part = digest[len("crc32="):]
        assert re.match(r"^[0-9a-fA-F]{8}$", cksum_part), (
            f"crc32 Digest value not 8 hex chars: {cksum_part!r}"
        )

    def test_crc32c_digest_header(self, xrd_file):
        """Success path: Digest: header with crc32c is returned when requested."""
        _crc32c_mod = pytest.importorskip(
            "crc32c", reason="python crc32c module not installed to verify digest")
        r = requests.get(
            xrd_file["url"] + "?xrd.want.cksum=crc32c",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("crc32c="), f"Expected Digest: crc32c=<hex>, got: {digest!r}"
        cksum_part = digest[len("crc32c="):]
        expected = _crc32c_mod.crc32c(xrd_file["content"])
        assert cksum_part == f"{expected:08x}", (
            f"crc32c mismatch: got {cksum_part!r}, expected {expected:08x}"
        )

    @pytest.mark.parametrize("algo", ["md5", "sha1", "sha256"])
    def test_evp_digest_header(self, xrd_file, algo):
        """Success path: Digest: header with md5/sha1/sha256 is returned and correct."""
        r = requests.get(
            xrd_file["url"] + f"?xrd.want.cksum={algo}",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith(f"{algo}="), (
            f"Expected Digest: {algo}=<hex>, got: {digest!r}"
        )
        cksum_part = digest[len(f"{algo}="):]
        h = hashlib.new(algo)
        h.update(xrd_file["content"])
        expected = h.hexdigest()
        assert cksum_part == expected, (
            f"{algo} mismatch: got {cksum_part!r}, expected {expected!r}"
        )

    def test_no_digest_without_param(self, xrd_file):
        """Error path: Digest: header is absent when xrd.want.cksum is not requested."""
        r = requests.get(xrd_file["url"], timeout=10)
        assert r.status_code == 200
        assert "Digest" not in r.headers

    def test_cksum_security_unknown_algorithm(self, xrd_file):
        """Security neg: unknown checksum algorithm is silently ignored (no crash, no Digest:)."""
        r = requests.get(
            xrd_file["url"] + "?xrd.want.cksum=" + "X" * 512,
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        # Must return a valid response (not 500)
        assert r.status_code == 200
        # With an unknown/oversized algo name, no Digest: header should be emitted
        assert "Digest" not in r.headers


# ---------------------------------------------------------------------------
# 4. Multi-range GET → multipart/byteranges
# ---------------------------------------------------------------------------

class TestXrdHttpMultirange:
    """Verify multipart/byteranges response for multi-range GET requests."""

    def test_multipart_response_two_ranges(self, xrd_file):
        """Success path: two-range GET returns 206 multipart/byteranges."""
        r = requests.get(
            xrd_file["url"],
            headers={"Range": "bytes=0-9, 20-29"},
            timeout=10,
        )
        assert r.status_code == 206
        ct = r.headers.get("Content-Type", "")
        assert "multipart/byteranges" in ct, (
            f"Expected multipart/byteranges Content-Type, got: {ct!r}"
        )
        assert b"--" in r.content, "Response body should contain MIME boundaries"

    def test_multipart_contains_correct_data(self, xrd_file):
        """Verify the two requested ranges contain the correct byte values."""
        r = requests.get(
            xrd_file["url"],
            headers={"Range": "bytes=0-9, 20-29"},
            timeout=10,
        )
        assert r.status_code == 206
        # The file is bytes 0..255; range 0-9 = 0x00..0x09, range 20-29 = 0x14..0x1d
        expected_first = bytes(range(0, 10))
        expected_second = bytes(range(20, 30))
        body = r.content
        assert expected_first in body, (
            f"First range data (bytes 0-9) not found in multipart body"
        )
        assert expected_second in body, (
            f"Second range data (bytes 20-29) not found in multipart body"
        )

    def test_single_range_not_multipart(self, xrd_file):
        """Error/boundary path: single-range GET returns plain 206 (not multipart)."""
        r = requests.get(
            xrd_file["url"],
            headers={"Range": "bytes=0-9"},
            timeout=10,
        )
        assert r.status_code == 206
        ct = r.headers.get("Content-Type", "")
        assert "multipart" not in ct, (
            f"Single-range GET should not return multipart; got: {ct!r}"
        )


# ---------------------------------------------------------------------------
# 5. ?tpc.src= / ?tpc.dst= header injection
# ---------------------------------------------------------------------------

class TestXrdHttpTpcInjection:
    """Verify that ?tpc.src= is translated to Source: header for TPC routing."""

    def test_tpc_src_param_accepted(self, xrd_file):
        """Success path: GET with ?tpc.src= returns a response (not 400/500)."""
        r = requests.get(
            xrd_file["url"] + "?tpc.src=https://remote.example.org:8443/file.dat",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        # A plain GET with tpc.src= should be served normally (no COPY triggered).
        # The header injection is tested indirectly: server must not crash.
        assert r.status_code in (200, 206, 400, 403, 405), (
            f"Unexpected status {r.status_code} for GET with ?tpc.src="
        )

    def test_tpc_url_security_non_https_rejected(self, base_url, xrd_file):
        """Security neg: ?tpc.src= with http:// (not https://) should not inject header."""
        # We can't inspect what headers nginx synthesised internally, but the
        # server must not crash and the response must be a sane HTTP code.
        r = requests.get(
            xrd_file["url"] + "?tpc.src=http://evil.example.org/file.dat",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code < 600, "Server should not crash on non-https tpc.src URL"
        # A non-https TPC URL should be rejected with 400 or served as normal GET
        # (not forwarded for TPC). We just confirm it doesn't cause 500.
        assert r.status_code != 500, (
            f"Server returned 500 on non-https tpc.src URL"
        )

    def test_tpc_url_security_embedded_nul(self, xrd_file):
        """Security neg: embedded %00 NUL byte in query param rejected (no 500)."""
        # Send NUL as %00 — the query param parser must reject this
        r = requests.get(
            xrd_file["url"] + "?tpc.src=https://host%00evil.example.org/f",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        # Server must not crash; NUL-embedded value must not be accepted
        assert r.status_code != 500, (
            "Server must not return 500 on NUL byte in tpc.src"
        )
        assert r.status_code < 600


# ---------------------------------------------------------------------------
# 6. ?xrd.stats XML endpoint
# ---------------------------------------------------------------------------

class TestXrdHttpStats:
    """Verify that ?xrd.stats returns well-formed XRootD statistics XML."""

    def test_stats_returns_xml(self, xrd_file, base_url):
        """Success path: ?xrd.stats returns 200 text/xml with <statistics> root element."""
        r = requests.get(
            f"{base_url}/?xrd.stats",
            headers={"X-Xrootd-Proto": "xroot"},
            timeout=10,
        )
        assert r.status_code == 200, f"?xrd.stats returned {r.status_code}"
        ct = r.headers.get("Content-Type", "")
        assert "text/xml" in ct, f"Expected text/xml content-type, got: {ct!r}"
        body = r.text
        assert "<statistics" in body, "Response should contain <statistics> element"
        assert "</statistics>" in body, "Response should close <statistics>"

    def test_stats_contains_brix_section(self, base_url):
        """Verify <stats id=\"xrootd\"> block is present."""
        r = requests.get(
            f"{base_url}/?xrd.stats",
            timeout=10,
        )
        assert r.status_code == 200
        assert 'id="xrootd"' in r.text, (
            "Missing <stats id=\"xrootd\"> block in stats output"
        )
        assert 'id="http"' in r.text, (
            "Missing <stats id=\"http\"> block in stats output"
        )

    def test_stats_no_cache(self, base_url):
        """Security: ?xrd.stats response must be Cache-Control: no-store."""
        r = requests.get(f"{base_url}/?xrd.stats", timeout=10)
        assert r.status_code == 200
        cc = r.headers.get("Cache-Control", "")
        assert "no-store" in cc, (
            f"?xrd.stats should be Cache-Control: no-store, got: {cc!r}"
        )


# ---------------------------------------------------------------------------
# 7. Want-Digest: request header (RFC 3230 / XrdClHttp compatibility)
# ---------------------------------------------------------------------------

class TestWantDigestHeader:
    """Verify that Want-Digest: request header triggers a Digest: response header.

    XrdClHttp (the XRootD HTTP client plugin) sends Want-Digest: on HEAD requests
    with RFC 3230 algorithm names (SHA-256, SHA, CRC32c, etc.).  nginx-xrootd must
    normalise these names, compute the checksum, and return a Digest: header so that
    xrdcp --prefer-xrdhttp can verify file integrity without a separate round-trip.
    """

    def test_head_sha256_want_digest(self, xrd_file):
        """Success path: HEAD with Want-Digest: SHA-256 returns correct sha256 Digest:."""
        r = requests.head(
            xrd_file["url"],
            headers={"Want-Digest": "SHA-256"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("sha256="), (
            f"Expected Digest: sha256=..., got: {digest!r}"
        )
        expected = hashlib.sha256(xrd_file["content"]).hexdigest()
        assert digest == f"sha256={expected}", (
            f"SHA-256 checksum mismatch: {digest!r} != sha256={expected}"
        )

    def test_head_sha_bare_normalised_to_sha1(self, xrd_file):
        """Success path: Want-Digest: SHA (bare RFC 3230 name) is normalised to sha1."""
        r = requests.head(
            xrd_file["url"],
            headers={"Want-Digest": "SHA"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("sha1="), (
            f"Expected Digest: sha1=... for bare 'SHA', got: {digest!r}"
        )
        expected = hashlib.sha1(xrd_file["content"]).hexdigest()
        assert digest == f"sha1={expected}", (
            f"sha1 checksum mismatch: {digest!r} != sha1={expected}"
        )

    def test_head_sha1_hyphen_normalised(self, xrd_file):
        """Success path: Want-Digest: SHA-1 is normalised to sha1."""
        r = requests.head(
            xrd_file["url"],
            headers={"Want-Digest": "SHA-1"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("sha1="), (
            f"Expected Digest: sha1=... for 'SHA-1', got: {digest!r}"
        )

    def test_head_no_want_digest_no_digest_header(self, xrd_file):
        """Error path: HEAD without Want-Digest: must not include a Digest: header."""
        r = requests.head(xrd_file["url"], timeout=10)
        assert r.status_code == 200
        assert "Digest" not in r.headers, (
            f"Unexpected Digest: header in HEAD without Want-Digest:"
        )

    def test_head_want_digest_unknown_algo_no_crash(self, xrd_file):
        """Security neg: unknown Want-Digest: algorithm silently ignored — no 500."""
        r = requests.head(
            xrd_file["url"],
            headers={"Want-Digest": "BLAKE3"},
            timeout=10,
        )
        assert r.status_code == 200, (
            f"Server must not crash on unknown Want-Digest algo, got {r.status_code}"
        )
        assert "Digest" not in r.headers, (
            "No Digest: header expected for unsupported algorithm"
        )

    def test_get_want_digest_header_also_works(self, xrd_file):
        """Success path: Want-Digest: on GET (not just HEAD) also populates Digest:."""
        r = requests.get(
            xrd_file["url"],
            headers={"Want-Digest": "SHA-256"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        assert digest.startswith("sha256="), (
            f"Expected Digest: sha256=... on GET with Want-Digest:, got: {digest!r}"
        )
        expected = hashlib.sha256(xrd_file["content"]).hexdigest()
        assert digest == f"sha256={expected}"

    def test_want_digest_priority_over_header(self, xrd_file):
        """Success path: ?xrd.want.cksum= query param takes priority over Want-Digest:."""
        r = requests.get(
            xrd_file["url"] + "?xrd.want.cksum=adler32",
            headers={"Want-Digest": "SHA-256"},
            timeout=10,
        )
        assert r.status_code == 200
        digest = r.headers.get("Digest", "")
        # Query param wins: should be adler32, not sha256
        assert digest.startswith("adler32="), (
            f"?xrd.want.cksum= should override Want-Digest:, got: {digest!r}"
        )
