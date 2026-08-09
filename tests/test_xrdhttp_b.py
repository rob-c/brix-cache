from split_continuation import reexport as _reexport
_reexport(globals(), "_test_xrdhttp_helpers")

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
