from _test_gsi_handshake_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestRootCrossServer:
    def test_nginx_to_stock_and_back(self, pki, nginx_root_off, stock_root,
                                     tmp_path):
        src = str(tmp_path / "xfer.bin")
        blob = _big(src, 1024 * 1024)
        u = pki["env"]
        # local → our nginx
        assert _run([STOCK_XRDCP, "-f", src,
                     f"{nginx_root_off['url']}//xfer.bin"], env=u).returncode == 0
        # our nginx → stock xrootd (client-mediated copy, GSI on both ends)
        assert _run([STOCK_XRDCP, "-f", f"{nginx_root_off['url']}//xfer.bin",
                     f"{stock_root['url']}//gsidata/xfer.bin"],
                    env=u).returncode == 0
        # stock → local, verify byte-exact
        out = str(tmp_path / "xfer.back")
        assert _run([STOCK_XRDCP, "-f",
                     f"{stock_root['url']}//gsidata/xfer.bin", out],
                    env=u).returncode == 0
        assert open(out, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — further authenticated metadata ops over the GSI session
# --------------------------------------------------------------------------- #
class TestRootMoreOps:
    def test_truncate(self, pki, nginx_root_off, tmp_path):
        src = str(tmp_path / "t.bin")
        _big(src, 4096)
        u = pki["env"]
        assert _run([STOCK_XRDCP, "-f", src,
                     f"{nginx_root_off['url']}//trunc.bin"], env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root_off["url"], "truncate",
                     "/trunc.bin", "1024"], env=u).returncode == 0
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "stat", "/trunc.bin"], env=u)
        assert r.returncode == 0 and "1024" in r.stdout, \
            f"truncate did not resize: {r.stdout!r}"

    def test_cat(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "cat", "/hello.txt"],
                 env=pki["env"])
        assert r.returncode == 0 and "hello-gsi-handshake" in r.stdout


# --------------------------------------------------------------------------- #
# root:// — query opcodes over the authenticated GSI session
# --------------------------------------------------------------------------- #
class TestRootQueryOps:
    def test_query_config(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "query", "config",
                  "version"], env=pki["env"])
        # `xrdfs query config version` prints the bare version value (e.g.
        # "v5.0.0"), not "version=" — match stock's output shape (digits present).
        assert r.returncode == 0 and any(ch.isdigit() for ch in r.stdout), \
            f"query config: rc={r.returncode} {r.stdout!r} {r.stderr!r}"

    def test_locate(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "locate", "/"],
                 env=pki["env"])
        assert r.returncode == 0 and ":" in r.stdout, \
            f"locate: rc={r.returncode} {r.stdout!r} {r.stderr!r}"

    def test_stat_q_readable(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "stat", "-q", "IsReadable",
                  "/hello.txt"], env=pki["env"])
        assert r.returncode == 0, f"stat -q: {r.stderr}"


# --------------------------------------------------------------------------- #
# root:// — a spread of file sizes (0, 1, odd, block-spanning) over GSI, to
# exercise the session cipher / data plane at every boundary.
# --------------------------------------------------------------------------- #
class TestRootFileSizes:
    @pytest.mark.parametrize("size", [0, 1, 16, 17, 9973, 65537])
    def test_roundtrip(self, pki, nginx_root_off, tmp_path, size):
        src = str(tmp_path / f"sz{size}")
        blob = _big(src, size)
        key = f"/sz_{size}.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_off['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"upload size={size}: {up.stderr}"
        back = str(tmp_path / f"b{size}")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root_off['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"download size={size}: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — kXR_sigver request signing (security_level intense)
# --------------------------------------------------------------------------- #
class TestSigverEnforcement:
    """At `intense` the server requires a kXR_sigver signature (HMAC keyed by
    signing_key = SHA-256 of the GSI DH secret) on the protected opcodes.  GSI
    auth itself completes (it is pre-key), arming `signing_active`; the very next
    real op then fails with kXR_error 3010 ("request signing required") because
    the unsigned-by-default stock client does not sign — proving the enforcement
    is correctly wired to the GSI session key."""

    def test_unsigned_dirlist_refused(self, pki, nginx_root_sigver):
        # The 3010 (not an auth error) proves GSI auth succeeded first, then the
        # protected dirlist was rejected for lacking a signature.
        r = _run([STOCK_XRDFS, nginx_root_sigver["url"], "ls", "/"], env=pki["env"])
        assert r.returncode != 0 and "signing" in r.stderr.lower(), \
            f"intense must refuse the unsigned dirlist: {r.stderr}"

    def test_unsigned_read_refused(self, pki, nginx_root_sigver, tmp_path):
        out = str(tmp_path / "sv.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_sigver['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode != 0 and "signing" in r.stderr.lower(), \
            f"intense must refuse the unsigned open/read: {r.stderr}"

    def test_unsigned_write_refused(self, pki, nginx_root_sigver, tmp_path):
        src = str(tmp_path / "svu.bin")
        open(src, "w").write("should-be-refused\n")
        r = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_sigver['url']}//sv.bin"],
                 env=pki["env"])
        assert r.returncode != 0 and "signing" in r.stderr.lower(), \
            f"intense must refuse the unsigned write: {r.stderr}"


# --------------------------------------------------------------------------- #
# root:// — RSA-4096 host + proxy keys through the signed-DH handshake
# --------------------------------------------------------------------------- #
class TestRsa4096:
    def test_stock_auth_and_read(self, nginx_rsa4096, tmp_path):
        r = _run([STOCK_XRDFS, nginx_rsa4096["url"], "ls", "/"],
                 env=nginx_rsa4096["env"])
        assert r.returncode == 0, f"rsa4096 ls: {r.stderr}"
        assert "/hello.txt" in r.stdout
        out = str(tmp_path / "r4.txt")
        rc = _run([STOCK_XRDCP, "-f", f"{nginx_rsa4096['url']}//hello.txt", out],
                  env=nginx_rsa4096["env"])
        assert rc.returncode == 0, f"rsa4096 read: {rc.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_native_auth(self, nginx_rsa4096):
        if not os.path.exists(NATIVE_XRDFS):
            assert False, "native client must be built"
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_rsa4096["url"], "ls", "/"],
                 env=nginx_rsa4096["env"])
        assert r.returncode == 0, f"rsa4096 native ls: {r.stderr}"
        assert "/hello.txt" in r.stdout


# --------------------------------------------------------------------------- #
# root:// — VOMS attribute extraction + VO ACL enforcement
# --------------------------------------------------------------------------- #
# serial + generous timeout: drives a self-started GSI `nginx_voms` server through
# full VOMS-AC handshakes (crypto-heavy).  The flake under the parallel pool is a
# *timeout*, not a port/state collision — the VOMS handshake just runs slow when
# the box is CPU-saturated — so the fix is headroom over the 30s pytest.ini
# default, not de-serialisation.  `serial` keeps it off the saturated pool;
# timeout(180) absorbs the residual crypto cost if it does land under load.
@pytest.mark.serial
@pytest.mark.timeout(180)
class TestVomsExtraction:
    """The server parses the VOMS attribute certificate, extracts the VO, and
    enforces `require_vo`: a proxy carrying `testvo` reaches the VO-gated path
    while the plain (no-VO) proxy is refused — proving the VO was extracted."""

    def test_voms_proxy_allowed_on_vo_path(self, voms, nginx_voms):
        r = _run([STOCK_XRDFS, nginx_voms["url"], "ls", "/vodata"],
                 env=voms["env"])
        assert r.returncode == 0, f"VOMS proxy denied its own VO path: {r.stderr}"
        assert "secret.txt" in r.stdout

    def test_voms_proxy_can_read_vo_file(self, voms, nginx_voms, tmp_path):
        out = str(tmp_path / "vo.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_voms['url']}//vodata/secret.txt",
                  out], env=voms["env"])
        assert r.returncode == 0, f"VOMS proxy read denied: {r.stderr}"
        assert open(out).read() == "vo-only\n"

    def test_plain_proxy_denied_on_vo_path(self, pki, voms, nginx_voms):
        # Same identity/CA, but NO VO attribute → must be refused on /vodata.
        r = _run([STOCK_XRDFS, nginx_voms["url"], "ls", "/vodata"],
                 env=pki["env"])
        assert r.returncode != 0, \
            "a proxy without the required VO must be refused on /vodata"

    def test_native_voms_proxy_allowed(self, voms, nginx_voms):
        if not os.path.exists(NATIVE_XRDFS):
            assert False, "native client must be built"
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_voms["url"],
                  "ls", "/vodata"], env=voms["env"])
        assert r.returncode == 0, f"native VOMS proxy denied: {r.stderr}"
        assert "secret.txt" in r.stdout


# --------------------------------------------------------------------------- #
# root:// — xrootd_auth both: the GSI client picks gsi from a ztn+gsi offer
# --------------------------------------------------------------------------- #
class TestBothAuthMode:
    def test_gsi_client_authenticates(self, pki, nginx_root_both):
        r = _run([STOCK_XRDFS, nginx_root_both["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"both-mode GSI ls: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_advertises_both_protocols(self, pki, nginx_root_both):
        s, body = _wire_login("127.0.0.1",
                              int(nginx_root_both["url"].rsplit(":", 1)[1]))
        s.close()
        assert b"&P=ztn" in body and b"&P=gsi" in body, \
            f"both mode must advertise ztn and gsi: {body!r}"

    def test_native_client_authenticates(self, pki, nginx_root_both):
        if not os.path.exists(NATIVE_XRDFS):
            assert False, "native client must be built"
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root_both["url"],
                  "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"both-mode native GSI ls: {r.stderr}"
        assert "/hello.txt" in r.stdout


# --------------------------------------------------------------------------- #
# Wire-level — drive the handshake by hand and inspect each stage's bytes.
# --------------------------------------------------------------------------- #
class TestWireHandshake:
    EXPECT_VER = {"off": b"v:10000", "auto": b"v:10600", "require": b"v:10600"}

    @staticmethod
    def _port(url):
        return int(url.rsplit(":", 1)[1])

    def test_login_advertises_gsi(self, pki, nginx_root):
        """The kXR_login response carries the `&P=gsi,v:…,c:ssl,ca:…` block, and
        the advertised version matches the signed-DH policy — read straight off
        the wire, no client library."""
        s, body = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        s.close()
        assert b"&P=gsi" in body, f"login did not advertise gsi: {body!r}"
        assert b"c:ssl" in body and b"ca:" in body, \
            f"gsi advertisement missing crypto/CA hint: {body!r}"
        assert self.EXPECT_VER[nginx_root["policy"]] in body, \
            f"{nginx_root['policy']}: wrong advertised version in {body!r}"

    def test_certreq_response_buckets(self, pki, nginx_root):
        """A real certreq elicits kXGS_cert; assert the response carries the
        server cert, a cipher list with aes-128-cbc first, and the right
        DH-public bucket for the policy (kXRS_puk unsigned vs kXRS_cipher signed)."""
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        status, bk = _send_certreq(s, 10600)
        s.close()
        assert status == kXR_authmore, \
            f"certreq → status {status}, expected kXR_authmore"
        assert kXRS_x509 in bk, "kXGS_cert missing the server cert (kXRS_x509)"
        assert kXRS_cipher_alg in bk, "kXGS_cert missing kXRS_cipher_alg"
        assert bk[kXRS_cipher_alg].startswith(b"aes-128-cbc"), \
            f"cipher list must offer aes-128-cbc first: {bk[kXRS_cipher_alg]!r}"
        if nginx_root["policy"] == "off":
            assert kXRS_puk in bk and kXRS_cipher not in bk, \
                "unsigned policy must send a bare kXRS_puk"
        else:
            assert kXRS_cipher in bk and kXRS_puk not in bk, \
                "signed policy must send an RSA-signed kXRS_cipher"

    def test_old_client_version_negotiation(self, pki, nginx_root):
        """A pre-DHsigned (v10300) certreq: off & auto fall back to unsigned;
        require always signs — proving the per-client version gate works."""
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        _status, bk = _send_certreq(s, 10300)
        s.close()
        if nginx_root["policy"] == "require":
            assert kXRS_cipher in bk and kXRS_puk not in bk, \
                "require signs even a <10400 client"
        else:
            assert kXRS_puk in bk and kXRS_cipher not in bk, \
                f"{nginx_root['policy']}: a <10400 client must get unsigned DH"

    def test_certreq_advertises_digest(self, pki, nginx_root):
        """kXGS_cert offers a digest list including sha256."""
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        _status, bk = _send_certreq(s, 10600)
        s.close()
        assert kXRS_md_alg in bk and b"sha256" in bk[kXRS_md_alg], \
            f"kXGS_cert should offer a sha256 digest: {bk.get(kXRS_md_alg)!r}"

    def test_login_advertises_8hex_ca_hash(self, pki, nginx_root):
        """The gsi advertisement carries the server CA subject hash as 8 hex."""
        s, body = _wire_login("127.0.0.1", self._port(nginx_root["url"]))
        s.close()
        assert re.search(rb"ca:[0-9a-fA-F]{8}", body), \
            f"login must advertise an 8-hex CA hash: {body!r}"


# --------------------------------------------------------------------------- #
# GSI session-cipher negotiation (WS-A): client must negotiate a non-default cipher
# --------------------------------------------------------------------------- #
class TestCipherNegotiation:
    def test_native_negotiates_aes256(self, pki, nginx_root_aes256, tmp_path):
        """Our client authenticates to a server that offers ONLY aes-256-cbc —
        proving the session-cipher negotiation actually keys the negotiated
        cipher, not the hard-wired aes-128-cbc default."""
        out = str(tmp_path / "neg.txt")
        r = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                  f"{nginx_root_aes256['url']}//hello.txt", out], env=pki["env"])
        assert r.returncode == 0, f"aes-256 negotiation failed: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_aes256_server_advertises_only_aes256(self, pki, nginx_root_aes256):
        """The kXGS_cert cipher_alg list offers aes-256-cbc and NOT aes-128-cbc,
        so the handshake above cannot fall back to the default."""
        del pki
        s, _ = _wire_login("127.0.0.1", self._port(nginx_root_aes256["url"]))
        status, bk = _send_certreq(s, 10600)
        s.close()
        assert status == kXR_authmore, f"certreq → {status}, want kXR_authmore"
        assert kXRS_cipher_alg in bk, "kXGS_cert missing kXRS_cipher_alg"
        offered = bk[kXRS_cipher_alg]
        assert offered.startswith(b"aes-256-cbc"), \
            f"server must advertise aes-256-cbc: {offered!r}"
        assert b"aes-128-cbc" not in offered, \
            f"aes-256-only server must NOT offer aes-128-cbc: {offered!r}"

    @staticmethod
    def _port(url):
        return int(url.rsplit(":", 1)[1])


# --------------------------------------------------------------------------- #
# S3: GSI is not applicable.  Documented here so the omission is intentional.
# --------------------------------------------------------------------------- #
def test_s3_uses_sigv4_not_gsi():
    """Guard the design invariant: S3 (ours and official XrdS3) authenticates
    with AWS SigV4, never GSI — so there is deliberately no S3 GSI test."""
    handler = os.path.join(REPO, "src", "protocols", "s3", "handler.c")
    assert os.path.exists(handler), "src/protocols/s3/handler.c not present"
    text = open(handler).read().lower()
    assert "sigv4" in text, "S3 handler should authenticate via SigV4"
