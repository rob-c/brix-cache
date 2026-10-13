class TestIdentityExtraction:
    def test_dn_logged(self, pki, nginx_root_off):
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, r.stderr
        time.sleep(0.2)
        log = open(nginx_root_off["log"]).read() if os.path.exists(
            nginx_root_off["log"]) else ""
        assert "GSI auth OK" in log, "server did not log a GSI auth"
        # The log sanitizer escapes the space in "Test User" → "Test\x20User",
        # so match the stable, unescaped CN prefix instead.
        assert "CN=Test" in log, f"expected the proxy DN in the log:\n{log[-800:]}"


# --------------------------------------------------------------------------- #
# root:// — negative paths: the credential must be REFUSED
# --------------------------------------------------------------------------- #
class TestRootNegative:
    def test_no_proxy_rejected(self, pki, nginx_root_off):
        env = dict(os.environ, X509_CERT_DIR=pki["certs"],
                   X509_USER_PROXY="/nonexistent/proxy.pem")
        env.pop("BEARER_TOKEN", None)
        r = _run([STOCK_XRDFS, "--noasync", nginx_root_off["url"], "ls", "/"],
                 env=env)
        assert r.returncode != 0, "auth without a proxy must fail"

    def test_untrusted_ca_proxy_rejected(self, pki, nginx_root_off):
        assert pki["untrusted_proxy"], "untrusted proxy not provisioned"
        # Present the untrusted proxy but keep the trusted certdir so the client
        # offers gsi; the server must reject the chain (unknown CA).
        env = dict(os.environ, X509_CERT_DIR=pki["certs"],
                   X509_USER_PROXY=pki["untrusted_proxy"])
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=env)
        assert r.returncode != 0, "a proxy from an untrusted CA must be refused"

    def test_expired_proxy_rejected(self, pki, nginx_root_off):
        assert pki["expired_proxy"], "expired credential not provisioned"
        env = _env_with(pki, pki["expired_proxy"])
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=env)
        assert r.returncode != 0, "an expired credential must be refused"

    def test_wrong_server_ca_rejected(self, pki, nginx_root_off):
        # Client trusts only the untrusted CA → must reject the server host cert.
        env = dict(os.environ, X509_CERT_DIR=os.path.join(pki["base"], "ucerts"),
                   X509_USER_PROXY=pki["valid_proxy"])
        r = _run([STOCK_XRDFS, nginx_root_off["url"], "ls", "/"], env=env)
        assert r.returncode != 0, "client must reject an untrusted server cert"


# --------------------------------------------------------------------------- #
# root:// — foreign-CA host cert: the client's kXRS_issuer_hash must name the
# proxy's OWN issuing CA, never the server's advertised ca: (which is only the
# SERVER host cert's CA). Regression guard for the "certificate chain
# verification failed: chain is inconsistent" interop bug our native client hit
# against UK e-Science CA 2B grid sites (Glasgow/Lancaster) where the stock
# client authenticated with the very same proxy.
# --------------------------------------------------------------------------- #
class TestForeignCaHostCert:
    def _skip(self):
        assert os.path.exists(NATIVE_XRDFS), \
            "native client/bin/xrdfs must be built (make -C client)"

    def test_native_auth_foreign_ca_host(self, pki, stock_root_foreign_ca):
        # Success + regression guard: our native client authenticates to a STOCK
        # XrdSecgsi server whose host cert is signed by a CA distinct from our
        # proxy's CA. A client that echoes the server's advertised ca: as its
        # issuer hash makes the stock server anchor our chain on the wrong CA and
        # reject it ("chain is inconsistent") — this fails on the pre-fix client.
        self._skip()
        r = _run([NATIVE_XRDFS, "--auth", "gsi",
                  stock_root_foreign_ca["url"], "ls", "/gsidata"], env=pki["env"])
        assert r.returncode == 0, f"native→foreign-CA stock host: {r.stderr}"
        assert "/gsidata/hello.txt" in r.stdout

    def test_stock_auth_foreign_ca_host(self, pki, stock_root_foreign_ca):
        # Oracle: the stock client authenticates too, proving the foreign-CA
        # server is correctly configured (it trusts our proxy CA). So a native
        # failure here is our client's bug, not a lax/broken fixture.
        r = _run([STOCK_XRDFS, stock_root_foreign_ca["url"], "ls", "/gsidata"],
                 env=pki["env"])
        assert r.returncode == 0, f"stock→foreign-CA stock host: {r.stderr}"
        assert "/gsidata/hello.txt" in r.stdout

    def test_native_untrusted_proxy_rejected_foreign_ca(
            self, pki, stock_root_foreign_ca):
        # Security-negative: naming our own proxy CA in the issuer hash must not
        # weaken verification — a proxy from a CA the server does not trust is
        # still refused (the server anchors on its real trust store, not the hint).
        self._skip()
        env = dict(os.environ, X509_CERT_DIR=pki["certs"],
                   X509_USER_PROXY=pki["untrusted_proxy"])
        r = _run([NATIVE_XRDFS, "--auth", "gsi",
                  stock_root_foreign_ca["url"], "ls", "/gsidata"], env=env)
        assert r.returncode != 0, "a proxy from an untrusted CA must be refused"

    def test_native_no_proxy_fails_cleanly_foreign_ca(
            self, pki, stock_root_foreign_ca):
        # Error path: with no readable proxy, gsi_client_issuer_hash returns -1
        # and gsi_first falls back to the echoed server ca:. Auth must fail
        # cleanly (no crash), exercising the fallback branch.
        self._skip()
        env = dict(os.environ, X509_CERT_DIR=pki["certs"],
                   X509_USER_PROXY="/nonexistent/proxy.pem")
        env.pop("BEARER_TOKEN", None)
        r = _run([NATIVE_XRDFS, "--auth", "gsi",
                  stock_root_foreign_ca["url"], "ls", "/gsidata"], env=env)
        assert r.returncode != 0, "auth without a proxy must fail cleanly"


# --------------------------------------------------------------------------- #
# Native client ↔ real stock xrootd server (the reverse keystone, with ops)
# --------------------------------------------------------------------------- #
class TestNativeAgainstStock:
    def _skip(self):
        assert os.path.exists(NATIVE_XRDFS) and os.path.exists(NATIVE_XRDCP), \
            "native client/bin/xrd{fs,cp} must be built (make -C client)"

    def test_native_ls_stock(self, pki, stock_root):
        self._skip()
        r = _run([NATIVE_XRDFS, "--auth", "gsi", stock_root["url"],
                  "ls", "/gsidata"], env=pki["env"])
        assert r.returncode == 0, f"native→stock ls: {r.stderr}"
        assert "/gsidata/hello.txt" in r.stdout

    def test_native_read_stock(self, pki, stock_root, tmp_path):
        self._skip()
        out = str(tmp_path / "ns.txt")
        r = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                  f"{stock_root['url']}//gsidata/hello.txt", out], env=pki["env"])
        assert r.returncode == 0, f"native→stock read: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_native_write_stock(self, pki, stock_root, tmp_path):
        self._skip()
        src = str(tmp_path / "nw.bin")
        blob = _big(src, 2 * 1024 * 1024)
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{stock_root['url']}//gsidata/nw.bin"], env=pki["env"])
        assert up.returncode == 0, f"native→stock write: {up.stderr}"
        back = str(tmp_path / "nwback.bin")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{stock_root['url']}//gsidata/nw.bin", back], env=pki["env"])
        assert dl.returncode == 0, f"native→stock readback: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# https:// WebDAV — the SAME x509 proxy credential over TLS client-cert auth
# --------------------------------------------------------------------------- #
