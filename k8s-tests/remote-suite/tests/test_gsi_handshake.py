from _test_gsi_handshake_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestRootStockClient:
    def test_ls(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "ls", "/"], env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_stat(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "stat", "/hello.txt"],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "Size" in r.stdout or "size" in r.stdout.lower()

    def test_read(self, pki, nginx_root, tmp_path):
        out = str(tmp_path / f"dl_{nginx_root['policy']}")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_write_then_read(self, pki, nginx_root, tmp_path):
        src = str(tmp_path / "up.txt")
        payload = f"signed={nginx_root['policy']}-roundtrip\n" * 8
        open(src, "w").write(payload)
        key = f"/up_stock_{nginx_root['policy']}.txt"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "back.txt")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"download {nginx_root['policy']}: {dl.stderr}"
        assert open(back).read() == payload

    def test_large_write_then_read(self, pki, nginx_root, tmp_path):
        # 5 MiB: the session cipher must hold over thousands of AES-CBC blocks
        # in BOTH directions, not just the tiny single-block proxy-chain main.
        src = str(tmp_path / "big.bin")
        blob = _big(src, 5 * 1024 * 1024)
        key = f"/big_stock_{nginx_root['policy']}.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"big upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "bigback.bin")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"big download: {dl.stderr}"
        assert open(back, "rb").read() == blob

    def test_mkdir_stat_rmdir(self, pki, nginx_root):
        d = f"/dir_stock_{nginx_root['policy']}"
        u = pki["env"]
        assert _run([STOCK_XRDFS, nginx_root["url"], "mkdir", d],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", d],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "rmdir", d],
                    env=u).returncode == 0
        # gone now
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", d],
                    env=u).returncode != 0

    def test_mv_then_rm(self, pki, nginx_root, tmp_path):
        src = str(tmp_path / "mv.txt")
        open(src, "w").write("mv-payload\n")
        a = f"/mv_a_{nginx_root['policy']}.txt"
        b = f"/mv_b_{nginx_root['policy']}.txt"
        u = pki["env"]
        assert _run([STOCK_XRDCP, "-f", src, f"{nginx_root['url']}/{a}"],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "mv", a, b],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", b],
                    env=u).returncode == 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "stat", a],
                    env=u).returncode != 0
        assert _run([STOCK_XRDFS, nginx_root["url"], "rm", b],
                    env=u).returncode == 0

    def test_query_checksum(self, pki, nginx_root):
        r = _run([STOCK_XRDFS, nginx_root["url"], "query", "checksum",
                  "/hello.txt"], env=pki["env"])
        assert r.returncode == 0, f"query checksum: {r.stderr}"
        # the response is "<algo> <hexdigest>"
        assert len(r.stdout.split()) >= 2, f"unexpected checksum reply: {r.stdout!r}"


class TestRootNativeClient:
    def _skip_if_unbuilt(self):
        assert os.path.exists(NATIVE_XRDFS) and os.path.exists(NATIVE_XRDCP), \
            "native client/bin/xrd{fs,cp} must be built (make -C client)"

    def test_ls(self, pki, nginx_root):
        self._skip_if_unbuilt()
        r = _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"], "ls", "/"],
                 env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert "/hello.txt" in r.stdout

    def test_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        out = str(tmp_path / f"ndl_{nginx_root['policy']}")
        r = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                  f"{nginx_root['url']}//hello.txt", out], env=pki["env"])
        assert r.returncode == 0, f"{nginx_root['policy']}: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_write_then_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        src = str(tmp_path / "nup.txt")
        payload = f"native={nginx_root['policy']}-roundtrip\n" * 8
        open(src, "w").write(payload)
        key = f"/up_native_{nginx_root['policy']}.txt"
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{nginx_root['url']}/{key}"], env=pki["env"])
        assert up.returncode == 0, f"upload {nginx_root['policy']}: {up.stderr}"
        back = str(tmp_path / "nback.txt")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{nginx_root['url']}/{key}", back], env=pki["env"])
        assert dl.returncode == 0, f"download {nginx_root['policy']}: {dl.stderr}"
        assert open(back).read() == payload

    def test_large_write_then_read(self, pki, nginx_root, tmp_path):
        self._skip_if_unbuilt()
        src = str(tmp_path / "nbig.bin")
        blob = _big(src, 5 * 1024 * 1024)
        key = f"/nbig_{nginx_root['policy']}.bin"
        up = _run([NATIVE_XRDCP, "--auth", "gsi", "-f", src,
                   f"{nginx_root['url']}/{key}"], env=pki["env"])
        assert up.returncode == 0, f"native big upload: {up.stderr}"
        back = str(tmp_path / "nbigback.bin")
        dl = _run([NATIVE_XRDCP, "--auth", "gsi", "-f",
                   f"{nginx_root['url']}/{key}", back], env=pki["env"])
        assert dl.returncode == 0, f"native big download: {dl.stderr}"
        assert open(back, "rb").read() == blob

    def test_mkdir_rmdir(self, pki, nginx_root):
        self._skip_if_unbuilt()
        d = f"/ndir_{nginx_root['policy']}"
        u = pki["env"]
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "mkdir", d], env=u).returncode == 0
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "stat", d], env=u).returncode == 0
        assert _run([NATIVE_XRDFS, "--auth", "gsi", nginx_root["url"],
                     "rmdir", d], env=u).returncode == 0


# --------------------------------------------------------------------------- #
# root:// — GSI authentication followed by an in-protocol TLS upgrade (roots://)
# --------------------------------------------------------------------------- #
class TestRootGsiTls:
    def test_stock_read_over_tls(self, pki, nginx_root_tls, tmp_path):
        out = str(tmp_path / "tls.txt")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_tls['url']}//hello.txt", out],
                 env=pki["env"])
        assert r.returncode == 0, f"GSI+TLS read: {r.stderr}"
        assert open(out).read() == "hello-gsi-handshake\n"

    def test_stock_write_then_read_over_tls(self, pki, nginx_root_tls, tmp_path):
        src = str(tmp_path / "tlsup.bin")
        blob = _big(src, 2 * 1024 * 1024)
        key = "/tls_rt.bin"
        up = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_tls['url']}/{key}"],
                  env=pki["env"])
        assert up.returncode == 0, f"GSI+TLS upload: {up.stderr}"
        back = str(tmp_path / "tlsback.bin")
        dl = _run([STOCK_XRDCP, "-f", f"{nginx_root_tls['url']}/{key}", back],
                  env=pki["env"])
        assert dl.returncode == 0, f"GSI+TLS download: {dl.stderr}"
        assert open(back, "rb").read() == blob


# --------------------------------------------------------------------------- #
# root:// — concurrent GSI handshakes (the ephemeral-DH keypool under load)
# --------------------------------------------------------------------------- #
class TestRootConcurrency:
    def test_many_concurrent_signed_handshakes(self, pki, nginx_root):
        # Fire N independent stat handshakes at once; the per-worker DH keypool
        # must answer every certreq without head-of-line blocking, for signed and
        # unsigned alike.
        import concurrent.futures as cf

        def one(_):
            return _run([STOCK_XRDFS, nginx_root["url"], "stat", "/hello.txt"],
                        env=pki["env"]).returncode

        with cf.ThreadPoolExecutor(max_workers=12) as ex:
            rcs = list(ex.map(one, range(12)))
        assert all(rc == 0 for rc in rcs), \
            f"{nginx_root['policy']}: concurrent handshakes failed: {rcs}"


# --------------------------------------------------------------------------- #
# root:// — protocol-version advertisement (the signed-vs-unsigned switch)
# --------------------------------------------------------------------------- #
class TestVersionAdvertisement:
    # off → unsigned v:10000; auto/require → signed-capable v:10600.
    EXPECT = {"off": "v:10000", "auto": "v:10600", "require": "v:10600"}

    def test_advertised_version_matches_policy(self, pki, nginx_root):
        env = dict(pki["env"], XrdSecDEBUG="3")
        r = _run([STOCK_XRDFS, nginx_root["url"], "ls", "/"], env=env)
        m = re.search(r"token='([^']*P=gsi[^']*)'", r.stdout + r.stderr)
        assert m, ("could not capture the advertised &P=gsi token from the "
                   f"stock client debug output:\n{(r.stdout + r.stderr)[:400]}")
        want = self.EXPECT[nginx_root["policy"]]
        assert want in m.group(1), \
            f"policy {nginx_root['policy']}: expected {want}, got {m.group(1)!r}"


# --------------------------------------------------------------------------- #
# root:// — identity (DN) extraction from the verified proxy chain
# --------------------------------------------------------------------------- #
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
def _rejected(http_code):
    """A WebDAV auth rejection is any non-2xx outcome — the request was refused
    by the TLS/cert layer (400), the access phase (401/403), or curl failed the
    handshake outright (000).  The only failure that matters is being *served*."""
    code = (http_code or "").strip()
    return bool(code) and not code.startswith("2")


def _curl(pki, webdav, proxy, *args, method=None, upload=None):
    cf, kf = _split_for_curl(proxy, pki["base"], "wc") if proxy else (None, None)
    cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}"]
    if cf and kf:
        cmd += ["--cert", cf, "--key", kf]
    if method:
        cmd += ["-X", method]
    if upload:
        cmd += ["-T", upload]
    cmd += list(args)
    return _run(cmd)


class TestHttpsProxyCert:
    def test_propfind_with_proxy(self, pki, nginx_webdav):
        r = _curl(pki, nginx_webdav, pki["valid_proxy"], nginx_webdav["url"] + "/",
                  method="PROPFIND")
        assert r.stdout.strip() in ("200", "207"), f"PROPFIND → {r.stdout}"

    def test_get_with_proxy(self, pki, nginx_webdav, tmp_path):
        out = str(tmp_path / "wget.txt")
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wg")
        assert cf, "could not split the proxy into cert/key for curl"
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
                  nginx_webdav["url"] + "/hello.txt"])
        assert r.returncode == 0 and open(out).read() == "hello-webdav-gsi\n", \
            f"GET body mismatch: {open(out).read()!r}"

    def test_put_then_get_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wp")
        assert cf, "could not split the proxy into cert/key for curl"
        src = str(tmp_path / "wput.txt")
        payload = "webdav-proxy-roundtrip\n" * 4
        open(src, "w").write(payload)
        put = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", "-T", src,
                    nginx_webdav["url"] + "/put.txt"])
        assert put.stdout.strip() in ("200", "201", "204"), f"PUT → {put.stdout}"
        out = str(tmp_path / "wback.txt")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
              nginx_webdav["url"] + "/put.txt"])
        assert open(out).read() == payload

    def test_head_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wh")
        r = _run(["curl", "-sk", "-I", "--cert", cf, "--key", kf, "-o",
                  "/dev/null", "-w", "%{http_code}",
                  nginx_webdav["url"] + "/hello.txt"])
        assert r.stdout.strip() == "200", f"HEAD → {r.stdout}"

    def test_propfind_depth1_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wd1")
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-X", "PROPFIND",
                  "-H", "Depth: 1", nginx_webdav["url"] + "/"])
        assert "hello.txt" in r.stdout, \
            f"Depth:1 PROPFIND should list children:\n{r.stdout[:300]}"

    def test_mkcol_then_propfind(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wmk")
        col = nginx_webdav["url"] + "/coll/"
        mk = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "MKCOL", col])
        assert mk.stdout.strip() in ("201", "200"), f"MKCOL → {mk.stdout}"
        pf = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "PROPFIND", col])
        assert pf.stdout.strip() in ("200", "207"), f"PROPFIND coll → {pf.stdout}"

    def test_put_delete_then_absent(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wdel")
        src = str(tmp_path / "del.txt")
        open(src, "w").write("to-be-deleted\n")
        url = nginx_webdav["url"] + "/todelete.txt"
        put = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", "-T", src, url])
        assert put.stdout.strip() in ("200", "201", "204"), f"PUT → {put.stdout}"
        dl = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "DELETE", url])
        assert dl.stdout.strip() in ("200", "204"), f"DELETE → {dl.stdout}"
        get = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", url])
        assert get.stdout.strip() == "404", f"deleted file should 404, got {get.stdout}"

    def test_range_get_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wr")
        # hello.txt = "hello-webdav-gsi\n"; bytes 0-4 → "hello"
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-r", "0-4",
                  nginx_webdav["url"] + "/hello.txt"])
        assert r.stdout == "hello", f"range GET → {r.stdout!r}"

    def test_large_put_get_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wl")
        src = str(tmp_path / "wbig.bin")
        blob = _big(src, 4 * 1024 * 1024)
        url = nginx_webdav["url"] + "/wbig.bin"
        put = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                    "-w", "%{http_code}", "-T", src, url])
        assert put.stdout.strip() in ("200", "201", "204"), f"big PUT → {put.stdout}"
        out = str(tmp_path / "wbigback.bin")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out, url])
        assert open(out, "rb").read() == blob

    def test_options_with_proxy(self, pki, nginx_webdav):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wo")
        r = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                  "-w", "%{http_code}", "-X", "OPTIONS", nginx_webdav["url"] + "/"])
        assert r.stdout.strip() in ("200", "204"), f"OPTIONS → {r.stdout}"

    def test_copy_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wcp")
        base = nginx_webdav["url"]
        src = str(tmp_path / "c.txt")
        open(src, "w").write("copy-src\n")
        assert _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                     "-w", "%{http_code}", "-T", src, base + "/csrc.txt"]
                    ).stdout.strip() in ("200", "201", "204")
        cp = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "COPY",
                   "-H", f"Destination: {base}/cdst.txt", base + "/csrc.txt"])
        assert cp.stdout.strip() in ("200", "201", "204"), f"COPY → {cp.stdout}"
        out = str(tmp_path / "c.out")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
              base + "/cdst.txt"])
        assert open(out).read() == "copy-src\n"

    def test_move_with_proxy(self, pki, nginx_webdav, tmp_path):
        cf, kf = _split_for_curl(pki["valid_proxy"], pki["base"], "wmv")
        base = nginx_webdav["url"]
        src = str(tmp_path / "m.txt")
        open(src, "w").write("move-src\n")
        assert _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                     "-w", "%{http_code}", "-T", src, base + "/msrc.txt"]
                    ).stdout.strip() in ("200", "201", "204")
        mv = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                   "-w", "%{http_code}", "-X", "MOVE",
                   "-H", f"Destination: {base}/mdst.txt", base + "/msrc.txt"])
        assert mv.stdout.strip() in ("200", "201", "204"), f"MOVE → {mv.stdout}"
        gone = _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", "/dev/null",
                     "-w", "%{http_code}", base + "/msrc.txt"])
        assert gone.stdout.strip() == "404", f"moved source should 404: {gone.stdout}"
        out = str(tmp_path / "m.out")
        _run(["curl", "-sk", "--cert", cf, "--key", kf, "-o", out,
              base + "/mdst.txt"])
        assert open(out).read() == "move-src\n"

    def test_concurrent_proxy_requests(self, pki, nginx_webdav):
        import concurrent.futures as cf
        cfp, kfp = _split_for_curl(pki["valid_proxy"], pki["base"], "wcc")

        def one(_):
            return _run(["curl", "-sk", "--cert", cfp, "--key", kfp, "-o",
                         "/dev/null", "-w", "%{http_code}", "-X", "PROPFIND",
                         nginx_webdav["url"] + "/"]).stdout.strip()

        with cf.ThreadPoolExecutor(max_workers=10) as ex:
            codes = list(ex.map(one, range(10)))
        assert all(c in ("200", "207") for c in codes), \
            f"concurrent proxy-cert PROPFINDs: {codes}"

    def test_no_client_cert_rejected(self, pki, nginx_webdav):
        r = _curl(pki, nginx_webdav, None, nginx_webdav["url"] + "/",
                  method="PROPFIND")
        assert _rejected(r.stdout), f"no-cert request must be refused, got {r.stdout}"

    def test_untrusted_proxy_rejected(self, pki, nginx_webdav):
        assert pki["untrusted_proxy"], "untrusted proxy not provisioned"
        r = _curl(pki, nginx_webdav, pki["untrusted_proxy"],
                  nginx_webdav["url"] + "/", method="PROPFIND")
        assert _rejected(r.stdout), \
            f"untrusted-CA proxy must be refused, got {r.stdout}"

    def test_expired_proxy_rejected(self, pki, nginx_webdav):
        assert pki["expired_proxy"], "expired credential not provisioned"
        r = _curl(pki, nginx_webdav, pki["expired_proxy"],
                  nginx_webdav["url"] + "/", method="PROPFIND")
        assert _rejected(r.stdout), \
            f"expired credential must be refused, got {r.stdout}"


# --------------------------------------------------------------------------- #
# root:// — GSI auth ENFORCEMENT (the server must refuse unauthenticated I/O)
# --------------------------------------------------------------------------- #
class TestRootAuthEnforcement:
    def _anon_env(self):
        env = dict(os.environ)
        env["X509_USER_PROXY"] = "/nonexistent/proxy.pem"
        env.pop("BEARER_TOKEN", None)
        return env

    def test_anon_read_refused(self, pki, nginx_root_off, tmp_path):
        out = str(tmp_path / "anon.bin")
        r = _run([STOCK_XRDCP, "-f", f"{nginx_root_off['url']}//hello.txt", out],
                 env=self._anon_env())
        assert r.returncode != 0, "unauthenticated read must be refused"

    def test_anon_write_refused(self, pki, nginx_root_off, tmp_path):
        src = str(tmp_path / "anon_up.txt")
        open(src, "w").write("should-not-land\n")
        r = _run([STOCK_XRDCP, "-f", src, f"{nginx_root_off['url']}//anon_up.txt"],
                 env=self._anon_env())
        assert r.returncode != 0, "unauthenticated write must be refused"


# --------------------------------------------------------------------------- #
# root:// — cross-server transfer (our nginx ↔ a real stock xrootd), GSI both
# ends.  The self-contained equivalent of the bridge suite.
# --------------------------------------------------------------------------- #
