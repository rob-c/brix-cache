from split_continuation import reexport as _reexport
_reexport(globals(), "_test_gsi_handshake_helpers")

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
