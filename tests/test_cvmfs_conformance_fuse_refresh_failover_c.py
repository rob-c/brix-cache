from split_continuation import reexport as _reexport
def _check_scn_1(mnt):
    assert os.path.ismount(mnt), "mount failed"

def _check_scn_2(mnt):
    assert os.path.ismount(mnt), "mount failed"

def _check_scn_3(mnt):
    assert os.path.ismount(mnt), "mount failed"

def _check_scn_4(mnt):
    assert os.path.ismount(mnt), "mount failed"


_reexport(globals(), "_test_cvmfs_conformance_fuse_refresh_failover_helpers")

@pytest.mark.timeout(150)
class TestRangeResume:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        rnd = Random(85)
        big = rnd.randbytes(256 * 1024)
        blind_big = rnd.randbytes(128 * 1024)
        small = rnd.randbytes(4096)
        tmp = tmp_path_factory.mktemp("resume")
        forge, web, pub = _forge(
            tmp, tree={"big.bin": File(big), "blind.bin": File(blind_big),
                       "small.bin": File(small)})
        origin = LocalOrigin(P_RESUME, web).start()
        obs = {"big": big, "blind_big": blind_big, "small": small}
        try:
            # -- honouring origin, 64KiB sever per response --------------------
            with conf_mount(REPO, pub, server_env=_url(P_RESUME), retries=1) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                origin.reset_counters()
                origin.sever_after = 64 * 1024
                obs["got_big"] = (mnt / "big.bin").read_bytes()
                origin.sever_after = 0
            obs["big_reqs"] = origin.requests(cas_needle(big))
            obs["big_stored_len"] = len(zlib.compress(big))
            origin.stop()

            # -- Range-blind origin: one sever, resume answered 200-full -------
            blind = LocalOrigin(P_BLIND, web)
            blind.ignore_range = True
            blind.start()
            try:
                with conf_mount(REPO, pub, server_env=_url(P_BLIND), retries=2) as (mnt, _):
                    assert os.path.ismount(mnt), "mount failed"
                    blind.reset_counters()
                    blind.set_fault("sever_half", 1, path_re=cas_needle(blind_big))
                    try:
                        obs["got_blind"] = (mnt / "blind.bin").read_bytes()
                        obs["blind_errno"] = 0
                    except OSError as e:
                        obs["got_blind"] = None
                        obs["blind_errno"] = e.errno
                    obs["blind_reqs"] = blind.requests(cas_needle(blind_big))
                    blind.clear_faults()
                    time.sleep(2.5)                      # failure blacklist lapses

                    # persistent sever + Range-blind: can never progress past the
                    # sever point → must end in a clean error, never bad bytes
                    blind.sever_after = 1024
                    try:
                        (mnt / "small.bin").read_bytes()
                        obs["stuck_exc"] = None
                    except OSError as e:
                        obs["stuck_exc"] = e.errno
                    blind.sever_after = 0
                    time.sleep(2.5)                      # blacklist lapses
                    obs["small_after"] = (mnt / "small.bin").read_bytes()
            finally:
                blind.stop()
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_severed_transfer_delivers_byte_exact_result(self, scn):
        assert scn["got_big"] == scn["big"]

    def test_client_actually_resumed(self, scn):
        assert len(scn["big_reqs"]) >= 3

    def test_first_request_has_no_range_header(self, scn):
        assert scn["big_reqs"][0]["range"] is None

    def test_resume_requests_carry_range_from_delivered_offset(self, scn):
        offs = [int(r["range"][len("bytes="):].rstrip("-"))
                for r in scn["big_reqs"][1:]]
        step = 64 * 1024
        assert offs == list(range(step, scn["big_stored_len"], step))

    def test_range_blind_origin_still_byte_exact(self, scn):
        # RETIRED DIVERGENCE (D6): CURLE_RANGE_ERROR on a resume attempt now
        # discards the partial prefix and restarts the object from byte 0
        # (brixcvmfs_transport), matching official CVMFS's prompt full restart
        # against Range-blind origins — byte-exact, no stall-out.
        assert scn["got_blind"] == scn["blind_big"]

    def test_range_blind_resume_request_was_sent(self, scn):
        # the client did attempt Range-resume after the sever (first request
        # plain, followed by bytes=<offset>- retries) — observable regardless
        # of the D6 outcome.  Later from-scratch retries (range None) may
        # follow once the resume attempts stall out.
        ranges = [r["range"] for r in scn["blind_reqs"]]
        assert (len(ranges) >= 2 and ranges[0] is None
                and any(r and r.startswith("bytes=") for r in ranges[1:]))

    def test_range_blind_never_wrong_bytes(self, scn):
        # holds in both worlds: byte-exact success or a clean error, never a
        # corrupted/short object served as good.
        import errno
        assert scn["got_blind"] == scn["blind_big"] or scn["blind_errno"] == errno.EIO

    def test_range_blind_persistent_sever_fails_cleanly(self, scn):
        import errno
        assert scn["stuck_exc"] == errno.EIO

    def test_range_blind_recovers_once_sever_lifted(self, scn):
        assert scn["small_after"] == scn["small"]


# ============================================================================
# Redirect / scheme confinement — a poisoned mirror or DPI middlebox answers a
# CAS fetch with a 3xx.  The client confines redirects to HTTP(S) (never a
# local file:// or an internal-service scheme), bounds the chain length so a
# redirect loop can't wedge the mount, yet still follows a legitimate HTTP
# mirror redirect.  Guards CURLOPT_{PROTOCOLS,REDIR_PROTOCOLS,MAXREDIRS}.
# ============================================================================

@pytest.mark.timeout(120)
class TestRedirectConfinement:
    SECRET = b"redirect-confinement-probe-payload\n"

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("redir")
        forge, web, pub = _forge(tmp, tree={"secret.bin": File(self.SECRET)})
        needle = cas_needle(self.SECRET)

        # A LOCAL file holding the CORRECT stored (zlib) object bytes.  If the
        # client ever followed a file:// redirect, libcurl would read this, the
        # CAS hash would MATCH, and the read would succeed — so a *failed* read
        # here can only mean the file:// scheme was refused up front.  This is
        # what makes the test prove confinement rather than the hash backstop.
        bait = tmp / "bait.cas"
        bait.write_bytes(zlib.compress(self.SECRET))

        origin = LocalOrigin(P_REDIR, web).start()
        mirror = LocalOrigin(P_REDIR_MIRROR, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_REDIR), retries=1) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"

                # -- security-neg: object fetch redirected to file:// ----------
                origin.set_fault(f"redirect:file://{bait}", 99, path_re=needle)
                t0 = time.monotonic()
                try:
                    (mnt / "secret.bin").read_bytes()
                    obs["file_errno"] = 0
                except OSError as e:
                    obs["file_errno"] = e.errno
                obs["file_secs"] = time.monotonic() - t0
                origin.clear_faults()
                time.sleep(2.5)                       # failed-route blacklist lapses

                # -- bound: self-referential redirect loop ---------------------
                # Location keeps the needle in the path, so every follow re-fires
                # the fault → an unbounded loop unless MAXREDIRS caps it.
                origin.set_fault(f"redirect:/cvmfs/{REPO}/data/{needle}", 999,
                                 path_re=needle)
                t0 = time.monotonic()
                try:
                    (mnt / "secret.bin").read_bytes()
                    obs["loop_errno"] = 0
                except OSError as e:
                    obs["loop_errno"] = e.errno
                obs["loop_secs"] = time.monotonic() - t0
                origin.clear_faults()

            # -- success: legitimate http->http mirror redirect ---------------
            # Fresh mount: the abuse cases above blacklisted the primary route,
            # which would otherwise mask the redirect under a failover error.
            with conf_mount(REPO, pub, server_env=_url(P_REDIR), retries=1) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                origin.set_fault(f"redirect_host:{HOST}:{P_REDIR_MIRROR}", 1,
                                 path_re=needle)
                try:
                    obs["mirror_bytes"] = (mnt / "secret.bin").read_bytes()
                    obs["mirror_errno"] = 0
                except OSError as e:
                    obs["mirror_bytes"] = None
                    obs["mirror_errno"] = e.errno
                obs["mirror_hits"] = mirror.requests(needle)
                origin.clear_faults()
            yield obs
        finally:
            origin.stop()
            mirror.stop()
            forge.close()

    def test_file_scheme_redirect_refused(self, scn):
        # bait file has valid content, so a followed file:// would SUCCEED —
        # the read must instead fail, proving the scheme was blocked.
        import errno
        assert scn["file_errno"] == errno.EIO

    def test_file_scheme_redirect_fails_promptly(self, scn):
        # confinement rejects at the redirect, so no wait on a local read either
        assert scn["file_secs"] < 30

    def test_redirect_loop_bounded_not_hung(self, scn):
        import errno
        assert scn["loop_errno"] == errno.EIO
        assert scn["loop_secs"] < 30          # MAXREDIRS cap, not a wedge

    def test_legitimate_http_mirror_redirect_followed(self, scn):
        # http->http cross-host redirect is allowed; the mirror served it and
        # the bytes are exact — confinement did not over-block real redirects.
        assert scn["mirror_errno"] == 0
        assert scn["mirror_bytes"] == self.SECRET
        assert len(scn["mirror_hits"]) >= 1


# ============================================================================
# Proxy precedence — env http_proxy beats CVMFS_HTTP_PROXY beats DIRECT.
# ============================================================================


@pytest.mark.timeout(120)
class TestProxyPrecedence:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("proxy")
        forge, web, pub = _forge(tmp)
        origin = LocalOrigin(P_PROXY_ORIGIN, web).start()
        procs = []
        obs = {}
        try:
            log_a = tmp / "proxy_a.log"
            log_b = tmp / "proxy_b.log"
            _spawn_proxy(procs, P_PROXY_A, log_a)
            _spawn_proxy(procs, P_PROXY_B, log_b)
            purl_a = f"http://{HOST}:{P_PROXY_A}"
            purl_b = f"http://{HOST}:{P_PROXY_B}"

            # env http_proxy → all traffic through proxy A
            with conf_mount(REPO, pub, server_env=_url(P_PROXY_ORIGIN),
                            env_extra={"http_proxy": purl_a}) as (mnt, _):
                obs["env_mounted"] = os.path.ismount(mnt)
                if obs["env_mounted"]:
                    obs["env_keep"] = (mnt / "keep.txt").read_bytes()
            obs["env_fwd"] = len(_forwards(log_a))

            # env http_proxy + matching no_proxy → direct again
            mark = len(_forwards(log_a))
            with conf_mount(REPO, pub, server_env=_url(P_PROXY_ORIGIN),
                            env_extra={"http_proxy": purl_a,
                                       "no_proxy": HOST}) as (mnt, _):
                _check_scn_1(mnt)
                obs["np_keep"] = (mnt / "change.txt").read_bytes()
            obs["np_new_fwd"] = len(_forwards(log_a)) - mark

            # config CVMFS_HTTP_PROXY, no env → proxy B
            with conf_mount(REPO, pub, server_url=_url(P_PROXY_ORIGIN),
                            proxy_conf=purl_b) as (mnt, _):
                _check_scn_2(mnt)
                obs["cfg_keep"] = (mnt / "keep.txt").read_bytes()
            obs["cfg_fwd"] = len(_forwards(log_b))

            # both set → env wins over config
            mark_a, mark_b = len(_forwards(log_a)), len(_forwards(log_b))
            with conf_mount(REPO, pub, server_url=_url(P_PROXY_ORIGIN),
                            proxy_conf=purl_b,
                            env_extra={"http_proxy": purl_a}) as (mnt, _):
                _check_scn_3(mnt)
                (mnt / "sub" / "leaf.txt").read_bytes()
            obs["both_a"] = len(_forwards(log_a)) - mark_a
            obs["both_b"] = len(_forwards(log_b)) - mark_b

            # explicit DIRECT in config, no env → direct works
            mark_a, mark_b = len(_forwards(log_a)), len(_forwards(log_b))
            with conf_mount(REPO, pub, server_url=_url(P_PROXY_ORIGIN),
                            proxy_conf="DIRECT") as (mnt, _):
                _check_scn_4(mnt)
                obs["direct_keep"] = (mnt / "keep.txt").read_bytes()
            obs["direct_a"] = len(_forwards(log_a)) - mark_a
            obs["direct_b"] = len(_forwards(log_b)) - mark_b
            yield obs
        finally:
            for p in procs:
                p.terminate()
            for p in procs:
                try:
                    p.wait(3)
                except subprocess.TimeoutExpired:
                    p.kill()
            origin.stop()
            forge.close()

    def test_env_proxy_carries_the_mount(self, scn):
        assert scn["env_mounted"] and scn["env_keep"] == KEEP_V1

    def test_env_proxy_actually_used(self, scn):
        assert scn["env_fwd"] >= 1

    def test_no_proxy_exclusion_bypasses_env_proxy(self, scn):
        assert scn["np_new_fwd"] == 0 and scn["np_keep"] == CHANGE_V1

    def test_config_proxy_used_when_env_absent(self, scn):
        assert scn["cfg_fwd"] >= 1 and scn["cfg_keep"] == KEEP_V1

    def test_env_proxy_wins_over_config_proxy(self, scn):
        assert scn["both_a"] >= 1

    def test_config_proxy_unused_when_env_present(self, scn):
        assert scn["both_b"] == 0

    def test_explicit_direct_bypasses_all_proxies(self, scn):
        assert (scn["direct_keep"] == KEEP_V1
                and scn["direct_a"] == 0 and scn["direct_b"] == 0)


# ============================================================================
# Options — -o fresh (no connection reuse) and -o tls (https-first fallback).
# ============================================================================

@pytest.mark.timeout(120)
class TestOptions:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("opts")
        forge, web, pub = _forge(tmp)
        origin = LocalOrigin(P_OPTS, web, keepalive=True).start()
        obs = {}
        try:
            # -o fresh: one TCP connection per request, cache-first thereafter
            with conf_mount(REPO, pub, server_env=_url(P_OPTS),
                            opts_extra="fresh") as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                origin.reset_counters()
                for f in ("keep.txt", "change.txt", "remove.txt"):
                    (mnt / f).read_bytes()
                with origin.lock:
                    obs["fresh_conns"] = origin.connections
                    obs["fresh_reqs"] = len(origin.log)
                (mnt / "keep.txt").read_bytes()          # warm re-read: cache only
                with origin.lock:
                    obs["fresh_conns_after_warm"] = origin.connections

            # default mount (no fresh) against the same keepalive origin
            origin.reset_counters()
            with conf_mount(REPO, pub, server_env=_url(P_OPTS)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                for f in ("keep.txt", "change.txt", "remove.txt"):
                    (mnt / f).read_bytes()
                with origin.lock:
                    obs["dflt_conns"] = origin.connections
                    obs["dflt_reqs"] = len(origin.log)

            # -o tls against a plain-HTTP origin: https probe fails, http works
            with conf_mount(REPO, pub, server_env=_url(P_OPTS),
                            opts_extra="tls", timeout=25) as (mnt, _):
                obs["tls_mounted"] = os.path.ismount(mnt)
                if obs["tls_mounted"]:
                    obs["tls_keep"] = (mnt / "keep.txt").read_bytes()
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_fresh_forbids_connection_reuse(self, scn):
        assert scn["fresh_reqs"] >= 3
        assert scn["fresh_conns"] >= scn["fresh_reqs"], \
            "-o fresh must open a new TCP connection per request"

    def test_fresh_warm_reread_hits_cache_not_network(self, scn):
        assert scn["fresh_conns_after_warm"] == scn["fresh_conns"]

    def test_default_mount_reuses_connections(self, scn):
        # Official CVMFS keeps persistent origin connections when not configured
        # otherwise; brixcvmfs matches via a persistent curl easy handle whose
        # connection cache spans fetches (http_get_range g_curl), so a keepalive
        # origin sees fewer connections than requests.
        assert scn["dflt_conns"] < scn["dflt_reqs"]

    def test_tls_option_falls_back_to_plain_http(self, scn):
        assert scn["tls_mounted"], \
            "-o tls against an http-only origin must fall back, not fail"

    def test_tls_fallback_reads_correct_bytes(self, scn):
        assert scn.get("tls_keep") == KEEP_V1
