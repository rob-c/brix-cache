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

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_fuse_refresh_failover")

@pytest.mark.timeout(90)
class TestFailoverPrimaryDownAtMount:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_a")
        forge, web, pub = _forge(tmp)
        sec = LocalOrigin(P_FO_A_LIVE, web).start()      # nothing on P_FO_A_DEAD
        obs = {"mounted": False, "keep": None, "sec_manifest_hits": 0}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_A_DEAD)};{_url(P_FO_A_LIVE)}"
                            ) as (mnt, _):
                obs["mounted"] = os.path.ismount(mnt)
                if obs["mounted"]:
                    obs["keep"] = (mnt / "keep.txt").read_bytes()
                obs["sec_manifest_hits"] = len(sec.requests(".cvmfspublished"))
            yield obs
        finally:
            sec.stop()
            forge.close()

    def test_mounts_despite_dead_primary(self, scn):
        assert scn["mounted"], "secondary mirror did not carry the mount"

    def test_reads_correct_via_secondary(self, scn):
        assert scn["keep"] == KEEP_V1

    def test_trust_chain_fetched_from_secondary(self, scn):
        assert scn["sec_manifest_hits"] >= 1


@pytest.mark.timeout(60)
class TestFailoverPrimaryDiesMidSession:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_b")
        forge, web, pub = _forge(tmp)
        pri = LocalOrigin(P_FO_B_PRI, web).start()
        sec = LocalOrigin(P_FO_B_SEC, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_B_PRI)};{_url(P_FO_B_SEC)}"
                            ) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["warm"] = (mnt / "keep.txt").read_bytes()
                obs["keep_via_pri"] = len(pri.requests(cas_needle(KEEP_V1)))
                pri.stop()
                try:
                    obs["cold"] = (mnt / "change.txt").read_bytes()
                    obs["cold_errno"] = 0
                except OSError as e:
                    obs["cold"] = None
                    obs["cold_errno"] = e.errno
                obs["change_via_sec"] = len(sec.requests(cas_needle(CHANGE_V1)))
                obs["warm_again"] = (mnt / "keep.txt").read_bytes()
            yield obs
        finally:
            pri.stop()
            sec.stop()
            forge.close()

    def test_sticky_primary_served_the_warm_read(self, scn):
        assert scn["keep_via_pri"] >= 1

    def test_cold_read_continues_via_secondary(self, scn):
        assert scn["cold"] == CHANGE_V1

    def test_secondary_actually_served_the_object(self, scn):
        assert scn["change_via_sec"] >= 1

    def test_cold_read_never_serves_wrong_bytes(self, scn):
        # holds in both worlds: either the correct bytes or a clean EIO.
        import errno
        assert scn["cold"] == CHANGE_V1 or scn["cold_errno"] == errno.EIO

    def test_warm_reread_unaffected(self, scn):
        assert scn["warm_again"] == KEEP_V1


@pytest.mark.timeout(60)
class TestFailoverBothDownAfterWarm:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_c")
        forge, web, pub = _forge(tmp)
        pri = LocalOrigin(P_FO_C_PRI, web).start()
        sec = LocalOrigin(P_FO_C_SEC, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_C_PRI)};{_url(P_FO_C_SEC)}"
                            ) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "keep.txt").read_bytes()          # warm one file
                pri.stop()
                sec.stop()
                obs["warm"] = (mnt / "keep.txt").read_bytes()
                try:
                    (mnt / "change.txt").read_bytes()
                    obs["cold_exc"] = None
                except OSError as e:
                    obs["cold_exc"] = e.errno
                obs["ls"] = sorted(os.listdir(mnt))
                obs["alive"] = os.path.ismount(mnt)
            yield obs
        finally:
            pri.stop()
            sec.stop()
            forge.close()

    def test_warm_read_served_from_cache_offline(self, scn):
        assert scn["warm"] == KEEP_V1

    def test_cold_read_fails_cleanly(self, scn):
        import errno
        assert scn["cold_exc"] == errno.EIO, \
            "offline cold read must be a clean EIO, never wrong bytes"

    def test_catalog_listing_still_works_offline(self, scn):
        assert "keep.txt" in scn["ls"]

    def test_mount_survives_total_outage(self, scn):
        assert scn["alive"]


@pytest.mark.timeout(90)
class TestFailoverPrimaryReturns:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("fo_d")
        forge, web, pub = _forge(tmp)
        pri = LocalOrigin(P_FO_D_PRI, web).start()
        sec = LocalOrigin(P_FO_D_SEC, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub,
                            server_url=f"{_url(P_FO_D_PRI)};{_url(P_FO_D_SEC)}",
                            timeout=25) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "keep.txt").read_bytes()
                pri.stop()
                try:
                    (mnt / "change.txt").read_bytes()    # official: via secondary
                except OSError:
                    pass                                 # brix D5: EIO while pri is dead
                pri.start()                              # primary returns
                time.sleep(3.5)                          # snap-back blacklist lapses
                obs["leaf"] = (mnt / "sub" / "leaf.txt").read_bytes()
                obs["leaf_via_pri"] = len(pri.requests(cas_needle(LEAF_V1)))
            yield obs
        finally:
            pri.stop()
            sec.stop()
            forge.close()

    def test_read_after_recovery_correct(self, scn):
        assert scn["leaf"] == LEAF_V1

    def test_sticky_selection_returns_to_primary(self, scn):
        assert scn["leaf_via_pri"] >= 1, \
            "after the blacklist lapses the geo-closest mirror must be reused"


@pytest.mark.timeout(120)
class TestServerListSyntax:
    @pytest.fixture(scope="class")
    def live(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("syntax")
        forge, web, pub = _forge(tmp)
        origin = LocalOrigin(P_SYN_LIVE, web).start()
        try:
            yield web, pub
        finally:
            origin.stop()
            forge.close()

    def test_comma_separated_server_list_survives_dead_first_entry(self, live):
        # comma is a valid CVMFS_SERVER_URL separator; official mounts via the
        # live second entry (fails here per D5: no replica failover).
        _, pub = live
        with conf_mount(REPO, pub, timeout=20,
                        server_url=f"{_url(P_SYN_DEAD)},{_url(P_SYN_LIVE)}") as (mnt, _):
            assert os.path.ismount(mnt)
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    def test_comma_separated_server_list_parses(self, live):
        # separator acceptance alone (both entries live — no failover needed).
        _, pub = live
        with conf_mount(REPO, pub,
                        server_url=f"{_url(P_SYN_LIVE)},{_url(P_SYN_LIVE)}") as (mnt, _):
            assert os.path.ismount(mnt)
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    def test_fqrn_placeholder_expansion(self, live):
        _, pub = live
        url = f"http://{HOST}:{P_SYN_LIVE}/cvmfs/@fqrn@"
        with conf_mount(REPO, pub, server_url=url) as (mnt, _):
            assert os.path.ismount(mnt)
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    def test_env_pin_beats_config_server_list(self, live):
        _, pub = live
        with conf_mount(REPO, pub, server_env=_url(P_SYN_LIVE),
                        server_url=_url(P_SYN_DEAD)) as (mnt, _):
            assert os.path.ismount(mnt), \
                "BRIXCVMFS_SERVER must override the config server list"
            assert (mnt / "keep.txt").read_bytes() == KEEP_V1

    @pytest.mark.timeout(90)
    def test_env_pin_is_single_host_not_a_list(self, live):
        # brixcvmfs.c: BRIXCVMFS_SERVER is added verbatim as ONE host — a
        # semicolon list is not split, so the mount cannot come up.
        _, pub = live
        with conf_mount(REPO, pub,
                        server_env=f"{_url(P_SYN_LIVE)};{_url(P_SYN_LIVE)}",
                        timeout=20) as (mnt, _):
            assert not os.path.ismount(mnt)


# ============================================================================
# Retry budget — only NO-PROGRESS attempts consume `-o retries=N`.
# ============================================================================

@pytest.mark.timeout(150)
class TestRetryBudget:
    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        rnd = Random(84)
        obj_a, obj_b, obj_c = (rnd.randbytes(4096) for _ in range(3))
        payload = rnd.randbytes(6144)
        tree = {"a.bin": File(obj_a), "b.bin": File(obj_b),
                "c.bin": File(obj_c), "payload.bin": File(payload)}
        tmp = tmp_path_factory.mktemp("retry")
        forge, web, pub = _forge(tmp, tree=tree)
        origin = LocalOrigin(P_RETRY, web).start()
        obs = {}
        try:
            # -- resets within budget: N=2 faults, retries=3 → success ---------
            origin.set_fault("refuse", 2, path_re=cas_needle(obj_a))
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=3) as (mnt, _):
                _check_scn_1(mnt)
                obs["a"] = (mnt / "a.bin").read_bytes()
            obs["a_attempts"] = len(origin.requests(cas_needle(obj_a)))
            origin.clear_faults()

            # -- resets beyond budget: retries=1 → clean error, then recovery --
            origin.set_fault("refuse", 5, path_re=cas_needle(obj_b))
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=1) as (mnt, _):
                _check_scn_2(mnt)
                try:
                    (mnt / "b.bin").read_bytes()
                    obs["b_exc"] = None
                except OSError as e:
                    obs["b_exc"] = e.errno
                origin.clear_faults()
                time.sleep(2.5)                          # snap-back blacklist lapses
                obs["b_retry"] = (mnt / "b.bin").read_bytes()
            origin.clear_faults()

            # -- retries=0 falls back to the built-in default budget (6) -------
            origin.set_fault("refuse", 4, path_re=cas_needle(obj_c))
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=0) as (mnt, _):
                _check_scn_3(mnt)
                obs["c"] = (mnt / "c.bin").read_bytes()
            origin.clear_faults()

            # -- progress does NOT consume budget: 1KiB sever per response,
            #    ~6 resumes needed, but retries=1 still succeeds ---------------
            with conf_mount(REPO, pub, server_env=_url(P_RETRY), retries=1) as (mnt, _):
                _check_scn_4(mnt)
                origin.reset_counters()
                origin.sever_after = 1024
                obs["p"] = (mnt / "payload.bin").read_bytes()
                origin.sever_after = 0
            obs["p_reqs"] = origin.requests(cas_needle(payload))
            obs["payload"] = payload
            obs["obj_a"], obs["obj_b"], obs["obj_c"] = obj_a, obj_b, obj_c
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_resets_within_budget_read_succeeds(self, scn):
        assert scn["a"] == scn["obj_a"]

    def test_each_reset_consumed_one_attempt(self, scn):
        assert scn["a_attempts"] == 3          # 2 refused + 1 clean

    def test_resets_beyond_budget_clean_error(self, scn):
        import errno
        assert scn["b_exc"] == errno.EIO

    def test_recovery_after_faults_cleared(self, scn):
        assert scn["b_retry"] == scn["obj_b"]

    def test_retries_zero_means_default_budget(self, scn):
        assert scn["c"] == scn["obj_c"]

    def test_progress_attempts_do_not_consume_budget(self, scn):
        # ~6 severed-but-progressing attempts, budget 1: delivered-bytes progress
        # resets the stall counter (brixcvmfs.c transport loop).
        assert scn["p"] == scn["payload"]

    def test_progress_path_used_multiple_resumes(self, scn):
        assert len(scn["p_reqs"]) >= 3

    def test_resume_offsets_strictly_increase(self, scn):
        offs = [int(r["range"][len("bytes="):].rstrip("-"))
                for r in scn["p_reqs"] if r["range"]]
        assert offs == sorted(offs) and len(offs) == len(set(offs)) and offs, \
            "resume must continue from delivered bytes, never restart"


# ============================================================================
# Range-resume — severed large-object transfer resumes with a Range request;
# a Range-blind origin (200-full) is still handled byte-exactly (200-slide).
# ============================================================================
