from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_refresh_failover_helpers")

@pytest.mark.timeout(60)
class TestTtlRefresh:
    TTL = 5

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("ttl")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_TTL, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_TTL)) as (mnt, _):
                assert os.path.ismount(mnt), "brixMount failed to mount rev1"
                t0 = time.monotonic()
                obs["pre_ls"] = sorted(os.listdir(mnt))
                obs["pre_keep"] = (mnt / "keep.txt").read_bytes()
                obs["pre_rev"] = xattr(mnt, "user.revision")
                obs["pre_root"] = xattr(mnt, "user.root_hash")

                obs["rev2_hash"] = publish_revision(forge, _tree_v2(), 2)

                # -- inside the TTL window: the OLD catalog must keep serving --
                obs["in_ls"] = sorted(os.listdir(mnt))
                obs["in_change"] = (mnt / "change.txt").read_bytes()
                # deleted-in-rev2 file: still readable from the old catalog
                obs["in_remove"] = (mnt / "remove.txt").read_bytes()
                obs["in_rev"] = xattr(mnt, "user.revision")
                obs["in_root"] = xattr(mnt, "user.root_hash")
                assert time.monotonic() - t0 < self.TTL - 1, \
                    "in-TTL observations took too long to be meaningful"

                # -- past the TTL: a getattr triggers the refresh --
                time.sleep(max(0.0, (self.TTL + 1.5) - (time.monotonic() - t0)))
                os.stat(mnt)
                obs["post_ls"] = sorted(os.listdir(mnt))
                obs["post_new"] = (mnt / "new.txt").read_bytes()
                obs["post_change"] = (mnt / "change.txt").read_bytes()
                obs["post_keep"] = (mnt / "keep.txt").read_bytes()
                obs["post_remove_errno"] = _stat_errno(mnt / "remove.txt")
                obs["post_rev"] = xattr(mnt, "user.revision")
                obs["post_root"] = xattr(mnt, "user.root_hash")
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_pre_listing_is_rev1(self, scn):
        assert scn["pre_ls"] == ["change.txt", "keep.txt", "remove.txt", "sub"]

    def test_pre_content(self, scn):
        assert scn["pre_keep"] == KEEP_V1

    def test_pre_revision_xattr(self, scn):
        assert scn["pre_rev"] == "1"

    def test_pre_root_hash_xattr(self, scn):
        assert scn["pre_root"] == scn["rev1_hash"]

    def test_within_ttl_new_file_not_visible(self, scn):
        assert "new.txt" not in scn["in_ls"]

    def test_within_ttl_listing_unchanged(self, scn):
        assert scn["in_ls"] == scn["pre_ls"]

    def test_within_ttl_changed_file_serves_old_bytes(self, scn):
        assert scn["in_change"] == CHANGE_V1

    def test_within_ttl_deleted_file_still_readable(self, scn):
        # rev2 removed it, but inside D the old catalog still serves it.
        assert scn["in_remove"] == REMOVE_V1

    def test_within_ttl_revision_xattr_stable(self, scn):
        assert scn["in_rev"] == "1"

    def test_within_ttl_root_hash_stable(self, scn):
        assert scn["in_root"] == scn["rev1_hash"]

    def test_post_ttl_new_file_visible(self, scn):
        assert "new.txt" in scn["post_ls"]

    def test_post_ttl_new_file_content(self, scn):
        assert scn["post_new"] == NEW_V2

    def test_post_ttl_changed_file_serves_new_bytes(self, scn):
        assert scn["post_change"] == CHANGE_V2

    def test_post_ttl_unchanged_file_stable(self, scn):
        assert scn["post_keep"] == KEEP_V1

    def test_post_ttl_removed_file_enoent(self, scn):
        import errno
        assert scn["post_remove_errno"] == errno.ENOENT

    def test_post_ttl_revision_xattr_updated(self, scn):
        assert scn["post_rev"] == "2"

    def test_post_ttl_root_hash_updated(self, scn):
        assert scn["post_root"] == scn["rev2_hash"]


# ============================================================================
# Refresh failure — origin down at TTL expiry: old catalog keeps serving,
# origin return → the NEXT due refresh succeeds.
# ============================================================================

@pytest.mark.timeout(90)
class TestRefreshOriginDown:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("down")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_DOWN, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_DOWN)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                (mnt / "keep.txt").read_bytes()          # warm the cache
                (mnt / "change.txt").read_bytes()
                publish_revision(forge, _tree_v2(), 2)
                origin.stop()

                time.sleep(self.TTL + 1.5)
                os.stat(mnt)                             # refresh attempt → fails
                obs["out_keep"] = (mnt / "keep.txt").read_bytes()
                obs["out_change"] = (mnt / "change.txt").read_bytes()
                obs["out_ls"] = sorted(os.listdir(mnt))
                obs["out_rev"] = xattr(mnt, "user.revision")
                obs["out_root"] = xattr(mnt, "user.root_hash")

                origin.start()                           # origin returns
                time.sleep(self.TTL + 1.5)               # next refresh window + blacklist lapse
                os.stat(mnt)
                obs["rec_ls"] = sorted(os.listdir(mnt))
                obs["rec_change"] = (mnt / "change.txt").read_bytes()
                obs["rec_rev"] = xattr(mnt, "user.revision")
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_outage_warm_reads_still_correct(self, scn):
        assert scn["out_keep"] == KEEP_V1

    def test_outage_changed_file_serves_old_bytes(self, scn):
        assert scn["out_change"] == CHANGE_V1

    def test_outage_listing_unchanged(self, scn):
        assert "new.txt" not in scn["out_ls"] and "remove.txt" in scn["out_ls"]

    def test_outage_revision_xattr_stable(self, scn):
        # raw whitelist fetch fails FIRST, before the manifest buffer is touched,
        # so the manifest state stays rev1 on a full-outage refresh failure.
        assert scn["out_rev"] == "1"

    def test_outage_root_hash_stable(self, scn):
        assert scn["out_root"] == scn["rev1_hash"]

    def test_recovery_new_revision_visible(self, scn):
        assert "new.txt" in scn["rec_ls"] and "remove.txt" not in scn["rec_ls"]

    def test_recovery_changed_content(self, scn):
        assert scn["rec_change"] == CHANGE_V2

    def test_recovery_revision_xattr(self, scn):
        assert scn["rec_rev"] == "2"


# ============================================================================
# Refresh to a TAMPERED rev2 manifest — rejected; old catalog keeps serving.
# ============================================================================

@pytest.mark.timeout(90)
class TestRefreshTamperedManifest:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("tamper")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_TAMPER, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_TAMPER)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["rev2_hash"] = publish_revision(forge, _tree_v2(), 2)
                # tamper: zero out the manifest signature (verify must fail)
                forge.rewrite_manifest(forge._manifest_fields(), stale_sig=True)

                time.sleep(self.TTL + 1.5)
                os.stat(mnt)                             # refresh → verify fails
                obs["t_change"] = (mnt / "change.txt").read_bytes()
                obs["t_ls"] = sorted(os.listdir(mnt))
                obs["t_rev"] = xattr(mnt, "user.revision")
                obs["t_root"] = xattr(mnt, "user.root_hash")

                # repair the manifest signature → refresh should now succeed
                forge.rewrite_manifest(forge._manifest_fields())
                time.sleep(self.TTL + 1.5)
                os.stat(mnt)
                obs["rec_ls"] = sorted(os.listdir(mnt))
                obs["rec_rev"] = xattr(mnt, "user.revision")
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_tampered_manifest_old_content_keeps_serving(self, scn):
        assert scn["t_change"] == CHANGE_V1

    def test_tampered_manifest_no_partial_upgrade_in_listing(self, scn):
        assert "new.txt" not in scn["t_ls"] and "remove.txt" in scn["t_ls"]

    # RETIRED DIVERGENCE: refresh is now staged — load_trust_and_catalog parses
    # into a staging buffer and commit_manifest() installs it only after the
    # full chain verifies (client.c), so a rejected refresh leaves metadata
    # untouched and recovery is not wedged on "same revision".
    def test_tampered_manifest_revision_xattr_stable(self, scn):
        assert scn["t_rev"] == "1"

    def test_tampered_manifest_root_hash_xattr_stable(self, scn):
        assert scn["t_root"] == scn["rev1_hash"]

    def test_repaired_manifest_recovers_to_rev2(self, scn):
        assert "new.txt" in scn["rec_ls"]

    def test_repaired_manifest_revision_consistent_with_content(self, scn):
        # Official: metadata and served catalog always agree post-recovery.
        assert (scn["rec_rev"] == "2") == ("new.txt" in scn["rec_ls"])


# ============================================================================
# Revision downgrade — official client refuses a root-catalog rollback.
# ============================================================================

@pytest.mark.timeout(60)
class TestRevisionDowngrade:
    TTL = 4

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("downgrade")
        forge, web, pub = _forge(tmp, ttl=self.TTL, revision=2, tree=_tree_v2())
        origin = LocalOrigin(P_DOWNGRADE, web).start()
        obs = {}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_DOWNGRADE)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                obs["pre_rev"] = xattr(mnt, "user.revision")
                obs["pre_ls"] = sorted(os.listdir(mnt))
                publish_revision(forge, _tree_v1(), 1)   # properly signed rollback
                time.sleep(self.TTL + 1.5)
                os.stat(mnt)
                obs["post_ls"] = sorted(os.listdir(mnt))
                obs["post_rev"] = xattr(mnt, "user.revision")
                obs["post_keep"] = (mnt / "keep.txt").read_bytes()
                obs["mount_alive"] = os.path.ismount(mnt)
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_mounted_rev2_before_rollback(self, scn):
        assert scn["pre_rev"] == "2" and "new.txt" in scn["pre_ls"]

    # RETIRED DIVERGENCE: cvmfs_client_refresh now refuses a revision downgrade
    # (staged manifest revision < installed revision → refresh rejected), so a
    # properly-signed rollback is ignored and rev2 keeps serving.
    def test_rollback_rejected_content_stays_rev2(self, scn):
        assert "new.txt" in scn["post_ls"]

    def test_rollback_rejected_revision_xattr_stays_2(self, scn):
        assert scn["post_rev"] == "2"

    def test_mount_remains_consistent_after_rollback_event(self, scn):
        # Whatever was decided, the mount must stay healthy and self-consistent.
        assert scn["mount_alive"] and scn["post_keep"] == KEEP_V1


# ============================================================================
# Mid-refresh catalog-object 404 — manifest bumped but new catalog CAS missing.
# ============================================================================

@pytest.mark.timeout(90)
class TestMidRefreshCatalog404:
    TTL = 6

    @pytest.fixture(scope="class")
    def scn(self, tmp_path_factory):
        tmp = tmp_path_factory.mktemp("midref")
        forge, web, pub = _forge(tmp, ttl=self.TTL)
        rev1_hash = forge.root_catalog_hash
        origin = LocalOrigin(P_MIDREF, web).start()
        obs = {"rev1_hash": rev1_hash}
        try:
            with conf_mount(REPO, pub, server_env=_url(P_MIDREF)) as (mnt, _):
                assert os.path.ismount(mnt), "mount failed"
                rev2_hash = publish_revision(forge, _tree_v2(), 2)
                obs["rev2_hash"] = rev2_hash
                cat = forge.artifact_path(rev2_hash + "C")
                saved = cat.read_bytes()
                cat.unlink()                              # the new catalog CAS is missing

                time.sleep(self.TTL + 1.5)
                os.stat(mnt)                              # refresh → catalog fetch 404
                # the 404 blacklists the (only) host+proxy for 2s — let the
                # snap-back lapse so observations reflect steady-state serving,
                # inside the TTL window so no second refresh interferes
                time.sleep(2.7)
                obs["m_change"] = (mnt / "change.txt").read_bytes()
                obs["m_ls"] = sorted(os.listdir(mnt))
                obs["m_root"] = xattr(mnt, "user.root_hash")

                cat.write_bytes(saved)                    # catalog appears at origin
                time.sleep(self.TTL + 1.5)
                os.stat(mnt)
                obs["rec_ls"] = sorted(os.listdir(mnt))
            yield obs
        finally:
            origin.stop()
            forge.close()

    def test_missing_catalog_old_content_keeps_serving(self, scn):
        assert scn["m_change"] == CHANGE_V1

    def test_missing_catalog_no_partial_upgrade(self, scn):
        assert "new.txt" not in scn["m_ls"] and "remove.txt" in scn["m_ls"]

    # RETIRED DIVERGENCE: the staged refresh commits nothing until the new root
    # catalog is fetched and verified, so a mid-refresh 404 leaves rev1 metadata
    # intact and the restored catalog upgrades cleanly to rev2.
    def test_missing_catalog_root_hash_xattr_stable(self, scn):
        assert scn["m_root"] == scn["rev1_hash"]

    def test_catalog_restored_recovers_to_rev2(self, scn):
        assert "new.txt" in scn["rec_ls"]


# ============================================================================
# Host failover — CVMFS_SERVER_URL mirror lists (conf cascade; the env var
# BRIXCVMFS_SERVER pins a single host and cannot express a list).
# ============================================================================

# RETIRED DIVERGENCE (D5): cvmfs_failover_record() no longer blacklists a
# DIRECT pseudo-proxy on failure (failover.c) — a replica failure marks only the
# host, so cvmfs_failover_select() hands back the next replica instead of
# reporting offline.  Replica failover now matches official CVMFS.
