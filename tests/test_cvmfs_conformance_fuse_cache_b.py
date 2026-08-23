from split_continuation import reexport as _reexport
def _check_test_quota_fill_past_watermark_reaps_to_75pct_1(expect):
    assert len(expect) == 8 and all(len(v) == 300_000 for v in expect.values())

def _check_test_quota_fill_past_watermark_reaps_to_75pct_2(du):
    assert du <= QUOTA, f"cache {du}B exceeded the hard quota"

def _check_test_quota_fill_past_watermark_reaps_to_75pct_3(du):
    assert du <= (QUOTA * 3) // 4 + 300_000, \
        f"cache {du}B more than one object above the 75% reap target"

def _check_test_quota_fill_past_watermark_reaps_to_75pct_4(du):
    assert du < 8 * 300_000, "reap must have evicted something (cache < full 2.4MB)"

def _check_test_quota_fill_past_watermark_reaps_to_75pct_5(du):
    assert du > 0, "reap must not empty the cache entirely"


_reexport(globals(), "_test_cvmfs_conformance_fuse_cache_helpers")

@pytest.mark.timeout(240)
def test_corrupt_cached_catalog_entry_remount_recovers(tmp_path, make_origin):
    # RETIRED DIVERGENCE: a damaged cached 'C' (catalog) entry now fails the
    # sidecar re-verification, is purged, and the pristine object is refetched
    # from the origin — the remount succeeds.
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
    ent = cache_entry(cache, forge.root_catalog_hash, "C")
    blob = bytearray(ent.read_bytes())
    blob[16] ^= 0xFF                                # inside the sqlite header
    ent.write_bytes(bytes(blob))
    try:
        with fuse_mount(REPO, origin.url, pub, cache=str(cache), timeout=25,
                        bringup_retries=1) as (mnt, _):
            assert os.path.ismount(str(mnt)), "remount must survive a damaged cached catalog"
    finally:
        forge.close()


# ===========================================================================
# E. quota: high-watermark reap to 75%, enforced synchronously at fill time
# ===========================================================================

QUOTA_MB = 1
QUOTA = QUOTA_MB * 1024 * 1024


@pytest.mark.timeout(180)
def test_quota_fill_past_watermark_reaps_to_75pct(tmp_path, make_origin):
    # 8 x 300KB (2.4MB plaintext) through a 1MB quota: brix_cas_put enforces the
    # quota on every fill, reaping atime-LRU down to the 75% target — no need to
    # wait for the 30s reap_tick.
    with mounted(tmp_path, make_origin, tree=_quota_tree(),
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        expect = read_tree(m.mnt)
        _check_test_quota_fill_past_watermark_reaps_to_75pct_1(expect)
        du = cache_du(m.cache)
        # The reap fires when a fill would cross the hard quota, evicting LRU down
        # to the 75% low-watermark. The final resting size therefore depends on
        # whether the LAST fill crossed the quota: if it did not (600K + 300K =
        # 900K < 1M) the cache legitimately rests one object above the low
        # watermark. Both outcomes are correct; the invariant under test is that
        # the cache stays bounded near 75% and never exceeds the hard quota — not
        # that it always lands at-or-below the low watermark on the final fill.
        _check_test_quota_fill_past_watermark_reaps_to_75pct_2(du)
        _check_test_quota_fill_past_watermark_reaps_to_75pct_3(du)
        _check_test_quota_fill_past_watermark_reaps_to_75pct_4(du)
        _check_test_quota_fill_past_watermark_reaps_to_75pct_5(du)


@pytest.mark.timeout(180)
def test_quota_under_watermark_keeps_all_entries(tmp_path, make_origin):
    tree = _quota_tree(n=3, size=200_000)           # 600KB < 1MB: no reap
    with mounted(tmp_path, make_origin, tree=tree,
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        read_tree(m.mnt)
        for node in tree.values():
            assert cache_entry(m.cache, content_key(node.content)).is_file(), \
                "entry reaped while the cache was under quota"


@pytest.mark.timeout(180)
def test_reaped_entries_are_refetchable(tmp_path, make_origin):
    tree = _quota_tree()
    with mounted(tmp_path, make_origin, tree=tree,
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        expect = read_tree(m.mnt)                   # drives multiple reaps
        reaped = [f"f{i}" for i in range(8)
                  if not cache_entry(m.cache, content_key(tree[f"f{i}"].content)).is_file()]
        assert reaped, "2.4MB through a 1MB quota must have evicted something"
        m.origin.reset_log()
        name = reaped[0]
        assert (m.mnt / name).read_bytes() == expect[name]
        assert m.origin.data_fetches(content_key(tree[name].content)) >= 1


@pytest.mark.timeout(180)
def test_currently_open_file_survives_reap(tmp_path, make_origin):
    tree = _quota_tree()
    with mounted(tmp_path, make_origin, tree=tree,
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        first = (m.mnt / "f0").read_bytes()
        fd = os.open(m.mnt / "f0", os.O_RDONLY)
        try:
            for i in range(1, 8):                   # push f0 out of the cache
                (m.mnt / f"f{i}").read_bytes()
            got = bytearray()
            while chunk := os.read(fd, 65536):
                got += chunk
            assert bytes(got) == first, "open handle broke when its entry was reaped"
        finally:
            os.close(fd)


@pytest.mark.timeout(240)
def test_single_object_larger_than_quota_served_not_wedged(tmp_path, make_origin):
    big = random.Random(11).randbytes(2 * 1024 * 1024)
    with mounted(tmp_path, make_origin, tree={"big": File(big)},
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        assert (m.mnt / "big").read_bytes() == big, "over-quota object must still be served"
        assert os.path.ismount(str(m.mnt))
        assert (m.mnt / "big").read_bytes() == big  # and again, via refetch
        assert cache_du(m.cache) <= QUOTA


@pytest.mark.timeout(180)
def test_no_quota_means_unbounded_cache(tmp_path, make_origin):
    tree = _quota_tree()                            # 2.4MB, no quota option
    with mounted(tmp_path, make_origin, tree=tree) as m:
        read_tree(m.mnt)
        for node in tree.values():
            assert cache_entry(m.cache, content_key(node.content)).is_file()
        assert cache_du(m.cache) >= 8 * 300_000


@pytest.mark.timeout(180)
def test_preexisting_overquota_cache_reaped_on_next_fill(tmp_path, make_origin):
    # Adopt a 2.7MB cache under a 1MB quota: brix_cas_init re-counts the disk, so
    # the FIRST new fill trips the watermark and reaps the adopted entries too.
    tree = _quota_tree(n=9)
    forge, web, pub = _forge(tmp_path, tree)
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        for i in range(8):
            (mnt / f"f{i}").read_bytes()            # no quota: 2.4MB adopted
    assert cache_du(cache) >= 8 * 300_000
    with fuse_mount(REPO, origin.url, pub, cache=str(cache),
                    extra_args=("-o", f"quota={QUOTA_MB}")) as (mnt, _):
        (mnt / "f8").read_bytes()                   # cold fill -> synchronous enforce
        assert cache_du(cache) <= (QUOTA * 3) // 4
    forge.close()


# ===========================================================================
# F. cache dir precedence: -o cache= > $BRIXCVMFS_CACHE > default
# ===========================================================================

def test_opt_cache_beats_env_cache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    optdir, envdir = tmp_path / "optcache", tmp_path / "envcache"
    with own_mount(REPO, origin.url, pub, cache_env=envdir,
                   extra_args=("-o", f"cache={optdir}")) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert cas_entries(optdir), "-o cache= dir did not receive the entries"
    assert not cas_entries(envdir), "$BRIXCVMFS_CACHE was used despite -o cache="
    forge.close()


def test_env_cache_used_when_no_opt(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    envdir = tmp_path / "envcache"
    with own_mount(REPO, origin.url, pub, cache_env=envdir) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert cas_entries(envdir), "$BRIXCVMFS_CACHE dir did not receive the entries"
    forge.close()


def test_opt_cache_disables_clever_overlay(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    optdir, mnt_dir = tmp_path / "optcache", tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir,
                   extra_args=("-o", f"cache={optdir}")) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert not (mnt_dir / ".brixcache").exists(), "-o cache= must disable the overlay"
    assert cas_entries(optdir)
    forge.close()


@pytest.mark.skipif(not os.access("/var/lib", os.W_OK),
                    reason="default cache dir /var/lib/brixcvmfs needs a writable /var/lib")
def test_default_cache_dir_when_no_opt_no_env(tmp_path, make_origin):
    # -o noclever with neither -o cache= nor $BRIXCVMFS_CACHE: the binary's
    # built-in default /var/lib/brixcvmfs/<repo> is the fallback.
    default_dir = Path("/var/lib/brixcvmfs") / REPO
    shutil.rmtree(default_dir, ignore_errors=True)
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    try:
        with own_mount(REPO, origin.url, pub, extra_args=("-o", "noclever")) as (mnt, _):
            assert os.path.ismount(str(mnt))
            (mnt / "hello").read_bytes()
        assert cas_entries(default_dir), "default /var/lib/brixcvmfs/<repo> not used"
    finally:
        shutil.rmtree(default_dir, ignore_errors=True)
        forge.close()


# ===========================================================================
# G. clever overlay: .brixcache inside the mountpoint
# ===========================================================================

def test_clever_brixcache_hidden_from_readdir(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    with own_mount(REPO, origin.url, pub, mnt=tmp_path / "m") as (mnt, _):
        assert os.path.ismount(str(mnt))
        names = os.listdir(mnt)
        assert ".brixcache" not in names, "overlay dir leaked into the FUSE readdir"
        assert sorted(names) == ["hello", "link", "secret", "sub"]
    forge.close()


def test_clever_entries_land_in_underlying_brixcache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    # the mount is gone: the pre-mount dirfd wrote into the UNDERLYING dir
    keys = cas_entries(mnt_dir / ".brixcache")
    assert content_key(b"Hello fuse-cache corpus!\n") in [k[:40] for k in keys]
    forge.close()


def test_clever_cache_warm_across_remounts(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir) as (mnt, _):
        first = read_tree(mnt)
    origin.reset_log()
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir) as (mnt, _):
        assert os.path.ismount(str(mnt))
        assert read_tree(mnt) == first
    assert origin.data_fetches() == 0, "second clever mount did not reuse .brixcache"
    forge.close()


def test_noclever_does_not_create_brixcache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir, cache_env=tmp_path / "envcache",
                   extra_args=("-o", "noclever")) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert not (mnt_dir / ".brixcache").exists()
    assert cas_entries(tmp_path / "envcache")
    forge.close()


def test_env_cache_disables_clever_overlay(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir,
                   cache_env=tmp_path / "envcache") as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert not (mnt_dir / ".brixcache").exists(), \
        "$BRIXCVMFS_CACHE must opt out of the clever overlay"
    forge.close()


# ===========================================================================
# H. unusable cache dir: clean mount failure, no crash, mountpoint reusable
# ===========================================================================


def test_cache_dir_under_regular_file_clean_mount_failure(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    blob = tmp_path / "blob"
    blob.write_bytes(b"not a directory")
    mnt = tmp_path / "m"
    mnt.mkdir()
    rc = _expect_mount_failure(REPO, origin.url, pub, mnt, blob / "sub")
    assert rc is not None and rc > 0, f"expected a clean nonzero exit, got {rc}"
    assert not os.path.ismount(str(mnt))
    forge.close()


def test_cache_dir_under_devnull_clean_mount_failure(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt = tmp_path / "m"
    mnt.mkdir()
    rc = _expect_mount_failure(REPO, origin.url, pub, mnt, "/dev/null/cache")
    assert rc is not None and rc > 0, "crash (signal) or hang instead of a clean error"
    assert not os.path.ismount(str(mnt))
    forge.close()


def test_mountpoint_reusable_after_failed_mount(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt = tmp_path / "m"
    mnt.mkdir()
    rc = _expect_mount_failure(REPO, origin.url, pub, mnt, "/dev/null/cache")
    assert rc > 0
    with own_mount(REPO, origin.url, pub, mnt=mnt,
                   cache_env=tmp_path / "cache") as (mnt2, _):
        assert os.path.ismount(str(mnt2))
        assert (mnt2 / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
    forge.close()


# ===========================================================================
# I. BRIXCVMFS_TMP: catalog spill location + cleanup
# ===========================================================================

def test_tmp_env_hosts_catalog_spill(tmp_path, make_origin):
    spill = tmp_path / "spill"
    spill.mkdir()
    with mounted(tmp_path, make_origin, tmp=str(spill)) as m:
        cats = list(spill.glob("brixcvmfs.cat.*"))
        assert cats, "root catalog spill file not in $BRIXCVMFS_TMP"
        assert cats[0].read_bytes()[:16] == b"SQLite format 3\x00"


def test_tmp_spill_cleaned_up_on_umount(tmp_path, make_origin):
    spill = tmp_path / "spill"
    spill.mkdir()
    with mounted(tmp_path, make_origin, tmp=str(spill)) as m:
        assert list(spill.glob("brixcvmfs.cat.*"))
        _unmount(m.mnt)
        m.proc.wait(10)                             # umount path unlinks the spill
    assert not list(spill.glob("brixcvmfs.cat.*")), "catalog spill leaked after umount"


def test_tmp_suite_artifact_dir(tmp_path, make_origin):
    default_tmp = Path(ARTIFACTS_DIR) / f"brixcvmfs-{REPO}"
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    try:
        with own_mount(REPO, origin.url, pub, cache_env=tmp_path / "cache",
                       tmp_env=default_tmp) as (mnt, _):
            assert os.path.ismount(str(mnt))
            assert default_tmp.is_dir(), "default scratch dir not created"
            assert list(default_tmp.glob("brixcvmfs.cat.*"))
    finally:
        shutil.rmtree(default_tmp, ignore_errors=True)
        forge.close()


# ===========================================================================
# J. robustness
# ===========================================================================
