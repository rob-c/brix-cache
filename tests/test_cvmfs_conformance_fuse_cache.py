from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_cache_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_fuse_cache")

def test_cold_read_fetches_object_exactly_once(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        key = content_key(b"Hello fuse-cache corpus!\n")
        m.origin.reset_log()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
        assert m.origin.data_fetches(key) == 1


def test_warm_reread_zero_new_origin_fetches(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.reset_log()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
        assert m.origin.data_fetches() == 0


def test_warm_reread_repeated_stays_zero(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "sub" / "leaf").read_bytes()
        m.origin.reset_log()
        for _ in range(5):
            assert (m.mnt / "sub" / "leaf").read_bytes() == b"leaf bytes\n"
        assert m.origin.data_fetches() == 0


def test_each_object_fetched_once_across_rereads(tmp_path, make_origin):
    contents = {"hello": b"Hello fuse-cache corpus!\n", "secret": b"trust me exactly, byte for byte\n",
                "sub/leaf": b"leaf bytes\n"}
    with mounted(tmp_path, make_origin) as m:
        m.origin.reset_log()
        for _ in range(3):
            for rel, data in contents.items():
                assert (m.mnt / rel).read_bytes() == data
        for data in contents.values():
            assert m.origin.data_fetches(content_key(data)) == 1


def test_tree_walk_twice_second_walk_zero_data_fetches(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        first = read_tree(m.mnt)
        assert len(first) == 4
        m.origin.reset_log()
        assert read_tree(m.mnt) == first
        assert m.origin.data_fetches() == 0


def test_cold_read_populates_cache_entry_with_plaintext(tmp_path, make_origin):
    data = b"Hello fuse-cache corpus!\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "hello").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        assert ent.is_file(), "cold read did not populate the CAS cache"
        assert ent.read_bytes() == data, "cache stores verified plaintext"


def test_metadata_cert_and_catalog_are_cached(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        assert cache_entry(m.cache, m.forge.cert_hash, "X").is_file()
        assert cache_entry(m.cache, m.forge.root_catalog_hash, "C").is_file()


def test_warm_stat_and_listing_zero_origin_traffic(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        read_tree(m.mnt)
        m.origin.reset_log()
        assert sorted(os.listdir(m.mnt)) == ["hello", "link", "secret", "sub"]
        assert (m.mnt / "hello").stat().st_size == 25
        assert os.readlink(m.mnt / "link") == "hello"
        assert m.origin.data_fetches() == 0


def test_warm_partial_reads_served_from_cache(tmp_path, make_origin):
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        m.origin.reset_log()
        fd = os.open(m.mnt / "secret", os.O_RDONLY)
        try:
            assert os.pread(fd, 8, 6) == data[6:14]
            assert os.pread(fd, 100, 24) == data[24:]
        finally:
            os.close(fd)
        assert m.origin.data_fetches() == 0


def test_cache_entries_use_two_hex_fanout_layout(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "hello").read_bytes()
        keys = cas_entries(m.cache)
        assert keys, "no cache entries after a cold read"
        for k in keys:
            hexpart = k[:40]
            assert all(c in "0123456789abcdef" for c in hexpart)
            assert cache_entry(m.cache, hexpart, k[40:]).is_file()


# ===========================================================================
# B. persistence: umount/remount over the same cache dir
# ===========================================================================

def test_cache_persists_across_remount_zero_data_fetches(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
        first = read_tree(mnt)
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
        assert read_tree(mnt) == first
    assert origin.data_fetches() == 0, "warm remount refetched data from the origin"
    forge.close()


def test_remount_refetches_manifest_but_no_data(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        read_tree(mnt)
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
    log = [e["path"] for e in origin.log()]
    assert any(".cvmfswhitelist" in p for p in log), "trust chain must be re-fetched raw"
    assert any(".cvmfspublished" in p for p in log)
    assert origin.data_fetches() == 0
    forge.close()


def test_sequential_mounts_share_single_fill_per_object(tmp_path, make_origin):
    data = b"Hello fuse-cache corpus!\n"
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "shared-cache"
    for _ in range(2):
        with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
            assert (mnt / "hello").read_bytes() == data
    assert origin.data_fetches(content_key(data)) == 1, \
        "second mount over the shared cache dir re-filled an existing entry"
    forge.close()


def test_remount_serves_after_origin_data_removed(tmp_path, make_origin):
    # The strongest persistence proof: wipe the origin's entire /data tree; a
    # warm remount (manifest/whitelist still served) must run fully off cache.
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        first = read_tree(mnt)
    shutil.rmtree(web / "cvmfs" / REPO / "data")
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt)), "remount must not need /data/ when cache is warm"
        assert read_tree(mnt) == first
    forge.close()


def test_remount_with_different_tmp_dir_still_warm(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache), tmp=str(tmp_path / "t1")) as (mnt, _):
        read_tree(mnt)
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache), tmp=str(tmp_path / "t2")) as (mnt, _):
        assert (mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
    assert origin.data_fetches() == 0
    forge.close()


# ===========================================================================
# C. offline tolerance: warm cache serves with the origin dead
# ===========================================================================

_FAST = ("-o", "retries=1")     # trim the transport retry budget for dead-origin paths


def test_offline_warm_read_ok(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


def test_offline_warm_tree_walk_ok(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        first = read_tree(m.mnt)
        m.origin.kill()
        assert read_tree(m.mnt) == first
        assert sorted(os.listdir(m.mnt)) == ["hello", "link", "secret", "sub"]


@pytest.mark.timeout(180)
def test_offline_cold_read_fails_cleanly(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()          # warm ONE file only
        m.origin.kill()
        with pytest.raises(OSError) as e:
            (m.mnt / "secret").read_bytes()     # cold: never fetched
        assert e.value.errno == errno.EIO


def test_offline_cold_stat_ok_metadata_from_catalog(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        m.origin.kill()
        st = (m.mnt / "secret").stat()          # never read: pure catalog metadata
        assert st.st_size == len(b"trust me exactly, byte for byte\n")


@pytest.mark.timeout(180)
def test_offline_warm_still_ok_after_cold_failure(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        with pytest.raises(OSError):
            (m.mnt / "secret").read_bytes()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


@pytest.mark.timeout(240)
def test_origin_restart_makes_cold_file_readable(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        with pytest.raises(OSError):
            (m.mnt / "secret").read_bytes()
        m.origin.restart()
        # host blacklist snap-back is 2s doubling per consecutive failure — a
        # bounded retry loop rides it out.
        assert wait_read(m.mnt / "secret", 30) == b"trust me exactly, byte for byte\n"


def test_offline_getxattr_fqrn_ok(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        m.origin.kill()
        assert os.getxattr(m.mnt / "hello", "user.fqrn") == REPO.encode()


def test_offline_umount_is_clean(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        mnt = m.mnt
        _unmount(mnt)
        deadline = time.monotonic() + 10
        while os.path.ismount(str(mnt)) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not os.path.ismount(str(mnt)), "umount wedged with the origin dead"


# ===========================================================================
# D. on-disk cache corruption: official behavior = detect + refetch
# ===========================================================================

def test_corrupt_cached_entry_is_not_served(tmp_path, make_origin):
    # RETIRED DIVERGENCE: serve_from_cache() re-verifies every hit against the
    # entry's integrity sidecar (fetch.c) — tampered/bit-rotted local bytes are
    # purged and transparently refetched, never served.
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        blob = bytearray(ent.read_bytes())
        blob[6] ^= 0xFF
        ent.write_bytes(bytes(blob))
        assert (m.mnt / "secret").read_bytes() == data, "corrupt cache entry served as-is"


def test_corrupt_cached_entry_triggers_refetch(tmp_path, make_origin):
    # companion oracle to the test above — the damaged object must cost at
    # least one new origin fetch (purge + refetch).
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        blob = bytearray(ent.read_bytes())
        blob[0] ^= 0x01
        ent.write_bytes(bytes(blob))
        m.origin.reset_log()
        (m.mnt / "secret").read_bytes()
        assert m.origin.data_fetches(content_key(data)) >= 1


def test_corrupt_cached_entry_does_not_crash_mount(tmp_path, make_origin):
    # Actual-behavior guard: whatever is served, the mount must stay alive and
    # untouched objects must remain correct.
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        (m.mnt / "hello").read_bytes()
        ent = cache_entry(m.cache, content_key(b"trust me exactly, byte for byte\n"))
        blob = bytearray(ent.read_bytes())
        blob[3] ^= 0xFF
        ent.write_bytes(bytes(blob))
        try:
            (m.mnt / "secret").read_bytes()
        except OSError:
            pass                                    # a clean error is acceptable
        assert os.path.ismount(str(m.mnt))
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


def test_truncated_cached_entry_refetched_not_served_empty(tmp_path, make_origin):
    # RETIRED DIVERGENCE: the sidecar records the plaintext length, so a
    # truncated entry fails re-verification and is treated as a miss + refetch
    # instead of serving an empty file.
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        cache_entry(m.cache, content_key(data)).write_bytes(b"")
        assert (m.mnt / "secret").read_bytes() == data


def test_truncated_cached_entry_does_not_crash_mount(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        (m.mnt / "hello").read_bytes()
        cache_entry(m.cache, content_key(b"trust me exactly, byte for byte\n")).write_bytes(b"")
        try:
            (m.mnt / "secret").read_bytes()
        except OSError:
            pass
        assert os.path.ismount(str(m.mnt))
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


def test_deleted_cached_entry_transparent_refetch(tmp_path, make_origin):
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        cache_entry(m.cache, content_key(data)).unlink()
        m.origin.reset_log()
        assert (m.mnt / "secret").read_bytes() == data
        assert m.origin.data_fetches(content_key(data)) == 1


def test_deleted_entry_refetch_repopulates_cache(tmp_path, make_origin):
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        ent.unlink()
        (m.mnt / "secret").read_bytes()
        assert ent.is_file() and ent.read_bytes() == data
