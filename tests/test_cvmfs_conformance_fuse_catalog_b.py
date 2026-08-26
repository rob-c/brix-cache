from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_catalog_helpers")

pytestmark = pytest.mark.xdist_group("test_cvmfs_conformance_fuse_catalog")

def test_craft_control_plain_file_reads(craft_mnt):
    # proves the hand-built root catalog itself is well-formed
    assert (craft_mnt / "plain").read_bytes() == b"plain payload\n"


def test_craft_mountpoint_flag_without_row_stats(craft_mnt):
    # DIR_NESTED_MOUNT flag set but no nested_catalogs row: the dir must still
    # stat cleanly (longest_nested_prefix simply finds no row).
    assert st_mod.S_ISDIR(os.stat(craft_mnt / "norow").st_mode)


def test_craft_mountpoint_without_row_child_enoent(craft_mnt):
    with pytest.raises(FileNotFoundError):
        os.stat(craft_mnt / "norow" / "child")


def test_craft_bogus_nested_hash_mountpoint_stats(craft_mnt):
    assert st_mod.S_ISDIR(os.stat(craft_mnt / "bogus").st_mode)


def test_craft_bogus_nested_hash_child_refused(craft_mnt):
    # nested row points at a nonexistent catalog hash: descent fetch 404s,
    # fallback root lookup misses -> ENOENT/EIO, never fabricated entries.
    with pytest.raises(OSError) as e:
        os.stat(craft_mnt / "bogus" / "deep" / "file")
    assert e.value.errno in (errno.ENOENT, errno.EIO)


def test_craft_bogus_nested_hash_readdir_empty_not_crash(craft_mnt):
    assert os.listdir(craft_mnt / "bogus") == []
    assert sorted(os.listdir(craft_mnt)) == ["bogus", "norow", "plain"]


# --------------------------------------------------------------------------- #
# whole-tree stat walk vs forged truth
# --------------------------------------------------------------------------- #


def test_stat_walk_whole_tree_matches_forged_truth(main_mnt):
    # every lstat field across the entire main tree vs the forge spec
    checked = _assert_subtree(main_mnt, _main_tree())
    assert checked > 80          # sanity: the walk actually covered the tree
