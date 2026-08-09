from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_catalog_helpers")

def test_getattr_regular_file_type(main_mnt):
    assert st_mod.S_ISREG(os.lstat(main_mnt / "sizes" / "s1").st_mode)


def test_getattr_directory_type(main_mnt):
    assert st_mod.S_ISDIR(os.lstat(main_mnt / "sizes").st_mode)


def test_getattr_symlink_type(main_mnt):
    assert st_mod.S_ISLNK(os.lstat(main_mnt / "sym" / "rel").st_mode)


def test_getattr_root_is_directory(main_mnt):
    # FUSE "/" maps to the catalog root entry "" (brixcvmfs.c cat_path).
    st = os.stat(main_mnt)
    assert st_mod.S_ISDIR(st.st_mode)
    assert st_mod.S_IMODE(st.st_mode) == 0o755
    assert st.st_nlink == 2


@pytest.mark.parametrize("n", SIZES)
def test_getattr_size_exact(main_mnt, n):
    assert os.stat(main_mnt / "sizes" / f"s{n}").st_size == n


def test_read_matches_size(main_mnt):
    assert (main_mnt / "sizes" / "s65537").read_bytes() == b"x" * 65537
    assert (main_mnt / "sizes" / "s0").read_bytes() == b""


@pytest.mark.parametrize("name,mode", sorted(FILE_MODES.items()))
def test_getattr_file_mode_bits_surfaced(main_mnt, name, mode):
    # brixcvmfs surfaces st_mode verbatim from the catalog (brixcvmfs.c:209),
    # including setuid/setgid/sticky. The mount itself is nosuid (unprivileged
    # FUSE), so the bits are visible in stat but never effective — matching
    # official CVMFS, which also stores/serves the published mode bits.
    assert st_mod.S_IMODE(os.lstat(main_mnt / "modes" / name).st_mode) == mode


@pytest.mark.parametrize("name,mode", sorted(DIR_MODES.items()))
def test_getattr_dir_mode_bits_surfaced(main_mnt, name, mode):
    assert st_mod.S_IMODE(os.lstat(main_mnt / "modes" / name).st_mode) == mode


def test_getattr_uid0_squashed_to_mount_user(main_mnt):
    # catalog uid 0 -> getuid() (brixcvmfs.c:212) — matches official's
    # mount-user ownership for the common publish-as-root case.
    assert os.stat(main_mnt / "owner" / "squash").st_uid == os.getuid()


def test_getattr_gid0_squashed_to_mount_group(main_mnt):
    assert os.stat(main_mnt / "owner" / "squash").st_gid == os.getgid()


def test_getattr_nonzero_uid_surfaced_verbatim(main_mnt):
    # Actual brix behavior: st_uid = e.uid ? e.uid : getuid().
    assert os.stat(main_mnt / "owner" / "alien").st_uid == ALIEN_UID
    assert os.stat(main_mnt / "owner" / "alien").st_gid == ALIEN_GID


@pytest.mark.xfail(strict=True, reason="brix surfaces nonzero catalog uid")
def test_official_uid_squash_all_entries(main_mnt):
    # DIVERGENCE: official CVMFS by default presents EVERY entry as owned by
    # the mounting user (catalog uid/gid ignored; cvmfs docs "Repository
    # Contents"/claim_ownership). brix squashes only uid==0 and surfaces
    # nonzero catalog uids verbatim (brixcvmfs.c:212).
    assert os.stat(main_mnt / "owner" / "alien").st_uid == os.getuid()


@pytest.mark.xfail(strict=True, reason="brix surfaces nonzero catalog gid")
def test_official_gid_squash_all_entries(main_mnt):
    # DIVERGENCE: same as uid — official squashes gid to the mount user's group.
    assert os.stat(main_mnt / "owner" / "alien").st_gid == os.getgid()


def test_getattr_file_mtime_surfaced(main_mnt):
    assert os.stat(main_mnt / "times" / "epoch").st_mtime == 1234567890


def test_getattr_dir_mtime_surfaced(main_mnt):
    assert os.stat(main_mnt / "times").st_mtime == 1111111111


def test_getattr_linkcount_default_one(main_mnt):
    assert os.stat(main_mnt / "links" / "one").st_nlink == 1


def test_getattr_linkcount_surfaced(main_mnt):
    # low 32 bits of the hardlinks column (catalog.c:63-65)
    assert os.stat(main_mnt / "links" / "five").st_nlink == 5


def test_getattr_dir_nlink_always_two(main_mnt):
    # brixcvmfs hardcodes st_nlink=2 for dirs regardless of child count
    # (brixcvmfs.c:211); official cvmfs does the same for catalog dirs.
    assert os.stat(main_mnt / "names").st_nlink == 2
    assert os.stat(main_mnt / "modes" / "sticky_d").st_nlink == 2


def test_getattr_missing_path_enoent(main_mnt):
    with pytest.raises(FileNotFoundError):
        os.stat(main_mnt / "no-such-entry")


def test_stat_follows_symlink_lstat_does_not(main_mnt):
    s, l = os.stat(main_mnt / "sym" / "rel"), os.lstat(main_mnt / "sym" / "rel")
    assert st_mod.S_ISREG(s.st_mode) and st_mod.S_ISLNK(l.st_mode)
    assert s.st_size == len(b"sym target\n")


# --------------------------------------------------------------------------- #
# name corpus
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [n for _, n in NAME_CORPUS],
                         ids=[i for i, _ in NAME_CORPUS])
def test_name_lookup_and_read(main_mnt, name):
    p = main_mnt / "names" / name
    assert os.stat(p).st_size == len(name.encode())
    assert p.read_bytes() == name.encode()


def test_names_readdir_set_equality(main_mnt):
    # dot-prefixed names MUST be listed (readdir hides nothing).
    assert sorted(os.listdir(main_mnt / "names")) == sorted(n for _, n in NAME_CORPUS)


def test_case_sensitive_names_coexist(main_mnt):
    assert (main_mnt / "names" / "Case").read_bytes() == b"Case"
    assert (main_mnt / "names" / "case").read_bytes() == b"case"


def test_unicode_composed_and_combining_are_distinct(main_mnt):
    # NFC "café…" and the NFD combining variant are different byte strings —
    # both coexist and each resolves to its own content (no normalization).
    names = dict(NAME_CORPUS)
    for name in (names["utf8"], names["combining"]):
        assert (main_mnt / "names" / name).read_bytes() == name.encode()


def test_255_byte_name_round_trips(main_mnt):
    # catalog.h dirent name[256] holds exactly 255 bytes + NUL.
    name = "n" * 255
    assert os.stat(main_mnt / "names" / name).st_size == 255
    assert name in os.listdir(main_mnt / "names")


# --------------------------------------------------------------------------- #
# md5path sign edge cases
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name", [*NEG_M1, *NEG_M2, NEG_BOTH])
def test_md5path_negative_int64_lookup(main_mnt, name):
    # md5path halves are SIGNED little-endian int64 (catalog.c:26-31); a lookup
    # failure here would be the classic unsigned-vs-signed key mismatch bug.
    half = 0 if name.startswith("hb0") else 1
    if name.startswith("hbb"):
        assert md5path(f"/m/{name}")[0] < 0 and md5path(f"/m/{name}")[1] < 0
    else:
        assert md5path(f"/m/{name}")[half] < 0
    assert (main_mnt / "m" / name).read_bytes() == name.encode()


def test_md5path_negative_dir_readdir(main_mnt):
    assert sorted(os.listdir(main_mnt / "m")) == sorted([*NEG_M1, *NEG_M2, NEG_BOTH])


# --------------------------------------------------------------------------- #
# deep paths
# --------------------------------------------------------------------------- #


def test_deep_path_stat(main_mnt):
    st = os.stat(_deep_path(main_mnt) / "leaf.txt")
    assert st.st_size == len(b"deep leaf\n")


def test_deep_path_read(main_mnt):
    assert (_deep_path(main_mnt) / "leaf.txt").read_bytes() == b"deep leaf\n"


def test_deep_path_mid_level_readdir(main_mnt):
    mid = main_mnt / "deep"
    for i in range(DEEP_LEVELS // 2):
        mid = mid / f"d{i:02d}"
    assert os.listdir(mid) == [f"d{DEEP_LEVELS // 2:02d}"]


# --------------------------------------------------------------------------- #
# symlinks
# --------------------------------------------------------------------------- #

def test_readlink_relative_exact(main_mnt):
    assert os.readlink(main_mnt / "sym" / "rel") == "target.txt"


def test_read_through_relative_symlink(main_mnt):
    assert (main_mnt / "sym" / "rel").read_bytes() == b"sym target\n"


def test_readlink_absolute_exact(main_mnt):
    assert os.readlink(main_mnt / "sym" / "abs") == "/absolutely/nowhere"


def test_dangling_symlink_lstat_ok_stat_enoent(main_mnt):
    assert st_mod.S_ISLNK(os.lstat(main_mnt / "sym" / "dang").st_mode)
    with pytest.raises(FileNotFoundError):
        os.stat(main_mnt / "sym" / "dang")


def test_symlink_to_dir_traversal(main_mnt):
    assert (main_mnt / "sym" / "dirlink" / "inside.txt").read_bytes() == b"inside\n"
    assert os.listdir(main_mnt / "sym" / "dirlink") == ["inside.txt"]


def test_symlink_loop_eloop_not_hang(main_mnt):
    with pytest.raises(OSError) as e:
        os.stat(main_mnt / "sym" / "loopa")
    assert e.value.errno == errno.ELOOP


def test_symlink_self_loop_eloop(main_mnt):
    with pytest.raises(OSError) as e:
        os.stat(main_mnt / "sym" / "self")
    assert e.value.errno == errno.ELOOP


def test_long_symlink_target_exact(main_mnt):
    # 999-byte target, just under the 1024-byte dirent symlink cap
    assert os.readlink(main_mnt / "sym" / "long") == LONG_TARGET


def test_symlink_size_is_target_length(main_mnt):
    assert os.lstat(main_mnt / "sym" / "long").st_size == len(LONG_TARGET)
    assert os.lstat(main_mnt / "sym" / "rel").st_size == len("target.txt")


# --------------------------------------------------------------------------- #
# readdir completeness
# --------------------------------------------------------------------------- #

def test_readdir_empty_dir(rdir_mnt):
    assert os.listdir(rdir_mnt / "empty") == []
    assert st_mod.S_ISDIR(os.stat(rdir_mnt / "empty").st_mode)


def test_readdir_single_entry(rdir_mnt):
    assert os.listdir(rdir_mnt / "one") == ["only"]


def test_readdir_100_entries(rdir_mnt):
    assert set(os.listdir(rdir_mnt / "hundred")) == {f"f{i:03d}" for i in range(100)}


def test_readdir_1000_entries(rdir_mnt):
    names = os.listdir(rdir_mnt / "thousand")
    assert len(names) == 1000
    assert set(names) == {f"g{i:04d}" for i in range(1000)}


def test_readdir_root_set_equality(rdir_mnt):
    assert sorted(os.listdir(rdir_mnt)) == ["empty", "hundred", "mixed", "one",
                                            "thousand"]


def test_readdir_stable_across_rereads(rdir_mnt):
    a, b = sorted(os.listdir(rdir_mnt / "hundred")), sorted(os.listdir(rdir_mnt / "hundred"))
    assert a == b


def test_readdir_emits_dot_and_dotdot(rdir_mnt):
    # brixcvmfs_op_readdir fills "." and ".." explicitly (brixcvmfs.c:229-230);
    # python's listdir filters them, so ask ls -a.
    out = subprocess.run(["ls", "-a", str(rdir_mnt / "one")],
                         capture_output=True, text=True, check=True).stdout.split()
    assert "." in out and ".." in out and "only" in out


def test_readdir_entry_types(rdir_mnt):
    # readdir passes a NULL stat to the filler (d_type DT_UNKNOWN), so type
    # classification falls back to per-entry stat — assert it lands right.
    ents = {e.name: e for e in os.scandir(rdir_mnt / "mixed")}
    assert set(ents) == {"f", "d", "l"}
    assert ents["f"].is_file(follow_symlinks=False)
    assert ents["d"].is_dir(follow_symlinks=False)
    assert ents["l"].is_symlink()


# --------------------------------------------------------------------------- #
# nested catalogs — known-good transitions
# --------------------------------------------------------------------------- #

def test_nested_mountpoint_stats_as_dir(nest_mnt):
    st = os.stat(nest_mnt / "n1")
    assert st_mod.S_ISDIR(st.st_mode) and st_mod.S_IMODE(st.st_mode) == 0o755


def test_nested_root_readdir_lists_mountpoint(nest_mnt):
    assert sorted(os.listdir(nest_mnt)) == ["marker.txt", "n1"]


def test_nested_one_level_file_read(nest_mnt):
    assert (nest_mnt / "n1" / "inner.txt").read_bytes() == b"one deep\n"


def test_nested_subdir_stat(nest_mnt):
    assert st_mod.S_ISDIR(os.stat(nest_mnt / "n1" / "sub").st_mode)


def test_nested_subdir_file_read(nest_mnt):
    assert (nest_mnt / "n1" / "sub" / "deep.txt").read_bytes() == b"below mount\n"


def test_nested_two_levels_file_read(nest_mnt):
    # crosses two transitions: root -> /n1 -> /n1/n2 (client.c resolve loop)
    assert (nest_mnt / "n1" / "n2" / "two.txt").read_bytes() == b"two deep\n"


def test_nested_two_levels_deep_stat(nest_mnt):
    st = os.stat(nest_mnt / "n1" / "n2" / "d" / "leaf.txt")
    assert st.st_size == len(b"nested leaf\n")


def test_inner_mountpoint_stats_as_dir(nest_mnt):
    # /n1/n2's mount row lives in n1's catalog — one descent, then lookup
    assert st_mod.S_ISDIR(os.stat(nest_mnt / "n1" / "n2").st_mode)


def test_readdir_nested_mountpoint_lists_children(nest_mnt):
    # Official CVMFS lists a nested mountpoint's children (it attaches the
    # nested catalog for the listing). cvmfs_client_readdir descends via
    # longest_nested_prefix(include_self=1) so /n1 lists from n1's catalog.
    assert sorted(os.listdir(nest_mnt / "n1")) == ["inner.txt", "n2", "sub"]


def test_readdir_below_nested_mountpoint_lists_children(nest_mnt):
    # Same descent one level down — /n1/sub's children live in n1's catalog,
    # and readdir now resolves into it.
    assert os.listdir(nest_mnt / "n1" / "sub") == ["deep.txt"]


# --------------------------------------------------------------------------- #
# nested catalogs — tampered (never crash, never wrong bytes)
# --------------------------------------------------------------------------- #

def test_tamper_control_intact_nested_works(evil_mnt):
    assert (evil_mnt / "ok" / "f").read_bytes() == b"ok payload\n"


def test_tamper_missing_nested_cas_object_enoent(evil_mnt):
    # nested row present, CAS 'C' object deleted: descent fails, fallback
    # lookup in the root catalog misses -> ENOENT (client.c:113 break path).
    with pytest.raises(OSError) as e:
        os.stat(evil_mnt / "gone" / "f")
    assert e.value.errno in (errno.ENOENT, errno.EIO)


def test_tamper_missing_nested_cas_mountpoint_still_dir(evil_mnt):
    # the mountpoint row itself lives in the (intact) root catalog
    assert st_mod.S_ISDIR(os.stat(evil_mnt / "gone").st_mode)


def test_tamper_corrupt_nested_cas_refused(evil_mnt):
    # stored nested-catalog bytes flipped: content hash mismatch -> the fetch
    # layer refuses the object; children are unreachable, never wrong bytes.
    with pytest.raises(OSError) as e:
        os.stat(evil_mnt / "corrupt" / "f")
    assert e.value.errno in (errno.ENOENT, errno.EIO)


def test_tamper_root_listing_survives(evil_mnt):
    assert sorted(os.listdir(evil_mnt)) == ["corrupt", "gone", "ok"]
