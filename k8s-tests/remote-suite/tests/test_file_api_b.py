from _test_file_api_helpers import *  # noqa: F401,F403  (Phase-38 split shared header)

class TestMkdir:

    def test_mkdir_basic(self):
        fs = anon_fs()
        status, _ = fs.mkdir(f"/{PREFIX}mkdir_basic", MkDirFlags.NONE)
        assert status.ok, f"mkdir failed: {status.message}"
        assert os.path.isdir(disk(f"{PREFIX}mkdir_basic"))

    def test_mkdir_nested_with_makepath(self):
        fs = anon_fs()
        status, _ = fs.mkdir(
            f"/{PREFIX}mkdir_nested/a/b/c", MkDirFlags.MAKEPATH
        )
        assert status.ok, f"mkdir -p failed: {status.message}"
        assert os.path.isdir(disk(f"{PREFIX}mkdir_nested/a/b/c"))

    def test_mkdir_idempotent(self):
        """mkdir on an existing directory: either idempotent OK or the
        POSIX-correct kXR_ItExists (3018).  Stock xrootd is idempotent only for a
        directory IT created in the same process (oss namespace cache); OUR server
        is deterministically POSIX-correct (ItExists).  Both conform — a failure
        must be the exists error.  See test_conf_errors.py."""
        os.makedirs(disk(f"{PREFIX}mkdir_idem"), exist_ok=True)
        fs = anon_fs()
        status, _ = fs.mkdir(f"/{PREFIX}mkdir_idem", MkDirFlags.NONE)
        assert status.ok or status.errno == 3018, \
            f"mkdir on existing gave unexpected error: {status.message}"

    def test_mkdir_gsi(self):
        fs = gsi_fs()
        status, _ = fs.mkdir(f"/{PREFIX}mkdir_gsi", MkDirFlags.NONE)
        assert status.ok, f"GSI mkdir failed: {status.message}"
        assert os.path.isdir(disk(f"{PREFIX}mkdir_gsi"))


# ---------------------------------------------------------------------------
# TestRmdir — directory removal (extended)
# ---------------------------------------------------------------------------

class TestRmdir:

    def test_rmdir_empty(self):
        os.makedirs(disk(f"{PREFIX}rmdir_empty"), exist_ok=True)
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_empty")
        assert status.ok, f"rmdir failed: {status.message}"
        assert not os.path.exists(disk(f"{PREFIX}rmdir_empty"))

    def test_rmdir_nonempty_fails(self):
        d = disk(f"{PREFIX}rmdir_full")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "f.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_full")
        assert not status.ok, "Expected rmdir of non-empty dir to fail"

    def test_rmdir_nonexistent_is_idempotent(self):
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_ghost")
        assert status.ok, f"rmdir of nonexistent dir should be idempotent: {status.message}"

    def test_rmdir_on_file_fails(self):
        """rmdir on a regular file must fail."""
        open(disk(f"{PREFIX}rmdir_isfile.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_isfile.txt")
        assert not status.ok, "Expected rmdir on a file to fail"

    def test_rmdir_gsi(self):
        os.makedirs(disk(f"{PREFIX}rmdir_gsi"), exist_ok=True)
        fs = gsi_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_gsi")
        assert status.ok, f"GSI rmdir failed: {status.message}"


# ---------------------------------------------------------------------------
# TestRm — file removal (extended)
# ---------------------------------------------------------------------------

class TestRm:

    def test_rm_file(self):
        p = disk(f"{PREFIX}rm_file.txt")
        open(p, "w").write("delete me")
        fs = anon_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_file.txt")
        assert status.ok, f"rm failed: {status.message}"
        assert not os.path.exists(p)

    def test_rm_nonexistent_fails(self):
        fs = anon_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_ghost.txt")
        assert not status.ok, "Expected rm of nonexistent file to fail"

    def test_rm_empty_directory(self):
        """Reference XRootD treats rm of an empty directory like rmdir."""
        os.makedirs(disk(f"{PREFIX}rm_dir"), exist_ok=True)
        fs = anon_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_dir")
        assert status.ok, f"Expected rm on empty directory to succeed: {status.message}"
        assert not os.path.exists(disk(f"{PREFIX}rm_dir"))

    def test_rm_gsi(self):
        p = disk(f"{PREFIX}rm_gsi.txt")
        open(p, "w").write("gsi delete me")
        fs = gsi_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_gsi.txt")
        assert status.ok, f"GSI rm failed: {status.message}"
        assert not os.path.exists(p)

    def test_rm_then_recreate(self):
        """After rm, the same name can be created again."""
        p = disk(f"{PREFIX}rm_recr.txt")
        open(p, "w").write("v1")
        fs = anon_fs()
        fs.rm(f"/{PREFIX}rm_recr.txt")
        assert not os.path.exists(p)
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}rm_recr.txt",
                            OpenFlags.NEW | OpenFlags.UPDATE)
        assert status.ok, "Expected re-create after rm to succeed"
        f.write(b"v2", offset=0)
        f.close()
        assert open(p, "rb").read() == b"v2"


# ---------------------------------------------------------------------------
# TestMv — rename / move (extended)
# ---------------------------------------------------------------------------

class TestMv:

    def test_mv_file(self):
        src = disk(f"{PREFIX}mv_src.txt")
        dst = disk(f"{PREFIX}mv_dst.txt")
        open(src, "w").write("move me")
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_src.txt", f"/{PREFIX}mv_dst.txt")
        assert status.ok, f"mv failed: {status.message}"
        assert not os.path.exists(src)
        assert open(dst).read() == "move me"

    def test_mv_directory(self):
        src = disk(f"{PREFIX}mv_dir_src")
        dst = disk(f"{PREFIX}mv_dir_dst")
        os.makedirs(src, exist_ok=True)
        open(os.path.join(src, "f.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_dir_src", f"/{PREFIX}mv_dir_dst")
        assert status.ok, f"mv dir failed: {status.message}"
        assert not os.path.exists(src)
        assert os.path.isdir(dst)
        assert os.path.exists(os.path.join(dst, "f.txt"))

    def test_mv_overwrites_destination(self):
        """mv onto an existing file replaces it (rename() semantics)."""
        src = disk(f"{PREFIX}mv_ow_src.txt")
        dst = disk(f"{PREFIX}mv_ow_dst.txt")
        open(src, "wb").write(b"source content")
        open(dst, "wb").write(b"old destination")
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_ow_src.txt", f"/{PREFIX}mv_ow_dst.txt")
        assert status.ok, f"mv overwrite failed: {status.message}"
        assert not os.path.exists(src)
        assert open(dst, "rb").read() == b"source content"

    def test_mv_nonexistent_source_fails(self):
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_ghost.txt", f"/{PREFIX}mv_nowhere.txt")
        assert not status.ok, "Expected mv of nonexistent source to fail"

    def test_mv_gsi(self):
        src = disk(f"{PREFIX}mv_gsi_src.txt")
        dst = disk(f"{PREFIX}mv_gsi_dst.txt")
        open(src, "w").write("gsi move")
        fs = gsi_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_gsi_src.txt", f"/{PREFIX}mv_gsi_dst.txt")
        assert status.ok, f"GSI mv failed: {status.message}"
        assert not os.path.exists(src)
        assert os.path.exists(dst)


# ---------------------------------------------------------------------------
# TestChmod — permission changes (extended)
# ---------------------------------------------------------------------------

class TestChmod:

    def test_chmod_file_to_readonly(self):
        p = disk(f"{PREFIX}chmod_ro.txt")
        open(p, "w").write("data")
        os.chmod(p, 0o644)
        fs = anon_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_ro.txt",
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        assert status.ok, f"chmod failed: {status.message}"
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o444

    def test_chmod_file_to_executable(self):
        p = disk(f"{PREFIX}chmod_exec.sh")
        open(p, "w").write("#!/bin/sh\n")
        os.chmod(p, 0o644)
        fs = anon_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_exec.sh",
            AccessMode.UR | AccessMode.UW | AccessMode.UX |
            AccessMode.GR | AccessMode.GX |
            AccessMode.OR | AccessMode.OX,
        )
        assert status.ok
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o755

    def test_chmod_directory(self):
        d = disk(f"{PREFIX}chmod_dir")
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o755)
        fs = anon_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_dir",
            AccessMode.UR | AccessMode.UW | AccessMode.UX |
            AccessMode.GR | AccessMode.GX,
        )
        assert status.ok, f"chmod dir failed: {status.message}"
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o750

    def test_chmod_nonexistent_fails(self):
        fs = anon_fs()
        status, _ = fs.chmod(f"/{PREFIX}chmod_ghost.txt", AccessMode.UR)
        assert not status.ok, "Expected chmod of nonexistent path to fail"

    def test_chmod_stat_reflects_change(self):
        """After chmod, stat flags show the new permissions."""
        p = disk(f"{PREFIX}chmod_stat.txt")
        open(p, "wb").write(b"data")
        os.chmod(p, 0o000)          # no permissions
        fs = anon_fs()
        fs.chmod(
            f"/{PREFIX}chmod_stat.txt",
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        status, info = fs.stat(f"/{PREFIX}chmod_stat.txt")
        assert status.ok
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_chmod_gsi(self):
        p = disk(f"{PREFIX}chmod_gsi.txt")
        open(p, "w").write("gsi chmod")
        os.chmod(p, 0o644)
        fs = gsi_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_gsi.txt",
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        assert status.ok, f"GSI chmod failed: {status.message}"
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o444


# ---------------------------------------------------------------------------
# TestPathSecurity — path traversal boundaries
# ---------------------------------------------------------------------------

class TestPathSecurity:

    def test_open_dotdot_path_rejected(self):
        """Paths containing '..' must be rejected at open."""
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//../../etc/passwd", OpenFlags.READ)
        assert not status.ok, "Expected .. traversal to be rejected"

    def test_stat_dotdot_path_rejected(self):
        """Paths containing '..' must be rejected at stat."""
        fs = anon_fs()
        status, _ = fs.stat("/../../etc/passwd")
        assert not status.ok, "Expected .. traversal in stat to be rejected"

    def test_rm_dotdot_path_rejected(self):
        """rm with '..' in path must be rejected."""
        fs = anon_fs()
        status, _ = fs.rm("/../../tmp/something")
        assert not status.ok, "Expected .. traversal in rm to be rejected"

    def test_mkdir_dotdot_path_rejected(self):
        """mkdir with '..' must be rejected."""
        fs = anon_fs()
        status, _ = fs.mkdir("/../../tmp/evil", MkDirFlags.MAKEPATH)
        assert not status.ok, "Expected .. traversal in mkdir to be rejected"
