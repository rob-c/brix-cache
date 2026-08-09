from split_continuation import reexport as _reexport
_reexport(globals(), "_test_file_api_helpers")

class TestStat:

    def test_stat_regular_file(self):
        """Stat a regular file: correct size and IS_READABLE flag."""
        content = b"stat me"
        p = disk(f"{PREFIX}stat_file.txt")
        open(p, "wb").write(content)
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_file.txt")
        assert status.ok, f"stat failed: {status.message}"
        assert info.size == len(content)
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_stat_directory(self):
        """Stat a directory: IS_DIR flag must be set."""
        p = disk(f"{PREFIX}stat_dir")
        os.makedirs(p, exist_ok=True)
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_dir")
        assert status.ok, f"stat dir failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR

    def test_stat_nonexistent_fails(self):
        """Stat of a nonexistent path must return an error."""
        fs = anon_fs()
        status, _ = fs.stat(f"/{PREFIX}ghost.txt")
        assert not status.ok, "Expected stat of nonexistent file to fail"

    def test_stat_root(self):
        """Stat the root directory: IS_DIR, no error."""
        fs = anon_fs()
        status, info = fs.stat("/")
        assert status.ok, f"stat root failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR

    def test_stat_size_after_write(self):
        """stat reflects updated size after writing."""
        content = b"x" * 4096
        p = disk(f"{PREFIX}stat_size.bin")
        open(p, "wb").write(content)
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_size.bin")
        assert status.ok
        assert info.size == 4096

    def test_stat_modtime_is_recent(self):
        """stat modtime is set to a plausible timestamp."""
        import time
        p = disk(f"{PREFIX}stat_mtime.txt")
        open(p, "w").write("hello")
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_mtime.txt")
        assert status.ok
        assert info.modtime > 0
        assert abs(info.modtime - time.time()) < 60, (
            f"modtime {info.modtime} suspiciously far from now"
        )

    def test_handle_stat_read_open(self):
        """File.stat() via handle returns correct size for a read-opened file."""
        content = b"handle stat data"
        p = disk(f"{PREFIX}hstat.bin")
        open(p, "wb").write(content)
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}hstat.bin", OpenFlags.READ)
        status, info = f.stat()
        assert status.ok, f"handle stat failed: {status.message}"
        assert info.size == len(content)
        f.close()

    def test_stat_gsi(self):
        """Stat a file over the GSI endpoint."""
        content = b"gsi stat test"
        p = disk(f"{PREFIX}gsi_stat.txt")
        open(p, "wb").write(content)
        fs = gsi_fs()
        status, info = fs.stat(f"/{PREFIX}gsi_stat.txt")
        assert status.ok, f"GSI stat failed: {status.message}"
        assert info.size == len(content)


# ---------------------------------------------------------------------------
# TestDirList — directory listing
# ---------------------------------------------------------------------------

class TestDirList:

    def _names(self, listing) -> set:
        return {e.name for e in listing} if listing else set()

    def test_dirlist_root(self):
        """Listing the root succeeds and returns at least one entry."""
        open(disk(f"{PREFIX}dl_file.txt"), "w").write("x")
        fs = anon_fs()
        status, listing = fs.dirlist("/")
        assert status.ok, f"dirlist failed: {status.message}"
        names = self._names(listing)
        assert f"{PREFIX}dl_file.txt" in names

    def test_dirlist_with_stat(self):
        """DirListFlags.STAT provides statinfo for each entry."""
        p = disk(f"{PREFIX}dl_stat.bin")
        open(p, "wb").write(b"y" * 42)
        fs = anon_fs()
        status, listing = fs.dirlist("/", DirListFlags.STAT)
        assert status.ok
        entry = next(
            (e for e in listing if e.name == f"{PREFIX}dl_stat.bin"), None
        )
        assert entry is not None, "Expected file in listing"
        assert entry.statinfo is not None
        assert entry.statinfo.size == 42

    def test_dirlist_subdirectory(self):
        """List a subdirectory; only its immediate children appear."""
        sub = disk(f"{PREFIX}dl_sub")
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, "child.txt"), "w").write("c")
        os.makedirs(os.path.join(sub, "nested"), exist_ok=True)
        fs = anon_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_sub")
        assert status.ok, f"dirlist subdir failed: {status.message}"
        names = self._names(listing)
        assert "child.txt" in names
        assert "nested" in names

    def test_dirlist_empty_directory(self):
        """Listing an empty directory succeeds with zero entries."""
        os.makedirs(disk(f"{PREFIX}dl_empty"), exist_ok=True)
        fs = anon_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_empty")
        assert status.ok, f"dirlist empty dir failed: {status.message}"
        assert len(list(listing)) == 0

    def test_dirlist_nonexistent_fails(self):
        """Listing a nonexistent directory must fail."""
        fs = anon_fs()
        status, _ = fs.dirlist(f"/{PREFIX}dl_ghost")
        assert not status.ok, "Expected dirlist of nonexistent dir to fail"

    def test_dirlist_distinguishes_files_and_dirs(self):
        """STAT listing marks directories with IS_DIR flag."""
        sub = disk(f"{PREFIX}dl_types")
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, "file.txt"), "w").write("f")
        os.makedirs(os.path.join(sub, "subdir"), exist_ok=True)
        fs = anon_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_types", DirListFlags.STAT)
        assert status.ok
        by_name = {e.name: e for e in listing}
        assert by_name["file.txt"].statinfo.flags & StatInfoFlags.IS_DIR == 0
        assert by_name["subdir"].statinfo.flags & StatInfoFlags.IS_DIR

    def test_dirlist_gsi(self):
        """List a directory over the GSI endpoint."""
        sub = disk(f"{PREFIX}dl_gsi")
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, "gsi_child.txt"), "w").write("g")
        fs = gsi_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_gsi")
        assert status.ok, f"GSI dirlist failed: {status.message}"
        assert "gsi_child.txt" in self._names(listing)


# ---------------------------------------------------------------------------
# TestMkdir — directory creation (extended)
# ---------------------------------------------------------------------------
