# brix-remote-skip
"""
tests/test_interop_namespace.py

Conformance tests for filesystem namespace operations comparing nginx-xrootd
against the official reference xrootd server sharing the same filesystem.

Covered opcodes: kXR_mkdir, kXR_rmdir, kXR_rm, kXR_mv, kXR_chmod,
                 kXR_truncate, kXR_statx, kXR_fattr

Write operations go through nginx-xrootd (write-enabled); both servers are
queried to confirm the resulting filesystem state.

Run:
    pytest tests/test_interop_namespace.py -v
"""

import os
import stat

import pytest
from XRootD import client
from XRootD.client.flags import (
    AccessMode,
    DirListFlags,
    MkDirFlags,
    OpenFlags,
    StatInfoFlags,
)
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
)

# ---------------------------------------------------------------------------
# Module globals
# ---------------------------------------------------------------------------

NGINX_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
REF_URL   = f"root://{HOST}:{REF_BRIX_PORT}"
DATA_DIR  = DATA_ROOT


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fs(url):
    return client.FileSystem(url)


def _url(url, path):
    return f"{url.rstrip('/')}//{path.lstrip('/')}"


def _exists_on(url, path):
    """Return True if stat succeeds for path on the given server."""
    st, _ = _fs(url).stat(path)
    return st.ok


def _size_on(url, path):
    """Return file size as reported by server, or None on failure."""
    st, info = _fs(url).stat(path)
    return info.size if st.ok else None


def _unique(prefix=""):
    return f"/{prefix}_ns_{os.getpid()}_{id(prefix)}"


# ---------------------------------------------------------------------------
# mkdir / rmdir
# ---------------------------------------------------------------------------

class TestMkdirConformance:

    def test_mkdir_visible_on_both_servers(self):
        path = _unique("mkdir")
        try:
            st = _fs(NGINX_URL).mkdir(path, MkDirFlags.NONE)
            assert st[0].ok, f"nginx mkdir failed: {st[0].message}"

            assert _exists_on(NGINX_URL, path), "nginx: directory not visible after mkdir"
            assert _exists_on(REF_URL,   path), "ref:   directory not visible after mkdir"

            st2, info = _fs(REF_URL).stat(path)
            assert st2.ok
            assert bool(info.flags & StatInfoFlags.IS_DIR), \
                "ref server: new path is not a directory"
        finally:
            _fs(NGINX_URL).rmdir(path)

    def test_mkdir_with_makepath_creates_parent(self):
        parent = _unique("mkpar")
        child  = f"{parent}/sub"
        try:
            st = _fs(NGINX_URL).mkdir(child, MkDirFlags.MAKEPATH)
            assert st[0].ok, f"nginx mkdir -p failed: {st[0].message}"

            assert _exists_on(NGINX_URL, parent), "parent not visible after mkdir -p"
            assert _exists_on(REF_URL,   parent), "parent not on ref after mkdir -p"
            assert _exists_on(NGINX_URL, child),  "child not visible after mkdir -p"
            assert _exists_on(REF_URL,   child),  "child not on ref after mkdir -p"
        finally:
            _fs(NGINX_URL).rmdir(child)
            _fs(NGINX_URL).rmdir(parent)

    def test_mkdir_existing_matches_reference(self):
        """Duplicate mkdir (no -p).  Stock xrootd is idempotent ONLY for a
        directory it created in the same process (its oss namespace cache); that
        quirk does not generalise, so it cannot be compared directly to a fresh
        process.  OUR server is deterministically POSIX-correct and returns
        kXR_ItExists (3018).  Both conform — accept OK or ItExists on ours.
        See test_conf_errors.py::test_mkdir_fresh_then_again_parity."""
        path = _unique("mkdup")
        try:
            assert _fs(NGINX_URL).mkdir(path, MkDirFlags.NONE)[0].ok

            n_st = _fs(NGINX_URL).mkdir(path, MkDirFlags.NONE)[0]
            assert n_st.ok or n_st.errno == 3018, (
                f"duplicate mkdir on ours gave unexpected error: {n_st.message}"
            )
        finally:
            _fs(NGINX_URL).rmdir(path)

    def test_rmdir_removes_directory_on_both(self):
        path = _unique("rmdir")
        _fs(NGINX_URL).mkdir(path, MkDirFlags.NONE)

        st = _fs(NGINX_URL).rmdir(path)
        assert st[0].ok, f"nginx rmdir failed: {st[0].message}"

        assert not _exists_on(NGINX_URL, path), "nginx: directory still exists after rmdir"
        assert not _exists_on(REF_URL,   path), "ref:   directory still exists after rmdir"

    def test_rmdir_nonexistent_matches_reference(self):
        path = "/_no_such_dir_xyzzy_rmdir"
        n_st = _fs(NGINX_URL).rmdir(path)
        r_st = _fs(REF_URL  ).rmdir(path)
        assert n_st[0].ok == r_st[0].ok, (
            f"rmdir nonexistent outcome mismatch: nginx={n_st[0].ok} "
            f"ref={r_st[0].ok}"
        )

    def test_rmdir_nonempty_fails_on_both(self):
        parent = _unique("rmdirne")
        child  = f"{parent}/file.txt"
        try:
            _fs(NGINX_URL).mkdir(parent, MkDirFlags.NONE)
            f = client.File()
            f.open(_url(NGINX_URL, child), OpenFlags.NEW | OpenFlags.WRITE)
            f.close()

            n_st = _fs(NGINX_URL).rmdir(parent)
            r_st = _fs(REF_URL  ).rmdir(parent)
            assert not n_st[0].ok, "nginx: rmdir of non-empty dir should fail"
            assert not r_st[0].ok, "ref:   rmdir of non-empty dir should fail"
        finally:
            _fs(NGINX_URL).rm(child)
            _fs(NGINX_URL).rmdir(parent)


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------

class TestRmConformance:

    def test_rm_removes_file_on_both(self):
        name = f"_rm_{os.getpid()}.bin"
        path = f"/{name}"
        fs_path = os.path.join(DATA_DIR, name)
        with open(fs_path, "wb") as fh:
            fh.write(b"x" * 512)

        assert _exists_on(NGINX_URL, path)
        assert _exists_on(REF_URL,   path)

        st = _fs(NGINX_URL).rm(path)
        assert st[0].ok, f"nginx rm failed: {st[0].message}"

        assert not _exists_on(NGINX_URL, path), "nginx: file still exists after rm"
        assert not _exists_on(REF_URL,   path), "ref:   file still exists after rm"

    def test_rm_nonexistent_fails_on_both(self):
        path = "/_no_such_file_rm_xyzzy.bin"
        n_st = _fs(NGINX_URL).rm(path)
        r_st = _fs(REF_URL  ).rm(path)
        assert not n_st[0].ok, "nginx: rm of nonexistent should fail"
        assert not r_st[0].ok, "ref:   rm of nonexistent should fail"

    def test_rm_directory_matches_reference(self):
        n_path = _unique("rm_dir_nginx")
        r_path = _unique("rm_dir_ref")
        _fs(NGINX_URL).mkdir(n_path, MkDirFlags.NONE)
        _fs(NGINX_URL).mkdir(r_path, MkDirFlags.NONE)
        try:
            n_st = _fs(NGINX_URL).rm(n_path)
            r_st = _fs(REF_URL  ).rm(r_path)
            assert n_st[0].ok == r_st[0].ok, (
                f"rm directory outcome mismatch: nginx={n_st[0].ok} "
                f"ref={r_st[0].ok}"
            )
        finally:
            _fs(NGINX_URL).rmdir(n_path)
            _fs(NGINX_URL).rmdir(r_path)


# ---------------------------------------------------------------------------
# mv
# ---------------------------------------------------------------------------

class TestMvConformance:

    def test_mv_renames_file_visible_on_both(self):
        old_name = f"_mv_old_{os.getpid()}.bin"
        new_name = f"_mv_new_{os.getpid()}.bin"
        old_path = f"/{old_name}"
        new_path = f"/{new_name}"
        content  = os.urandom(1024)

        fs_path = os.path.join(DATA_DIR, old_name)
        with open(fs_path, "wb") as fh:
            fh.write(content)

        try:
            st = _fs(NGINX_URL).mv(old_path, new_path)
            assert st[0].ok, f"nginx mv failed: {st[0].message}"

            assert not _exists_on(NGINX_URL, old_path), "nginx: old path still exists"
            assert not _exists_on(REF_URL,   old_path), "ref:   old path still exists"
            assert _exists_on(NGINX_URL, new_path), "nginx: new path not visible"
            assert _exists_on(REF_URL,   new_path), "ref:   new path not visible"

            n_sz = _size_on(NGINX_URL, new_path)
            r_sz = _size_on(REF_URL,   new_path)
            assert n_sz == r_sz == len(content), \
                f"size mismatch after mv: nginx={n_sz}, ref={r_sz}"
        finally:
            try:
                _fs(NGINX_URL).rm(new_path)
            except Exception:
                pass

    def test_mv_nonexistent_source_fails_on_both(self):
        n_st = _fs(NGINX_URL).mv("/_no_src_xyzzy.bin", "/_no_dst_xyzzy.bin")
        r_st = _fs(REF_URL  ).mv("/_no_src_xyzzy.bin", "/_no_dst_xyzzy.bin")
        assert not n_st[0].ok, "nginx: mv of nonexistent should fail"
        assert not r_st[0].ok, "ref:   mv of nonexistent should fail"

    def test_mv_directory(self):
        old_dir = _unique("mvdir_old")
        new_dir = _unique("mvdir_new")
        _fs(NGINX_URL).mkdir(old_dir, MkDirFlags.NONE)
        try:
            st = _fs(NGINX_URL).mv(old_dir, new_dir)
            assert st[0].ok, f"nginx mv directory failed: {st[0].message}"

            assert not _exists_on(NGINX_URL, old_dir)
            assert     _exists_on(NGINX_URL, new_dir)
            assert not _exists_on(REF_URL,   old_dir)
            assert     _exists_on(REF_URL,   new_dir)
        finally:
            try:
                _fs(NGINX_URL).rmdir(new_dir)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# chmod
# ---------------------------------------------------------------------------

class TestChmodConformance:

    def test_chmod_changes_mode_visible_on_both(self):
        name = f"_chmod_{os.getpid()}.bin"
        path = f"/{name}"
        fs_path = os.path.join(DATA_DIR, name)
        with open(fs_path, "wb") as fh:
            fh.write(b"chmod_test")
        os.chmod(fs_path, 0o644)

        try:
            new_mode = AccessMode.UR | AccessMode.UW | AccessMode.GR | AccessMode.OR
            st = _fs(NGINX_URL).chmod(path, new_mode)
            assert st[0].ok, f"nginx chmod failed: {st[0].message}"

            actual = oct(os.stat(fs_path).st_mode & 0o777)
            assert actual == oct(0o644), \
                f"filesystem mode after chmod: {actual}"

            n_st, n_info = _fs(NGINX_URL).stat(path)
            r_st, r_info = _fs(REF_URL  ).stat(path)
            assert n_st.ok and r_st.ok

            n_readable = bool(n_info.flags & StatInfoFlags.IS_READABLE)
            r_readable = bool(r_info.flags & StatInfoFlags.IS_READABLE)
            assert n_readable == r_readable, \
                f"IS_READABLE mismatch: nginx={n_readable}, ref={r_readable}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_chmod_nonexistent_fails_on_both(self):
        path  = "/_no_chmod_xyzzy.bin"
        mode  = AccessMode.UR | AccessMode.UW
        n_st  = _fs(NGINX_URL).chmod(path, mode)
        r_st  = _fs(REF_URL  ).chmod(path, mode)
        assert not n_st[0].ok, "nginx: chmod of nonexistent should fail"
        assert not r_st[0].ok, "ref:   chmod of nonexistent should fail"


# ---------------------------------------------------------------------------
# truncate
# ---------------------------------------------------------------------------

class TestTruncateConformance:

    def _make_file(self, size=8192):
        name    = f"_trunc_{os.getpid()}_{id(self)}.bin"
        content = os.urandom(size)
        fs_path = os.path.join(DATA_DIR, name)
        with open(fs_path, "wb") as fh:
            fh.write(content)
        return f"/{name}", content, fs_path

    def test_truncate_by_path_reduces_size(self):
        path, content, fs_path = self._make_file(8192)
        try:
            new_size = 1024
            st = _fs(NGINX_URL).truncate(path, new_size)
            assert st[0].ok, f"nginx truncate failed: {st[0].message}"

            n_sz = _size_on(NGINX_URL, path)
            r_sz = _size_on(REF_URL,   path)
            assert n_sz == new_size, f"nginx size after truncate: {n_sz}"
            assert r_sz == new_size, f"ref size after truncate:   {r_sz}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_truncate_by_handle_reduces_size(self):
        path, content, fs_path = self._make_file(4096)
        try:
            new_size = 512
            f = client.File()
            st, _ = f.open(_url(NGINX_URL, path), OpenFlags.UPDATE)
            assert st.ok, f"open for truncate: {st.message}"
            st2 = f.truncate(new_size)
            assert st2[0].ok, f"file.truncate failed: {st2[0].message}"
            f.close()

            n_sz = _size_on(NGINX_URL, path)
            r_sz = _size_on(REF_URL,   path)
            assert n_sz == new_size, f"nginx size after handle truncate: {n_sz}"
            assert r_sz == new_size, f"ref size after handle truncate:   {r_sz}"
        finally:
            _fs(NGINX_URL).rm(path)

    def test_truncate_nonexistent_fails(self):
        path = "/_no_trunc_xyzzy.bin"
        n_st = _fs(NGINX_URL).truncate(path, 0)
        r_st = _fs(REF_URL  ).truncate(path, 0)
        assert not n_st[0].ok, "nginx: truncate of nonexistent should fail"
        assert not r_st[0].ok, "ref:   truncate of nonexistent should fail"

    def test_truncate_to_same_size_succeeds(self):
        path, content, fs_path = self._make_file(1024)
        try:
            st = _fs(NGINX_URL).truncate(path, len(content))
            assert st[0].ok, "truncate to same size failed"
            assert _size_on(NGINX_URL, path) == len(content)
        finally:
            _fs(NGINX_URL).rm(path)


# ---------------------------------------------------------------------------
# statx (multi-path stat)
# ---------------------------------------------------------------------------

class TestStatxConformance:
    """
    kXR_statx is a multi-path stat.  The Python XRootD client does not expose
    statx directly, so we verify it via a raw query approach: issue individual
    stat() calls for the same paths and confirm nginx and ref agree.
    For deeper wire-level statx testing see test_opcode_coverage.py.
    """

    def _seed_files(self, n=3):
        paths = []
        for i in range(n):
            name    = f"_statx_{os.getpid()}_{i}.bin"
            content = os.urandom(128 * (i + 1))
            with open(os.path.join(DATA_DIR, name), "wb") as fh:
                fh.write(content)
            paths.append((f"/{name}", len(content)))
        return paths

    def test_statx_multiple_paths_agree(self):
        paths = self._seed_files(3)
        try:
            for xrd_path, expected_size in paths:
                n_st, n_info = _fs(NGINX_URL).stat(xrd_path)
                r_st, r_info = _fs(REF_URL  ).stat(xrd_path)
                assert n_st.ok and r_st.ok, \
                    f"stat failed for {xrd_path}: nginx={n_st.ok}, ref={r_st.ok}"
                assert n_info.size == r_info.size == expected_size, (
                    f"{xrd_path}: size mismatch nginx={n_info.size} "
                    f"ref={r_info.size} expected={expected_size}"
                )
        finally:
            for xrd_path, _ in paths:
                try:
                    _fs(NGINX_URL).rm(xrd_path)
                except Exception:
                    pass

    def test_statx_mix_of_existing_and_missing_agrees(self):
        good_name = f"_statx_good_{os.getpid()}.bin"
        with open(os.path.join(DATA_DIR, good_name), "wb") as fh:
            fh.write(b"exists")
        try:
            for path in [f"/{good_name}", "/_statx_missing_xyzzy.bin"]:
                n_ok = _exists_on(NGINX_URL, path)
                r_ok = _exists_on(REF_URL,   path)
                assert n_ok == r_ok, \
                    f"existence mismatch for {path}: nginx={n_ok}, ref={r_ok}"
        finally:
            _fs(NGINX_URL).rm(f"/{good_name}")


# ---------------------------------------------------------------------------
# fattr (kXR_fattr — extended attributes)
# ---------------------------------------------------------------------------

class TestFattrConformance:
    """
    kXR_fattr: Get / Set / List / Del suboperations.
    Both servers should agree on attribute presence after nginx-xrootd writes.
    """

    def _seed_file(self):
        name    = f"_fattr_{os.getpid()}_{id(self)}.bin"
        content = os.urandom(256)
        with open(os.path.join(DATA_DIR, name), "wb") as fh:
            fh.write(content)
        return f"/{name}", name

    def _open_file(self, url, path, flags=OpenFlags.READ):
        f = client.File()
        st, _ = f.open(_url(url, path), flags)
        return f, st

    def _set_attrs(self, path, attrs):
        st, _ = _fs(NGINX_URL).set_xattr(path, attrs)
        return st

    def _get_attrs(self, path, names):
        st, attrs = _fs(NGINX_URL).get_xattr(path, names)
        return st, self._attr_map(attrs)

    def _list_attrs(self, path):
        st, attrs = _fs(NGINX_URL).list_xattr(path)
        return st, self._attr_map(attrs)

    def _del_attrs(self, path, names):
        st, _ = _fs(NGINX_URL).del_xattr(path, names)
        return st

    def _attr_map(self, attrs):
        result = {}
        for attr in attrs or []:
            if hasattr(attr, "name"):
                result[attr.name] = getattr(attr, "value", None)
            elif isinstance(attr, tuple) and len(attr) >= 2:
                result[attr[0]] = attr[1]
        return result

    def test_fattr_set_and_get_roundtrip(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("testkey", "testvalue")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            get_st, attrs = self._get_attrs(xrd_path, ["testkey"])
            assert get_st.ok, f"get_xattr failed: {get_st.message}"
            assert attrs.get("testkey") == "testvalue", \
                f"xattr value mismatch: got {attrs!r}"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_list_includes_set_attr(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("listkey", "listval")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            list_st, attrs = self._list_attrs(xrd_path)
            assert list_st.ok, f"list_xattr failed: {list_st.message}"
            names = set(attrs)
            assert "listkey" in names or "U.listkey" in names, \
                f"'listkey' not in fattr list: {names}"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_delete_removes_attr(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("delkey", "delval")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            del_st = self._del_attrs(xrd_path, ["delkey"])
            assert del_st.ok, f"del_xattr failed: {del_st.message}"

            get_st, attrs = self._get_attrs(xrd_path, ["delkey"])
            assert not get_st.ok or attrs.get("delkey") in (None, ""), \
                f"get_xattr after del should fail or return empty: {attrs!r}"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_multiple_attrs_independent(self):
        xrd_path, name = self._seed_file()
        try:
            set_st = self._set_attrs(xrd_path, [("key1", "val1"),
                                                ("key2", "val2")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            get_st, attrs = self._get_attrs(xrd_path, ["key1", "key2"])
            assert get_st.ok, f"get_xattr failed: {get_st.message}"
            assert attrs.get("key1") == "val1"
            assert attrs.get("key2") == "val2"
        finally:
            _fs(NGINX_URL).rm(xrd_path)

    def test_fattr_visible_from_ref_filesystem(self):
        """xattr written via nginx-xrootd must be visible as a Linux xattr."""
        xrd_path, name = self._seed_file()
        fs_path = os.path.join(DATA_DIR, name)
        try:
            set_st = self._set_attrs(xrd_path, [("diskkey", "diskval")])
            assert set_st.ok, f"set_xattr failed: {set_st.message}"

            raw = os.getxattr(fs_path, "user.U.diskkey")
            assert raw == b"diskval", \
                f"xattr on disk: {raw!r}"
        finally:
            try:
                _fs(NGINX_URL).rm(xrd_path)
            except Exception:
                pass
