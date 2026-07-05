# brix-remote-adapted
"""
Filesystem operation tests for nginx-xrootd: mkdir, rmdir, rm, mv, chmod.

Tests both the anonymous (port 11094) and GSI (port 11095) endpoints.
Uses the XRootD Python FileSystem API so operations go through the full
XRootD protocol stack rather than xrdcp.

Run:
    pytest tests/test_fs_ops.py -v -s
"""

import os
import stat
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import MkDirFlags, AccessMode
from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    SERVER_HOST,
)

import klib  # remote: mkdir/write/verify happen on the SERVER, driven via kubectl exec

ANON_URL  = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
GSI_URL   = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
# remote: DATA_DIR names the mega SERVER's data root; setup/verify go through klib.
DATA_DIR  = "/data/xrootd"
SERVER_SVC = "mega"
PROXY_PEM = PROXY_STD


def anon_fs() -> client.FileSystem:
    return client.FileSystem(ANON_URL)


def gsi_fs() -> client.FileSystem:
    os.environ["X509_CERT_DIR"]  = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    return client.FileSystem(GSI_URL)


@pytest.fixture(autouse=True)
def clean_test_paths():
    """Remove any _fstest_* artefacts before and after each test."""
    _cleanup()
    yield
    _cleanup()


def _cleanup():
    """Remove _fstest_* artefacts from the SERVER's data dir (best-effort)."""
    try:
        for name in klib.svc_listdir(SERVER_SVC, DATA_DIR):
            if name.startswith("_fstest_"):
                klib.svc_rmtree(SERVER_SVC, os.path.join(DATA_DIR, name))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# kXR_mkdir
# ---------------------------------------------------------------------------

class TestMkdir:

    def test_mkdir_simple(self):
        """Create a single directory."""
        fs = anon_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_simple", MkDirFlags.NONE)
        assert status.ok, f"mkdir failed: {status.message}"
        assert klib.svc_isdir(SERVER_SVC, os.path.join(DATA_DIR, "_fstest_mkdir_simple"))

    def test_mkdir_with_parents(self):
        """Create nested directories in one call (MkDirFlags.MAKEPATH)."""
        fs = anon_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_parents/sub/deep",
                              MkDirFlags.MAKEPATH)
        assert status.ok, f"mkdir -p failed: {status.message}"
        assert klib.svc_isdir(SERVER_SVC, 
            os.path.join(DATA_DIR, "_fstest_mkdir_parents", "sub", "deep")
        )

    def test_mkdir_idempotent(self):
        """mkdir on an existing directory: either idempotent OK or the
        POSIX-correct kXR_ItExists (3018).  Stock xrootd is idempotent only for a
        directory IT created in the same process (oss namespace cache); OUR server
        is deterministically POSIX-correct and returns ItExists.  Both conform —
        but a failure must be the exists error, not something unrelated.
        See test_conf_errors.py::test_mkdir_fresh_then_again_parity."""
        path = os.path.join(DATA_DIR, "_fstest_mkdir_idem")
        klib.svc_mkdir(SERVER_SVC, path)
        fs = anon_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_idem", MkDirFlags.NONE)
        assert status.ok or status.errno == 3018, \
            f"mkdir on existing dir gave unexpected error: {status.message}"

    def test_mkdir_gsi(self):
        """Create a directory over the GSI endpoint."""
        fs = gsi_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_gsi", MkDirFlags.NONE)
        assert status.ok, f"GSI mkdir failed: {status.message}"
        assert klib.svc_isdir(SERVER_SVC, os.path.join(DATA_DIR, "_fstest_mkdir_gsi"))


# ---------------------------------------------------------------------------
# kXR_rmdir
# ---------------------------------------------------------------------------

class TestRmdir:

    def test_rmdir_empty(self):
        """Remove an empty directory."""
        path = os.path.join(DATA_DIR, "_fstest_rmdir_empty")
        klib.svc_mkdir(SERVER_SVC, path)
        fs = anon_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_empty")
        assert status.ok, f"rmdir failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, path)

    def test_rmdir_nonempty_fails(self):
        """Removing a non-empty directory must fail."""
        path = os.path.join(DATA_DIR, "_fstest_rmdir_nonempty")
        klib.svc_mkdir(SERVER_SVC, path)
        klib.svc_write(SERVER_SVC, os.path.join(path, "file.txt"), "")
        fs = anon_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_nonempty")
        assert not status.ok, "Expected rmdir of non-empty dir to fail"

    def test_rmdir_nonexistent_fails(self):
        """Removing a directory that doesn't exist is idempotent."""
        fs = anon_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_gone")
        assert status.ok, f"rmdir of nonexistent dir failed: {status.message}"

    def test_rmdir_gsi(self):
        """Remove a directory over the GSI endpoint."""
        path = os.path.join(DATA_DIR, "_fstest_rmdir_gsi")
        klib.svc_mkdir(SERVER_SVC, path)
        fs = gsi_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_gsi")
        assert status.ok, f"GSI rmdir failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, path)


# ---------------------------------------------------------------------------
# kXR_rm (file removal)
# ---------------------------------------------------------------------------

class TestRm:

    def test_rm_file(self):
        """Remove an existing file."""
        path = os.path.join(DATA_DIR, "_fstest_rm_file.txt")
        klib.svc_write(SERVER_SVC, path, "delete me\n")
        fs = anon_fs()
        status, _ = fs.rm("/_fstest_rm_file.txt")
        assert status.ok, f"rm failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, path)

    def test_rm_nonexistent_fails(self):
        """Removing a file that doesn't exist must fail."""
        fs = anon_fs()
        status, _ = fs.rm("/_fstest_rm_gone.txt")
        assert not status.ok, "Expected rm of nonexistent file to fail"

    def test_rm_empty_directory(self):
        """rm on an empty directory follows reference XRootD semantics."""
        path = os.path.join(DATA_DIR, "_fstest_rm_empty_dir")
        klib.svc_mkdir(SERVER_SVC, path)
        fs = anon_fs()
        status, _ = fs.rm("/_fstest_rm_empty_dir")
        assert status.ok, f"rm of empty directory failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, path)

    def test_rm_gsi(self):
        """Remove a file over the GSI endpoint."""
        path = os.path.join(DATA_DIR, "_fstest_rm_gsi.txt")
        klib.svc_write(SERVER_SVC, path, "gsi delete me\n")
        fs = gsi_fs()
        status, _ = fs.rm("/_fstest_rm_gsi.txt")
        assert status.ok, f"GSI rm failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, path)


# ---------------------------------------------------------------------------
# kXR_mv (rename/move)
# ---------------------------------------------------------------------------

class TestMv:

    def test_mv_file(self):
        """Rename a file."""
        src = os.path.join(DATA_DIR, "_fstest_mv_src.txt")
        dst = os.path.join(DATA_DIR, "_fstest_mv_dst.txt")
        klib.svc_write(SERVER_SVC, src, "move me\n")
        fs = anon_fs()
        status, _ = fs.mv("/_fstest_mv_src.txt", "/_fstest_mv_dst.txt")
        assert status.ok, f"mv failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, src), "source should be gone after mv"
        assert klib.svc_read(SERVER_SVC, dst).decode() == "move me\n", "destination content wrong"

    def test_mv_directory(self):
        """Rename a directory."""
        src = os.path.join(DATA_DIR, "_fstest_mv_dir_src")
        dst = os.path.join(DATA_DIR, "_fstest_mv_dir_dst")
        klib.svc_mkdir(SERVER_SVC, src)
        fs = anon_fs()
        status, _ = fs.mv("/_fstest_mv_dir_src", "/_fstest_mv_dir_dst")
        assert status.ok, f"mv dir failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, src)
        assert klib.svc_isdir(SERVER_SVC, dst)

    def test_mv_nonexistent_source_fails(self):
        """Moving a nonexistent source must fail."""
        fs = anon_fs()
        status, _ = fs.mv("/_fstest_mv_gone.txt", "/_fstest_mv_dst2.txt")
        assert not status.ok, "Expected mv of nonexistent source to fail"

    def test_mv_gsi(self):
        """Rename a file over the GSI endpoint."""
        src = os.path.join(DATA_DIR, "_fstest_mv_gsi_src.txt")
        dst = os.path.join(DATA_DIR, "_fstest_mv_gsi_dst.txt")
        klib.svc_write(SERVER_SVC, src, "gsi move\n")
        fs = gsi_fs()
        status, _ = fs.mv("/_fstest_mv_gsi_src.txt", "/_fstest_mv_gsi_dst.txt")
        assert status.ok, f"GSI mv failed: {status.message}"
        assert not klib.svc_exists(SERVER_SVC, src)
        assert klib.svc_exists(SERVER_SVC, dst)


# ---------------------------------------------------------------------------
# kXR_chmod
# ---------------------------------------------------------------------------

class TestChmod:

    def test_chmod_file(self):
        """Change file permissions."""
        path = os.path.join(DATA_DIR, "_fstest_chmod_file.txt")
        klib.svc_write(SERVER_SVC, path, "chmod me\n")
        klib.svc_chmod(SERVER_SVC, path, 0o644)
        fs = anon_fs()
        # Set to 0o444 (read-only for all)
        status, _ = fs.chmod("/_fstest_chmod_file.txt",
                              AccessMode.UR | AccessMode.GR | AccessMode.OR)
        assert status.ok, f"chmod failed: {status.message}"
        mode = klib.svc_mode(SERVER_SVC, path)
        assert mode == 0o444, f"expected 0o444, got 0o{mode:o}"

    def test_chmod_directory(self):
        """Change directory permissions."""
        path = os.path.join(DATA_DIR, "_fstest_chmod_dir")
        klib.svc_mkdir(SERVER_SVC, path)
        klib.svc_chmod(SERVER_SVC, path, 0o755)
        fs = anon_fs()
        status, _ = fs.chmod("/_fstest_chmod_dir",
                              AccessMode.UR | AccessMode.UW | AccessMode.UX |
                              AccessMode.GR | AccessMode.GX)
        assert status.ok, f"chmod dir failed: {status.message}"
        mode = klib.svc_mode(SERVER_SVC, path)
        assert mode == 0o750, f"expected 0o750, got 0o{mode:o}"

    def test_chmod_nonexistent_fails(self):
        """chmod on a nonexistent path must fail."""
        fs = anon_fs()
        status, _ = fs.chmod("/_fstest_chmod_gone.txt", AccessMode.UR)
        assert not status.ok, "Expected chmod of nonexistent path to fail"

    def test_chmod_gsi(self):
        """Change file permissions over the GSI endpoint."""
        path = os.path.join(DATA_DIR, "_fstest_chmod_gsi.txt")
        klib.svc_write(SERVER_SVC, path, "gsi chmod\n")
        klib.svc_chmod(SERVER_SVC, path, 0o644)
        fs = gsi_fs()
        status, _ = fs.chmod("/_fstest_chmod_gsi.txt",
                              AccessMode.UR | AccessMode.GR | AccessMode.OR)
        assert status.ok, f"GSI chmod failed: {status.message}"
        mode = klib.svc_mode(SERVER_SVC, path)
        assert mode == 0o444, f"expected 0o444, got 0o{mode:o}"
