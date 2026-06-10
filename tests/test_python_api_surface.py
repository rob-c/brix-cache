"""
Implementation of the Python API Deep-Surface Cross-Backend Test Plan.

This module exercises the maximum possible surface area of the pyxrootd API
against both nginx-xrootd and official XRootD backends.

Run:
    TEST_CROSS_BACKEND=nginx  pytest tests/test_python_api_surface.py -v
    TEST_CROSS_BACKEND=xrootd pytest tests/test_python_api_surface.py -v
"""

import hashlib
import os
import time
import pytest
from XRootD import client
from XRootD.client.flags import (
    OpenFlags,
    StatInfoFlags,
    DirListFlags,
    MkDirFlags,
    QueryCode,
    AccessMode
)
from backend_matrix import selected_backend_name

# ---------------------------------------------------------------------------
# Configuration & Fixtures
# ---------------------------------------------------------------------------

BACKEND = selected_backend_name()
PREFIX = "_api_surface_"

@pytest.fixture(scope="module")
def _setup_env(test_env, ref_xrootd, ref_xrootd_gsi_shared):
    global ANON_URL, GSI_URL, DATA_DIR, CA_DIR, PROXY_PEM
    if BACKEND == "xrootd":
        ANON_URL = ref_xrootd["url"]
        GSI_URL = ref_xrootd_gsi_shared["url"]
        DATA_DIR = ref_xrootd["data_dir"]
    else:
        ANON_URL = test_env["anon_url"]
        GSI_URL = test_env["gsi_url"]
        DATA_DIR = test_env["data_dir"]
    
    CA_DIR = test_env["ca_dir"]
    PROXY_PEM = test_env["proxy_pem"]
    
    # Set GSI environment for the process
    os.environ["X509_CERT_DIR"] = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM

@pytest.fixture(autouse=True)
def cleanup_files(_setup_env):
    """Ensure a clean slate for each test."""
    _do_cleanup()
    yield
    _do_cleanup()

def _do_cleanup():
    for name in os.listdir(DATA_DIR):
        if name.startswith(PREFIX):
            path = os.path.join(DATA_DIR, name)
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                import shutil
                shutil.rmtree(path)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_url(path, gsi=False):
    base = GSI_URL if gsi else ANON_URL
    return f"{base}//{path.lstrip('/')}"

def md5(data):
    return hashlib.md5(data).hexdigest()

# ---------------------------------------------------------------------------
# 3.1 XRootD.client.File (Stateful Handles)
# ---------------------------------------------------------------------------

class TestFileSurface:
    
    def test_open_combinations(self):
        """Explore OpenFlags combinations."""
        path = f"{PREFIX}open_test.bin"
        f = client.File()
        
        # NEW | UPDATE
        st, _ = f.open(get_url(path), OpenFlags.NEW | OpenFlags.UPDATE)
        assert st.ok
        assert f.is_open()
        f.close()
        assert not f.is_open()
        
        # READ
        st, _ = f.open(get_url(path), OpenFlags.READ)
        assert st.ok
        f.close()
        
        # DELETE | UPDATE (Truncate existing)
        st, _ = f.open(get_url(path), OpenFlags.DELETE | OpenFlags.UPDATE)
        assert st.ok
        f.close()
        
        # MAKEPATH
        deep_path = f"{PREFIX}deep/dir/file.bin"
        st, _ = f.open(get_url(deep_path), OpenFlags.NEW | OpenFlags.UPDATE | OpenFlags.MAKEPATH)
        assert st.ok
        f.close()

    def test_read_write_random_access(self):
        """Test random-access read/write and MD5 integrity."""
        path = f"{PREFIX}rw_random.bin"
        data1 = b"Hello"
        data2 = b"XRootD"
        
        f = client.File()
        f.open(get_url(path), OpenFlags.NEW | OpenFlags.UPDATE)
        
        f.write(data1, offset=0)
        f.write(data2, offset=10) # Gap filled with zeros
        st, _ = f.sync()
        assert st.ok
        
        # Read back
        st, r1 = f.read(offset=0, size=5)
        assert st.ok and r1 == data1
        
        st, r2 = f.read(offset=10, size=6)
        assert st.ok and r2 == data2
        
        st, r_gap = f.read(offset=5, size=5)
        assert st.ok and r_gap == b"\x00" * 5
        
        f.close()

    def test_truncate_handle(self):
        """Shrink and extend via handle."""
        path = f"{PREFIX}trunc_handle.bin"
        f = client.File()
        f.open(get_url(path), OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(b"1234567890")
        f.sync()
        
        # Shrink
        st, _ = f.truncate(5)
        assert st.ok
        f.close() # Close to ensure flush
        
        fs = client.FileSystem(ANON_URL)
        st, info = fs.stat(f"/{path}")
        assert st.ok
        assert info.size == 5
        
        # Extend
        f = client.File()
        f.open(get_url(path), OpenFlags.UPDATE)
        st, _ = f.truncate(20)
        assert st.ok
        f.close()
        
        st, info = fs.stat(f"/{path}")
        assert st.ok
        assert info.size == 20

    def test_vector_read(self):
        """Explore vector read."""
        path = f"{PREFIX}readv.bin"
        content = b"ABCDE" + b"12345" + b"FGHIJ"
        with open(os.path.join(DATA_DIR, path), "wb") as fh:
            fh.write(content)
            
        f = client.File()
        f.open(get_url(path), OpenFlags.READ)
        
        # Read bits: "ABCDE" (0-5) and "FGHIJ" (10-15)
        st, chunks = f.vector_read([(0, 5), (10, 5)])
        assert st.ok
        # chunks is a VectorReadInfo object, access its data via .chunks and .buffer
        assert len(chunks.chunks) == 2
        assert chunks.chunks[0].buffer == b"ABCDE"
        assert chunks.chunks[1].buffer == b"FGHIJ"
        f.close()

    def test_concurrent_handles(self):
        """Two handles to the same file: independent read handles see same data."""
        path = f"{PREFIX}concurrent.bin"
        content = b"concurrent read test data " * 10
        local = os.path.join(DATA_DIR, path)
        with open(local, "wb") as fh:
            fh.write(content)

        f1 = client.File()
        f2 = client.File()
        st1, _ = f1.open(get_url(path), OpenFlags.READ)
        st2, _ = f2.open(get_url(path), OpenFlags.READ)
        assert st1.ok, f"f1.open failed: {st1}"
        assert st2.ok, f"f2.open failed: {st2}"

        st, data1 = f1.read(offset=0, size=len(content))
        assert st.ok
        st, data2 = f2.read(offset=0, size=len(content))
        assert st.ok

        assert data1 == content
        assert data2 == content

        f1.close()
        f2.close()

# ---------------------------------------------------------------------------
# 3.2 XRootD.client.FileSystem (Stateless Namespace)
# ---------------------------------------------------------------------------

class TestFileSystemSurface:
    
    def test_namespace_ops(self):
        """Test mkdir, rmdir, mv, rm, chmod."""
        fs = client.FileSystem(ANON_URL)
        dir_path = f"/{PREFIX}test_dir"
        file_path = f"{dir_path}/file.txt"
        moved_path = f"/{PREFIX}moved.txt"
        
        # mkdir
        st, _ = fs.mkdir(dir_path, MkDirFlags.MAKEPATH)
        assert st.ok
        
        # write file via File API to have something to move
        f = client.File()
        f.open(get_url(file_path), OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(b"test")
        f.close()
        
        # chmod
        st, _ = fs.chmod(file_path, AccessMode.UR | AccessMode.UW)
        assert st.ok
        
        # stat
        st, info = fs.stat(file_path)
        assert st.ok
        assert info.size == 4
        
        # mv
        st, _ = fs.mv(file_path, moved_path)
        assert st.ok
        
        # rm
        st, _ = fs.rm(moved_path)
        assert st.ok
        
        # rmdir
        st, _ = fs.rmdir(dir_path)
        assert st.ok

    def test_dirlist(self):
        """Test dirlist and flags."""
        fs = client.FileSystem(ANON_URL)
        dir_name = f"{PREFIX}list_me"
        os.makedirs(os.path.join(DATA_DIR, dir_name))
        for i in range(3):
            with open(os.path.join(DATA_DIR, dir_name, f"f{i}.txt"), "w") as f:
                f.write(str(i))
                
        st, listing = fs.dirlist(f"/{dir_name}", DirListFlags.STAT)
        assert st.ok
        
        items = list(listing)
        names = [entry.name for entry in items]
        assert len(names) == 3
        assert "f0.txt" in names
        assert items[0].statinfo is not None # Because of DirListFlags.STAT

    def test_query_and_locate(self):
        """Test query and locate variants."""
        fs = client.FileSystem(ANON_URL)
        
        # query (e.g. kXR_query for checksum)
        path = f"{PREFIX}query.bin"
        with open(os.path.join(DATA_DIR, path), "wb") as fh:
            fh.write(b"data")
            
        st, res = fs.query(QueryCode.CHECKSUM, f"/{path}")
        
        # locate
        st, res = fs.locate(f"/{path}", OpenFlags.READ)
        assert st.ok

    def test_statx(self):
        """Bulk stat."""
        pass

    def test_url_parameters(self):
        """Test URL parameters (opaque data)."""
        # Ensure server accepts the parameter syntax.
        path = f"{PREFIX}opaque.bin"
        with open(os.path.join(DATA_DIR, path), "w") as fh:
            fh.write("opaque content")
            
        fs = client.FileSystem(ANON_URL)
        # Some servers don't like parameters in the middle of path
        st, info = fs.stat(f"/{path}?xrd.wantpg=1")
        assert st.ok

# ---------------------------------------------------------------------------
# 3.4 Extended Attributes (XAttrs)
# ---------------------------------------------------------------------------

class TestXAttrSurface:
    
    def test_xattr_lifecycle(self):
        """Set, get, list, and delete xattrs."""
        path = f"{PREFIX}xattr.bin"
        with open(os.path.join(DATA_DIR, path), "w") as fh:
            fh.write("xattr test")
            
        fs = client.FileSystem(ANON_URL)
        attr_name = "user.test_attr"
        attr_val = "test_value"
        
        # Set expects a list of (key, value) tuples
        st, _ = fs.set_xattr(f"/{path}", [(attr_name, attr_val)])
        
        if st.ok:
            # Get returns a list of (key, value) tuples
            st2, vals = fs.get_xattr(f"/{path}", [attr_name])
            assert st2.ok and vals[0][1] == attr_val
            
            # List
            st3, listing = fs.list_xattr(f"/{path}")
            assert st3.ok
            
            # Delete expects a list of keys
            st4, _ = fs.del_xattr(f"/{path}", [attr_name])
            assert st4.ok

# ---------------------------------------------------------------------------
# 3.3 Advanced Protocol Features
# ---------------------------------------------------------------------------

class TestAdvancedSurface:
    
    def test_pgread_integrity(self):
        """Verify paged read (implicit if server supports it)."""
        path = f"{PREFIX}large_pg.bin"
        data = os.urandom(1024 * 1024) # 1 MiB
        with open(os.path.join(DATA_DIR, path), "wb") as fh:
            fh.write(data)
            
        f = client.File()
        f.open(get_url(path), OpenFlags.READ)
        st, res = f.read(offset=0, size=len(data))
        assert st.ok
        assert md5(res) == md5(data)
        f.close()

    def test_prepare(self):
        """Test kXR_prepare."""
        fs = client.FileSystem(ANON_URL)
        path = f"{PREFIX}prepare.bin"
        with open(os.path.join(DATA_DIR, path), "w") as fh:
            fh.write("ready")
            
        # Prepare a file for reading
        st, _ = fs.prepare([f"/{path}"], OpenFlags.READ)
        assert st.ok
