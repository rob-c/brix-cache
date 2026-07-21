import pytest
import requests
import uuid
import time

_PFX = "lockcopy_"

@pytest.fixture(scope="module", autouse=True)
def _base(test_env):
    global BASE
    BASE = test_env["http_webdav_url"]

def _url(path):
    return BASE + path

def _uid():
    return uuid.uuid4().hex[:12]

def _put(path, data=b"hello"):
    return requests.put(_url(path), data=data, timeout=10)

def _get(path):
    return requests.get(_url(path), timeout=10)

def _mkcol(path):
    return requests.request("MKCOL", _url(path), timeout=10)

def _copy(src, dst, overwrite="T"):
    headers = {
        "Destination": BASE + dst,
        "Overwrite": overwrite,
    }
    return requests.request("COPY", _url(src), headers=headers, timeout=10)

def _lock(path):
    body = (
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<D:lockinfo xmlns:D="DAV:">'
        '<D:lockscope><D:exclusive/></D:lockscope>'
        '<D:locktype><D:write/></D:locktype>'
        '</D:lockinfo>'
    )
    return requests.request("LOCK", _url(path), data=body, timeout=10)

def test_copy_overwrites_locked_file_fails():
    """COPY should not overwrite a locked destination file."""
    src = f"/{_PFX}src_{_uid()}.txt"
    _put(src, b"source content")
    
    dst = f"/{_PFX}dst_{_uid()}.txt"
    _put(dst, b"original destination content")
    
    # Lock the destination
    r_lock = _lock(dst)
    assert r_lock.status_code == 201
    
    # Try to copy source over destination without lock token
    r = _copy(src, dst)
    
    # RFC 4918 §9.8.5: "If the Overwrite header has a value of 'T' and the 
    # destination resource exists, the server MUST perform a DELETE on the 
    # destination resource before executing the COPY."
    # DELETE on a locked resource should return 423.
    assert r.status_code == 423
    
    # Verify destination content was NOT changed
    assert _get(dst).content == b"original destination content"

def test_copy_collection_overwrites_locked_member_fails():
    """COPY a collection should not overwrite a destination if any member is locked."""
    src_dir = f"/{_PFX}srcdir_{_uid()}"
    _mkcol(src_dir)
    _put(f"{src_dir}/file.txt", b"new content")
    
    dst_dir = f"/{_PFX}dstdir_{_uid()}"
    _mkcol(dst_dir)
    locked_file = f"{dst_dir}/locked.txt"
    _put(locked_file, b"locked content")
    
    # Lock the child file in destination
    r_lock = _lock(locked_file)
    assert r_lock.status_code == 201
    
    # Try to copy collection over destination
    r = _copy(src_dir, dst_dir)
    
    # Should fail because a member of the destination collection is locked
    assert r.status_code == 423
    
    # Verify locked file still exists
    assert _get(locked_file).content == b"locked content"

def _move(src, dst, overwrite="T"):
    headers = {
        "Destination": BASE + dst,
        "Overwrite": overwrite,
    }
    return requests.request("MOVE", _url(src), headers=headers, timeout=10)

def test_move_collection_overwrites_locked_member_fails():
    """MOVE a collection should not overwrite a destination if any member is locked."""
    src_dir = f"/{_PFX}srcdir_mv_{_uid()}"
    _mkcol(src_dir)
    _put(f"{src_dir}/file.txt", b"new content")
    
    dst_dir = f"/{_PFX}dstdir_mv_{_uid()}"
    _mkcol(dst_dir)
    locked_file = f"{dst_dir}/locked.txt"
    _put(locked_file, b"locked content")
    
    # Lock the child file in destination
    r_lock = _lock(locked_file)
    assert r_lock.status_code == 201
    
    # Try to move collection over destination
    r = _move(src_dir, dst_dir)
    
    assert r.status_code == 423
    assert _get(locked_file).content == b"locked content"

def _delete(path):
    return requests.delete(_url(path), timeout=10)

def test_delete_collection_with_locked_member_fails():
    """DELETE a collection should fail if any member is locked."""
    dst_dir = f"/{_PFX}dstdir_del_{_uid()}"
    _mkcol(dst_dir)
    locked_file = f"{dst_dir}/locked.txt"
    _put(locked_file, b"locked content")
    
    # Lock the child file
    r_lock = _lock(locked_file)
    assert r_lock.status_code == 201
    
    # Try to delete the collection
    r = _delete(dst_dir)
    
    assert r.status_code == 423
    assert _get(locked_file).content == b"locked content"

def test_copy_preserves_xattrs():
    """COPY should preserve XRootD-mapped extended attributes."""
    import os
    try:
        import xattr
    except ImportError:
        pytest.skip("python-xattr not installed")

    src = f"/{_PFX}src_xattr_{_uid()}.txt"
    _put(src, b"content")
    
    # Map virtual path to physical path
    # TEST_ROOT is /tmp/xrd-test, export root is /tmp/xrd-test/data
    src_phys = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "data", src.lstrip("/"))
    
    # Set an XRootD-mapped xattr: user.U.testkey
    xattr_name = "user.U.testkey"
    xattr_val = b"testvalue"
    try:
        xattr.setxattr(src_phys, xattr_name, xattr_val)
    except OSError as e:
        pytest.skip(f"Filesystem does not support xattrs: {e}")

    dst = f"/{_PFX}dst_xattr_{_uid()}.txt"
    r = _copy(src, dst)
    assert r.status_code == 201
    
    dst_phys = os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "data", dst.lstrip("/"))
    
    # Verify xattr was copied
    try:
        val = xattr.getxattr(dst_phys, xattr_name)
        assert val == xattr_val
    except OSError as e:
        pytest.fail(f"xattr was not copied or inaccessible: {e}")
