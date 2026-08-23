"""
tests/test_conformance.py

Protocol conformance tests: compare nginx-xrootd plugin responses to an
official xrootd server running against the same data.

  nginx-xrootd : root://localhost:11094  (already running)
  reference    : root://localhost:11096  (started by session fixture below)

Both servers serve /tmp/xrd-test/data via the same path namespace, so every
operation that succeeds on one should succeed on the other, and every error
should be an error on both.

We compare *semantics*, not raw bytes:
  - same ok/error outcome for each operation
  - same XRootD error code family on failures (file-not-found vs IO-error, …)
  - identical read data (byte-for-byte or MD5 for large files)
  - identical stat size and IS_DIR / readable flags
  - identical directory entry name sets
  - identical adler32 checksums
  - identical write-then-read-back round-trips

Run:
    pytest tests/test_conformance.py -v
"""

import hashlib
import os
import struct
import time
import zlib

import pytest
from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, StatInfoFlags
from _xrdcl_proxy import real_bindings_available
from settings import (
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
    url_host,
)

def _expression_1(status):
    return (
        (status.message or "").lower()
    )

def _expression_2(msg):
    return (
        "no such" in msg or "not found" in msg or "doesn't exist" in msg
    )

def _expression_3(msg):
    return (
        "permission" in msg or "not authoriz" in msg
    )

def _expression_4(msg):
    return (
        "is a directory" in msg or "isdirectory" in msg or "is directory" in msg
    )

def _expression_5(msg):
    return (
        "path" in msg and "invalid" in msg
    )


pytestmark = [
    pytest.mark.registry_servers("main", "ref-anon"),
    pytest.mark.xdist_group("interop-central"),
]

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

# The nginx-side target.  Defaults to the direct anon endpoint, but can be
# pointed at any front that serves the same DATA_ROOT (a proxy, a multi-hop
# mesh, or a CMS cluster redirector) via CONFORMANCE_NGINX_URL so the entire
# suite runs unchanged through that topology — see test_conformance_topologies.py.
NGINX_URL = os.environ.get(
    "CONFORMANCE_NGINX_URL", f"root://{SERVER_HOST}:{NGINX_ANON_PORT}")
REF_URL   = f"root://{url_host(HOST)}:{REF_BRIX_PORT}"
DATA_DIR  = DATA_ROOT


@pytest.fixture(scope="module", autouse=True)
def _require_conformance_infrastructure():
    assert real_bindings_available(), (
        "real libXrdCl bindings unavailable; run the suite with its configured venv")

# ---------------------------------------------------------------------------
# Test-scoped fixture: per-test scratch file
# ---------------------------------------------------------------------------

@pytest.fixture()
def scratch(tmp_path_factory):
    """
    A small unique file written into DATA_DIR so both servers can serve it.
    Yields (logical_path, content_bytes).  Cleaned up after the test.
    """
    content = os.urandom(4096)  # 4 KiB of random bytes
    name    = f"_conf_{os.getpid()}_{id(content)}.bin"
    fs_path = os.path.join(DATA_DIR, name)
    with open(fs_path, "wb") as fh:
        fh.write(content)
    yield f"/{name}", content
    try:
        os.unlink(fs_path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fs(url: str) -> client.FileSystem:
    return client.FileSystem(url)


def _read_all(base_url: str, path: str) -> tuple:
    """Open + read the entire file.  Returns (status, bytes | None)."""
    f = client.File()
    st, _ = f.open(f"{base_url}/{path}")
    if not st.ok:
        return st, None
    st2, info = f.stat()
    if not st2.ok:
        return st2, None
    st3, data = f.read(size=info.size)
    f.close()
    return st3, data


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def _error_family(status) -> str:
    """Map an XRootD error status to a coarse family string for comparison."""
    msg = _expression_1(status)
    if not status.ok:
        if _expression_2(msg):
            return "not_found"
        if _expression_3(msg):
            return "permission"
        if _expression_4(msg):
            return "is_directory"
        if _expression_5(msg):
            return "invalid_path"
        return "error"          # generic — both failed, details differ
    return "ok"


# ---------------------------------------------------------------------------
# Ping
# ---------------------------------------------------------------------------

def _dirlist_retry(fs, path, flags=DirListFlags.STAT, attempts=24, delay=0.3):
    """dirlist with a retry.  The reference OFFICIAL xrootd transiently returns
    '[ERROR] Invalid response' to a dirlist issued while it is under concurrent
    dirlist load (an xrootd-client framing quirk, not an nginx behaviour).

    That error corrupts the pooled client connection, so retrying on the SAME
    FileSystem can keep hitting it under sustained full-suite load.  When the
    caller passes a URL string we therefore reconnect on a FRESH FileSystem each
    attempt (a new connection sidesteps the poisoned one); a FileSystem object is
    still accepted for callers that already hold one.

    Under the full parallel suite the reference can stay flaky for several
    seconds, so we retry with a capped-exponential backoff (~0.3s→2s) for a long
    enough window that a clean snapshot is reached — this is the reference's
    framing quirk, not nginx, so a longer wait is the correct robustness lever."""
    st = listing = None
    for i in range(attempts):
        this_fs = _fs(fs) if isinstance(fs, str) else fs
        st, listing = this_fs.dirlist(path, flags)
        if st.ok:
            return st, listing
        time.sleep(min(delay * (1.5 ** min(i, 6)), 2.0))
    return st, listing



def _adler32_hex(data: bytes) -> str:
    """Compute adler32 of data and return as 8-character lowercase hex."""
    return format(zlib.adler32(data) & 0xFFFFFFFF, "08x")
