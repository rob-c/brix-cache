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
