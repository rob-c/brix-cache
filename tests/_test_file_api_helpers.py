# _test_file_api_helpers.py - shared header/helpers/fixtures for the Phase-38 split of
# test_file_api.py.  `from _test_file_api_helpers import *` re-exports EVERYTHING (incl imported
# names and `_`-prefixed helpers) via the __all__ below, so every split
# sibling shares the exact module-level environment of the original.
"""
Comprehensive file-management tests for nginx-xrootd via the XRootD Python API.

Covers the File API (open/read/write/truncate/sync/stat) and the FileSystem
API (stat, dirlist, truncate, mkdir, rmdir, rm, mv, chmod) on both the
anonymous (port 11094) and GSI (port 11095) endpoints.

Run:
    pytest tests/test_file_api.py -v -s
"""

import hashlib
import os
import stat
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import (
    AccessMode,
    DirListFlags,
    MkDirFlags,
    OpenFlags,
    StatInfoFlags,
)
from backend_matrix import selected_backend_name
from official_interop_lib import worker_prefix
from settings import (
    CA_DIR,
    DATA_ROOT,
    HOST,
    NGINX_ANON_PORT,
    NGINX_ANON_RESUME_OFF_PORT,
    NGINX_GSI_PORT,
    PROXY_STD,
    REF_BRIX_GSI_SHARED_PORT,
    REF_BRIX_PORT,
    SERVER_HOST,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CROSS_BACKEND = selected_backend_name()

if CROSS_BACKEND == "xrootd":
    ANON_URL = f"root://{HOST}:{REF_BRIX_PORT}"
    GSI_URL  = f"root://{HOST}:{REF_BRIX_GSI_SHARED_PORT}"
    # Stock xrootd has no upload_resume — it is already direct-to-disk.
    RESUME_OFF_URL = ANON_URL
else:
    ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
    GSI_URL  = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
    # Same shared data root, upload_resume OFF — direct-to-disk (stock posture).
    RESUME_OFF_URL = f"root://{SERVER_HOST}:{NGINX_ANON_RESUME_OFF_PORT}"

# Whether the resume-ON (staging) posture is exercisable here.  Only the nginx
# backend implements upload_resume; against real xrootd both URLs are the same
# stock endpoint, so the resume-ON variant is skipped.
RESUME_ON_AVAILABLE = (CROSS_BACKEND != "xrootd")

DATA_DIR  = DATA_ROOT
PROXY_PEM = PROXY_STD

# All test files/dirs carry this prefix.  worker_prefix() scopes it per xdist
# worker so the autouse `clean_prefix` fixture (which deletes *all* PREFIX-named
# artefacts in the shared fleet DATA_DIR) can't nuke another worker's in-flight
# files under `--dist load`.  See official_interop_lib.worker_prefix.
PREFIX = worker_prefix("_api_test_")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def anon_fs() -> client.FileSystem:
    return client.FileSystem(ANON_URL)


def gsi_fs() -> client.FileSystem:
    os.environ["X509_CERT_DIR"]   = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    return client.FileSystem(GSI_URL)


def anon_file() -> client.File:
    return client.File()


def gsi_file() -> client.File:
    os.environ["X509_CERT_DIR"]   = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    return client.File()


def disk(name: str) -> str:
    """Absolute on-disk path for a name inside DATA_DIR."""
    return os.path.join(DATA_DIR, name.lstrip("/"))


def worker_own(path: str) -> str:
    """Hand a freshly-created test artefact to the server's `nobody` worker so the
    worker can chmod/chown it.  chmod(2) requires OWNERSHIP, not a mode bit — a
    root-created file is root-owned, and the fleet's nobody worker gets EPERM
    trying to chmod it (this is the whole "chmod fails under root" cluster).
    Best-effort and a no-op unprivileged (the invoking user already owns it).
    Returns ``path`` so it can wrap a creation expression."""
    from official_interop_lib import chown_stock  # noqa: PLC0415
    chown_stock(path)
    return path


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def md5file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@pytest.fixture(autouse=True)
def clean_prefix():
    """Remove all PREFIX artefacts before and after every test."""
    _cleanup_prefix()
    yield
    _cleanup_prefix()


def _cleanup_prefix():
    for name in list(os.listdir(DATA_DIR)):
        if not name.startswith(PREFIX):
            continue
        full = os.path.join(DATA_DIR, name)
        if os.path.isfile(full) or os.path.islink(full):
            os.unlink(full)
        elif os.path.isdir(full):
            _rmtree(full)


def _rmtree(path: str):
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            os.rmdir(os.path.join(root, d))
    os.rmdir(path)


# ---------------------------------------------------------------------------
# TestFileCreate — opening files for writing
# ---------------------------------------------------------------------------


__all__ = [n for n in dir() if not n.startswith('__')]
