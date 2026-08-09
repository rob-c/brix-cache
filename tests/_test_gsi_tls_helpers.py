"""
Functional read tests for root:// with GSI authentication + in-protocol TLS
(brix_tls).

The server on port 11096 advertises kXR_haveTLS in its kXR_protocol response,
so the XRootD client upgrades the connection to TLS before sending kXR_auth.
This validates that the full read path works correctly over an encrypted
transport with x509 proxy-certificate authentication.

Prerequisites:
  - nginx running with brix_tls + brix_auth gsi on port 11096
  - Test PKI at /tmp/xrd-test/pki/
  - Test data at /tmp/xrd-test/data/ (test.txt, random.bin)

Run:
    pytest tests/test_gsi_tls.py -v
    pytest tests/test_gsi_tls.py -v -k partial   # just partial-read tests
"""

import hashlib
import os
import subprocess
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, StatInfoFlags
from official_interop_lib import worker_prefix
from settings import (
    CA_DIR,
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_GSI_PORT,
    NGINX_GSI_TLS_PORT,
    PROXY_STD,
    SERVER_HOST,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GSI_TLS_URL = f"roots://{SERVER_HOST}:{NGINX_GSI_TLS_PORT}"
GSI_URL     = f"root://{SERVER_HOST}:{NGINX_GSI_PORT}"
ANON_URL    = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
PROXY_PEM   = PROXY_STD

TEST_FILES = {
    "test.txt":   {"size": 24,      "content": b"hello from nginx-xrootd\n"},
    "random.bin": {"size": 5242880, "content": None},
}


@pytest.fixture(scope="module")
def fs():
    """FileSystem handle for the GSI+TLS endpoint."""
    return client.FileSystem(GSI_TLS_URL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def md5_of_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_of_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def xrd_read_all(url: str) -> bytes:
    """Read all bytes from an XRootD URL using File.read()."""
    f = client.File()
    status, _ = f.open(url)
    assert status.ok, f"open({url}) failed: {status.message}"
    status, st = f.stat()
    assert status.ok
    status, data = f.read(size=st.size)
    assert status.ok, f"read failed: {status.message}"
    f.close()
    return data


# ===========================================================================
# Connection and metadata tests
# ===========================================================================

@pytest.fixture(autouse=False)
def cleanup_gsi_tls_writes():
    """Remove uploaded files from the data dir after each test."""
    yield
    for fname in os.listdir(DATA_ROOT):
        if fname.startswith(WRITE_PREFIX):
            try:
                os.unlink(os.path.join(DATA_ROOT, fname))
            except OSError:
                pass
