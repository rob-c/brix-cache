"""
tests/test_interop_query.py

Conformance tests for kXR_query subtypes, kXR_prepare semantics, open-flag
edge cases, and protocol-level error-code families.

Covered areas:
  - kXR_query: QStats, Qspace, Qconfig, Qvisa, QFinfo
  - kXR_prepare: stage, cancel, response format
  - kXR_protocol: version/capability flag negotiation
  - kXR_open flags: kXR_retstat, kXR_new, kXR_mkpath, append mode
  - Error code families: not-found, is-directory, permission, invalid-path
  - kXR_endsess: graceful session termination

The reference xrootd server is used to verify semantics match for
operations that both servers support.

Run:
    pytest tests/test_interop_query.py -v
"""

import os
import re
import struct
import time

import pytest
from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, QueryCode
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


# Session-seeded files both servers must agree on; everything else in the shared
# data root is transient scratch from concurrent tests (races a cross-server
# comparison under parallel -n N execution).
_BASELINE_FILES = {"test.txt", "random.bin", "large200.bin"}


def _dirlist_retry(fs, path, flags=DirListFlags.STAT, attempts=6, delay=0.25):
    """dirlist with retry: the reference official xrootd transiently returns
    '[ERROR] Invalid response' to a dirlist issued under concurrent dirlist load
    (an xrootd-client quirk, not nginx behaviour); retrying keeps it deterministic."""
    st = listing = None
    for _ in range(attempts):
        st, listing = fs.dirlist(path, flags)
        if st.ok:
            return st, listing
        time.sleep(delay)
    return st, listing


def _url(url, path):
    return f"{url.rstrip('/')}//{path.lstrip('/')}"


def _query(url, code, arg=""):
    return _fs(url).query(code, arg)


def _seed(content, name_prefix="q"):
    name = f"_{name_prefix}_{os.getpid()}_{id(content)}.bin"
    with open(os.path.join(DATA_DIR, name), "wb") as fh:
        fh.write(content)
    return f"/{name}"


# ---------------------------------------------------------------------------
# kXR_query QStats (code 1)
# ---------------------------------------------------------------------------

def _read_all(url, path):
    """Read all bytes from a file at url+path; returns (status, bytes|None)."""
    f = client.File()
    st, _ = f.open(_url(url, path), OpenFlags.READ)
    if not st.ok:
        f.close()
        return st, None
    s_st, info = f.stat()
    if not s_st.ok:
        f.close()
        return s_st, None
    r_st, data = f.read(offset=0, size=info.size)
    f.close()
    return r_st, data


# ---------------------------------------------------------------------------
# Open flag conformance
# ---------------------------------------------------------------------------
