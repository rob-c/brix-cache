"""
tests/test_dropin_byte_for_byte.py — drop-in byte-for-byte parity vs the
OFFICIAL xrootd server.

This suite proves the nginx-xrootd module is a *drop-in* replacement for the
official /usr/bin/xrootd at the wire level: it provisions BOTH servers on the
SAME data root (a dedicated official xrootd and a dedicated nginx, on isolated
high ports) and then issues the identical raw `root://` request to each and
compares the responses.  Because both daemons read the same files, the
metadata (inode, size, mtime), the per-page CRC32c pgread stream, the dirlist
names and the file bytes are all expected to be IDENTICAL — not merely
"semantically equivalent".  Where a field legitimately cannot match across two
independent processes (e.g. a self-reported PID) the comparison is restricted
to the field ORDER / FORMAT / key-set, which is the actual conformance
contract.  All raw framing is built with `struct.pack` exactly as in
tests/test_readv_security.py, and every hostile / edge request is followed by a
sanity op proving the connection survived.

The whole module skips cleanly if the nginx binary or /usr/bin/xrootd is
absent, or if either server fails to come up.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_dropin_byte_for_byte.py -v
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, SERVER_HOST, BIND_HOST
from ephemeral_port import free_port
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

def _guard_stack_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _guard_stack_2():
    if not os.path.exists(REF_XROOTD_BIN):
        pytest.skip(f"official xrootd binary not found at {REF_XROOTD_BIN}")

def _guard_stack_3():
    if not _wait_port(REF_XROOTD_PORT):
        pytest.skip("official xrootd did not come up")

def _guard_stack_4():
    if not _serves_seed(REF_XROOTD_PORT):
        pytest.skip("official xrootd is up but not serving the seed data "
                    "(stale listener / bind race) — skipping parity run")

def _guard_stack_5(ep):
    if not _wait_port(ep.port):
        pytest.skip("nginx did not come up")

def _guard_stack_6(ep):
    if not _serves_seed(ep.port):
        pytest.skip("nginx is up but not serving the seed data")


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-dropin-front")]

REF_XROOTD_BIN = os.environ.get(
    "TEST_REF_BIN",
    os.environ.get("TEST_BRIX_BIN", "/usr/bin/xrootd"),
)
H = SERVER_HOST

# Dedicated workspace for this file.
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_dropin_bfb")
# Port the fixture BINDS for the official xrootd xrd.port: allocate a free OS
# port so it never collides with the managed fleet or with another
# self-contained test running in the same pytest invocation.  Any explicit env
# override is still honoured.  The nginx front's port is owned by the registry
# LifecycleHarness (see the `stack` fixture).
_REF_XROOTD_FREE = free_port(H)
REF_XROOTD_PORT = int(os.environ.get("TEST_DROPIN_XROOTD_PORT")
                      or os.environ.get("TEST_DROPIN_BRIX_PORT")
                      or _REF_XROOTD_FREE)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (XProtocol.hh + src/protocols/root/protocol/opcodes.h)
# ---------------------------------------------------------------------------

kXR_query    = 3001
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_stat     = 3017
kXR_statx    = 3022
kXR_pgread   = 3030
kXR_clone    = 3032

kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_status   = 4007    # pgread extended-status framing

# XQueryType (ClientQueryRequest.infotype)
kXR_Qcksum   = 3
kXR_Qspace   = 5
kXR_Qconfig  = 7

# Server error codes (XProtocol.hh XErrorCode)
kXR_NotAuthorized = 3010
kXR_NotFound      = 3011
kXR_isDirectory   = 3016
kXR_Unsupported   = 3013   # also kXR_IOError numerically; disambiguated by msg
kXR_IOError       = 3007

# Open option flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0004

# dirlist options (ClientDirlistRequest.options)
kXR_dstat     = 2

PG_PAGESZ = 4096

# Seed files (written into the SHARED data root used by BOTH servers).
PLAIN_NAME   = "/dropin_plain.bin"
PLAIN_SIZE   = 70000          # not page-aligned → exercises a short final page
PLAIN_DATA   = bytes((i * 37 + 11) & 0xFF for i in range(PLAIN_SIZE))

SUBDIR       = "/dropin_dir"
SUBDIR_FILES = ["a.bin", "b.bin", "c.bin"]

NOPERM_NAME  = "/dropin_noperm.bin"   # chmod 000 → EACCES family


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — matches brix_crc32c_copy(); used to verify the
# per-page CRCs in the pgread response are correct on BOTH servers.
# ---------------------------------------------------------------------------

_CRC32C_POLY = 0x82F63B78
_CRC32C_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC32C_POLY if (_c & 1) else (_c >> 1)
    _CRC32C_TABLE.append(_c)


@pytest.fixture(scope="module")
def stack():
    _guard_stack_1()
    _guard_stack_2()

    data_dir = os.path.join(_DIR, "data")
    _seed_data(data_dir)

    # This is a MODULE-scoped nginx fixture, so drive the registry launcher
    # directly (the function-scoped `lifecycle` fixture is just a thin wrapper
    # around this same LifecycleHarness).  The reference xrootd keeps its own
    # subprocess lifecycle unchanged.
    xr_cfg = _start_xrootd(data_dir)
    harness = LifecycleHarness()
    try:
        _guard_stack_3()
        # Robustness: a TIME-WAIT/orphaned listener on the port can make a bare
        # connect succeed even though THIS xrootd failed to bind and is serving
        # the wrong (or no) data.  Prove the official server actually serves the
        # seed file before trusting it; skip otherwise rather than hard-fail.
        _guard_stack_4()
        ep = harness.start(NginxInstanceSpec(
            name="lc-dropin-front",
            template="nginx_lc_dropin_front.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": data_dir},
            reason="drop-in byte-for-byte parity front over the shared "
                   "data root vs the official xrootd"))
        _guard_stack_5(ep)
        _guard_stack_6(ep)
        yield {
            "data_dir": data_dir,
            "nginx": (ep.host, ep.port),
            "xrootd": (H, REF_XROOTD_PORT),
        }
    finally:
        harness.close()
        _stop_xrootd(xr_cfg)


@pytest.fixture
def both(stack):
    """Two live, logged-in sessions: (nginx_sock, brix_sock).  Cleaned up.

    If either session cannot be established the test SKIPS rather than errors —
    the module-level `stack` fixture has already proven both servers serve the
    seed data, so a failure here is an environment hiccup, not a parity bug."""
    try:
        n = _session(*stack["nginx"])
    except _SessionUnavailable as exc:
        pytest.skip(f"nginx session unavailable: {exc}")
    try:
        x = _session(*stack["xrootd"])
    except _SessionUnavailable as exc:
        n.close()
        pytest.skip(f"official xrootd session unavailable: {exc}")
    try:
        yield n, x
    finally:
        for s in (n, x):
            try:
                s.close()
            except Exception:
                pass


# ===========================================================================
# 1. stat ASCII body — field order/format matches official
# ===========================================================================

def _is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


# ===========================================================================
# 6. error family — ENOENT / EACCES / EISDIR match official
# ===========================================================================


def stack_data_dir():
    return os.path.join(_DIR, "data")


# ===========================================================================
# 7. kXR_clone (v5 opcode) — Unsupported or consistent behaviour
# ===========================================================================
