"""
Tests for manager-mode XRootD redirector functionality:

  Part 1 — Static brix_manager_map: a fixed path-prefix → backend mapping
            that returns kXR_redirect for matching kXR_locate requests.

  Part 2 — Dynamic cluster mode (brix_manager_mode + brix_cms_server):
            data servers register via the CMS protocol; kXR_locate and
            kXR_open on the redirector return kXR_redirect to the best
            registered data server.

Both parts use raw sockets so we can assert wire-level response contents
without a PyXRootD dependency.
"""

import os
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from settings import (
    CLUSTER_3T_LEAF_PORT,
    CLUSTER_3T_META_CMS_PORT,
    CLUSTER_3T_META_PORT,
    CLUSTER_3T_SUB_CMS_PORT,
    CLUSTER_3T_SUB_PORT,
    CLUSTER_CMS_PORT,
    CLUSTER_DS_DATA_ROOT,
    CLUSTER_DS_PORT,
    CLUSTER_ESC_LEAF_DATA_ROOT,
    CLUSTER_ESC_LEAF_PORT,
    CLUSTER_ESC_SUB_PORT,
    CLUSTER_GONE_DS_PORT,
    CLUSTER_GONE_DS_PORT_A,
    CLUSTER_GONE_DS_PORT_B,
    CLUSTER_MP_CMS_PORT,
    CLUSTER_MP_DS_PORT,
    CLUSTER_MP_REDIR_PORT,
    CLUSTER_MS_CMS_PORT,
    CLUSTER_MS_DS1_DATA_ROOT,
    CLUSTER_MS_DS1_PORT,
    CLUSTER_MS_DS2_DATA_ROOT,
    CLUSTER_MS_DS2_PORT,
    CLUSTER_MS_REDIR_PORT,
    CLUSTER_MW_CMS_PORT,
    CLUSTER_MW_PORT,
    CLUSTER_REDIR_PORT,
    CLUSTER_SELECT_PORT,
    CLUSTER_SELECT_REDIRECT_PORT,
    CLUSTER_SLOTS_DS1_DATA_ROOT,
    CLUSTER_SLOTS_DS1_PORT,
    CLUSTER_SLOTS_DS2_DATA_ROOT,
    CLUSTER_SLOTS_DS2_PORT,
    CLUSTER_SLOTS_DS3_DATA_ROOT,
    CLUSTER_SLOTS_DS3_PORT,
    CLUSTER_SLOTS_DS4_DATA_ROOT,
    CLUSTER_SLOTS_DS4_PORT,
    CLUSTER_SLOTS_METRICS_PORT,
    CLUSTER_SLOTS_REDIR_PORT,
    CLUSTER_TRY_FIRST_PORT,
    CLUSTER_TRY_PORT,
    CLUSTER_TRY_SECOND_PORT,
    HOST,
    MANAGER_PORT,
    NGINX_BIN,
    REGISTRY_ROOT,
    TEST_ROOT,
    url_host,
)


def _cms_login_payload(port: int, path: str = "/") -> bytes:
    """Build the LOGIN payload in the real XrdCms CmsLoginData wire order
    (XrdOucPup), matching cms/send.c: ten type-tagged scalars (version, mode,
    holdtime, tSpace, fSpace, mSpace, fsNum, fsUtil, dPort, sPort) followed by
    four strings (SID, Paths, ifList, envCGI).  Paths is a newline-separated
    list of "<type> <namespace-path>" entries; server_recv.c strips the leading
    type token, so "w /gone-test" registers the bare path "/gone-test"."""
    paths_str = ("w " + path).encode()
    return (
        _cms_put_short(3)            # version
        + _cms_put_int(0x00000008)   # mode = DataServer
        + _cms_put_int(0)            # holdtime
        + _cms_put_int(0)            # tSpace (total GB)
        + _cms_put_int(1024)         # fSpace ← free_mb
        + _cms_put_int(100)          # mSpace (min free MB)
        + _cms_put_short(1)          # fsNum
        + _cms_put_short(0)          # fsUtil ← util_pct
        + _cms_put_short(port)       # dPort ← registered XRootD port
        + _cms_put_short(0)          # sPort
        + _cms_put_string(b"test-ds")  # SID (ignored by the server)
        + _cms_put_string(paths_str)   # Paths "<type> <path>"
        + _cms_put_string(b"")         # ifList (empty)
        + _cms_put_string(b"")         # envCGI (empty)
    )


def _cms_recv_frame(sock: socket.socket):
    """Read one complete CMS frame; return (streamid, opcode, payload)."""
    hdr = _cluster_recv_exact(sock, 8)
    streamid, opcode, _modifier, dlen = struct.unpack(">IBBH", hdr)
    payload = _cluster_recv_exact(sock, dlen) if dlen else b""
    return streamid, opcode, payload


# ═══════════════════════════════════════════════════════════════════════════
# Part 5 — Three-tier topology
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def three_tier():
    """Use the pre-launched cluster-3t-meta + cluster-3t-sub + cluster-3t-leaf."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    t3_data = os.path.join(TEST_ROOT, "data-cluster-3t-leaf")
    os.makedirs(t3_data, exist_ok=True)
    Path(t3_data, "test.txt").write_text("three-tier test file")

    _wait_port(CLUSTER_3T_META_PORT, "cluster-3t-meta")
    _wait_for_redirect(CLUSTER_3T_META_PORT, "/test.txt", CLUSTER_3T_SUB_PORT)

    yield {
        "meta_port":     CLUSTER_3T_META_PORT,
        "sub_port":      CLUSTER_3T_SUB_PORT,
        "leaf_port":     CLUSTER_3T_LEAF_PORT,
        "meta_cms_port": CLUSTER_3T_META_CMS_PORT,
        "sub_cms_port":  CLUSTER_3T_SUB_CMS_PORT,
    }



@pytest.fixture(scope="module")
def cms_select():
    """Pre-started cluster-select nginx at CLUSTER_SELECT_PORT backed by CMS stub."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    _wait_port(CLUSTER_SELECT_PORT, "cluster-select")
    yield {
        "redir_port":    CLUSTER_SELECT_PORT,
        "redirect_port": CLUSTER_SELECT_REDIRECT_PORT,
    }



@pytest.fixture(scope="module")
def cluster_full_registry():
    """Use pre-launched cluster-slots-redir + 4 cluster-slots-ds instances."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    ds_data_roots = [
        CLUSTER_SLOTS_DS1_DATA_ROOT,
        CLUSTER_SLOTS_DS2_DATA_ROOT,
        CLUSTER_SLOTS_DS3_DATA_ROOT,
        CLUSTER_SLOTS_DS4_DATA_ROOT,
    ]
    ds_ports = [
        CLUSTER_SLOTS_DS1_PORT,
        CLUSTER_SLOTS_DS2_PORT,
        CLUSTER_SLOTS_DS3_PORT,
        CLUSTER_SLOTS_DS4_PORT,
    ]
    for i, dr in enumerate(ds_data_roots):
        os.makedirs(dr, exist_ok=True)
        Path(dr, "file.txt").write_text(f"server {i}")

    _wait_port(CLUSTER_SLOTS_REDIR_PORT, "cluster-slots-redir")
    # Give all 4 data servers time to attempt CMS registration.
    time.sleep(5.0)

    yield {
        "redir_port":   CLUSTER_SLOTS_REDIR_PORT,
        "metrics_port": CLUSTER_SLOTS_METRICS_PORT,
        "ds_ports":     ds_ports,
    }



def _cms_connect_and_register(cms_port: int, xrd_port: int,
                                   path: str) -> socket.socket:
    """Connect to the nginx CMS server port and send a LOGIN frame for the
    given XRootD port and path.  Returns the open TCP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, cms_port))
    payload = _cms_login_payload(xrd_port, path)
    sock.sendall(_cms_frame(1, CMS_RR_LOGIN, payload))
    return sock



@pytest.fixture(scope="module")
def cms_try():
    """Pre-started CMS-try cluster at CLUSTER_TRY_PORT backed by cms_parent_stubs.py."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")
    _wait_port(CLUSTER_TRY_PORT, "cms-try")
    yield {
        "redir_port":  CLUSTER_TRY_PORT,
        "first_port":  CLUSTER_TRY_FIRST_PORT,
        "second_port": CLUSTER_TRY_SECOND_PORT,
    }



@pytest.fixture(scope="module")
def cms_escalation():
    """Pre-started escalation cluster backed by cms_parent_stubs.py."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found: {NGINX_BIN}")

    leaf_file = Path(CLUSTER_ESC_LEAF_DATA_ROOT, "escalate", "file.dat")
    leaf_file.parent.mkdir(parents=True, exist_ok=True)
    leaf_file.write_text("cms escalation target")

    _wait_port(CLUSTER_ESC_SUB_PORT, "cms-escalation-sub")
    yield {
        "sub_port":  CLUSTER_ESC_SUB_PORT,
        "leaf_port": CLUSTER_ESC_LEAF_PORT,
    }
