# _test_proxy_protocol_edges_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_proxy_protocol_edges.py.  `from _test_proxy_protocol_edges_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.


"""
tests/test_proxy_protocol_edges.py — protocol-edge conformance for nginx's
transparent XRootD proxy (``brix_tap_proxy on`` + ``brix_tap_proxy_upstream``).

This suite stands up its OWN dedicated nginx proxy front in front of a
self-contained, deterministic Python protocol stub (modelled on
tests/upstream_protocol_stubs.py + tests/test_a_upstream_redirect.py) that
emits wire sequences a real xrootd never produces on demand — repeated
kXR_wait, kXR_redirect chains, streaming kXR_oksofar, oksofar interrupted by a
mid-stream wait, and friends.  It then drives the proxy from a raw-wire client
(struct-packed requests over a TCP socket, exactly like
tests/test_readv_security.py) so every hostile/edge response path through the
proxy relay is exercised, and proves the documented behaviour:

  * file-handle map saturation -> a single clean kXR_error, no crash;
  * a closed handle's slot is reusable and maps to a fresh upstream handle;
  * kXR_wait retry exhaustion (after BRIX_PROXY_MAX_WAIT_RETRIES) is relayed
    to the client rather than looping forever;
  * a kXR_wait whose in-flight request payload is too large to buffer is NOT
    saved for retry, so the wait is relayed immediately;
  * the redirect-follow hop limit (3) is honoured — the 4th redirect is relayed;
  * following a redirect invalidates the proxy's handle map (new upstream);
  * a kXR_oksofar streamed dirlist is reassembled by the client;
  * an oksofar stream interrupted mid-flight by a kXR_wait still completes;
  * dirlist entry names are returned verbatim (no path rewrite of payload);
  * kXR_chmod is forwarded and its status relayed;
  * an endsess mid-flight is handled cleanly (connection torn down, no hang).

Each edge request is followed by a sanity op (a fresh session + ping, or a
follow-up request on the survivor connection) proving the proxy worker survived.
The suite is fully self-provisioned on dedicated high ports (>= 12950) and skips
cleanly if the nginx binary is missing or the stack does not come up.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_proxy_protocol_edges.py -v
"""

import os
import socket
import struct
import threading
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, SERVER_HOST
from ephemeral_port import free_ports
from server_launcher import LifecycleHarness, RegistryCommandFailure
from server_registry import NginxInstanceSpec

# This suite stands up its own throwaway nginx proxy fronts through the phase-81
# registry (LifecycleHarness) rather than launching nginx directly; the marker
# keeps it out of the registry-lint direct-launch scope.
pytestmark = [pytest.mark.timeout(90), pytest.mark.uses_lifecycle_harness]

H = SERVER_HOST

# ---------------------------------------------------------------------------
# Dedicated high ports (>= 12950, unique to this file to avoid collisions).
# Each scenario gets its own stub-backend port + nginx-front port so the
# fixtures stay independent and a wedged stub cannot poison another test.
# ---------------------------------------------------------------------------
# Every port below is BOUND by this file's own fixtures (each nginx proxy front
# listens on a FRONT port; the in-process stub server listens on each BACKEND /
# TARGET port).  None are fleet/remote ports.  Allocate them all as DISTINCT
# free OS ports in one shot so this self-contained suite never collides with the
# managed fleet or another test, while keeping any explicit env override.
(_p_sat_front, _p_sat_backend, _p_reuse_front, _p_reuse_backend,
 _p_waitx_front, _p_waitx_backend, _p_waitbig_front, _p_waitbig_backend,
 _p_hop_front, _p_hop_backend, _p_redir_front, _p_redir_backend,
 _p_redir_target, _p_oks_front, _p_oks_backend, _p_oksw_front,
 _p_oksw_backend, _p_chmod_front, _p_chmod_backend, _p_endsess_front,
 _p_endsess_backend, _p_prw_front, _p_prw_backend) = free_ports(23)

SAT_FRONT_PORT      = int(os.environ.get("TEST_PPE_SAT_FRONT_PORT")      or _p_sat_front)
SAT_BACKEND_PORT    = int(os.environ.get("TEST_PPE_SAT_BACKEND_PORT")    or _p_sat_backend)
REUSE_FRONT_PORT    = int(os.environ.get("TEST_PPE_REUSE_FRONT_PORT")    or _p_reuse_front)
REUSE_BACKEND_PORT  = int(os.environ.get("TEST_PPE_REUSE_BACKEND_PORT")  or _p_reuse_backend)
WAITX_FRONT_PORT    = int(os.environ.get("TEST_PPE_WAITX_FRONT_PORT")    or _p_waitx_front)
WAITX_BACKEND_PORT  = int(os.environ.get("TEST_PPE_WAITX_BACKEND_PORT")  or _p_waitx_backend)
WAITBIG_FRONT_PORT  = int(os.environ.get("TEST_PPE_WAITBIG_FRONT_PORT")  or _p_waitbig_front)
WAITBIG_BACKEND_PORT= int(os.environ.get("TEST_PPE_WAITBIG_BACKEND_PORT")or _p_waitbig_backend)
HOP_FRONT_PORT      = int(os.environ.get("TEST_PPE_HOP_FRONT_PORT")      or _p_hop_front)
HOP_BACKEND_PORT    = int(os.environ.get("TEST_PPE_HOP_BACKEND_PORT")    or _p_hop_backend)
REDIR_FRONT_PORT    = int(os.environ.get("TEST_PPE_REDIR_FRONT_PORT")    or _p_redir_front)
REDIR_BACKEND_PORT  = int(os.environ.get("TEST_PPE_REDIR_BACKEND_PORT")  or _p_redir_backend)
REDIR_TARGET_PORT   = int(os.environ.get("TEST_PPE_REDIR_TARGET_PORT")   or _p_redir_target)
OKS_FRONT_PORT      = int(os.environ.get("TEST_PPE_OKS_FRONT_PORT")      or _p_oks_front)
OKS_BACKEND_PORT    = int(os.environ.get("TEST_PPE_OKS_BACKEND_PORT")    or _p_oks_backend)
OKSW_FRONT_PORT     = int(os.environ.get("TEST_PPE_OKSW_FRONT_PORT")     or _p_oksw_front)
OKSW_BACKEND_PORT   = int(os.environ.get("TEST_PPE_OKSW_BACKEND_PORT")   or _p_oksw_backend)
CHMOD_FRONT_PORT    = int(os.environ.get("TEST_PPE_CHMOD_FRONT_PORT")    or _p_chmod_front)
CHMOD_BACKEND_PORT  = int(os.environ.get("TEST_PPE_CHMOD_BACKEND_PORT")  or _p_chmod_backend)
ENDSESS_FRONT_PORT  = int(os.environ.get("TEST_PPE_ENDSESS_FRONT_PORT")  or _p_endsess_front)
ENDSESS_BACKEND_PORT= int(os.environ.get("TEST_PPE_ENDSESS_BACKEND_PORT")or _p_endsess_backend)
PRW_FRONT_PORT      = int(os.environ.get("TEST_PPE_PRW_FRONT_PORT")      or _p_prw_front)
PRW_BACKEND_PORT    = int(os.environ.get("TEST_PPE_PRW_BACKEND_PORT")    or _p_prw_backend)

# ---------------------------------------------------------------------------
# XRootD wire constants (authoritative: src/XProtocol/XProtocol.hh).
# ---------------------------------------------------------------------------
kXR_auth     = 3000
kXR_chmod    = 3002
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_protocol = 3006
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_stat     = 3017
kXR_endsess  = 3023

kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_redirect = 4004
kXR_wait     = 4005
kXR_waitresp = 4006

kXR_open_read = 0x0010

# Source-of-truth limits (src/net/proxy/proxy_internal.h, src/core/types/tunables.h).
BRIX_PROXY_MAX_WAIT_RETRIES = 5
BRIX_MAX_FILES              = 16   # proxy fh_map slot count -> saturation point
WAIT_SAVE_LIMIT               = 128 * 1024  # rlen < this is saved for retry

ROOTD_PQ = 2012


# ===========================================================================
# Client-side raw wire helpers (mirror tests/test_readv_security.py style)
# ===========================================================================

@pytest.fixture
def path_rewrite_stack():
    # Dedicated ports so this does not collide with oksofar_stack (which reuses
    # the same listen ports and would otherwise EADDRINUSE back-to-back).
    stub, harness, port = _stack("ppe_prw", PRW_FRONT_PORT,
                        [(PRW_BACKEND_PORT, _h_oksofar_dirlist)], PRW_BACKEND_PORT)
    try:
        yield port
    finally:
        harness.close()
        stub.stop()


# ===========================================================================
# Scenarios
# ===========================================================================

__all__ = [n for n in dir() if not n.startswith('__')]
