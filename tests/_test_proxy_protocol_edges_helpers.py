# _test_proxy_protocol_edges_helpers.py - shared header/helpers/fixtures/constants for the Phase-38
# split of test_proxy_protocol_edges.py.  `from _test_proxy_protocol_edges_helpers import *` re-exports EVERYTHING via
# the __all__ below so the test functions keep their exact module namespace.
#
# The body is split across three files, all executed into THIS module's
# namespace (see the loader at the foot of this file):
#
#   this file  - module docstring, ports, wire constants, client-side raw-wire
#                helpers (the request/response codecs the tests drive);
#   _test_proxy_protocol_edges_stub.py      - the deterministic stub upstream:
#                bootstrap, per-scenario handlers and the threaded _StubServer;
#   _test_proxy_protocol_edges_fixtures.py  - nginx proxy-front provisioning and
#                the per-scenario pytest fixtures that pair a stub with a front.


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

def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"socket closed, {n - len(buf)} bytes remaining")
        buf.extend(chunk)
    return bytes(buf)


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", hdr)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


# Redirect-follow warm-up paths, keyed by proxy-front port (see _connect_login).
#
# The transparent proxy only saves a request for transparent re-issue when it is
# forwarded from an already-IDLE upstream session (brix_proxy_save_wait_retry in
# src/net/proxy/forward_request.c).  The very first forwarded request instead
# rides the bootstrap-deferred path (brix_proxy_dispatch_pending ->
# pending_flush), which never populates the wait-retry buffer — so a kXR_redirect
# on the first forwarded op is followed but has nothing to re-issue, and the
# request stalls without surfacing to the client.  A single path op first drives
# the upstream session to IDLE so the op under test travels the real re-issue
# path.
#
# The hop front additionally needs the proxy's redirect counter (which is never
# reset for the life of a client connection, src/net/proxy/forward_relay_response.c)
# walked up to the 3-hop cap: three followed redirects before the scenario op, so
# the fourth redirect is the one relayed to the client rather than followed.
_HOP_WARMUP_PATHS   = ("/__ppe_hop_warm__", "/__ppe_hop_hop1__",
                       "/__ppe_hop_hop2__", "/__ppe_hop_hop3__")
_REDIR_WARMUP_PATHS = ("/__ppe_redir_warm__",)


def _redirect_warmup_paths(port):
    if port == HOP_FRONT_PORT:
        return _HOP_WARMUP_PATHS
    if port == REDIR_FRONT_PORT:
        return _REDIR_WARMUP_PATHS
    return ()


def _connect_login(host, port, timeout=10):
    """Full bootstrap against the proxy front: handshake + protocol + login.

    For the redirect-follow fronts a short warm-up of path ops runs after login
    (see _redirect_warmup_paths) so the scenario op under test exercises the
    proxy's real redirect follow/relay path instead of stalling on the
    first-forwarded-request edge case."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    # client hello (20 bytes)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, ROOTD_PQ))
    # kXR_protocol
    sock.sendall(struct.pack("!2sHIBB10sI",
                             b"\x00\x01", kXR_protocol,
                             0x00000520, 0x02, 0x03, b"\x00" * 10, 0))
    _recv_exact(sock, 16)   # server hello (8-byte hdr + 8-byte body)
    _read_response(sock)    # kXR_protocol response
    # kXR_login
    sock.sendall(struct.pack("!2sHI8sBBBBI",
                             b"\x00\x01", kXR_login,
                             os.getpid() & 0xFFFFFFFF,
                             b"pytest\x00\x00", 0, 0, 5, 0, 0))
    _read_response(sock)
    for warm_path in _redirect_warmup_paths(port):
        _stat(sock, warm_path, sid=b"\x00\x01")
    return sock


def _open(sock, path, options=kXR_open_read, sid=b"\x00\x20"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH12sI", sid, kXR_open, 0o644, options,
                      b"\x00" * 12, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, sid=b"\x00\x60"):
    req = struct.pack("!2sH4s12sI", sid, kXR_close, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, data, sid=b"\x00\x40"):
    # ClientWriteRequest: streamid[2] reqid[2] fhandle[4] offset[8] pathid+rsvd[4] dlen[4]
    req = struct.pack("!2sH4sQ4sI", sid, 3019, fhandle, offset, b"\x00" * 4,
                      len(data))
    sock.sendall(req + data)
    return _read_response(sock)


def _stat(sock, path, sid=b"\x00\x10"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHB11s4sI", sid, kXR_stat, 0, b"\x00" * 11,
                      b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _dirlist(sock, path, sid=b"\x00\x70"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sH15sBI", sid, kXR_dirlist, b"\x00" * 15, 0, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _chmod(sock, path, mode=0o755, sid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    # ClientChmodRequest: streamid[2] reqid[2] reserved[14] mode[2] dlen[4]
    req = struct.pack("!2sH14sHI", sid, kXR_chmod, b"\x00" * 14, mode, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _ping(sock, sid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", sid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read_dirlist_all(sock):
    """Accumulate a dirlist response across kXR_oksofar frames; the client
    reassembles the streamed chunks into the full listing body."""
    body = b""
    while True:
        _sid, status, chunk = _read_response(sock)
        body += chunk
        if status != kXR_oksofar:
            return status, body


from split_continuation import load as _load_continuations

# The stub upstream and the fixtures are physical continuations of this module,
# not standalone modules: they close over the ports, wire constants and client
# helpers above, and the fixtures hand the tests values produced by both.  One
# namespace is also what `reexport` needs -- it copies this module's vars into
# each test file, so a fixture defined in a shard must land here first.
_load_continuations(globals(), __file__,
                    "_test_proxy_protocol_edges_stub.py",
                    "_test_proxy_protocol_edges_fixtures.py")

__all__ = [n for n in dir() if not n.startswith('__')]
