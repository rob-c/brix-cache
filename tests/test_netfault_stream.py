"""
Phase 39 — network-fault resilience, stream (root://) plane.

Verifies the steady-state per-connection deadlines added in Phase 1 (WS1/WS2/WS3):
  * brix_handshake_timeout — a stalled/partial UNAUTHENTICATED handshake is reaped
  * brix_read_timeout      — a stalled/partial in-flight request PDU is reaped
  * brix_send_timeout      — a slow/half-open CONSUMER (not reading) is reaped
  * normal operations are unaffected, and an authenticated IDLE connection (no PDU
    in progress) is NOT killed (long-lived xrdcp keepalive must survive)
  * brix_tcp_keepalive / brix_tcp_user_timeout are accepted (WS3 setsockopt path)

These are SELF-CONTAINED: the test launches its own single-process nginx with the
deadlines set to small values, so it needs no running fleet and no privilege.  The
raw-wire protocol builders are reused from test_a_robustness.

Marker: netfault (own serial lane).  See docs/refactor/phase-39-network-fault-resilience.md.
"""
import os
import socket
import time

import pytest

from settings import BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

from test_a_robustness import (
    HANDSHAKE,
    make_ping_req,
    make_stat_req,
    make_open_req,
    make_read_req,
    _recv_response,
    _full_anon_login,
    kXR_ok,
)

pytestmark = [pytest.mark.netfault, pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness]

HOST = "127.0.0.1"

HANDSHAKE_TIMEOUT_MS = 1000
READ_TIMEOUT_MS = 2000
SEND_TIMEOUT_MS = 2000


@pytest.fixture()
def nf_server(lifecycle, tmp_path):
    """Launch a single-process nginx with the Phase-39 deadlines enabled."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    dataroot = tmp_path / "data"
    dataroot.mkdir()
    (dataroot / "hello.txt").write_bytes(b"hello netfault\n")
    # A file big enough that a full-file read cannot drain into the socket buffer
    # while the client refuses to read — forces the send-drain park (WS2).
    (dataroot / "big.bin").write_bytes(os.urandom(4 * 1024 * 1024))

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-netfault-stream",
        template="nginx_lc_netfault_stream.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(dataroot),
            "HANDSHAKE_TIMEOUT_MS": HANDSHAKE_TIMEOUT_MS,
            "READ_TIMEOUT_MS": READ_TIMEOUT_MS,
            "SEND_TIMEOUT_MS": SEND_TIMEOUT_MS,
        },
        reason="phase-39 stream per-connection deadlines"))
    return (HOST, ep.port)


def _connect(host, port, timeout=6.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def _time_until_close(s, max_wait):
    """Block reading until the peer closes (FIN/RST); return elapsed seconds, or
    max_wait if it stayed open."""
    s.settimeout(max_wait)
    start = time.monotonic()
    try:
        while True:
            data = s.recv(4096)
            if not data:
                return time.monotonic() - start          # clean FIN
    except (ConnectionResetError, BrokenPipeError):
        return time.monotonic() - start                  # RST
    except socket.timeout:
        return max_wait                                  # stayed open


# --------------------------------------------------------------------------- #
# success: normal operations are unaffected by the deadlines
# --------------------------------------------------------------------------- #

def test_normal_login_and_stat(nf_server):
    host, port = nf_server
    s = _connect(host, port)
    try:
        hs, pr, lg = _full_anon_login(s)
        assert hs == kXR_ok and pr == kXR_ok and lg == kXR_ok, (hs, pr, lg)
        # multiple serial ops on one connection — proves disarm-on-complete works
        for _ in range(5):
            s.sendall(make_stat_req(b"/hello.txt"))
            st, _body = _recv_response(s)
            assert st == kXR_ok, st
    finally:
        s.close()


def test_authed_idle_keepalive_survives(nf_server):
    """An AUTHENTICATED connection with no PDU in progress must NOT be reaped by
    read_timeout (only in-flight partial PDUs are) — long-lived xrdcp sessions
    that pause between ops must survive."""
    host, port = nf_server
    s = _connect(host, port)
    try:
        hs, pr, lg = _full_anon_login(s)
        assert (hs, pr, lg) == (kXR_ok, kXR_ok, kXR_ok)
        # Idle well past read_timeout WITHOUT sending a partial PDU.
        time.sleep(READ_TIMEOUT_MS / 1000.0 + 1.5)
        # Connection must still serve a request.
        s.sendall(make_ping_req())
        st, _body = _recv_response(s)
        assert st == kXR_ok, f"idle authed connection was killed (ping st={st})"
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# error/security: stalls are reaped within the configured deadline (not instantly,
# not never)
# --------------------------------------------------------------------------- #

def test_handshake_stall_dropped(nf_server):
    host, port = nf_server
    s = _connect(host, port)
    try:
        s.sendall(HANDSHAKE[:10])          # 10 of 20 handshake bytes, then silence
        elapsed = _time_until_close(s, max_wait=HANDSHAKE_TIMEOUT_MS / 1000.0 + 3.0)
        lo = HANDSHAKE_TIMEOUT_MS / 1000.0 * 0.5
        hi = HANDSHAKE_TIMEOUT_MS / 1000.0 + 2.0
        assert lo < elapsed < hi, (
            f"handshake stall closed in {elapsed:.2f}s; expected ~"
            f"{HANDSHAKE_TIMEOUT_MS/1000.0}s (not instant, not never)")
    finally:
        s.close()


def test_read_pdu_partial_header_dropped(nf_server):
    host, port = nf_server
    s = _connect(host, port)
    try:
        hs, pr, lg = _full_anon_login(s)
        assert (hs, pr, lg) == (kXR_ok, kXR_ok, kXR_ok)
        # 12 of a 24-byte request header, then silence — an in-flight partial PDU.
        partial = make_stat_req(b"/hello.txt")[:12]
        s.sendall(partial)
        elapsed = _time_until_close(s, max_wait=READ_TIMEOUT_MS / 1000.0 + 3.0)
        lo = READ_TIMEOUT_MS / 1000.0 * 0.5
        hi = READ_TIMEOUT_MS / 1000.0 + 2.0
        assert lo < elapsed < hi, (
            f"partial-PDU stall closed in {elapsed:.2f}s; expected ~"
            f"{READ_TIMEOUT_MS/1000.0}s")
    finally:
        s.close()


def test_send_drain_slow_consumer_dropped(nf_server):
    """A consumer that opens a large read and then STOPS reading entirely must be
    reaped by send_timeout — its parked response slots (and the read_scratch they
    reference) cannot pin the worker forever.  Detected via POLLRDHUP/POLLHUP
    WITHOUT draining the socket: draining would be 'progress' and (correctly) keep
    the connection alive, so the consumer must be genuinely stuck."""
    host, port = nf_server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Small receive buffer (set before connect) so the server's send blocks after
    # only a few KB rather than buffering the whole 4 MiB locally.
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    except OSError:
        pass
    s.settimeout(6.0)
    s.connect((host, port))
    try:
        hs, pr, lg = _full_anon_login(s)
        assert (hs, pr, lg) == (kXR_ok, kXR_ok, kXR_ok)
        s.sendall(make_open_req(b"/big.bin"))
        st, body = _recv_response(s)
        assert st == kXR_ok, f"open failed st={st}"
        handle = body[:4]
        # Request the whole 4 MiB and then never read it.
        s.sendall(make_read_req(handle, 0, 4 * 1024 * 1024))
        # Stay genuinely stuck (read NOTHING) past send_timeout so the deadline
        # fires server-side.  Draining here would count as progress and (correctly)
        # keep the connection alive, so we must not read until after the deadline.
        time.sleep(SEND_TIMEOUT_MS / 1000.0 + 1.5)
        # The server has now reaped us.  Confirm by draining to EOF/RST within a
        # bound: if the deadline had NOT fired the connection would still be open
        # and the recv would block until its timeout (closed stays False).
        s.settimeout(2.0)
        closed = False
        total = 0
        try:
            while total < 8 * 1024 * 1024:
                d = s.recv(65536)
                if not d:
                    closed = True           # clean FIN
                    break
                total += len(d)
        except (ConnectionResetError, BrokenPipeError):
            closed = True                   # RST
        except socket.timeout:
            closed = False                  # still open & blocked → not reaped
        assert closed, (
            "stuck consumer was NOT reaped by send_timeout (connection still "
            "open after the deadline window)")
    finally:
        s.close()
