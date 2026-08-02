"""
Phase-33 P3-B3 — SO_SNDBUF / SO_RCVBUF accept-path sizing (root:// plane).

Verifies the `brix_socket_sndbuf` / `brix_socket_rcvbuf` directives:
  * success:  a server with both buffers pinned logs in and serves a byte-exact
              read — proving the accept-time setsockopt does not disturb data flow
  * error:    an over-cap value (above net.core.wmem_max) is best-effort — the
              setsockopt fails silently, the server still boots and serves
  * neg:      a non-size argument is rejected at config parse (`nginx -t`)

The server-side SO_SNDBUF is not client-observable, so — like the Phase-39
tcp_keepalive/user_timeout checks — these assert acceptance + undisturbed
operation rather than the kernel buffer value.  Self-contained: the test launches
its own single-process nginx via the lifecycle harness; no fleet, no privilege.

Marker: netfault (own serial lane).  See
docs/refactor/phase-33-perf-optimization-post-feature-complete.md § P3-B3.
"""
import os

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN
from server_registry import NginxInstanceSpec
from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT

from _test_a_robustness_helpers import (
    make_open_req,
    make_read_req,
    make_close_req,
    _recv_response,
    _full_anon_login,
    _connect as _raw_connect,
    kXR_ok,
)

pytestmark = [pytest.mark.netfault, pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-socketbuf-stream")]

_PAYLOAD = b"phase33-p3-b3 socket-buffer byte-exact payload\n" * 64


def _boot(lifecycle, tmp_path, sndbuf, rcvbuf):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    dataroot = tmp_path / "data"
    dataroot.mkdir()
    (dataroot / "hello.bin").write_bytes(_PAYLOAD)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-socketbuf-stream",
        template="nginx_lc_socketbuf_stream.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(dataroot),
            "SNDBUF": sndbuf,
            "RCVBUF": rcvbuf,
        },
        reason="phase-33 P3-B3 socket-buffer sizing"))
    return HOST, ep.port


def _login_open_read(host, port):
    """Full anon login → open /hello.bin → read it back; return the bytes read."""
    s = _raw_connect(host, port)
    try:
        hs, pr, lg = _full_anon_login(s)
        assert hs == kXR_ok and pr == kXR_ok and lg == kXR_ok, (hs, pr, lg)

        s.sendall(make_open_req(b"/hello.bin"))
        st, body = _recv_response(s)
        assert st == kXR_ok, f"open failed: {st}"
        handle = body[:4]

        s.sendall(make_read_req(handle, 0, len(_PAYLOAD)))
        st, data = _recv_response(s)
        assert st == kXR_ok, f"read failed: {st}"

        s.sendall(make_close_req(handle))
        _recv_response(s)
        return data
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# success: sane buffers pinned, data still byte-exact
# --------------------------------------------------------------------------- #

def test_socketbuf_pinned_read_byte_exact(lifecycle, tmp_path):
    host, port = _boot(lifecycle, tmp_path, "1m", "512k")
    assert _login_open_read(host, port) == _PAYLOAD


# --------------------------------------------------------------------------- #
# error: an over-cap value is best-effort (setsockopt fails, connection unharmed)
# --------------------------------------------------------------------------- #

def test_socketbuf_oversized_is_nonfatal(lifecycle, tmp_path):
    # 4 GiB is far above any plausible net.core.wmem_max → setsockopt fails, but
    # the accept path swallows it and the read must still succeed byte-exact.
    host, port = _boot(lifecycle, tmp_path, "4096m", "4096m")
    assert _login_open_read(host, port) == _PAYLOAD


# --------------------------------------------------------------------------- #
# feature-off: 0 leaves the kernel default (the directive is opt-in, zero-impact)
# --------------------------------------------------------------------------- #

def test_socketbuf_zero_is_kernel_default(lifecycle, tmp_path):
    # Both knobs at 0 → the accept path skips setsockopt entirely; the read must
    # behave exactly as an un-tuned server would.
    host, port = _boot(lifecycle, tmp_path, "0", "0")
    assert _login_open_read(host, port) == _PAYLOAD


# --------------------------------------------------------------------------- #
# parse: a valid size on both knobs is accepted at config parse
# --------------------------------------------------------------------------- #

def _parse(tmp_path, sndbuf, rcvbuf):
    dataroot = tmp_path / "data"
    dataroot.mkdir()
    # A never-bound placeholder port keeps the listen line syntactically valid so
    # the only parse verdict under test comes from the size directives, not the
    # port (an invalid :0 would emit its own "invalid port" and mask the result).
    return nginx_t(
        "nginx_lc_socketbuf_stream.conf", tmp_path,
        BIND_HOST=BIND_HOST, PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
        DATA_DIR=str(dataroot), SNDBUF=sndbuf, RCVBUF=rcvbuf)


def test_socketbuf_parse_accepts_valid_sizes(tmp_path):
    result = _parse(tmp_path, "2m", "1m")
    assert result.returncode == 0, result.stdout + result.stderr


# --------------------------------------------------------------------------- #
# neg: a non-size argument on either knob is rejected at config parse
# --------------------------------------------------------------------------- #

def test_socketbuf_rejects_non_size_sndbuf(tmp_path):
    result = _parse(tmp_path, "not-a-size", "512k")
    assert result.returncode != 0, result.stdout + result.stderr
    diag = (result.stdout + result.stderr).lower()
    assert "brix_socket_sndbuf" in diag or "invalid" in diag


def test_socketbuf_rejects_non_size_rcvbuf(tmp_path):
    result = _parse(tmp_path, "512k", "not-a-size")
    assert result.returncode != 0, result.stdout + result.stderr
    diag = (result.stdout + result.stderr).lower()
    assert "brix_socket_rcvbuf" in diag or "invalid" in diag
