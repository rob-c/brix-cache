"""E-4 DoS resilience — negative-path (stat/locate-harvest) backoff.

Boots our nginx-xrootd data server with ``brix_negcache_backoff`` armed and
proves the SHIPPED throttle at the wire level, exactly to the plan's acceptance
("a stat-harvest loop trips backoff; a per-identity flood is throttled while
other identities are unaffected"):

  success   — a single principal stat-harvesting missing paths arms the throttle
              and subsequent misses come back as kXR_wait, while a stat of a real
              (non-missing) file on the very same over-budget connection still
              succeeds — the throttle targets misses, not the client;
  security  — a *second* identity (distinct source IP → distinct principal) is
              unaffected while the first is being throttled — one abuser cannot
              starve everyone;
  error/neg — a malformed ``brix_negcache_backoff`` is refused by ``nginx -t``.

Reuses the raw XRootD wire client shipped in test_phase25_ratelimit (stat / recv
/ status codes) so this test drives the real protocol, not the stock toolchain.
The isolation case binds the client socket to 127.0.0.2 so the server sees a
second loopback peer — the negcache keys anonymous principals by client IP.
"""

import socket
import struct

import pytest

from config_parse import nginx_t
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from test_phase25_ratelimit import (
    _xrd_stat, _xrd_open, KXR_WAIT, KXR_OK,
)

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-negcache")]


@pytest.fixture(autouse=True)
def _require_binary():
    import os
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _login(port, src_ip=None):
    """XRootD login handshake (mirrors test_phase25_ratelimit._xrd_login) with an
    optional source-IP bind so callers can present as distinct loopback peers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    if src_ip is not None:
        s.bind((src_ip, 0))
    s.connect((HOST, port))
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.sendall(struct.pack(">BB H I BB 10x I", 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))
    s.recv(16)
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    s.sendall(struct.pack(">BB H I 8s BB B B I", 0, 1, 3007, 0,
                          b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    hdr = s.recv(8)
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        s.recv(dlen)
    return s


def _stream_values(knobs):
    return {"BIND_HOST": BIND_HOST, "RL_KNOBS": knobs, "STREAM_EXTRA": ""}


def _start(lifecycle, data, name, knobs):
    ep = lifecycle.start(NginxInstanceSpec(
        name=name, template="nginx_rl_stream.conf", data_root=str(data),
        template_values=_stream_values(knobs),
        reason="E-4 negcache backoff functional coverage"))
    return ep.port


# threshold 5, 60 s window, 2 s wait: arms on the 5th miss, then paces.
_KNOBS = "        brix_negcache_backoff 5 60 2;\n"


# --------------------------------------------------------------------------- #
# success: a stat-harvest loop trips the backoff; real files still resolve.
# --------------------------------------------------------------------------- #
def test_stat_harvest_trips_backoff(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "real.dat").write_text("present\n")
    port = _start(lifecycle, data, "lc-negcache-harvest", _KNOBS)

    s = _login(port)
    statuses = [_xrd_stat(s, f"/ghost/miss-{i}.dat")[0] for i in range(15)]
    # A real file on the SAME (now over-budget) connection must still resolve —
    # the throttle keys on misses, never on the principal wholesale.
    st_real, _ = _xrd_stat(s, "/real.dat")
    st_open, _ = _xrd_open(s, "/real.dat")
    s.close()

    assert KXR_WAIT in statuses, ("stat-harvest loop must trip kXR_wait", statuses)
    assert st_real != KXR_WAIT, ("real-file stat must not be throttled", st_real)
    assert st_open == KXR_OK, ("real-file open must succeed", st_open)


# --------------------------------------------------------------------------- #
# security-negative: a distinct identity is unaffected by another's flood.
# --------------------------------------------------------------------------- #
def test_other_identity_unaffected(lifecycle, tmp_path):
    data = tmp_path / "data"; data.mkdir()
    port = _start(lifecycle, data, "lc-negcache-isolation", _KNOBS)

    # Identity A (127.0.0.1) floods missing paths until it is throttled.
    a = _login(port, src_ip=HOST)
    a_statuses = [_xrd_stat(a, f"/ghost/a-{i}.dat")[0] for i in range(12)]
    assert KXR_WAIT in a_statuses, ("flooding identity must be throttled", a_statuses)

    # Identity B (127.0.0.2 → distinct principal) makes its first miss: its own
    # budget is untouched, so it is served (NotFound), never made to wait.
    b = _login(port, src_ip="127.0.0.2")
    b_status, _ = _xrd_stat(b, "/ghost/b-0.dat")
    a.close(); b.close()

    assert b_status != KXR_WAIT, ("other identity must not be throttled", b_status)


# --------------------------------------------------------------------------- #
# error: a malformed directive is refused at config parse.
# --------------------------------------------------------------------------- #
def test_bogus_config_refused(tmp_path):
    # nginx -t rejects before any bind; a non-binding placeholder port suffices.
    port = PARSE_PLACEHOLDER_PORT
    data = tmp_path / "data"; data.mkdir()
    values = dict(_stream_values("        brix_negcache_backoff abc;\n"),
                  PORT=port, DATA_ROOT=str(data),
                  LOG_DIR=str(tmp_path), TMP_DIR=str(tmp_path))
    result = nginx_t("nginx_rl_stream.conf", tmp_path, **values)
    out = (result.stdout or "") + (result.stderr or "")
    assert result.returncode != 0, out
    assert "brix_negcache_backoff" in out, out
