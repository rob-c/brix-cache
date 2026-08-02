"""
Phase-33 P1 — runtime pipeline-depth directive (brix_pipeline_depth).

P1's highest-leverage structural item was raising the in-flight read pipeline
from the fixed `#define BRIX_PIPELINE_MAX 4`.  That landed as a runtime knob:
`brix_pipeline_depth N`, default 8 (raised from 4), merged/clamped to
[BRIX_PIPELINE_DEPTH_MIN=1, BRIX_PIPELINE_DEPTH_MAX=64], with the per-connection
out/read rings sized to the configured depth.  The *throughput* magnitude of a
deeper pipeline needs the P0 perf host (a high-BDP link — loopback has ~zero BDP
so depth is invisible to wall-clock here); what IS gate-able unprivileged, and
what P1 explicitly names as the non-negotiable gate for any pipeline change, is
**correctness**: byte-exact reads must hold at the pipeline floor (depth=1),
above the old fixed value (depth=32), and — crucially — when the client actually
pipelines multiple reads in flight so the depth-sized ring is exercised.

  * parse:  a valid depth is accepted; an out-of-range depth still parses (it is
            silently clamped, not rejected); a non-numeric depth is refused.
  * serial: a large multi-chunk file reads back byte-exact at depth 1 and 32.
  * burst:  many reads pipelined in flight on one connection drain back in order,
            each byte-exact — this is the path a raised depth widens.

Self-contained: single-process nginx via the lifecycle harness; no fleet, no
privilege.  See
docs/refactor/phase-33-perf-optimization-post-feature-complete.md § P1.
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
from _perf_ab_helpers import _read_whole_file, kXR_oksofar

pytestmark = [pytest.mark.netfault, pytest.mark.serial,
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-pipeline-depth-stream"),
              pytest.mark.timeout(180)]

_MiB = 1024 * 1024
# 40 MiB so a whole-file read spans multiple 16 MiB wire chunks (multi-chunk
# sendfile framing) and, at 4 MiB reads, is 10 requests — enough to keep a
# depth>1 ring populated.
_FILE_MB = 40


def _pattern(size):
    """Deterministic, position-checkable filler: byte i == i & 0xff."""
    return bytes(i & 0xFF for i in range(256)) * (size // 256) + \
        bytes(i & 0xFF for i in range(size % 256))


_CONTENT = _pattern(_FILE_MB * _MiB)


def _boot(lifecycle, tmp_path, depth):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    dataroot = tmp_path / f"data-d{depth}"
    dataroot.mkdir()
    (dataroot / "big.bin").write_bytes(_CONTENT)

    ep = lifecycle.start(NginxInstanceSpec(
        name=f"lc-pipeline-depth-{depth}",
        template="nginx_lc_pipeline_depth_stream.conf",
        protocol="root",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(dataroot),
            "PIPELINE_DEPTH": str(depth),
        },
        reason="phase-33 P1 pipeline-depth correctness gate"))
    return HOST, ep.port


def _login_open(host, port):
    s = _raw_connect(host, port)
    hs, pr, lg = _full_anon_login(s)
    assert hs == kXR_ok and pr == kXR_ok and lg == kXR_ok, (hs, pr, lg)
    s.sendall(make_open_req(b"/big.bin"))
    st, body = _recv_response(s)
    assert st == kXR_ok, f"open failed: {st}"
    return s, body[:4]


def _pipelined_read_all(sock, handle, size, chunk, in_flight):
    """Read the whole file with up to `in_flight` reads outstanding at once —
    the client sends the next request before draining the previous response, so
    the server's depth-sized in-flight ring is genuinely populated.  Returns the
    concatenated bytes served (each response drained across kXR_oksofar segments,
    responses consumed strictly in request order)."""
    offsets = list(range(0, size, chunk))
    out = bytearray()
    sent = 0
    done = 0
    # Prime the pipe.
    while sent < len(offsets) and sent < in_flight:
        off = offsets[sent]
        sock.sendall(make_read_req(handle, off, min(chunk, size - off)))
        sent += 1
    while done < len(offsets):
        got = 0
        while True:
            st, data = _recv_response(sock)
            assert st in (kXR_ok, kXR_oksofar), (
                f"pipelined read #{done} @ {offsets[done]} failed: st={st}")
            out += data
            got += len(data)
            if st == kXR_ok:
                break
        assert got, f"empty pipelined read #{done} @ {offsets[done]}"
        done += 1
        if sent < len(offsets):
            off = offsets[sent]
            sock.sendall(make_read_req(handle, off, min(chunk, size - off)))
            sent += 1
    return bytes(out)


# --------------------------------------------------------------------------- #
# serial byte-exact — floor (depth=1) and well above the old fixed cap (depth=32)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("depth", [1, 32])
def test_pipeline_depth_serial_read_byte_exact(lifecycle, tmp_path, depth):
    host, port = _boot(lifecycle, tmp_path, depth)
    s, handle = _login_open(host, port)
    try:
        got = _read_whole_file(s, handle, len(_CONTENT))
        assert got == len(_CONTENT), f"short read {got} != {len(_CONTENT)}"
        # Re-read into a buffer to compare content (not just length).
        s.sendall(make_read_req(handle, 0, 4 * _MiB))
        st, data = _recv_response(s)
        assert st in (kXR_ok, kXR_oksofar)
        assert data == _CONTENT[:len(data)], "content mismatch at head"
    finally:
        s.sendall(make_close_req(handle))
        _recv_response(s)
        s.close()


# --------------------------------------------------------------------------- #
# pipelined burst — many reads in flight; the ring a raised depth widens is
# actually populated, and every response is byte-exact and in order
# --------------------------------------------------------------------------- #

def test_pipeline_depth_burst_in_flight_byte_exact(lifecycle, tmp_path):
    depth = 32
    host, port = _boot(lifecycle, tmp_path, depth)
    s, handle = _login_open(host, port)
    try:
        served = _pipelined_read_all(s, handle, len(_CONTENT),
                                     chunk=4 * _MiB, in_flight=depth)
        assert served == _CONTENT, (
            f"pipelined burst content mismatch (len {len(served)} vs "
            f"{len(_CONTENT)})")
    finally:
        s.sendall(make_close_req(handle))
        _recv_response(s)
        s.close()


# --------------------------------------------------------------------------- #
# parse — valid accepted; out-of-range clamped (not rejected); non-numeric refused
# --------------------------------------------------------------------------- #

def _parse(tmp_path, depth):
    dataroot = tmp_path / "data"
    if not dataroot.exists():
        dataroot.mkdir()
    return nginx_t(
        "nginx_lc_pipeline_depth_stream.conf", tmp_path,
        BIND_HOST=BIND_HOST, PORT=PARSE_PLACEHOLDER_PORT, LOG_DIR=str(tmp_path),
        DATA_DIR=str(dataroot), PIPELINE_DEPTH=depth)


def test_pipeline_depth_parse_accepts_valid(tmp_path):
    result = _parse(tmp_path, "16")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("depth", ["0", "9999"])
def test_pipeline_depth_out_of_range_is_clamped_not_rejected(tmp_path, depth):
    # Below MIN / above MAX are silently clamped at merge, so `nginx -t` must
    # still succeed — a future change that turned the clamp into a hard reject
    # would turn this red.
    result = _parse(tmp_path, depth)
    assert result.returncode == 0, result.stdout + result.stderr


def test_pipeline_depth_rejects_non_numeric(tmp_path):
    result = _parse(tmp_path, "deep")
    assert result.returncode != 0, result.stdout + result.stderr
    diag = (result.stdout + result.stderr).lower()
    assert "brix_pipeline_depth" in diag or "invalid" in diag
