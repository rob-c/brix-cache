"""brix_io_offload_total — observability for §1.1 pathid response offloading.

The read-family offloading (kXR_read/readv/pgread route a reply over a bound
secondary data channel) had no way to tell, in production, whether it was
actually happening. `brix_io_offload_total{proto="stream"}` now counts each
offloaded response, so an operator can confirm multi-stream offloading is live
and measure its rate; the series is absent (never emitted) until the first
offload, so /metrics stays byte-identical for the common case.

Coverage:
  * success — after a pathid-tagged read whose reply is routed to the secondary,
              brix_io_offload_total{proto="stream"} == 1.
  * off     — a plain (pathid-0) read routes on the primary and increments
              nothing: the series stays absent.

Self-contained: launches one short-lived nginx carrying BOTH the offload-capable
stream server and an HTTP /metrics endpoint over the shared metrics SHM, drives a
manual bind + pathid read (the native client does not yet stamp pathids — §7),
then scrapes /metrics. No shared fleet / lifecycle harness.
"""

import socket
import struct
import urllib.request

import pytest

from settings import BIND_HOST
from metrics_helpers import value
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-offload-metric")]

_SERVER = "lc-offload-metric"

OFFLOAD = "brix_io_offload_total"
STREAM = {"proto": "stream"}


def _scrape(port):
    with urllib.request.urlopen(f"http://{BIND_HOST}:{port}/metrics",
                                timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def _launch(lifecycle):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_offload_metric.conf",
        template_values={"BIND_HOST": BIND_HOST},
        reason="pathid response-offload metric coverage"))
    return endpoint.port, endpoint.extra_ports["METRICS_PORT"], endpoint.data_root


def _read(stream_port, data_root, pathid_tagged):
    """One read against the stream server. When pathid_tagged, bind a secondary
    and tag the read so its reply is offloaded there (read from the secondary);
    otherwise a plain read on the primary. Returns nothing — the point is the
    server-side counter movement."""
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data_root
    content = b"offload-metric!!" * 32
    H._write_data_file("m.bin", content)
    primary, sessid, stream = H._establish_primary(stream_port)
    sec = None
    try:
        fh = H._open_read(primary, stream, "/m.bin")
        if pathid_tagged:
            sec, pathid = H._bind_on(stream_port, sessid)
            H._send_read_only(primary, b"\x00\x51", fh, len(content), pathid)
            sec.settimeout(5)
            _, status, data = H._recv_response(sec)
        else:
            status, data = H._read_handle(primary, stream, fh, len(content))
        assert status in (H.kXR_ok, H.kXR_oksofar), f"read status={status}"
        assert data == content, "read data mismatch"
    finally:
        if sec is not None:
            sec.close()
        primary.close()


def test_offloaded_read_increments_counter(lifecycle):
    """(success) a pathid-tagged read whose reply is routed to the secondary
    books exactly one brix_io_offload_total{proto="stream"}."""
    sport, mport, data = _launch(lifecycle)
    _read(sport, data, pathid_tagged=True)
    text = _scrape(mport)
    assert value(text, OFFLOAD, STREAM) == 1, \
        f"offloaded read not counted: {OFFLOAD}{STREAM}=" \
        f"{value(text, OFFLOAD, STREAM)}"


def test_plain_read_leaves_counter_absent(lifecycle):
    """(off) a plain pathid-0 read routes on the primary and offloads nothing —
    the series is never emitted."""
    sport, mport, data = _launch(lifecycle)
    _read(sport, data, pathid_tagged=False)
    text = _scrape(mport)
    assert value(text, OFFLOAD, STREAM) == -1, \
        "a non-offloaded read must not emit brix_io_offload_total"
