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

import os
import socket
import struct
import subprocess
import time
import urllib.request

import pytest

from settings import BIND_HOST, NGINX_BIN as H_NGINX
from metrics_helpers import value

import _test_session_bind_helpers as H

OFFLOAD = "brix_io_offload_total"
STREAM = {"proto": "stream"}


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_conf(tmp_path, stream_port, metrics_port):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    tmp = tmp_path / "tmp"
    tmp.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "daemon on;\n"
        "worker_processes 1;\n"
        f"pid {logs}/nginx.pid;\n"
        f"error_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{stream_port};\n"
        "    brix_root on;\n"
        f"    brix_export {data};\n"
        "    brix_auth none;\n"
        "    brix_allow_write on;\n"
        "    brix_data_substreams on;\n"
        "  }\n"
        "}\n"
        "http {\n"
        "  access_log off;\n"
        f"  client_body_temp_path {tmp}/cbt;\n"
        f"  proxy_temp_path {tmp}/pt;\n"
        f"  fastcgi_temp_path {tmp}/ft;\n"
        f"  uwsgi_temp_path {tmp}/ut;\n"
        f"  scgi_temp_path {tmp}/st;\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{metrics_port};\n"
        "    location /metrics { brix_metrics on; }\n"
        "  }\n"
        "}\n")
    return conf, str(data)


def _nginx(*args, timeout=30):
    return subprocess.run([H_NGINX, *args], capture_output=True, text=True,
                          timeout=timeout)


def _scrape(port):
    with urllib.request.urlopen(f"http://{BIND_HOST}:{port}/metrics",
                                timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def _launch(tmp_path):
    if not os.access(H_NGINX, os.X_OK):
        pytest.skip(f"nginx not executable: {H_NGINX}")
    sport, mport = _free_port(), _free_port()
    conf, data = _write_conf(tmp_path, sport, mport)
    t = _nginx("-p", str(tmp_path), "-c", str(conf), "-t")
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    started = _nginx("-p", str(tmp_path), "-c", str(conf))
    assert started.returncode == 0, f"nginx failed to start: {started.stderr}"
    for _ in range(50):
        try:
            socket.create_connection((BIND_HOST, sport), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    return sport, mport, data, conf


def _stop(tmp_path, conf):
    _nginx("-p", str(tmp_path), "-c", str(conf), "-s", "quit")
    time.sleep(0.2)


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


def test_offloaded_read_increments_counter(tmp_path):
    """(success) a pathid-tagged read whose reply is routed to the secondary
    books exactly one brix_io_offload_total{proto="stream"}."""
    sport, mport, data, conf = _launch(tmp_path)
    try:
        _read(sport, data, pathid_tagged=True)
        text = _scrape(mport)
        assert value(text, OFFLOAD, STREAM) == 1, \
            f"offloaded read not counted: {OFFLOAD}{STREAM}=" \
            f"{value(text, OFFLOAD, STREAM)}"
    finally:
        _stop(tmp_path, conf)


def test_plain_read_leaves_counter_absent(tmp_path):
    """(off) a plain pathid-0 read routes on the primary and offloads nothing —
    the series is never emitted."""
    sport, mport, data, conf = _launch(tmp_path)
    try:
        _read(sport, data, pathid_tagged=False)
        text = _scrape(mport)
        assert value(text, OFFLOAD, STREAM) == -1, \
            "a non-offloaded read must not emit brix_io_offload_total"
    finally:
        _stop(tmp_path, conf)
