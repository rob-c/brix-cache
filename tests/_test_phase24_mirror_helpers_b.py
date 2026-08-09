"""
Phase 24 — traffic mirroring (HTTP/WebDAV + XRootD stream).

Coverage:
  1. Source-marker checks: both mirror surfaces, the dispatch hook, the phase
     handlers, directives, and metrics are wired.
  2. Config validation: the HTTP and stream mirror directives parse; bad scheme
     / bad opcode are rejected; mirroring is off by default.
  3. HTTP/WebDAV functional: a GET fires a background shadow request (success);
     the shadow never sees the client's Authorization (security-neg / strip);
     a dead shadow is transparent to the client (error); sampling 0 mirrors
     nothing, 100 mirrors all; a write (PUT) is never mirrored.
  4. Stream functional: a kXR_stat replays to the shadow XRootD server
     (success), and a status mismatch increments the divergence counter
     (security-neg / divergence).

Registry-backed: every nginx here is a throwaway instance provisioned through
the `lifecycle` harness (templates nginx_mirror_http.conf /
nginx_mirror_stream_parse.conf / nginx_mirror_stream_pair.conf).
"""

import base64
import http.client
import json
import os
import re
import socket
import struct
import time
import urllib.request
from pathlib import Path

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT, lifecycle_ports_for
from server_registry import NginxInstanceSpec
from settings import (NGINX_BIN, HOST, BIND_HOST,
                      MIRROR_SHADOW_PORT, PROXY_DEAD_UPSTREAM_PORT)

# The shadow upstream is a shared fixed-port fleet mock whose capture is global
# state, so these tests run serial (one xdist worker) and each resets it first.
# Every nginx here draws a fixed exclusive-band port from the lifecycle ledger
# (lc-mir-*); xdist_group("lc-mir") keeps those fixed ports single-driver too.
pytestmark = [
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.serial,
    pytest.mark.registry_server("mirror-shadow"),
    pytest.mark.xdist_group("lc-mir"),
]

ROOT = Path(__file__).resolve().parents[1]


def _xrd_write(s, fh, off, data):
    s.sendall(struct.pack(">2sH4sqB3sI", b"\x00\x06", _kXR_write, fh, off,
                          0, b"\x00\x00\x00", len(data)) + data)
    return _xrd_resp(s)[0]


def _xrd_close_fh(s, fh):
    s.sendall(struct.pack(">2sH4s12sI", b"\x00\x07", _kXR_close, fh,
                          b"\x00" * 12, 0))
    return _xrd_resp(s)[0]


def _xrd_write_seq(host, port, path, data, chunk=4096):
    """open(create)->sequential writes->close; returns first non-ok status (0=ok)."""
    s = _xrd_login(host, port)
    try:
        st, fh = _xrd_open_wr(s, path)
        if st != 0:
            return st
        off = 0
        while off < len(data):
            wst = _xrd_write(s, fh, off, data[off:off + chunk])
            if wst != 0:
                return wst
            off += chunk
        return _xrd_close_fh(s, fh)
    finally:
        s.close()


def _xrd_write_gapped(host, port, path):
    """open->write@0->write@(gap)->close: the primary sparse-writes fine, but the
    non-contiguous offset aborts the mirror accumulator (no replay launches)."""
    s = _xrd_login(host, port)
    try:
        st, fh = _xrd_open_wr(s, path)
        if st != 0:
            return st
        if _xrd_write(s, fh, 0, b"A" * 64) != 0:
            return 1
        if _xrd_write(s, fh, 64 + 4096, b"B" * 64) != 0:   # gap -> non-sequential
            return 1
        return _xrd_close_fh(s, fh)
    finally:
        s.close()


def _start_wmirror_pair(lifecycle, tmp_path, name, writes):
    pdata = tmp_path / "pdata"; pdata.mkdir(exist_ok=True)
    sdata = tmp_path / "sdata"; sdata.mkdir(exist_ok=True)
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_mirror_stream_wpair.conf",
        data_root=str(pdata),
        template_values={"BIND_HOST": BIND_HOST, "HOST": HOST,
                         "SHADOW_DATA": str(sdata), "MIRROR_WRITES": writes},
        reason="stream data-write mirror e2e replay coverage",
    ))
    return endpoint.port, endpoint.extra_ports["METRICS_PORT"], sdata


def _wait_file(path, min_size, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.stat().st_size >= min_size:
            return True
        time.sleep(0.1)
    return False



def _xrd_open_write_drop(host, port, path, data, rst, do_close):
    """open(create) -> one write -> [optional kXR_close] -> drop the socket.

    rst=True forces a TCP RST (SO_LINGER 0) so the server sees an abrupt reset
    rather than a graceful FIN; do_close=False never sends kXR_close (the client
    vanishes mid-upload). Returns the open status (0=ok) so the caller can assert
    the primary leg itself was healthy before the drop.
    """
    s = _xrd_login(host, port)
    try:
        st, fh = _xrd_open_wr(s, path)
        if st != 0:
            return st
        if _xrd_write(s, fh, 0, data) != 0:
            return 1
        if do_close:
            _xrd_close_fh(s, fh)          # launches the detached replay
        if rst:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                         struct.pack("ii", 1, 0))   # close() -> RST, no FIN
        return 0
    finally:
        s.close()


def _primary_still_serves(host, port, sdata, tag):
    """A clean sequential write must still round-trip to the shadow after the
    disconnect churn — proves the worker survived (no crash/UAF took it down)."""
    body = b"post-disconnect-liveness\n" * 32
    assert _xrd_write_seq(host, port, f"/{tag}.bin", body) == 0, \
        "primary worker stopped serving after a mid-write disconnect"
    assert _wait_file(sdata / f"{tag}.bin", len(body)), \
        "shadow never received the liveness write — worker or replay wedged"
    assert (sdata / f"{tag}.bin").read_bytes() == body
