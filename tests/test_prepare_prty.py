"""
test_prepare_prty.py — §1.12 (parity-fix wave 21): the kXR_prepare request
priority (`prty`) is surfaced in the PREPARE access-log detail.

`prty` (ClientPrepareRequest byte 3) is DECODED by the handler but was silently
dropped from every observability surface — the access-log detail logged
opts/optx but not the priority, so an operator could not see what priority
clients requested. It is now included in the "paths=… opts=… prty=…" detail.

Scope note: this is a small observability step on §1.12, NOT a full close. BriX
stages disk immediately (reads fault the file in; no priority scheduler — FRM
was dissolved), so HONOURING prty in scheduling is largely N/A for its model.
Surfacing the decoded field is the honest, safe increment.

  * success  — a prepare with prty=7 logs "prty=7" on its PREPARE line.
  * default  — a prepare with prty=0 logs "prty=0" (always surfaced, not only
               when non-zero).
  * wiring   — the handler's detail string is built from req.prty.

Run:
    PYTHONPATH=tests pytest tests/test_prepare_prty.py -v
"""

import os
import re
import struct

import pytest

from settings import HOST, NGINX_BIN
from test_access_log_batch import _start, _read_log
from test_phase25_ratelimit import _xrd_login

pytestmark = pytest.mark.uses_lifecycle_harness

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
kXR_prepare = 3021


def _send_prepare(sock, streamid, options, optionX, prty, payload):
    """kXR_prepare with an explicit prty. Body: options[1] prty[1] port[2]
    optionX[2] reserved[10]. Reads and discards the reply so the op completes
    before the socket closes (the batched log flushes on disconnect)."""
    body = struct.pack(">BBH", options, prty, 0) + struct.pack(">H", optionX) \
        + b"\x00" * 10
    hdr = struct.pack(">2sH", streamid, kXR_prepare) + body \
        + struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    rsp = sock.recv(8)
    if rsp and len(rsp) >= 8:
        dlen = struct.unpack(">I", rsp[4:8])[0]
        while dlen > 0:
            chunk = sock.recv(dlen)
            if not chunk:
                break
            dlen -= len(chunk)
    return rsp


def _prepare_line(text):
    for ln in text.splitlines():
        if "PREPARE" in ln and "prty=" in ln:
            return ln
    return None


def test_prepare_prty_surfaced_in_access_log(lifecycle, tmp_path):
    """A non-zero prty (7) and the default (0) both appear on the PREPARE line."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    data = tmp_path / "export"
    data.mkdir()
    (data / "prepped.dat").write_bytes(b"x" * 64)   # a resolvable file to prepare

    port, alog = _start(lifecycle, data, "lc-prep-prty")

    # prty=7 on one connection, prty=0 on another (same server, distinct lines).
    _send_two_prepares(port)

    text = _read_log(alog, _both_prepares_logged)

    assert "prty=7" in text, \
        f"prepare prty=7 not surfaced in the access log:\n{text}"
    assert "prty=0" in text, \
        f"prepare prty=0 (default) not surfaced in the access log:\n{text}"
    # The prty token rides the same detail as the path count, not a stray field.
    line = _prepare_line(text)
    assert line is not None, f"no PREPARE line found:\n{text}"
    assert re.search(r"paths=\d+.*prty=\d+", line), \
        f"prty is not part of the PREPARE detail triple:\n{line}"


def _send_two_prepares(port):
    """Issue PREPARE with prty=7 and prty=0 on two distinct connections."""
    for streamid, prty in ((b"\x00\x07", 7), (b"\x00\x08", 0)):
        s = _xrd_login(HOST, port)
        try:
            _send_prepare(s, streamid, 0x00, 0x00, prty, b"/prepped.dat\n")
        finally:
            s.close()


def _both_prepares_logged(t):
    """True once both PREPARE lines (prty=7 and prty=0) have reached the log."""
    return all((t.count("PREPARE") >= 2, "prty=7" in t, "prty=0" in t))


def test_handler_detail_is_built_from_req_prty():
    """(wiring) the kXR_prepare handler's access-log detail includes req.prty,
    so a decoded priority can never again be silently dropped."""
    with open(os.path.join(_REPO, "src/protocols/root/query/prepare.c")) as f:
        src = f.read()
    assert 'prty=%u' in src, "the PREPARE detail no longer formats prty"
    assert "(unsigned int) req.prty" in src, \
        "the PREPARE detail no longer reads req.prty"
