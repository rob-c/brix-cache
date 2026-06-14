"""
Phase 33 C1 — batched access logging.

The stream access log now accumulates lines in a per-worker buffer and flushes
with a single write(2) on buffer-full / fd-switch / a 1s timer / connection close
(xrootd_on_disconnect).  These tests prove batching preserves correctness:

  1. flush-on-close      — every logged op for a connection is durable once it
                           closes (no lines lost in the buffer).
  2. no-loss interleaved — lines from two concurrent connections are all present.
  3. sanitisation        — a wire path with control bytes is still escaped, so a
                           malicious path cannot inject a forged log line (the
                           batch buffer must not bypass xrootd_sanitize_log_string).

The raw-wire + nginx-spawn helpers are reused from test_phase25_ratelimit.
"""

import os
import time

import pytest

from settings import NGINX_BIN
from test_phase25_ratelimit import (
    HEADER, _spawn, _stop, _xrd_login, _xrd_open, _xrd_read, KXR_OK,
)


@pytest.fixture(autouse=True)
def _require_binary():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _alog_conf(tmp_path, port, data, logfile):
    return HEADER.format(logs=tmp_path / "logs") + f"""
    stream {{
        server {{
            listen 127.0.0.1:{port};
            xrootd on;
            xrootd_root {data};
            xrootd_auth none;
            xrootd_access_log {logfile};
        }}
    }}
    """


def _read_log(path, pred, timeout=5.0):
    """Poll the log file until pred(text) is true (flush + disconnect are async).

    pred may be a substring (str) or a callable taking the current file text.
    """
    if isinstance(pred, str):
        substr = pred
        pred = lambda t: substr in t  # noqa: E731
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        if os.path.exists(path):
            text = open(path, "r", encoding="utf-8", errors="replace").read()
            if pred(text):
                return text
        time.sleep(0.1)
    return text


def test_batched_lines_durable_after_close(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello world\n")
    logfile = tmp_path / "access.log"
    port = 21980
    proc = _spawn(_alog_conf(tmp_path, port, data, logfile), tmp_path, port)
    try:
        s = _xrd_login("127.0.0.1", port)
        st, body = _xrd_open(s, "/f.txt")
        assert st == KXR_OK, st
        fh = body[:4]
        for _ in range(6):
            _xrd_read(s, fh, 0, 5)
        s.close()  # triggers xrootd_on_disconnect → flush

        text = _read_log(str(logfile),
                         lambda t: t.count(' "READ ') >= 6 and "DISCONNECT" in t)
        # All six reads plus the DISCONNECT record must be present post-close.
        assert text.count(' "READ ') >= 6, f"missing READ lines:\n{text}"
        assert "DISCONNECT" in text, f"missing DISCONNECT line:\n{text}"
    finally:
        _stop(proc)


def test_no_loss_interleaved_connections(tmp_path):
    data = tmp_path / "data"; data.mkdir()
    (data / "f.txt").write_text("hello world\n")
    logfile = tmp_path / "access.log"
    port = 21981
    proc = _spawn(_alog_conf(tmp_path, port, data, logfile), tmp_path, port)
    try:
        conns = []
        for _ in range(2):
            s = _xrd_login("127.0.0.1", port)
            st, body = _xrd_open(s, "/f.txt")
            assert st == KXR_OK, st
            conns.append((s, body[:4]))
        # Interleave reads across both connections (same fd, same worker buffer).
        for _ in range(4):
            for s, fh in conns:
                _xrd_read(s, fh, 0, 5)
        for s, _ in conns:
            s.close()

        text = _read_log(str(logfile), lambda t: t.count("DISCONNECT") >= 2)
        # 2 connections × 4 reads = 8 READ lines, both DISCONNECTs — none lost.
        assert text.count(' "READ ') >= 8, f"lost READ lines:\n{text}"
        assert text.count("DISCONNECT") >= 2, f"missing DISCONNECTs:\n{text}"
    finally:
        _stop(proc)


def test_control_bytes_in_path_are_escaped(tmp_path):
    # Security-neg: a path carrying a newline must be escaped in the log so it
    # cannot forge a second log line.  Batching must not bypass sanitisation.
    data = tmp_path / "data"; data.mkdir()
    logfile = tmp_path / "access.log"
    port = 21982
    proc = _spawn(_alog_conf(tmp_path, port, data, logfile), tmp_path, port)
    try:
        s = _xrd_login("127.0.0.1", port)
        # Open a nonexistent path with an embedded newline + injection marker.
        _xrd_open(s, "/evil\nINJECTED_LINE GET /x")
        s.close()

        text = _read_log(str(logfile), "DISCONNECT")
        # The raw control byte must be escaped (\x0a), never a literal newline
        # that splits the field — so no log line may *start* with the marker.
        for ln in text.splitlines():
            assert not ln.lstrip().startswith("INJECTED_LINE"), (
                f"unescaped newline forged a log line:\n{text}"
            )
        assert "\\x0a" in text or "INJECTED_LINE" in text, (
            "expected the evil path to appear (escaped) in the log"
        )
    finally:
        _stop(proc)


def test_wiring_present():
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]

    def rd(rel):
        return (root / rel).read_text(encoding="utf-8")

    alog = rd("src/path/access_log.c")
    assert "xrootd_access_log_flush" in alog
    assert "xrootd_alog_emit" in alog
    assert "ngx_add_timer" in alog          # bounded-latency flush
    assert "xrootd_access_log_flush" in rd("src/connection/disconnect.c")
    assert "xrootd_access_log_flush" in rd("src/path/path.h")
