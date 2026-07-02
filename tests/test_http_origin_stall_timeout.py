"""
test_http_origin_stall_timeout.py — guard: the libcurl cache-origin transport
must bound a STALLED transfer, not just the connect phase.

WHAT
    A static guard that fails if src/fs/cache/origin/http_transport.c performs a
    curl transfer (curl_easy_perform) without a stall/idle timeout — i.e. with
    only CURLOPT_CONNECTTIMEOUT and no CURLOPT_LOW_SPEED_TIME (or CURLOPT_TIMEOUT).

WHY
    The HTTP/Pelican cache fill runs on a thread-pool worker. CONNECTTIMEOUT
    bounds only the TCP connect; once connected, an origin that stops sending
    (connection alive, zero byte progress) makes curl_easy_perform block
    FOREVER, wedging that pool thread. Enough stalled fills exhaust the pool and
    ALL async I/O (every cache fill, every AIO read) stalls fleet-wide — a
    complex, hard-to-diagnose lockup. The xroot origin already guards this with
    SO_RCVTIMEO/SO_SNDTIMEO (origin_connection.c, XROOTD_CACHE_IO_TIMEOUT); the
    libcurl path must have the equivalent. CURLOPT_LOW_SPEED_LIMIT/TIME is the
    correct idiom: it aborts a stalled transfer without capping a large but
    progressing download (a hard CURLOPT_TIMEOUT would wrongly kill big fills).

    CURLOPT_NOSIGNAL is already set, so curl timeouts are safe under threads.

RUN
    PYTHONPATH=tests pytest tests/test_http_origin_stall_timeout.py -v
"""

import os
import re

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TRANSPORT = os.path.join(_REPO, "src", "cache", "origin", "http_transport.c")


def _strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def test_http_transport_bounds_stalled_transfer():
    if not os.path.exists(_TRANSPORT):
        pytest.skip("http_transport.c not present")
    code = _strip_comments(open(_TRANSPORT, errors="replace").read())

    performs = "curl_easy_perform" in code
    assert performs, "expected http_transport.c to run curl_easy_perform"

    has_low_speed = "CURLOPT_LOW_SPEED_TIME" in code
    has_total = "CURLOPT_TIMEOUT" in code and "CURLOPT_TIMEOUT_MS" not in code.replace(
        "CURLOPT_TIMEOUT_MS", "")
    # A stall bound is either LOW_SPEED_TIME (preferred) or an outright TIMEOUT.
    assert has_low_speed or has_total, (
        "http_transport.c sets CURLOPT_CONNECTTIMEOUT but no stall/idle bound "
        "(CURLOPT_LOW_SPEED_TIME). A stalled origin would wedge the fill "
        "pool thread forever -> pool exhaustion -> fleet-wide async-I/O lockup. "
        "Add CURLOPT_LOW_SPEED_LIMIT + CURLOPT_LOW_SPEED_TIME (mirrors the xroot "
        "origin's SO_RCVTIMEO/SO_SNDTIMEO guard)."
    )


def test_low_speed_time_paired_with_limit():
    """LOW_SPEED_TIME has no effect without LOW_SPEED_LIMIT — both are required."""
    if not os.path.exists(_TRANSPORT):
        pytest.skip("http_transport.c not present")
    code = _strip_comments(open(_TRANSPORT, errors="replace").read())
    if "CURLOPT_LOW_SPEED_TIME" in code:
        assert "CURLOPT_LOW_SPEED_LIMIT" in code, (
            "CURLOPT_LOW_SPEED_TIME set without CURLOPT_LOW_SPEED_LIMIT — the "
            "stall abort will never trigger (limit defaults to 0 = disabled)."
        )
