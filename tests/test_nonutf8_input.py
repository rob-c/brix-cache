"""Exhaustive non-UTF8 byte-input handling for the brix percent-codec and the
XRootD CGI-opaque gate — the pure kernels every user-supplied byte crosses on
the WebDAV/S3/XrdHttp and root:// surfaces before auth or storage.

Each case runs a real production kernel (compiled into
``tests/c/nonutf8_codec_harness.c``) against one byte vector and asserts the
result matches an independent Python oracle. Coverage:

  * decode ``%XX`` -> byte for every non-NUL byte, upper- and lower-case hex;
  * literal high bytes (0x80-0xFF) pass through untouched;
  * NUL semantics (``%00`` reject-vs-pass per flag, embedded-NUL C-string
    truncation), malformed-``%`` preserved verbatim, ``+`` handling, overflow
    and BADARG boundaries;
  * encode every byte 0x00-0xFF vs RFC 3986, ``safe_extra`` passthrough,
    encoder overflow;
  * round-trip encode->decode is the identity for every byte and for a battery
    of non-UTF8 multi-byte sequences (overlong, surrogate, out-of-range,
    truncated, BOM, Latin-1, CP1252, Shift-JIS/GB18030-ish, and deterministic
    high-byte blobs);
  * the XRootD opaque gate's verdict + offending byte for the full 0x01-0xFF
    space plus curated injection primitives.

Pure and fleet-free: rides the fast lane (``-m "not slow and not serial"``).
"""

from __future__ import annotations

import pytest

from cmdscripts.nonutf8_codec import VECTORS, run_all


@pytest.fixture(scope="session")
def results(tmp_path_factory) -> dict[str, tuple]:
    """Compile the harness once and run every vector through it in one pass."""
    workdir = tmp_path_factory.mktemp("nonutf8")
    return run_all(workdir)


@pytest.mark.timeout(120)
@pytest.mark.parametrize("vec", VECTORS, ids=lambda v: v.vid)
def test_nonutf8_byte_handling(results, vec):
    actual = results[vec.vid]
    assert actual == vec.expect, (
        f"{vec.vid}: line={vec.line!r} expected={vec.expect!r} actual={actual!r}"
    )
