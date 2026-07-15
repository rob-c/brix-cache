"""
Phase-42 W2 — outbound (GET) compression NEGOTIATION gaps.

These tests cover the corners of Accept-Encoding negotiation and the
incompressible-MIME deny list that the existing roundtrip suites
(test_compression_outbound.py / test_compression_s3_outbound.py) do not:

  (1) QVAL-ZERO   — "gzip;q=0", "q=0.0", "q=0.00", "q=0.000" are exactly zero
                    (= refused → identity), while "q=0.5"/"q=1" select gzip.
                    (The negotiator was just fixed so the fractional-zero
                    spellings are correctly treated as a refusal.)
  (2) QVAL-MULTI  — multi-token Accept-Encoding ("br, gzip;q=0.9",
                    "gzip, zstd") selects a codec the server has, and
                    leading/trailing whitespace around tokens is tolerated.
  (3) HEAD        — a HEAD with Accept-Encoding: gzip never carries a body.
  (4) DENYLIST    — with a types{} block mapping .gz→application/gzip and
                    .jpg→image/jpeg, GETting incompressible-MIME objects with
                    Accept-Encoding: gzip yields NO Content-Encoding (identity),
                    because the server resolves content-type from the extension
                    BEFORE negotiating; a .txt/.bin compressible control object
                    still gets compressed.

Attaches to the fleet's dedicated "compress" instance (WebDAV surface,
`brix_compress on` + an http-level types{} block) started once by
start_all_dedicated, rather than launching its own nginx: a fixed-port self-start
collides across pytest-xdist workers. Raw GETs go through urllib3 with
decode_content=False so we observe the real wire encoding. The types{} block maps
.gz/.jpg to incompressible MIME types (application/gzip, image/jpeg) and .txt/.bin
to compressible ones, which the deny-list cases below depend on.
"""

import gzip
import os
import shutil
import subprocess
import time
import uuid

import pytest
import requests
import urllib3

urllib3.disable_warnings()

# Fixed port of the fleet "compress" instance WebDAV surface (see
# tests/lib/dedicated.sh -> start_all_dedicated + tests/configs/nginx_compress.conf).
COMPRESS_WEBDAV_PORT = int(os.environ.get("TEST_COMPRESS_WEBDAV_PORT", "12960"))
BASE_URL = f"http://127.0.0.1:{COMPRESS_WEBDAV_PORT}"
_POOL = urllib3.PoolManager()


def _wait_listen(url, tries=50):
    for _ in range(tries):
        try:
            requests.get(url, timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def base():
    """Attach to the fleet "compress" WebDAV surface; skip cleanly if it is down.
    The tests PUT and GET their own uuid-named objects, so no seeding is needed."""
    if not _wait_listen(BASE_URL):
        pytest.skip(
            f"fleet compress instance not listening on {COMPRESS_WEBDAV_PORT}")
    yield BASE_URL


# A >256-byte highly-compressible payload (gzip-negotiation min size is 256).
def _payload(n=4096):
    return (b"the quick brown fox jumps over the lazy dog 0123456789\n"
            * (n // 54 + 1))[:n]


def _put(base, path, data):
    return requests.put(f"{base}{path}", data=data, timeout=60)


def _delete(base, path):
    try:
        requests.delete(f"{base}{path}", timeout=30)
    except Exception:
        pass


def _raw_get(base, path, headers):
    return _POOL.request("GET", f"{base}{path}", headers=headers,
                         decode_content=False, preload_content=True, retries=False)


def _name(tag, ext="bin"):
    return f"/neg_{tag}_{uuid.uuid4().hex}.{ext}"


# ---------------------------------------------------------------------------
# (1) QVAL-ZERO — fractional-zero q-values are a refusal; nonzero selects gzip.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("qval", ["gzip;q=0", "gzip;q=0.0", "gzip;q=0.00",
                                  "gzip;q=0.000"])
def test_qval_zero_is_identity(base, qval):
    """gzip with an exactly-zero q-value must NOT compress (identity body)."""
    data = _payload()
    path = _name("qz")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": qval})
        assert r.status == 200, f"{qval!r} status {r.status}"
        assert "Content-Encoding" not in r.headers, \
            f"{qval!r} should be identity, got {r.headers.get('Content-Encoding')!r}"
        assert r.data == data, f"{qval!r} body not byte-identical"
    finally:
        _delete(base, path)


@pytest.mark.parametrize("qval", ["gzip;q=0.5", "gzip;q=1", "gzip;q=1.0",
                                  "gzip;q=0.001"])
def test_qval_nonzero_selects_gzip(base, qval):
    """Any nonzero q-value (incl. q=0.001) selects gzip and compresses."""
    data = _payload()
    path = _name("qnz")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": qval})
        assert r.status == 200, f"{qval!r} status {r.status}"
        assert r.headers.get("Content-Encoding", "").lower() == "gzip", \
            f"{qval!r} should be gzip, got {r.headers.get('Content-Encoding')!r}"
        assert len(r.data) < len(data), f"{qval!r} not smaller"
        assert gzip.decompress(r.data) == data, f"{qval!r} body mismatch"
        assert "accept-encoding" in r.headers.get("Vary", "").lower()
    finally:
        _delete(base, path)


# ---------------------------------------------------------------------------
# (2) QVAL-MULTI — multi-token Accept-Encoding + whitespace tolerance.
# ---------------------------------------------------------------------------
# The server picks by a fixed preference (zstd > br > gzip > xz > deflate >
# bzip2 > lz4) intersected with what the client offered. We only assert the
# returned token is one the client actually offered and decodes byte-exact, so
# the test is robust to which optional codecs the build has.
_DECODERS = {
    "gzip": gzip.decompress,
}


def _decode(token, raw):
    if token in _DECODERS:
        return _DECODERS[token](raw)
    if token == "deflate":
        import zlib
        return zlib.decompress(raw)
    if token == "xz":
        import lzma
        return lzma.decompress(raw)
    if token == "bzip2":
        import bz2
        return bz2.decompress(raw)
    if token == "zstd":
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(raw)
        except Exception:
            pass
    # br, lz4, or zstd-without-python-module: shell out to the CLI.
    cli = {"br": ("brotli", ["-d", "-c"]),
           "lz4": ("lz4", ["-d", "-c"]),
           "zstd": ("zstd", ["-d", "-q", "-c"])}.get(token)
    if cli is None:
        pytest.skip(f"no decoder available for {token!r}")
    tool = shutil.which(cli[0])
    if tool is None:
        pytest.skip(f"{cli[0]} CLI not available to decode {token!r}")
    p = subprocess.run([tool, *cli[1]], input=raw, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=True)
    return p.stdout


@pytest.mark.parametrize("ae,offered", [
    ("br, gzip;q=0.9", {"br", "gzip"}),
    ("gzip, zstd", {"gzip", "zstd"}),
    ("   gzip   ,   zstd   ", {"gzip", "zstd"}),     # space whitespace around tokens
    (" br , gzip;q=0.9 ", {"br", "gzip"}),            # leading/trailing + inner spaces
])
def test_qval_multi_selects_offered_codec(base, ae, offered):
    """A multi-token Accept-Encoding selects one of the offered codecs and the
    body decodes byte-exact; surrounding whitespace is tolerated."""
    data = _payload()
    path = _name("multi")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": ae})
        assert r.status == 200, f"{ae!r} status {r.status}"
        enc = r.headers.get("Content-Encoding", "").lower()
        assert enc in offered, \
            f"{ae!r}: Content-Encoding {enc!r} not in offered {offered}"
        assert len(r.data) < len(data), f"{ae!r}: body not smaller"
        assert _decode(enc, r.data) == data, f"{ae!r}: {enc} body mismatch"
        assert "accept-encoding" in r.headers.get("Vary", "").lower()
    finally:
        _delete(base, path)


def test_qval_multi_tab_whitespace_tolerated(base):
    """RFC 7230 OWS permits HTAB (as well as SP) around Accept-Encoding list
    members. accept_encoding_has() now skips/trims both SP and HTAB, so a
    tab-delimited/-prefixed Accept-Encoding ("\\tbr ,\\tgzip;q=0.9\\t") is parsed
    and a codec is selected (regression test for the OWS-handling fix)."""
    data = _payload()
    path = _name("tabws")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "\tbr ,\tgzip;q=0.9\t"})
        assert r.status == 200
        enc = r.headers.get("Content-Encoding", "").lower()
        assert enc in {"br", "gzip"}, \
            f"tab-OWS Accept-Encoding ignored, CE={enc!r}"
    finally:
        _delete(base, path)


# ---------------------------------------------------------------------------
# (3) HEAD never carries a body even when compression is negotiable.
# ---------------------------------------------------------------------------
def test_head_with_accept_encoding_has_no_body(base):
    data = _payload()
    path = _name("head")
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _POOL.request("HEAD", f"{base}{path}",
                          headers={"Accept-Encoding": "gzip"},
                          decode_content=False, preload_content=True,
                          retries=False)
        assert r.status == 200, f"HEAD status {r.status}"
        assert r.data == b"", f"HEAD body should be empty, got {len(r.data)} bytes"
    finally:
        _delete(base, path)


# ---------------------------------------------------------------------------
# (4) DENYLIST-MIME — content-type resolved from extension BEFORE negotiation.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ext", ["gz", "jpg"])
def test_incompressible_mime_not_compressed(base, ext):
    """An object whose extension maps (via types{}) to an already-compressed
    MIME type (.gz→application/gzip, .jpg→image/jpeg) must be served identity
    even when the client offers gzip."""
    data = os.urandom(2048)        # >256 bytes; random => CE would shrink little
    path = _name("deny", ext=ext)
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip"})
        assert r.status == 200, f".{ext} status {r.status}"
        assert "Content-Encoding" not in r.headers, \
            f".{ext} should be identity, got {r.headers.get('Content-Encoding')!r}"
        assert r.data == data, f".{ext} body not byte-identical"
    finally:
        _delete(base, path)


@pytest.mark.parametrize("ext", ["txt", "bin"])
def test_compressible_mime_control_is_compressed(base, ext):
    """Control: a .txt (text/plain) / .bin (application/octet-stream) object is
    a compressible MIME type, so gzip IS applied (proves the deny list is
    selective, not blanket)."""
    data = _payload()
    path = _name("ctl", ext=ext)
    try:
        assert _put(base, path, data).status_code in (200, 201, 204)
        r = _raw_get(base, path, {"Accept-Encoding": "gzip"})
        assert r.status == 200, f".{ext} status {r.status}"
        assert r.headers.get("Content-Encoding", "").lower() == "gzip", \
            f".{ext} should be gzip, got {r.headers.get('Content-Encoding')!r}"
        assert len(r.data) < len(data), f".{ext} not smaller"
        assert gzip.decompress(r.data) == data, f".{ext} body mismatch"
    finally:
        _delete(base, path)
