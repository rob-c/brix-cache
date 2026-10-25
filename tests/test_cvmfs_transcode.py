"""Phase-85 F12 — edge compression transcode for the cvmfs site cache.

Theme
-----
A cvmfs proxy stores CAS objects verbatim and hands them to the client, which
does the cvmfs-object-layer decompression itself. F12 adds a *transport*
Content-Encoding on top: when ``brix_compress on`` and the client advertises a
codec we have (zstd preferred), the GET body is served compressed and the
client's HTTP layer transparently decodes it back to the exact stored bytes.

This reuses the shared negotiate/compress path that WebDAV and S3 already thread
into their serve opts (``brix_compress`` — a location flag on the common conf);
cvmfs simply never opted in, so cvmfs GETs never transcoded. Off by default =>
byte-frozen parity with the phase-84 corpus.

Integrity is orthogonal: F1's CAS verify runs at *fill* time against the stored
object, and the outbound Content-Encoding is a reversible wire transform that
never touches the bytes on disk. The three tests below prove exactly that
separation:

* success       — a zstd-capable client gets ``Content-Encoding: zstd`` and, once
                  decoded, the exact stored object whose sha1 IS its CAS address;
* legacy client — a client that advertises no codec gets the original object with
                  no Content-Encoding (identity), byte-for-byte;
* security-neg  — a persistently corrupt origin object is never smuggled to the
                  client as a compressed 200: verify-on-fill still rejects it
                  with a 5xx, transcode or not.

Port block srv_verify (13260) — registered but unused by any conformance file,
so this suite never collides in a full sequential sweep.
"""

import hashlib
from http.client import HTTPResponse, IncompleteRead
from io import BytesIO
import os
import socket
import sys
import time

import pytest

# zstandard is an optional dependency (requirements-optional.txt): every other
# suite that needs it skips rather than failing collection. This module used to
# import it outright, which made an optional package mandatory for anyone merely
# collecting tests/ — caught by tools/ci/check_python_deps.py.
zstandard = pytest.importorskip("zstandard")

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import (
    NGINX_BIN, PortBlock, raw_http, srv_instance, _request_blob, _parse_response,
)
from settings import HOST

REPO = "test.cern.ch"

pytestmark = pytest.mark.skipif(
    not os.path.exists(NGINX_BIN), reason=f"nginx binary not found: {NGINX_BIN}")

# ONE module-wide allocator (a fresh PortBlock restarts at base+10 and would
# collide with an earlier instance still tearing down).
_BLOCK = PortBlock("srv_verify")


class _BufferedHTTP:
    """Feed captured wire bytes to the standard library's strict chunk reader."""

    def __init__(self, payload):
        self.file = BytesIO(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + payload)

    def makefile(self, mode):
        return self.file


def _dechunk(payload: bytes) -> bytes:
    """Require complete chunks AND the mandatory zero chunk, never slice short."""
    with HTTPResponse(_BufferedHTTP(payload)) as response:
        response.begin()
        return response.read()


def test_captured_chunk_reader_accepts_complete_framing():
    assert _dechunk(b"3\r\nabc\r\n0\r\n\r\n") == b"abc"


@pytest.mark.parametrize("wire", [b"3\r\nab", b"3\r\nabc\r\n", b"ffff\r\nabc\r\n0\r\n\r\n"])
def test_captured_chunk_reader_refuses_truncation_or_oversized_claims(wire):
    with pytest.raises(IncompleteRead):
        _dechunk(wire)


def _get(srv, path, accept_encoding=None):
    hdrs = {}
    if accept_encoding is not None:
        hdrs["Accept-Encoding"] = accept_encoding
    return raw_http(HOST, srv.nginx_port, f"GET {path} HTTP/1.1", hdrs)


def _origin_bytes(srv, path):
    import urllib.request
    return urllib.request.urlopen(srv.mock_url + path, timeout=10).read()


def _plain_object(srv):
    """A CAS object with no catalog 'C' suffix — its path hash is a clean sha1
    of the stored bytes, so we can assert integrity against the CAS address."""
    for p in srv.objects():
        if not p.endswith("C"):
            return p
    raise AssertionError("no non-catalog CAS object in the mock")


@pytest.fixture(scope="module", params=["normal", "rate-limited"])
def srv(request):
    limits = "limit_rate 64k; send_timeout 2s;" if request.param == "rate-limited" else ""
    with srv_instance(_BLOCK, objects=8, seed=812,
                      extra_directives=f"brix_compress on; {limits}") as s:
        yield s


# ---- success: zstd-capable client gets zstd, decoded to the stored bytes ----

@pytest.mark.timeout(60)
def test_zstd_capable_client_gets_transcoded_object(srv):
    obj = _plain_object(srv)
    clean = _origin_bytes(srv, obj)

    st, hdrs, payload = _get(srv, obj, accept_encoding="zstd")
    assert st == 200, hdrs
    assert hdrs.get("content-encoding") == "zstd", hdrs
    assert hdrs.get("transfer-encoding", "").lower() == "chunked", hdrs

    decoded = zstandard.ZstdDecompressor().decompress(
        _dechunk(payload), max_output_size=len(clean))
    assert decoded == clean, "zstd transcode did not round-trip to the stored bytes"

    # F1 invariant: the bytes the client reconstructs are the plaintext whose
    # sha1 IS this object's CAS address — transcode never altered what verify
    # bound at fill time.
    cas_hex = obj.split("/data/")[1].replace("/", "")
    assert hashlib.sha1(decoded).hexdigest() == cas_hex


# ---- legacy client (no advertised codec) gets the original object -----------

@pytest.mark.timeout(60)
def test_legacy_client_gets_identity(srv):
    obj = _plain_object(srv)
    clean = _origin_bytes(srv, obj)

    # Client advertises only identity => no codec we serve => original bytes.
    st, hdrs, payload = _get(srv, obj, accept_encoding="identity")
    assert st == 200, hdrs
    assert "content-encoding" not in hdrs, hdrs
    assert payload == clean, "identity client did not get the verbatim object"


@pytest.mark.timeout(60)
def test_backpressured_reader_gets_the_complete_frame(srv):
    """A small receive window must park/resume, not terminate the first chunk."""
    obj = _plain_object(srv)
    clean = _origin_bytes(srv, obj)
    # HOST is the suite's IPv4 client address (HOST6 is a separate plane).
    # Configure the small window before SYN: shrinking it after connection
    # stalls ordinary identity reads too on the native FreeBSD test host.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.settimeout(15)
        sock.connect((HOST, srv.nginx_port))
        sock.sendall(_request_blob(HOST, srv.nginx_port, f"GET {obj} HTTP/1.1",
                                   {"Accept-Encoding": "zstd"}, b""))
        time.sleep(0.15)
        parts = []
        while part := sock.recv(8192):
            parts.append(part)
    status, headers, payload = _parse_response(b"".join(parts))
    assert status == 200 and headers.get("content-encoding") == "zstd"
    decoded = zstandard.ZstdDecompressor().decompress(
        _dechunk(payload), max_output_size=len(clean))
    assert decoded == clean


@pytest.mark.timeout(60)
def test_abandoned_compressed_response_does_not_break_the_worker(srv):
    """A disconnect while output is pending must leave later requests usable."""
    obj = _plain_object(srv)
    with socket.create_connection((HOST, srv.nginx_port), timeout=15) as sock:
        sock.sendall(_request_blob(HOST, srv.nginx_port, f"GET {obj} HTTP/1.1",
                                   {"Accept-Encoding": "zstd"}, b""))
        assert sock.recv(128).startswith(b"HTTP/1.1 200")
    status, headers, payload = _get(srv, obj, "zstd")
    clean = _origin_bytes(srv, obj)
    assert status == 200 and headers.get("content-encoding") == "zstd"
    assert zstandard.ZstdDecompressor().decompress(
        _dechunk(payload), max_output_size=len(clean)) == clean


# ---- security-negative: transcode never smuggles a corrupt fill -------------

@pytest.mark.timeout(60)
def test_corrupt_fill_is_never_a_compressed_200(srv):
    """With compression ON, a persistently corrupt origin object is still
    rejected by verify-on-fill (5xx) — the outbound codec runs strictly after
    a fill that verify already accepted, so it can never dress corrupt bytes up
    as a clean compressed 200."""
    # A valid-shape object the mock will serve, then corrupt on every attempt.
    obj = srv.objects()[1] if not srv.objects()[1].endswith("C") \
        else srv.objects()[2]
    srv.reset_log()
    srv.set_fault("corrupt", 99, path_re=obj.replace(".", r"\."))

    st, hdrs, _ = _get(srv, obj, accept_encoding="zstd")
    assert st >= 500, f"persistent corrupt fill answered {st} (compress on)"
    assert hdrs.get("content-encoding") != "zstd", \
        "corrupt bytes were transcoded and served — verify was bypassed"

    srv.set_fault("none", 0)
