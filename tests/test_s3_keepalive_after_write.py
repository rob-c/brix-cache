"""Regression: an S3 write must not poison its keepalive connection.

The three async S3 write completions (buffered PUT, streaming PUT chunk,
CompleteMultipartUpload) each post a thread task whose dispatch site takes
r->main->count++ to hold the request across the async hop.  The completion
callbacks were missing the balancing r->main->count-- (webdav_put_aio_done
precedent), so the response was sent but the request stayed one reference
high: the connection never re-entered keepalive and the NEXT request on it
was never read - a silent, size-independent wedge.

Invisible to the rest of the suite because `requests.*` calls here use one
connection per request; it surfaced when sd_remote's libcurl transport ran
UploadPart then CompleteMPU back-to-back on one kept-alive connection.

These tests speak raw HTTP/1.1 on ONE socket so connection reuse is a fact,
not a pooling heuristic: the second request timing out IS the regression.
"""

import socket
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

BUCKET = "testbucket"
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


@pytest.fixture()
def s3_sock(s3_url):
    u = urllib.parse.urlparse(s3_url)
    sock = socket.create_connection((u.hostname, u.port), timeout=10)
    try:
        yield sock
    finally:
        sock.close()


def _request(sock, method, target, body=b"", headers=None,
             allow_close=False):
    """One HTTP/1.1 exchange on an already-open socket; returns
    (status, header-dict, body).  Reading runs under the socket's 10 s
    timeout - the wedge under test presents as a TimeoutError here.

    A REFUSED request may honestly answer `Connection: close` (nginx
    semantics for a rejected request); pass allow_close=True there and do
    not reuse the socket afterwards.  The regression's signature was the
    opposite: no close header, yet the next request never read."""
    _send(sock, method, target, body, headers)
    status, hdrs, rest = _recv_head(sock)
    clen = int(hdrs.get("content-length", "0"))
    rest = _recv_until(sock, rest, clen, "mid-body")
    if not allow_close:
        assert hdrs.get("connection", "").lower() != "close", (
            f"{method} {target} answered Connection: close - "
            "the connection was taken out of keepalive")
    return status, hdrs, rest[:clen]


def _send(sock, method, target, body, headers):
    lines = [
        f"{method} {target} HTTP/1.1",
        "Host: s3.test",
        f"Content-Length: {len(body)}",
        "Connection: keep-alive",
    ]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)


def _recv_until(sock, buf, want, where):
    """Read until len(buf) >= want; a mid-transfer close is the failure."""
    while len(buf) < want:
        chunk = sock.recv(65536)
        assert chunk, f"server closed the connection {where}"
        buf += chunk
    return buf


def _recv_head(sock):
    """Read through the blank line; returns (status, header-dict, leftover)."""
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        assert chunk, "server closed the connection mid-response"
        raw += chunk
    head, rest = raw.split(b"\r\n\r\n", 1)
    head_lines = head.decode("latin-1").split("\r\n")
    hdrs = {}
    for line in head_lines[1:]:
        k, _, v = line.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return int(head_lines[0].split()[1]), hdrs, rest


def _key(stem):
    return f"/{BUCKET}/ka_{stem}_{uuid.uuid4().hex}.bin"


def test_get_after_buffered_put_same_connection(s3_sock):
    """(success) small PUT (buffered plane, s3_put_aio_done) then a GET on
    the SAME connection round-trips byte-exact."""
    target = _key("buffered")
    payload = b"keepalive-after-buffered-put"
    status, _, _ = _request(s3_sock, "PUT", target, payload)
    assert status == 200
    status, _, body = _request(s3_sock, "GET", target)
    assert status == 200
    assert body == payload


def test_get_after_streaming_put_same_connection(s3_sock):
    """(success) multi-MiB PUT (streaming plane, s3_chunk_aio_done) then a
    GET on the SAME connection round-trips byte-exact."""
    target = _key("streaming")
    payload = bytes(range(256)) * (4 * 4096)          # 4 MiB
    status, _, _ = _request(s3_sock, "PUT", target, payload)
    assert status == 200
    status, _, body = _request(s3_sock, "GET", target)
    assert status == 200
    assert body == payload


def test_complete_mpu_after_upload_part_same_connection(s3_url, s3_sock):
    """(success) the discovering sequence: UploadPart then CompleteMPU on ONE
    connection (exactly what sd_remote's libcurl transport does), then a GET
    on the same connection verifies the committed object."""
    target = _key("mpu")
    status, _, body = _request(s3_sock, "POST", target + "?uploads")
    assert status == 200
    upload_id = ET.fromstring(body).find(f"{{{S3_NS}}}UploadId").text

    part = b"P" * (64 * 1024)
    status, _, _ = _request(
        s3_sock, "PUT", f"{target}?partNumber=1&uploadId={upload_id}", part)
    assert status == 200

    status, _, _ = _request(
        s3_sock, "POST", f"{target}?uploadId={upload_id}",
        b"<CompleteMultipartUpload>"
        b"<Part><PartNumber>1</PartNumber></Part>"
        b"</CompleteMultipartUpload>")
    assert status == 200

    status, _, body = _request(s3_sock, "GET", target)
    assert status == 200
    assert body == part


def test_failed_put_signals_close_not_silence(s3_sock, s3_url):
    """(error) a REFUSED write must never wedge silently: either the
    connection stays in keepalive and serves the next request, or the
    refusal SAYS `Connection: close`.  The defect's signature was the third
    state - no close header, next request never read."""
    # empty body: a body byte left unread by the refusal makes nginx RST,
    # which can discard the buffered response - a different (correct)
    # mechanism than the wedge under test
    status, hdrs, _ = _request(
        s3_sock, "PUT", "/nonexistent-bucket/x.bin", b"", allow_close=True)
    assert status in (400, 403, 404)
    closed = hdrs.get("connection", "").lower() == "close"

    target = _key("after_error")
    payload = b"served-after-a-refused-put"
    if closed:
        u = urllib.parse.urlparse(s3_url)
        sock2 = socket.create_connection((u.hostname, u.port), timeout=10)
    else:
        sock2 = s3_sock
    try:
        status, _, _ = _request(sock2, "PUT", target, payload)
        assert status == 200
        status, _, body = _request(sock2, "GET", target)
        assert status == 200
        assert body == payload
    finally:
        if closed:
            sock2.close()


def test_traversal_key_after_put_same_connection(s3_sock, s3_url):
    """(security-neg) a second request on a reused post-write connection is
    still fully policy-checked: PUT ok, then a path-traversal key on the SAME
    connection is refused - keepalive reuse must not shortcut resolve_path().
    nginx closes after the malformed URI (honest close is fine); the escape
    target must never be served."""
    target = _key("sec")
    status, _, _ = _request(s3_sock, "PUT", target, b"legit")
    assert status == 200
    status, _, body = _request(
        s3_sock, "GET", f"/{BUCKET}/../../etc/passwd", allow_close=True)
    assert status in (400, 403, 404)
    assert b"root:" not in body

    u = urllib.parse.urlparse(s3_url)
    with socket.create_connection((u.hostname, u.port), timeout=10) as sock2:
        status, _, body = _request(sock2, "GET", target)
        assert status == 200
        assert body == b"legit"
