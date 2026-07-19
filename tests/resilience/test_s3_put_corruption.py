"""
test_s3_put_corruption.py — in-path corruption of the S3 PutObject ingest
gateway (client->server body integrity).

THE BREAK: brix authenticates a SigV4 PUT with a hard-coded UNSIGNED-PAYLOAD
canonical request (the body is never folded into the signature), and only the
modern x-amz-checksum-* header form was verified against the stored bytes.  The
historically dominant integrity header — the classic `Content-MD5` (RFC 1864,
which the S3 contract says the server MUST verify, answering 400 BadDigest on
mismatch) — was accepted into the CORS allow-list but never checked.  So a
middlebox/flaky-NIC that flips a byte in the body past the TCP checksum produced
a stored object that no longer matched the Content-MD5 the client asserted, yet
the gateway answered 200 and kept the poisoned bytes.  `brix-fault-proxy
corrupt <frac> up` reproduces exactly this — flip a random bit in a fraction of
the client->server bytes, length preserved.

THE FIX: when a PutObject carries a Content-MD5, verify it over the committed
object and, on mismatch, remove the object and answer 400 BadDigest (a malformed
Content-MD5 → 400 InvalidDigest) — the same read-back + unlink model the
x-amz-checksum-* path already uses.

CONTRACT proven here:
  * corrupt-up PUT carrying a valid Content-MD5 -> non-2xx and NO stored object
    (the gateway honoured the digest the client asserted).        [the fix fires]
  * honest PUT carrying a valid Content-MD5     -> 200 and the stored bytes match
    byte-for-byte (a good digest never penalises a good transfer).[no false pos]
  * malformed Content-MD5                       -> 400 and nothing stored (a bad
    integrity header is rejected, not silently ignored).            [error leg]

As with the WebDAV analogue, corruption occasionally lands in the request
line / headers rather than the body, which breaks HTTP framing / routing and
yields its own non-2xx; that is still a rejection, so the corrupt-body assertion
retries a few times to guarantee it observes a body-corruption round.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_s3_put_corruption.py -v
"""
import base64
import hashlib
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

try:
    import requests
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False

pytestmark = pytest.mark.timeout(240)

BODY_SIZE = 4 * 1024 * 1024   # 4 MiB — headers are a vanishing fraction, so wire
                              # corruption lands in the body ~99% of rounds.
CORRUPT_PCT = 0.01            # per-byte flip probability; ~400 expected body
                              # flips at 4 MiB, ~2% chance of a mangled header.


def _why_skip():
    if not os.path.isfile(servers.NGINX_BIN):
        return f"nginx not built: {servers.NGINX_BIN}"
    if not os.path.isfile(servers.FAULT_PROXY):
        return f"brix-fault-proxy not built: {servers.FAULT_PROXY}"
    if not _HAVE_REQUESTS:
        return "python requests not available"
    return None


_skip_reason = _why_skip()
if _skip_reason:
    pytest.skip(_skip_reason, allow_module_level=True)


def _body():
    return os.urandom(BODY_SIZE)


def _content_md5(body):
    """Classic S3 Content-MD5: base64 of the 128-bit MD5 over the object bytes."""
    return {"Content-MD5": base64.b64encode(hashlib.md5(body).digest()).decode()}


def _stored_path(data_root, name):
    return os.path.join(data_root, name)


def _key_url(host_port, name):
    # Anonymous S3: PUT to http://host:port/<bucket>/<key>.
    return f"http://{host_port}/{servers.NginxS3Anon.bucket}/{name}"


def test_corrupt_put_with_content_md5_is_rejected(tmp_path):
    """The fix: a body corrupted in flight no longer matches the Content-MD5 the
    client asserted, so the gateway must reject it (non-2xx) and keep nothing —
    never a 200 that persists poisoned bytes."""
    with servers.NginxS3Anon() as ng, servers.FaultProxy(ng.port) as fp:
        fp.set_corrupt(CORRUPT_PCT, "up")
        saw_body_reject = False
        for _ in range(8):
            name = f"corrupt-{uuid.uuid4().hex}.bin"
            body = _body()
            url = _key_url(f"127.0.0.1:{fp.listen}", name)
            try:
                r = requests.put(url, data=body, headers=_content_md5(body),
                                 timeout=60)
            except requests.exceptions.RequestException:
                continue  # framing so mangled the server reset — still a rejection
            # A 2xx here is the vulnerability: the asserted Content-MD5 was ignored
            # and corrupt bytes were committed.  Prove that never happens.
            assert not (200 <= r.status_code < 300), (
                f"gateway accepted a Content-MD5-mismatched PUT ({r.status_code}); "
                f"corrupt body committed silently")
            stored = _stored_path(ng.data, name)
            assert not os.path.exists(stored), (
                "rejected PUT must leave nothing stored (committed-then-unlinked)")
            saw_body_reject = True
        assert saw_body_reject, "never observed a completed corrupt round to judge"


def test_honest_put_with_content_md5_succeeds(tmp_path):
    """No false positive: with the proxy in path but NO corruption, a PUT carrying
    a valid Content-MD5 is accepted (200) and the stored bytes match byte-for-byte."""
    with servers.NginxS3Anon() as ng, servers.FaultProxy(ng.port) as fp:
        name = f"honest-{uuid.uuid4().hex}.bin"
        body = _body()
        url = _key_url(f"127.0.0.1:{fp.listen}", name)
        r = requests.put(url, data=body, headers=_content_md5(body), timeout=60)
        assert r.status_code == 200, f"honest PUT rejected: {r.status_code} {r.text}"
        stored = _stored_path(ng.data, name)
        assert os.path.isfile(stored), "accepted PUT must be stored"
        with open(stored, "rb") as fh:
            assert hashlib.md5(fh.read()).digest() == hashlib.md5(body).digest()


def test_malformed_content_md5_rejected(tmp_path):
    """Error leg: a Content-MD5 that is not valid base64 / not a 16-byte digest is
    rejected (400 InvalidDigest) and stores nothing — a malformed integrity header
    must not be silently ignored."""
    with servers.NginxS3Anon() as ng:
        # No fault proxy needed: the point is a syntactically bad Content-MD5.
        name = f"badmd5-{uuid.uuid4().hex}.bin"
        body = _body()
        url = _key_url(f"127.0.0.1:{ng.port}", name)
        r = requests.put(url, data=body,
                         headers={"Content-MD5": "not-a-valid-base64-md5!!"},
                         timeout=60)
        assert r.status_code == 400, (
            f"malformed Content-MD5 must be a 400, got {r.status_code}")
        assert "InvalidDigest" in r.text, (
            f"expected InvalidDigest XML error, got: {r.text[:200]}")
        assert not os.path.exists(_stored_path(ng.data, name)), (
            "rejected PUT must leave nothing stored")
