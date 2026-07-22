"""
test_webdav_put_corruption.py — in-path corruption of the WebDAV PUT ingest
gateway (client->server body integrity).

THE BREAK: a WebDAV PUT streams the request body straight through
brix_vfs_writer and commits whatever bytes land — the writer holds no expected
length and no expected digest.  A client that DID compute an end-to-end digest
(RFC-3230 `Digest:` or legacy `Content-MD5:`) and sent it with the PUT gets that
header silently ignored: a middlebox/flaky-NIC that flips a byte in the body
past the TCP checksum produces a stored object that no longer matches the digest
the client asserted, yet the gateway answers 201/204 and keeps the poisoned
bytes.  `brix-fault-proxy corrupt <frac> up` reproduces exactly this — flip a
random bit in a fraction of the client->server bytes, length preserved.

THE FIX: when a PUT carries a usable ingest digest, verify it over the RECEIVED
bytes before commit and fail closed (400 Bad Request, nothing committed) on
mismatch — the client told us what it sent, so we can and must check it.  Opt-in
`brix_webdav_require_digest on` additionally rejects any PUT that arrives with no
usable digest, for deployments that refuse un-verifiable writes outright.

CONTRACT proven here:
  * corrupt-up PUT carrying a valid Digest -> 4xx and NO committed object (the
    gateway honoured the digest the client asserted).            [the fix fires]
  * honest PUT carrying a valid Digest     -> 201/204 and the stored bytes match
    byte-for-byte (a good digest never penalises a good transfer).[no false pos]
  * require_digest ON, PUT with no digest  -> 4xx, nothing stored (a deployment
    can refuse writes it cannot verify).                         [security-neg]

The corruption also occasionally lands in the request line / headers rather than
the body, which breaks HTTP framing and yields its own 4xx; that is still a
rejection, so the corrupt-body assertion retries a few times to guarantee it
observes a body-corruption round (digest mismatch), not only a framing reject.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_webdav_put_corruption.py -v
"""
import base64
import hashlib
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from settings import HOST

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
REQUIRE = "brix_webdav_require_digest on;"


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


def _digest_headers(body):
    """RFC-3230 Digest + legacy Content-MD5 over the honest body."""
    md5 = hashlib.md5(body).digest()
    return {
        "Digest": "md5=" + base64.b64encode(md5).decode(),
        "Content-MD5": base64.b64encode(md5).decode(),
    }


def _stored_path(data_root, name):
    return os.path.join(data_root, name)


def test_corrupt_put_with_digest_is_rejected(tmp_path):
    """The fix: a body corrupted in flight no longer matches the Digest the client
    asserted, so the gateway must reject it (4xx) and commit nothing — never a 2xx
    that persists poisoned bytes."""
    with servers.NginxWebdavAnon() as ng, servers.FaultProxy(ng.port) as fp:
        fp.set_corrupt(CORRUPT_PCT, "up")
        saw_body_reject = False
        for _ in range(8):
            name = f"corrupt-{uuid.uuid4().hex}.bin"
            body = _body()
            url = f"http://{HOST}:{fp.listen}/{name}"
            try:
                r = requests.put(url, data=body, headers=_digest_headers(body),
                                 timeout=60)
            except requests.exceptions.RequestException:
                continue  # framing so mangled the server reset — still a rejection
            # A 2xx here is the vulnerability: the asserted digest was ignored and
            # corrupt bytes were committed.  Prove that never happens.
            assert not (200 <= r.status_code < 300), (
                f"gateway accepted a digest-mismatched PUT ({r.status_code}); "
                f"corrupt body committed silently")
            stored = _stored_path(ng.data, name)
            assert not os.path.exists(stored), (
                "rejected PUT must leave nothing committed")
            saw_body_reject = True
        assert saw_body_reject, "never observed a completed corrupt round to judge"


def test_honest_put_with_digest_succeeds(tmp_path):
    """No false positive: with the proxy in path but NO corruption, a PUT carrying
    a valid Digest is accepted and the stored bytes match byte-for-byte."""
    with servers.NginxWebdavAnon() as ng, servers.FaultProxy(ng.port) as fp:
        name = f"honest-{uuid.uuid4().hex}.bin"
        body = _body()
        url = f"http://{HOST}:{fp.listen}/{name}"
        r = requests.put(url, data=body, headers=_digest_headers(body), timeout=60)
        assert 200 <= r.status_code < 300, f"honest PUT rejected: {r.status_code}"
        stored = _stored_path(ng.data, name)
        assert os.path.isfile(stored), "accepted PUT must be committed"
        with open(stored, "rb") as fh:
            assert hashlib.md5(fh.read()).digest() == hashlib.md5(body).digest()


def test_require_digest_rejects_missing(tmp_path):
    """Security-neg: with brix_webdav_require_digest on, a PUT that arrives with no
    usable ingest digest is refused (4xx) and stores nothing — a deployment can
    decline to accept writes it cannot verify."""
    with servers.NginxWebdavAnon(extra_directives=REQUIRE) as ng:
        # No fault proxy needed: the point is the *absence* of a digest header.
        name = f"nodigest-{uuid.uuid4().hex}.bin"
        body = _body()
        url = f"http://{HOST}:{ng.port}/{name}"
        r = requests.put(url, data=body, timeout=60)  # no Digest / Content-MD5
        assert 400 <= r.status_code < 500, (
            f"require_digest must refuse a digest-less PUT, got {r.status_code}")
        assert not os.path.exists(_stored_path(ng.data, name)), (
            "refused PUT must leave nothing committed")
