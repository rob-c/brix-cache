"""S3 ListObjects per-worker sorted-listing cache (phase-47 W6c).

`brix_s3_list_cache on` caches the sorted (key+is_prefix) listing per worker,
keyed by (root, prefix, delimiter), validated by the bucket-root mtime + a TTL.
This test self-provisions a dedicated single-worker nginx with the cache enabled
(short TTL) so the behaviour is observable without touching the shared harness.

Cases:
  1. correctness    — a cache-on multi-page listing returns every key exactly
                      once in lexicographic order (identical to the uncached set).
  2. caching active — after warming the cache, a new key added in an existing
                      sub-directory (which does NOT bump the root mtime) is NOT
                      seen until the TTL expires (the cached result is served —
                      this is the documented bounded-staleness window).
  3. TTL refresh    — once the TTL lapses, the new key appears (re-walk).
  4. mtime refresh  — a new TOP-LEVEL key bumps the root mtime and is seen
                      immediately (cache invalidated).
"""

import os
import time
import uuid
import xml.etree.ElementTree as ET

import pytest
import requests

from settings import BIND_HOST, HOST as _HOST, NGINX_BIN  # noqa: F401  (NGINX_BIN: harness gate)
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness]

TTL_SECONDS = 2
BUCKET = "testbucket"
NS = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

# Base URL of the live per-test server; set by the ``cache_server`` fixture.
HOST = None


def _keys_in(xml_text):
    root = ET.fromstring(xml_text)
    return [e.text for e in root.findall(".//s3:Contents/s3:Key", NS)]


@pytest.fixture()
def cache_server(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    # The list cache watches the export-root (DATA_DIR) mtime at SECOND
    # granularity.  This per-test server (function scope) starts with no
    # accumulated history, so a warm + a top-level PUT within the same wall-clock
    # second would read an unchanged root mtime and serve the stale cached
    # listing.  Backdate the root so the top-level PUT lands on a strictly newer
    # second and the mtime-invalidation path fires.
    os.utime(data, (time.time() - 5, time.time() - 5))
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-s3-list-cache",
        template="nginx_lc_s3_list_cache_self.conf",
        protocol="s3",
        template_values={
            "BIND_HOST": BIND_HOST,
            "DATA_DIR": str(data),
            "BUCKET": BUCKET,
            "TTL_SECONDS": TTL_SECONDS,
        },
        reason="s3 list-cache TTL"))
    global HOST
    HOST = f"http://{_HOST}:{ep.port}"
    yield str(data)


def _put(key, body=b"x"):
    assert requests.put(f"{HOST}/{BUCKET}/{key}", data=body,
                        timeout=10).status_code == 200


def _list(**params):
    params.setdefault("list-type", "2")
    r = requests.get(f"{HOST}/{BUCKET}/", params=params, timeout=10)
    assert r.status_code == 200, (r.status_code, r.text)
    return r.text


def test_cached_listing_is_correct_and_ordered(cache_server):
    prefix = f"corr-{uuid.uuid4().hex}/"
    expected = sorted(f"{prefix}obj{i:03d}" for i in range(25))
    for k in expected:
        _put(k)

    # Paginate with a small page size; the cache serves pages 2..N.
    got = []
    token = None
    for _ in range(20):
        params = {"prefix": prefix, "max-keys": "10"}
        if token:
            params["continuation-token"] = token
        root = ET.fromstring(_list(**params))
        got += [e.text for e in root.findall(".//s3:Contents/s3:Key", NS)]
        nxt = root.find("s3:NextContinuationToken", NS)
        token = nxt.text if nxt is not None and nxt.text else None
        if not token:
            break

    assert got == expected           # every key once, lexicographic, no dups


def test_cache_serves_stale_then_refreshes_on_ttl(cache_server):
    data = cache_server
    prefix = f"stale-{uuid.uuid4().hex}/"
    _put(prefix + "a")               # ensure the sub-dir exists
    # Warm the cache for the whole-bucket listing.
    _ = _list()

    # Add a key under the existing sub-dir — this does NOT bump the root mtime,
    # so the cached listing (within TTL) must still be served (key absent).
    _put(prefix + "b")
    assert (prefix + "b") not in _keys_in(_list())

    # After the TTL lapses, the listing is re-walked and the key appears.
    time.sleep(TTL_SECONDS + 1)
    assert (prefix + "b") in _keys_in(_list())


def test_toplevel_change_bumps_mtime_and_invalidates(cache_server):
    _ = _list()                      # warm
    top = f"toplevel-{uuid.uuid4().hex}"
    _put(top)                        # a new top-level key bumps the root mtime
    # No TTL wait: the mtime change alone must invalidate immediately.
    assert top in _keys_in(_list())
