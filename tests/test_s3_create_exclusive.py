"""S3 atomic create-if-absent — PutObject with `If-None-Match: *` (phase-47 W6b).

The commit path uses renameat2(RENAME_NOREPLACE) so two racing creates of the
same key cannot both win (the pre-body stat only narrows the window; the rename
closes it).  Three cases:

  1. success      — If-None-Match:* on an absent key → 200.
  2. error        — If-None-Match:* on an existing key → 412 PreconditionFailed.
  3. security/neg — N concurrent If-None-Match:* creates of one key → exactly
                    one 200, the rest 412 (never two winners, never a 5xx).

Uses the pre-started nginx_shared S3 instance (port 9001), anonymous + write.
"""

import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from settings import S3_BUCKET

BUCKET = S3_BUCKET
EXCL = {"If-None-Match": "*"}


@pytest.fixture(scope="module")
def s3_url(test_env):
    return test_env["s3_url"]


def _key_url(s3_url):
    return f"{s3_url}/{BUCKET}/excl_{uuid.uuid4().hex}"


def test_create_if_absent_succeeds(s3_url):
    url = _key_url(s3_url)
    try:
        r = requests.put(url, data=b"first", headers=EXCL, timeout=10)
        assert r.status_code == 200
        assert requests.get(url, timeout=10).content == b"first"
    finally:
        requests.delete(url, timeout=10)


def test_create_if_absent_conflict_412(s3_url):
    url = _key_url(s3_url)
    try:
        assert requests.put(url, data=b"orig", timeout=10).status_code == 200
        # Key now exists — an exclusive create must fail with 412 and not modify.
        r = requests.put(url, data=b"overwrite", headers=EXCL, timeout=10)
        assert r.status_code == 412
        assert requests.get(url, timeout=10).content == b"orig"
    finally:
        requests.delete(url, timeout=10)


def test_concurrent_creates_single_winner(s3_url):
    url = _key_url(s3_url)
    n = 8

    def _create(i):
        return requests.put(url, data=f"body-{i}".encode(), headers=EXCL,
                            timeout=15).status_code

    try:
        with ThreadPoolExecutor(max_workers=n) as ex:
            codes = list(ex.map(_create, range(n)))

        # Exactly one creator wins; the rest see the atomic conflict.  No 5xx.
        assert codes.count(200) == 1, codes
        assert codes.count(412) == n - 1, codes
        assert all(c in (200, 412) for c in codes), codes

        # The surviving object is whole (one writer's body, not a mix).
        body = requests.get(url, timeout=10).content
        assert body.startswith(b"body-") and len(body) == len(b"body-0")
    finally:
        requests.delete(url, timeout=10)
