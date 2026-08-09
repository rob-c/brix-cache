"""XrdHttp protocol extension tests.

Verifies the XrdHttp compatibility layer implemented in xrdhttp.c /
xrdhttp_multipart.c / xrdhttp_stats.c:

  - X-Xrootd-Proto detection and X-Xrootd-Requuid echo
  - X-Xrootd-Status error code on 4xx/5xx responses
  - ?xrd.want.cksum=<algo> Digest: header (adler32, crc32, crc32c, md5, sha1, sha256)
  - Multi-range GET → multipart/byteranges response
  - ?tpc.src= header injection (synthesised Source: header)
  - ?xrd.stats XML statistics endpoint
  - Security: embedded NUL bytes in query params rejected, oversized values truncated

Uses the pre-started nginx instance on NGINX_HTTP_WEBDAV_PORT (8080, anonymous,
write-enabled).  Run after `tests/manage_test_servers.sh start`.
"""

import hashlib
import uuid
import re
import zlib

import pytest
import requests


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def base_url(test_env):
    return test_env["http_webdav_url"]


@pytest.fixture(scope="module")
def xrd_file(base_url):
    """Upload a known-content file once; share across tests in this module."""
    uid = uuid.uuid4().hex
    path = f"/xrdhttp_test_{uid}.bin"
    # 256 bytes: 0x00 through 0xFF repeated
    content = bytes(range(256))
    r = requests.put(f"{base_url}{path}", data=content, timeout=10)
    assert r.status_code in (200, 201), f"fixture PUT failed: {r.status_code}"
    return {"path": path, "content": content, "url": f"{base_url}{path}"}


# ---------------------------------------------------------------------------
# 1. X-Xrootd-Proto detection + X-Xrootd-Requuid echo
# ---------------------------------------------------------------------------
