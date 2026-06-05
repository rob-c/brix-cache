"""Section 3.1 — HTTP read-through cache hit tests.

Verifies that WebDAV GET serves files from the read-through cache when
``xrootd_webdav_cache_root`` is configured.  The dedicated ``http-cache``
server (port 18457) serves anonymous HTTP WebDAV with:

    xrootd_webdav_root       /tmp/xrd-test/data-http-cache
    xrootd_webdav_cache_root /tmp/xrd-test/data-http-cache/cache

Cache path formula (from src/webdav/get.c):
    cache_path = cache_root_canon + (fs_path - root_canon)
    e.g. GET /foo.txt → check /tmp/xrd-test/data-http-cache/cache/foo.txt

Three test cases (per AGENTS.md: success + error + security-neg):
  1. cache_hit_served  — cache file exists → response body == cache content
  2. cache_miss_fallthrough — cache file absent → origin file is served
  3. path_traversal_blocked — ``/../`` in URL → 400 Bad Request
"""

import os
import uuid

import pytest
import requests

from settings import (
    NGINX_HTTP_CACHE_PORT,
    SERVER_HOST,
    DATA_ROOT,
)

# Data directories created by start_dedicated_nginx "http-cache"
HTTP_CACHE_DATA = os.path.join(os.path.dirname(DATA_ROOT), "data-http-cache")
HTTP_CACHE_CACHE = os.path.join(HTTP_CACHE_DATA, "cache")


@pytest.fixture(scope="module")
def base_url():
    return f"http://{SERVER_HOST}:{NGINX_HTTP_CACHE_PORT}"


@pytest.fixture(autouse=True)
def ensure_cache_dir():
    """Ensure cache directory exists before each test."""
    os.makedirs(HTTP_CACHE_CACHE, exist_ok=True)


# ---------------------------------------------------------------------------
# 1. Success — cache file present → served from cache
# ---------------------------------------------------------------------------

def test_cache_hit_served(base_url):
    """GET returns the cached copy when a cache file exists at the expected path.

    The module appends the request URI to cache_root_canon and stat()s the
    result.  If the stat succeeds (S_ISREG), it swaps the open path so nginx
    serves the cached file instead of the origin file.
    """
    uid = uuid.uuid4().hex
    rel = f"cache_hit_{uid}.txt"

    origin_path = os.path.join(HTTP_CACHE_DATA, rel)
    cache_path = os.path.join(HTTP_CACHE_CACHE, rel)

    origin_content = b"origin-content-" + uid.encode()
    cache_content = b"cache-content-" + uid.encode()

    try:
        with open(origin_path, "wb") as f:
            f.write(origin_content)
        with open(cache_path, "wb") as f:
            f.write(cache_content)

        r = requests.get(f"{base_url}/{rel}", timeout=10)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        assert r.content == cache_content, (
            f"Expected cache content, got {r.content!r}"
        )
    finally:
        for p in (origin_path, cache_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass


# ---------------------------------------------------------------------------
# 2. Error path — cache file absent → falls through to origin
# ---------------------------------------------------------------------------

def test_cache_miss_fallthrough(base_url):
    """GET serves the origin file when the cache entry does not exist.

    When xrootd_cache_file_ready() returns 0 (ENOENT), get.c keeps the
    original fs_path and serves from the origin root unchanged.
    """
    uid = uuid.uuid4().hex
    rel = f"cache_miss_{uid}.txt"

    origin_path = os.path.join(HTTP_CACHE_DATA, rel)
    cache_path = os.path.join(HTTP_CACHE_CACHE, rel)

    origin_content = b"origin-only-" + uid.encode()

    # Ensure no stale cache file exists
    try:
        os.unlink(cache_path)
    except FileNotFoundError:
        pass

    try:
        with open(origin_path, "wb") as f:
            f.write(origin_content)

        r = requests.get(f"{base_url}/{rel}", timeout=10)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        assert r.content == origin_content, (
            f"Expected origin content, got {r.content!r}"
        )
    finally:
        try:
            os.unlink(origin_path)
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# 3. Security-neg — path traversal attempt is rejected
# ---------------------------------------------------------------------------

def test_path_traversal_blocked(base_url):
    """URL with ``..`` segments must not escape the webdav_root.

    ngx_http_xrootd_webdav_resolve_path() calls realpath() inside the confined
    root and returns 403 Forbidden (or 400 Bad Request) for any path that
    escapes confinement.  This ensures a crafted cache_path cannot be used to
    leak files outside root_canon even if a traversal reaches the cache check.
    """
    traversal_url = f"{base_url}/../../../etc/passwd"
    r = requests.get(traversal_url, timeout=10, allow_redirects=False)
    # nginx normalizes the URI before path resolution so a path-traversal
    # either collapses to "/" (→ 200/404 on the root) or is rejected with 400.
    # Either way it must NOT return the content of /etc/passwd.
    if r.status_code == 200:
        assert b"root:x:" not in r.content, (
            "Path traversal returned /etc/passwd content — security failure"
        )
    else:
        assert r.status_code in (400, 403, 404), (
            f"Unexpected status {r.status_code} for traversal attempt"
        )
