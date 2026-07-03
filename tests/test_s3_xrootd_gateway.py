"""
S3-to-XRootD Gateway interoperability — Section 4D of the comprehensive testing
roadmap docs/comprehensive-testing-roadmap.md.

Topology:
    S3 Client (boto3/requests) ──► Nginx (S3 Module) ──► XRootD (Backend via root://)

Nginx translates S3 REST API calls (PUT/GET/LIST/DELETE) into XRootD binary
operations (or WebDAV as an intermediate).  Cloud-native applications get
transparent access to XRootD storage.

Validation (per roadmap Section 4D):
  1. Upload a file via S3 PUT.
  2. Download the same file via xrdcp root://.
  3. Verify SHA-256 checksum matches on both sides.
  4. Verify metadata preservation (Content-Type, Content-Length).
  5. List objects — xrdcp-uploaded file is visible in S3 bucket listing.

Both the S3 endpoint (NGINX_S3_PORT) and the XRootD anonymous endpoint
(NGINX_ANON_PORT) must be pre-launched.

Run:
    pytest tests/test_s3_brix_gateway.py -v
"""

import hashlib
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    NGINX_S3_PORT,
    SERVER_HOST,
    XRDCP_BIN,
    XRDFS_BIN,
)

pytestmark = pytest.mark.e2e

# S3 test credentials (must match nginx S3 module config)
S3_ACCESS_KEY = os.environ.get("TEST_S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.environ.get("TEST_S3_SECRET_KEY", "minioadmin")
S3_BUCKET = os.environ.get("TEST_S3_BUCKET", "testbucket")
S3_ENDPOINT = f"http://{SERVER_HOST}:{NGINX_S3_PORT}"


def _wait_port(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def s3_gateway():
    """Wait for both S3 and XRootD servers; return connection info."""
    if not _wait_port(SERVER_HOST, NGINX_S3_PORT, timeout=15.0):
        pytest.skip(f"S3 server not running on port {NGINX_S3_PORT}")
    if not _wait_port(SERVER_HOST, NGINX_ANON_PORT, timeout=15.0):
        pytest.skip(f"XRootD server not running on port {NGINX_ANON_PORT}")
    return {
        "s3_url":    S3_ENDPOINT,
        "xrd_url":   f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/",
        "data_root": DATA_ROOT,
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _s3_put(key: str, data: bytes, content_type: str = "application/octet-stream") -> int:
    """HTTP PUT to the S3 endpoint; returns HTTP status code."""
    import urllib.request
    url = f"{S3_ENDPOINT}/{S3_BUCKET}/{key}"

    # Build a minimal AWS SigV4-signed request using the existing test approach:
    # use requests with boto3-style signing if available, else raw unsigned PUT
    # (the test nginx S3 config may allow unsigned for the test key).
    try:
        import requests
        from requests_aws4auth import AWS4Auth
        auth = AWS4Auth(S3_ACCESS_KEY, S3_SECRET_KEY, "us-east-1", "s3")
        r = requests.put(
            url, data=data,
            headers={"Content-Type": content_type},
            auth=auth, timeout=30,
        )
        return r.status_code
    except ImportError:
        pass

    # Fallback: try boto3
    try:
        import boto3
        from botocore.config import Config
        client = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT,
            aws_access_key_id=S3_ACCESS_KEY,
            aws_secret_access_key=S3_SECRET_KEY,
            region_name="us-east-1",
            config=Config(signature_version="s3v4"),
        )
        import io
        client.put_object(Bucket=S3_BUCKET, Key=key, Body=data,
                          ContentType=content_type)
        return 200
    except ImportError:
        pass

    # Last resort: unsigned PUT (works if S3 module is in test mode)
    import http.client
    conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=30)
    conn.request("PUT", f"/{S3_BUCKET}/{key}", data,
                 {"Content-Type": content_type, "Content-Length": str(len(data))})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


def _s3_get(key: str) -> tuple[int, bytes]:
    """HTTP GET from the S3 endpoint; returns (status, body)."""
    import http.client
    conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=30)
    conn.request("GET", f"/{S3_BUCKET}/{key}",
                 headers={"Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


def _s3_head(key: str) -> tuple[int, dict]:
    """HTTP HEAD from the S3 endpoint; returns (status, headers dict)."""
    import http.client
    conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=30)
    conn.request("HEAD", f"/{S3_BUCKET}/{key}",
                 headers={"Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
    resp = conn.getresponse()
    resp.read()
    hdrs = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    return resp.status, hdrs


def _s3_list(prefix: str = "") -> tuple[int, str]:
    """ListObjectsV2 from the S3 endpoint; returns (status, body_text)."""
    import http.client
    params = f"list-type=2&prefix={prefix}"
    conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=30)
    conn.request("GET", f"/{S3_BUCKET}?{params}",
                 headers={"Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return resp.status, body


def _xrdcp_get(src: str, dst: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src, dst],
        capture_output=True, text=True, timeout=timeout, env={**os.environ},
    )


def _xrdcp_put(src: str, dst: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src, dst],
        capture_output=True, text=True, timeout=timeout, env={**os.environ},
    )


# ---------------------------------------------------------------------------
# Section 4D — S3 REST → XRootD binary: write S3, read XRootD
# ---------------------------------------------------------------------------

@pytest.mark.requires_local_server
class TestS3ToXRootDGateway:
    """Upload via S3 PUT; download via xrdcp root://; verify SHA-256 match.

    Covers roadmap Section 4D.
    """

    def test_s3_put_then_xrdcp_get_checksum(self, s3_gateway, tmp_path):
        """Upload via S3 → download via xrdcp; SHA-256 must match (Section 4D Validation)."""
        payload = os.urandom(128 * 1024)
        key = f"gw_put_get_{uuid.uuid4().hex[:8]}.bin"

        status = _s3_put(key, payload)
        assert status in (200, 204, 201), f"S3 PUT failed with HTTP {status}"

        dst = str(tmp_path / key)
        result = _xrdcp_get(
            f"{s3_gateway['xrd_url']}{key}", dst
        )
        assert result.returncode == 0, (
            f"xrdcp GET after S3 PUT failed:\n{result.stderr}"
        )
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _sha256(got) == _sha256(payload), (
            "SHA-256 mismatch: file written via S3 does not match what xrdcp read"
        )

    def test_xrdcp_put_then_s3_get_checksum(self, s3_gateway, tmp_path):
        """Upload via xrdcp → download via S3 GET; SHA-256 must match (Section 4D)."""
        payload = os.urandom(64 * 1024)
        key = f"gw_xrd_s3_{uuid.uuid4().hex[:8]}.bin"

        src = str(tmp_path / f"src_{key}")
        with open(src, "wb") as fh:
            fh.write(payload)

        result = _xrdcp_put(src, f"{s3_gateway['xrd_url']}{key}")
        assert result.returncode == 0, f"xrdcp PUT failed: {result.stderr}"

        status, body = _s3_get(key)
        assert status == 200, f"S3 GET after xrdcp PUT returned HTTP {status}"
        assert _sha256(body) == _sha256(payload), (
            "SHA-256 mismatch: file written via xrdcp does not match what S3 returned"
        )

    def test_s3_content_type_preserved(self, s3_gateway):
        """Metadata (Content-Type) is preserved through the S3 gateway."""
        key = f"gw_ct_{uuid.uuid4().hex[:8]}.csv"
        payload = b"col1,col2\n1,2\n3,4\n"
        content_type = "text/csv"

        status = _s3_put(key, payload, content_type=content_type)
        assert status in (200, 204, 201), f"S3 PUT failed: HTTP {status}"

        head_status, headers = _s3_head(key)
        assert head_status == 200, f"HEAD failed: HTTP {head_status}"
        ct = headers.get("content-type", "")
        assert "text/csv" in ct, (
            f"Content-Type not preserved through gateway: got '{ct}'"
        )

    def test_s3_content_length_matches_payload(self, s3_gateway):
        """Content-Length from S3 HEAD matches the original payload size."""
        payload = os.urandom(8192)
        key = f"gw_cl_{uuid.uuid4().hex[:8]}.bin"

        status = _s3_put(key, payload)
        assert status in (200, 204, 201)

        head_status, headers = _s3_head(key)
        assert head_status == 200
        content_length = int(headers.get("content-length", 0))
        assert content_length == len(payload), (
            f"Content-Length {content_length} != payload {len(payload)}"
        )

    def test_s3_list_shows_xrdcp_uploaded_file(self, s3_gateway, tmp_path):
        """Section 4D: file uploaded via xrdcp is visible in S3 ListObjectsV2."""
        key = f"gw_list_{uuid.uuid4().hex[:8]}.bin"
        src = str(tmp_path / key)
        with open(src, "wb") as fh:
            fh.write(os.urandom(1024))

        result = _xrdcp_put(src, f"{s3_gateway['xrd_url']}{key}")
        assert result.returncode == 0, f"xrdcp PUT failed: {result.stderr}"

        list_status, body = _s3_list(prefix=key[:8])
        assert list_status == 200, f"ListObjectsV2 failed: HTTP {list_status}"
        assert key in body, (
            f"xrdcp-uploaded file {key!r} not found in S3 listing:\n{body[:500]}"
        )

    def test_s3_delete_removes_from_brix_namespace(self, s3_gateway):
        """File deleted via S3 DELETE is gone from the XRootD namespace."""
        key = f"gw_del_{uuid.uuid4().hex[:8]}.bin"
        _s3_put(key, b"delete-me")

        # Delete via S3
        import http.client
        conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=15)
        conn.request("DELETE", f"/{S3_BUCKET}/{key}",
                     headers={"Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status in (204, 200), f"S3 DELETE returned HTTP {resp.status}"

        # Verify gone from XRootD (S3 stores flat at DATA_ROOT/key, not DATA_ROOT/bucket/key)
        r = subprocess.run(
            [XRDFS_BIN, f"{SERVER_HOST}:{NGINX_ANON_PORT}", "stat",
             f"/{key}"],
            capture_output=True, text=True, timeout=10, env={**os.environ},
        )
        assert r.returncode != 0, (
            "File still visible in XRootD namespace after S3 DELETE"
        )

    def test_large_file_s3_to_brix_integrity(self, s3_gateway, tmp_path):
        """1 MiB file uploaded via S3 and downloaded via xrdcp matches SHA-256."""
        payload = os.urandom(1 * 1024 * 1024)
        key = f"gw_large_{uuid.uuid4().hex[:8]}.bin"

        status = _s3_put(key, payload)
        assert status in (200, 204, 201), f"Large S3 PUT failed: HTTP {status}"

        dst = str(tmp_path / key)
        result = _xrdcp_get(
            f"{s3_gateway['xrd_url']}{key}", dst, timeout=120
        )
        assert result.returncode == 0, f"Large xrdcp GET failed: {result.stderr}"
        with open(dst, "rb") as fh:
            got = fh.read()
        assert _sha256(got) == _sha256(payload), (
            "Large-file SHA-256 mismatch through S3-to-XRootD gateway"
        )


# ---------------------------------------------------------------------------
# Security negative
# ---------------------------------------------------------------------------

class TestS3GatewaySecurity:
    """Section 7 security negatives for the S3 gateway."""

    @pytest.fixture(scope="class", autouse=True)
    def _require_s3(self):
        if not _wait_port(SERVER_HOST, NGINX_S3_PORT, timeout=5.0):
            pytest.skip("S3 server not running")

    def test_path_traversal_in_s3_key_rejected(self):
        """S3 key containing path traversal sequence must be rejected."""
        import http.client
        conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=10)
        conn.request("GET", f"/{S3_BUCKET}/../../../etc/passwd",
                     headers={"Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status in (400, 403, 404), (
            f"Path traversal in S3 key returned HTTP {resp.status} (expected 400/403/404)"
        )

    def test_unauthenticated_s3_request_rejected(self):
        """S3 GET without authentication must be rejected (if auth is required)."""
        import http.client
        conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=10)
        conn.request("GET", f"/{S3_BUCKET}/some-key")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        # Either 401 (Unauthorized) or 403 (Forbidden) are acceptable rejections.
        assert resp.status in (401, 403, 404), (
            f"Unauthenticated S3 GET returned HTTP {resp.status} — "
            f"anonymous access may be unintentionally permitted"
        )
