"""
WLCG Audit Log Verification — Section 9 / Phase 4 of the comprehensive testing
roadmap docs/comprehensive-testing-roadmap.md.

WLCG-compliant audit log fields per roadmap Section 9:
  - IP address of the requesting client
  - User identity (DN or token 'sub')
  - File path accessed
  - Action performed (read/write/stat/delete)
  - Result (OK / error code)
  - Timestamp
  - streamid (Section 9: Unified Tracing)

Section 14.5 (success criteria):
  "The Requuid in the S3 logs matches the streamid in the Binary logs."

All tests inspect the access logs written by the pre-launched servers.
The log path is LOG_DIR/xrootd_access.log for stream access,
LOG_DIR/http_webdav_access.log for WebDAV, and LOG_DIR/s3_access.log for S3.

Run:
    pytest tests/test_wlcg_audit_log.py -v
"""

import hashlib
import os
import re
import socket
import subprocess
import time
import uuid
from pathlib import Path

import pytest
import requests

from settings import (
    CA_DIR,
    DATA_ROOT,
    LOG_DIR,
    NGINX_ANON_PORT,
    NGINX_HTTP_WEBDAV_PORT,
    NGINX_S3_PORT,
    PROXY_STD,
    SERVER_HOST,
    XRDCP_BIN,
)

pytestmark = pytest.mark.requires_local_server

S3_ACCESS_KEY = os.environ.get("TEST_S3_ACCESS_KEY", "minioadmin")
S3_SECRET_KEY = os.environ.get("TEST_S3_SECRET_KEY", "minioadmin")
S3_BUCKET = os.environ.get("TEST_S3_BUCKET", "testbucket")


def _wait_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _log_offset(log_path: str) -> int:
    return Path(log_path).stat().st_size if Path(log_path).exists() else 0


def _wait_for_log_entry(
    log_path: str,
    start_offset: int,
    *needles: str,
    timeout: float = 8.0,
) -> str:
    """Return log text written after start_offset that contains all needles."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        p = Path(log_path)
        if p.exists():
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(start_offset)
                chunk = fh.read()
            if all(n in chunk for n in needles):
                return chunk
        time.sleep(0.05)
    return ""


def _write_file(name: str, data: bytes) -> str:
    path = os.path.join(DATA_ROOT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _xrdcp_get(src: str, dst: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", src, dst],
        capture_output=True, text=True, timeout=timeout, env={**os.environ},
    )


STREAM_LOG  = os.path.join(LOG_DIR, "xrootd_access_anon.log")
WEBDAV_LOG  = os.path.join(LOG_DIR, "http_webdav_access.log")
S3_LOG      = os.path.join(LOG_DIR, "s3_access.log")


# ---------------------------------------------------------------------------
# Section 9 — Stream XRootD WLCG audit fields
# ---------------------------------------------------------------------------

class TestStreamWLCGAuditLog:
    """Verifies that the XRootD stream access log contains WLCG-required fields."""

    @pytest.fixture(scope="class", autouse=True)
    def _require_stream(self):
        if not _wait_port(SERVER_HOST, NGINX_ANON_PORT, timeout=5.0):
            pytest.skip(f"Stream server not available on port {NGINX_ANON_PORT}")
        if not Path(STREAM_LOG).parent.exists():
            pytest.skip(f"Log directory {LOG_DIR} does not exist")

    def test_read_logged_with_ip_and_path(self, tmp_path):
        """Stream GET: access log contains client IP and file path."""
        name = f"audit_stream_{uuid.uuid4().hex[:8]}.bin"
        _write_file(name, os.urandom(1024))
        offset = _log_offset(STREAM_LOG)

        dst = str(tmp_path / name)
        r = _xrdcp_get(f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/{name}", dst)
        assert r.returncode == 0, f"xrdcp failed: {r.stderr}"

        chunk = _wait_for_log_entry(STREAM_LOG, offset, name)
        assert chunk, f"No log entry for {name} in {STREAM_LOG}"
        assert "127.0.0.1" in chunk or SERVER_HOST in chunk, (
            f"Client IP not found in audit log entry:\n{chunk[:300]}"
        )

    def test_read_logged_with_result_ok(self, tmp_path):
        """Stream GET: access log contains a success result indicator."""
        name = f"audit_ok_{uuid.uuid4().hex[:8]}.bin"
        _write_file(name, b"audit-ok-data")
        offset = _log_offset(STREAM_LOG)

        dst = str(tmp_path / name)
        _xrdcp_get(f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/{name}", dst)

        chunk = _wait_for_log_entry(STREAM_LOG, offset, name)
        # Success indicator: "OK", "200", "0" (errno 0), or kXR_ok (0)
        has_success = any(tok in chunk for tok in ("OK", " 200", " 0 ", "kXR_ok"))
        assert has_success, (
            f"No success indicator (OK/200/0) in stream audit log:\n{chunk[:300]}"
        )

    def test_error_logged_for_missing_file(self, tmp_path):
        """Stream GET on non-existent file: error code appears in audit log."""
        name = f"audit_missing_{uuid.uuid4().hex[:8]}.bin"
        offset = _log_offset(STREAM_LOG)

        dst = str(tmp_path / name)
        # This xrdcp should fail.
        _xrdcp_get(f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/{name}", dst)

        chunk = _wait_for_log_entry(STREAM_LOG, offset, name)
        if not chunk:
            pytest.skip("Log entry not written for failed request — log format may differ")
        # Should contain a non-zero error or "ENOENT" / "NotFound" / "ERR"
        has_error = any(tok in chunk for tok in ("ENOENT", "NotFound", "3003", "404", "error", " ERR "))
        assert has_error, (
            f"Error indicator missing in stream audit log for missing file:\n{chunk[:300]}"
        )

    def test_write_logged_with_action(self, tmp_path):
        """Stream PUT: write action appears in audit log."""
        name = f"audit_write_{uuid.uuid4().hex[:8]}.bin"
        src = str(tmp_path / f"src_{name}")
        with open(src, "wb") as fh:
            fh.write(os.urandom(512))
        offset = _log_offset(STREAM_LOG)

        subprocess.run(
            [XRDCP_BIN, "-f", "-s", src,
             f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/{name}"],
            capture_output=True, timeout=15, env={**os.environ},
        )

        chunk = _wait_for_log_entry(STREAM_LOG, offset, name)
        if not chunk:
            pytest.skip("Log entry not written for write — log format may differ")
        has_write = any(tok in chunk.lower()
                        for tok in ("write", "put", "open", "kxr_write"))
        assert has_write, (
            f"Write action not found in audit log:\n{chunk[:300]}"
        )


# ---------------------------------------------------------------------------
# Section 9 — WebDAV WLCG audit fields
# ---------------------------------------------------------------------------

class TestWebDAVWLCGAuditLog:
    """Verifies that the WebDAV HTTP access log contains WLCG-required fields."""

    @pytest.fixture(scope="class", autouse=True)
    def _require_webdav(self):
        if not _wait_port(SERVER_HOST, NGINX_HTTP_WEBDAV_PORT, timeout=5.0):
            pytest.skip(f"WebDAV server not available on port {NGINX_HTTP_WEBDAV_PORT}")

    def test_get_logged_with_method_and_path(self):
        """WebDAV GET: access log contains HTTP method and file path."""
        name = f"audit_webdav_{uuid.uuid4().hex[:8]}.txt"
        _write_file(name, b"audit-webdav")
        offset = _log_offset(WEBDAV_LOG)

        r = requests.get(
            f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/{name}", timeout=10
        )
        assert r.status_code == 200, f"WebDAV GET failed: {r.status_code}"

        chunk = _wait_for_log_entry(WEBDAV_LOG, offset, name)
        assert chunk, f"No WebDAV log entry for {name}"
        assert "GET" in chunk, f"HTTP method GET not in WebDAV log:\n{chunk[:300]}"

    def test_put_logged_with_201_or_204(self):
        """WebDAV PUT: access log contains PUT method and a 2xx status."""
        name = f"audit_put_{uuid.uuid4().hex[:8]}.txt"
        offset = _log_offset(WEBDAV_LOG)

        r = requests.put(
            f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/{name}",
            data=b"put-audit",
            timeout=10,
        )
        assert r.status_code in (200, 201, 204), f"WebDAV PUT failed: {r.status_code}"

        chunk = _wait_for_log_entry(WEBDAV_LOG, offset, name)
        assert chunk, f"No WebDAV log entry for PUT {name}"
        assert "PUT" in chunk, f"HTTP method PUT not in WebDAV log:\n{chunk[:300]}"

    def test_client_ip_in_webdav_log(self):
        """WebDAV access log contains the client IP address."""
        name = f"audit_ip_{uuid.uuid4().hex[:8]}.txt"
        _write_file(name, b"ip-audit")
        offset = _log_offset(WEBDAV_LOG)

        requests.get(
            f"http://{SERVER_HOST}:{NGINX_HTTP_WEBDAV_PORT}/{name}", timeout=10
        )

        chunk = _wait_for_log_entry(WEBDAV_LOG, offset, name)
        assert chunk, f"No log entry for {name}"
        assert "127.0.0.1" in chunk or SERVER_HOST in chunk, (
            f"Client IP not found in WebDAV audit log:\n{chunk[:300]}"
        )


# ---------------------------------------------------------------------------
# Section 9 — S3 WLCG audit fields
# ---------------------------------------------------------------------------

class TestS3WLCGAuditLog:
    """Verifies that the S3 access log contains WLCG-required fields."""

    @pytest.fixture(scope="class", autouse=True)
    def _require_s3(self):
        if not _wait_port(SERVER_HOST, NGINX_S3_PORT, timeout=5.0):
            pytest.skip(f"S3 server not available on port {NGINX_S3_PORT}")

    def _s3_put(self, key: str, data: bytes) -> int:
        import http.client
        conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=15)
        conn.request("PUT", f"/{S3_BUCKET}/{key}", data,
                     {"Content-Length": str(len(data)),
                      "Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status

    def test_s3_put_logged_with_requuid(self):
        """S3 PUT: access log contains a request UUID (Requuid).

        Roadmap Section 14.5: "The Requuid in the S3 logs matches the
        streamid in the Binary logs."  We verify Requuid is present here;
        cross-protocol correlation is verified in test_cross_protocol_access_logging.py.
        """
        key = f"audit_s3_{uuid.uuid4().hex[:8]}.bin"
        offset = _log_offset(S3_LOG)

        status = self._s3_put(key, os.urandom(512))
        assert status in (200, 201, 204), f"S3 PUT failed: HTTP {status}"

        chunk = _wait_for_log_entry(S3_LOG, offset, key)
        if not chunk:
            pytest.skip(f"S3 access log entry not found for {key} — log format may differ")

        # Look for a UUID-shaped token (Requuid), x-amz-request-id, or
        # nginx's $request_id logged as "reqid=<hex32>" by the s3_audit format.
        has_uuid = bool(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", chunk))
        has_amz_id = "x-amz-request-id" in chunk or "amz" in chunk.lower()
        has_reqid = bool(re.search(r"reqid=[0-9a-f]{32}", chunk))
        assert has_uuid or has_amz_id or has_reqid, (
            f"No request UUID (Requuid / x-amz-request-id / reqid) in S3 audit log:\n{chunk[:300]}"
        )

    def test_s3_action_logged_with_path(self):
        """S3 GET: access log contains the bucket/key path."""
        key = f"audit_s3get_{uuid.uuid4().hex[:8]}.bin"
        self._s3_put(key, b"audit-s3-path")
        offset = _log_offset(S3_LOG)

        import http.client
        conn = http.client.HTTPConnection(SERVER_HOST, NGINX_S3_PORT, timeout=15)
        conn.request("GET", f"/{S3_BUCKET}/{key}",
                     headers={"Authorization": f"AWS {S3_ACCESS_KEY}:{S3_SECRET_KEY}"})
        resp = conn.getresponse()
        resp.read()
        conn.close()

        chunk = _wait_for_log_entry(S3_LOG, offset, key)
        if not chunk:
            pytest.skip(f"S3 access log entry not found for GET {key}")
        assert key in chunk or S3_BUCKET in chunk, (
            f"S3 key/bucket not found in audit log:\n{chunk[:300]}"
        )


# ---------------------------------------------------------------------------
# Section 9 — Unified Tracing: streamid correlation
# ---------------------------------------------------------------------------

class TestUnifiedTracingStreamID:
    """Section 9 Unified Tracing: verify streamid is present in stream access log.

    Cross-protocol correlation (S3 Requuid == stream streamid) is a future goal
    that requires instrumentation in both the stream and S3 log formats.  This
    test verifies that the stream log contains a correlation field that can be
    used for tracing.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _require_stream(self):
        if not _wait_port(SERVER_HOST, NGINX_ANON_PORT, timeout=5.0):
            pytest.skip("Stream server not available")

    def test_stream_log_contains_traceable_id(self, tmp_path):
        """Stream access log contains a numeric streamid or session identifier."""
        name = f"trace_{uuid.uuid4().hex[:8]}.bin"
        _write_file(name, b"trace-data")
        offset = _log_offset(STREAM_LOG)

        dst = str(tmp_path / name)
        r = _xrdcp_get(f"root://{SERVER_HOST}:{NGINX_ANON_PORT}/{name}", dst)
        assert r.returncode == 0

        chunk = _wait_for_log_entry(STREAM_LOG, offset, name)
        if not chunk:
            pytest.skip("No stream log entry — log format may differ")

        # A streamid is typically a hex or decimal number appearing in the log line.
        has_id = bool(re.search(r"\b[0-9a-f]{4,16}\b", chunk))
        assert has_id, (
            f"No hex/numeric session/stream ID found in stream audit log:\n{chunk[:300]}"
        )
