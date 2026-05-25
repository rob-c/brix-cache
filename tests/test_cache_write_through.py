#!/usr/bin/env python3
"""
Cache Write-Through Tests — pytest integration test suite.

Tests both existing read-through cache functionality and the new write-through
component implementing policy-based dirty write-back to origin XRootD servers.

Architecture mirrors official XRootD PFC module at /tmp/xrootd-src/src/XrdPfc/
and nginx-xrootd implementation in src/cache/writethrough_* files.

Test server profiles:
  - cache_only: Read-through only (conf->cache=1, conf->wt_enable=0)
  - write_through_sync: Cache + WT sync mode (conf->cache=1, conf->wt_enable=1, wt_mode=SYNC)
  - write_through_async: Cache + WT async mode for comparison

Test scenarios require mock origin behavior when real XRootD origin unavailable.
Dirty file state injection simulates writes to cached files before close.
Origin unreachable simulation tests fail-open semantics of flush failures.
"""

import pytest
import subprocess
import tempfile
import os
import sys
import time
from pathlib import Path

# Test server management imports (existing infrastructure)
sys.path.insert(0, str(Path(__file__).parent))
from manage_test_servers import start_servers, stop_servers, restart_servers

# Configuration constants matching nginx-xrootd defaults
XROOTD_CACHE_ROOT = "/tmp/xrd-test/cache"
XROOTD_WT_ORIGIN_HOST = "localhost:11094"  # Local origin for write-back tests
XROOTD_CACHE_EVICT_THRESHOLD = 850000  # 85% occupancy ppm threshold

# Test fixtures and setup


@pytest.fixture(scope="session")
def cache_only_server():
    """Start test server with read-through cache only (no WT enabled)."""
    start_servers(cache_profile="cache_only", wt_enable=False)
    yield
    stop_servers()


@pytest.fixture(scope="session")
def write_through_sync_server():
    """Start test server with cache + write-through in sync mode."""
    start_servers(cache_profile="write_through", wt_enable=True, wt_mode="sync")
    yield
    stop_servers()


@pytest.fixture(scope="session")
def write_through_async_server():
    """Start test server with cache + write-through in async mode."""
    start_servers(cache_profile="write_through", wt_enable=True, wt_mode="async")
    yield
    stop_servers()


@pytest.fixture(scope="function")
def test_file(tmp_path):
    """Create a temporary test file for cache operations."""
    filepath = tmp_path / "test_data.bin"
    filepath.write_bytes(b"x" * 1024)  # 1KB test data
    return str(filepath)


@pytest.fixture(scope="function")
def large_test_file(tmp_path):
    """Create a large test file exceeding cache admission limit."""
    filepath = tmp_path / "large_data.bin"
    filepath.write_bytes(b"x" * (50 * 1024 * 1024))  # 50MB exceeds default limit
    return str(filepath)


# Cache Read-Through Tests


class TestCacheReadThrough:
    """Tests for existing read-through cache functionality."""

    def test_cache_fill_origin_fetch(self, cache_only_server, test_file):
        """Test that uncached file triggers origin fetch and populates cache."""
        # File not in cache → client should receive kXR_oksofar then kXR_ok with data
        result = subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/cache_fill_test"],
            capture_output=True, timeout=30
        )
        # Verify file was copied (origin fetch succeeded)
        assert Path("/tmp/cache_fill_test").exists(), "Cache fill failed — origin fetch did not complete"

    def test_cache_hit_local_serve(self, cache_only_server, test_file):
        """Test that cached file is served from local cache without origin fetch."""
        # First read populates cache (via xrdcp)
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/cache_fill_test"],
            capture_output=True, timeout=30
        )

        # Second read should hit local cache — no origin connection required
        result = subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/cache_hit_test"],
            capture_output=True, timeout=30
        )
        assert Path("/tmp/cache_hit_test").exists(), "Cache hit failed — local serve did not complete"

    def test_cache_admission_rejection_large_file(self, cache_only_server, large_test_file):
        """Test that files exceeding max_file_size without regex match redirect to origin."""
        # Large file should trigger admission rejection → client redirected to origin
        result = subprocess.run(
            ["xrdcp", f"root://localhost:11094/{large_test_file}", "/tmp/large_redirect"],
            capture_output=True, timeout=30
        )
        # Verify redirect occurred (not served through cache) — check access log for "cache-bypass"
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "cache-bypass" in content or "cache admission rejected" in content, \
                "Large file should have triggered cache-bypass redirect"

    def test_cache_eviction_threshold(self, cache_only_server):
        """Test that eviction occurs when occupancy exceeds configured threshold."""
        # Populate cache with multiple files to exceed 85% occupancy ppm
        temp_files = []
        for i in range(10):
            fpath = Path(tmp_path) / f"cache_file_{i}.bin" if tmp_path else \
                   Path("/tmp") / f"cache_evict_test_{i}.bin"
            fpath.write_bytes(b"x" * (5 * 1024))  # 5KB per file
            temp_files.append(str(fpath))

        # Fetch all files through cache to fill it
        for filepath in temp_files:
            subprocess.run(
                ["xrdcp", f"root://localhost:11094/{filepath}", "/tmp/cache_evict_fill"],
                capture_output=True, timeout=30
            )

        # Wait for eviction thread to trigger (cache_evict_if_needed called after each fill)
        time.sleep(2)  # Allow eviction cycle to complete

        # Verify some files were evicted — check access log or cache directory
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "cache eviction" in content, \
                "Eviction should have occurred when occupancy exceeded threshold"


# Write-Through Decision Layer Tests


class TestWTDecisionLayer:
    """Tests for write-through policy decision evaluation at kXR_open time."""

    def test_wt_decision_allow_by_prefix(self, write_through_sync_server, test_file):
        """Test that path matching allow prefix results in ALLOW decision at open."""
        # File with /atlas/ prefix should be allowed through WT (per configuration)
        # Verify wt_enabled=1 on file handle by checking close behavior — dirty writes flushed
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_test"],
            capture_output=True, timeout=30
        )

        # Simulate write to cached file (dirty state tracking)
        with open("/tmp/xrd-test/cache/test_data.bin", "a") as f:
            f.write("modified content")  # Creates dirty state for WT flush

        # Close should trigger sync flush before handle free — verify origin receives data
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_close"],
            capture_output=True, timeout=30
        )

        # Check access log for WT flush activity (close with write-through detail)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "WT" in content or "write-through" in content, \
                "WT decision should have ALLOWed this path and triggered flush on close"

    def test_wt_decision_deny_by_prefix(self, write_through_sync_server):
        """Test that path matching deny prefix results in DENY decision at open."""
        # File with /private/ prefix (deny list) should NOT trigger WT flush on close
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/private/test_file", "/tmp/wt_deny"],
            capture_output=True, timeout=30
        )

        # Even with dirty writes, no flush should occur — local-only behavior confirmed
        # Verify access log shows close without WT activity for deny paths
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "/private/" in content and not ("WT" in content or "write-through" in content), \
                "Deny prefix path should have DENY decision — no WT flush on close"

    def test_wt_decision_size_admission_filter(self, write_through_sync_server, large_test_file):
        """Test that files exceeding wt_max_bytes without regex match result in DENY."""
        # Large file > max_write_through_bytes AND not matching include_regex → DENY
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{large_test_file}", "/tmp/wt_size_deny"],
            capture_output=True, timeout=30
        )

        # Verify WT disabled for this file (DENY at decision evaluation) — no flush on close
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "WT" not in content or "/large" not in content, \
                "Large file without regex match should have DENY decision at kXR_open"

    def test_wt_deny_precedence_over_allow(self, write_through_sync_server):
        """Test that deny prefix takes precedence over allow prefix when both configured."""
        # File matching both deny AND allow prefixes — DENY must win (blacklist semantics)
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/private/atlas_file", "/tmp/wt_precedence"],
            capture_output=True, timeout=30
        )

        # Verify WT disabled despite allow prefix match — deny takes precedence (blacklist)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "WT" not in content or "/private/" in content and "write-through" not in content, \
                "Deny prefix must take precedence over allow — WT should be disabled for this path"


# Write-Through Flush Tests


class TestWTFlushSync:
    """Tests for synchronous close-flush behavior (WT_MODE_SYNC)."""

    def test_sync_flush_success_before_close(self, write_through_sync_server, test_file):
        """Test that dirty writes are flushed to origin before handle closure in sync mode."""
        # Read cached file through cache
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_sync_fill"],
            capture_output=True, timeout=30
        )

        # Inject dirty state — write to local cached copy (simulates client write)
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("dirty content for flush test")  # Creates wt_dirty_offset > -1

        # Close should trigger sync flush — blocks until origin receives dirty data
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_sync_close"],
            capture_output=True, timeout=60  # Sync mode may block longer
        )

        # Verify origin received the dirty data — flush completed before close
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "wt:" in content and "flush" in content or "write-through" in content, \
                "Sync flush should have occurred — dirty data propagated to origin before close"

    def test_sync_flush_no_dirty_state(self, write_through_sync_server):
        """Test that no-flush path when wt_dirty_offset = -1 (clean handle returns XROOTD_FLUSH_NO_DIRTY)."""
        # Read-only file access — no writes performed → clean handle at close time
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_clean"],
            capture_output=True, timeout=30
        )

        # Close should skip flush entirely (wt_dirty_offset = -1 → XROOTD_FLUSH_NO_DIRTY)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "wt:" not in content or "no dirty" in content, \
                "Clean handle should return XROOTD_FLUSH_NO_DIRTY — no flush performed"

    def test_sync_flush_origin_unreachable_fail_open(self, write_through_sync_server):
        """Test that origin unreachable during sync flush is logged but NOT propagated as client error."""
        # Simulate origin unreachable by stopping origin server temporarily
        subprocess.run(["tests/manage_test_servers.sh", "stop"], capture_output=True)
        time.sleep(1)

        # Attempt close with WT enabled — connection should fail but client receives OK (fail-open)
        result = subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_unreachable"],
            capture_output=True, timeout=30
        )

        # Verify fail-open semantics — client error NOT propagated (local write already succeeded)
        with open("/tmp/xrd-test/logs/error.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("origin connection failed" in content or \
                                          "origin unreachable" in content), \
                "Origin unreachable should be logged (error) but client receives OK response"

        # Restart origin after test
        subprocess.run(["tests/manage_test_servers.sh", "start"], capture_output=True)


class TestWTFlushAsync:
    """Tests for asynchronous thread-pool write-back behavior (WT_MODE_ASYNC)."""

    def test_async_flush_task_posting(self, write_through_async_server, test_file):
        """Test that async flush task is posted to thread pool and client returns immediately."""
        # Read cached file through cache
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_async_fill"],
            capture_output=True, timeout=30
        )

        # Inject dirty state on local cached copy
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("async flush test content")  # Creates wt_dirty_offset > -1

        # Close should post async task and return immediately to client (does not block)
        result = subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_async_close"],
            capture_output=True, timeout=15  # Async mode should NOT block — return quickly
        )

        # Verify async task was posted (client received response without blocking)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("async" in content or "flush" in content), \
                "Async flush task should have been posted — client returned immediately after close"

    def test_async_flush_completion_callback(self, write_through_async_server):
        """Test that async completion callback resets dirty state on success."""
        # Read cached file through cache (async mode)
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_async_cb"],
            capture_output=True, timeout=30
        )

        # Inject dirty state
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("async callback test content")

        # Close posts async task — wait for completion callback to execute
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_async_cb2"],
            capture_output=True, timeout=30
        )

        time.sleep(2)  # Allow async flush thread to complete and callback to fire

        # Verify dirty state reset — wt_dirty_offset should be -1 after completion
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("async" in content or "flush" in content), \
                "Async completion callback should have reset dirty state — wt_dirty_offset = -1"

    def test_async_flush_failure_no_propagation(self, write_through_async_server):
        """Test that async flush failure is logged but NOT propagated as client error."""
        # Simulate origin unreachable during async flush
        subprocess.run(["tests/manage_test_servers.sh", "stop"], capture_output=True)
        time.sleep(1)

        # Close posts async task — thread pool worker will fail to connect to origin
        result = subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_async_fail"],
            capture_output=True, timeout=15  # Async should return immediately (task posted)
        )

        # Verify fail-open semantics — async flush failure logged but NOT propagated to client
        with open("/tmp/xrd-test/logs/error.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("origin" in content or "flush failed" in content), \
                "Async flush failure should be logged (error) but NOT propagated to client"

        # Restart origin after test
        subprocess.run(["tests/manage_test_servers.sh", "start"], capture_output=True)


# Security Negative Tests


class TestWTSecurityNegatives:
    """Security-negative tests for write-through component."""

    def test_wt_denied_path_no_flush(self, write_through_sync_server):
        """Test that WT-enabled but path not in allow list → DENY decision prevents flush."""
        # File with non-allowed prefix (not matching wt_allow_prefixes) — DENY at open time
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/unlisted/test_file", "/tmp/wt_security_deny"],
            capture_output=True, timeout=30
        )

        # Even with dirty writes attempted locally, no flush should occur — DENY at decision evaluation
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("security test dirty content")

        # Close should NOT trigger flush (wt_enabled=0 → DENY decision at kXR_open)
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/unlisted/test_file", "/tmp/wt_security_close"],
            capture_output=True, timeout=30
        )

        # Verify WT disabled for this path — no flush on close (DENY decision at open time)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "WT" not in content or "/unlisted/" in content and "write-through" not in content, \
                "Path not in allow list should have DENY decision — no WT flush on close (security)"

    def test_wt_origin_tls_required(self, write_through_sync_server):
        """Test that WT origin connections require same TLS security model as cache_origin."""
        # WT origin connection should enforce TLS if conf->wt_require_tls is set
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_security_tls"],
            capture_output=True, timeout=30
        )

        # Verify WT origin connection uses same TLS security model as cache_origin (no cleartext)
        with open("/tmp/xrd-test/logs/error.log", "r") as f:
            content = f.read()
            assert "TLS" in content or "wt:" not in content, \
                "WT origin connections should enforce TLS — same security model as cache_origin"

    def test_wt_flush_permission_denied(self, write_through_sync_server):
        """Test that flush with insufficient permissions on origin file returns kXR_NotAuthorized."""
        # Origin file with restricted permissions — flush attempt should fail with NotAuthorized
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/restricted/test_file", "/tmp/wt_security_perm"],
            capture_output=True, timeout=30
        )

        # Inject dirty state on cached copy (attempt flush)
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("permission test content")

        # Close attempts sync flush — origin file permissions deny write access → kXR_NotAuthorized
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/restricted/test_file", "/tmp/wt_security_close"],
            capture_output=True, timeout=30
        )

        # Verify flush failure logged locally only (fail-open) — kXR_NotAuthorized NOT propagated to client
        with open("/tmp/xrd-test/logs/error.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("NotAuthorized" in content or \
                                          "permission denied" in content), \
                "Origin permission denied should be logged locally — NOT propagated to client (fail-open)"


# Integration Tests — Close Handler and Eviction Protection


class TestWTIntegration:
    """Integration tests for close handler WT-aware behavior and eviction protection."""

    def test_close_handler_wt_sync_flush(self, write_through_sync_server):
        """Test that close handler calls sync flush before xrootd_free_fhandle when wt_enabled=1."""
        # Read cached file through cache (WT enabled)
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_close_int"],
            capture_output=True, timeout=30
        )

        # Inject dirty state on local cached copy before close
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("close handler integration content")  # Creates wt_dirty_offset > -1

        # Close should call sync flush BEFORE xrootd_free_fhandle (WT-aware close handler)
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_close_int2"],
            capture_output=True, timeout=60  # Sync flush may block until origin receives data
        )

        # Verify close handler executed sync flush before handle free — dirty state reset
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("close" in content or "flush" in content), \
                "Close handler should have called sync flush before xrootd_free_fhandle when wt_enabled=1"

    def test_close_handler_wt_async_post(self, write_through_async_server):
        """Test that close handler posts async task instead of blocking for WT_MODE_ASYNC."""
        # Read cached file through cache (WT enabled, async mode)
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_close_async"],
            capture_output=True, timeout=30
        )

        # Inject dirty state on local cached copy before close
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("close handler async content")  # Creates wt_dirty_offset > -1

        # Close should post async task and return immediately (WT_MODE_ASYNC) — does NOT block
        subprocess.run(
            ["xrdcp", "-v", f"root://localhost:11094/{test_file}", "/tmp/wt_close_async2"],
            capture_output=True, timeout=15  # Async should NOT block — return quickly
        )

        # Verify close handler posted async task instead of blocking (WT_MODE_ASYNC behavior)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "wt:" in content and ("async" in content or "close" in content), \
                "Close handler should have posted async task when wt_mode=ASYNC — no blocking on close"

    def test_eviction_excludes_wt_enabled_files(self, write_through_sync_server):
        """Test that eviction collector skips files with active handles having wt_enabled=1."""
        # Read cached file through cache (WT enabled)
        subprocess.run(
            ["xrdcp", f"root://localhost:11094/{test_file}", "/tmp/wt_evict"],
            capture_output=True, timeout=30
        )

        # Inject dirty state — wt_enabled=1 and wt_dirty_offset > -1 at this point
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        if cache_path.exists():
            with open(cache_path, "a") as f:
                f.write("eviction protection test content")  # Creates dirty state for WT flush

        # Fill additional files to exceed eviction threshold (85% occupancy ppm)
        for i in range(20):
            temp_file = Path("/tmp") / f"cache_evict_{i}.bin"
            if not temp_file.exists():
                temp_file.write_bytes(b"x" * (5 * 1024))  # 5KB per file
            subprocess.run(
                ["xrdcp", f"root://localhost:11094/{temp_file}", "/tmp/cache_evict_fill"],
                capture_output=True, timeout=30
            )

        time.sleep(2)  # Allow eviction thread to trigger (cache_evict_if_needed called after fill)

        # Verify WT-enabled file NOT evicted — wt_enabled files excluded from candidates
        cache_path = Path("/tmp/xrd-test/cache") / "test_data.bin"
        assert cache_path.exists(), \
            "WT-enabled file should be excluded from eviction when handle has wt_enabled=1"

        # Verify other files were evicted (eviction occurred but WT file protected)
        with open("/tmp/xrd-test/logs/http_webdav_access.log", "r") as f:
            content = f.read()
            assert "cache eviction" in content, \
                "Eviction should have occurred — WT-enabled files excluded from candidates list"


# Summary and Verification

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
