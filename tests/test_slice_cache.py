"""
tests/test_slice_cache.py — Phase 26 slice-granular caching tests.

Two layers:

  * TestSliceLibrary — compiles and runs the standalone C unit tests for the
    shared slice library (src/cache/slice.c) against the real build objects.
    This is the LANDED foundation (Phase 26 Step A) and runs with no server.

  * TestSliceCacheIntegration — end-to-end coverage of slice serving over the
    WebDAV and stream planes.  These are SKIPPED until the read-time slice
    serving path (Steps C/D) is wired into the cache open/VFS layer; the doc's
    original C/D design predates the current open-time/whole-file/VFS cache
    architecture and needs a redesign + a healthy origin+cache test env to
    validate.  The cases are kept here as the executable spec for that work.
"""

import os
import subprocess
import textwrap

import pytest

_HERE = os.path.dirname(__file__)
_RUNNER = os.path.join(_HERE, "c", "run_slice_tests.sh")
_OBJS = os.environ.get("TEST_NGINX_OBJS", "/tmp/nginx-1.28.3/objs")
_NGINX = os.environ.get("TEST_NGINX_BIN", os.path.join(_OBJS, "nginx"))


class TestSliceLibrary:
    """Step A — the shared slice enumeration/path/meta/evict library."""

    def test_slice_library_unit_tests_pass(self):
        slice_o = os.path.join(_OBJS, "addon", "cache", "slice.o")
        if not os.path.exists(slice_o):
            pytest.skip(f"slice.o not built under {_OBJS}; build the module first")

        proc = subprocess.run(
            [_RUNNER, _OBJS],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        out = proc.stdout.decode(errors="replace")
        # Surface the C harness output on failure for debugging.
        assert proc.returncode == 0, f"slice unit tests failed:\n{out}"
        assert ", 0 failed" in out, f"unexpected slice unit test output:\n{out}"


class TestSliceConfig:
    """Step F — the xrootd_cache_slice directive parses and validates."""

    def _nginx_t(self, tmp_path, slice_value):
        cache = tmp_path / "cache"
        cache.mkdir()
        (tmp_path / "logs").mkdir()
        conf = tmp_path / "nginx.conf"
        conf.write_text(textwrap.dedent(f"""\
            error_log {tmp_path}/logs/error.log;
            pid {tmp_path}/logs/nginx.pid;
            events {{}}
            thread_pool default threads=2 max_queue=128;
            stream {{
                server {{
                    listen 21794;
                    xrootd on;
                    xrootd_root {tmp_path};
                    xrootd_auth none;
                    xrootd_cache on;
                    xrootd_cache_root {cache};
                    xrootd_cache_origin 127.0.0.1:1095;
                    xrootd_cache_slice {slice_value};
                }}
            }}
            """))
        return subprocess.run(
            [_NGINX, "-t", "-p", str(tmp_path), "-c", "nginx.conf"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        )

    def test_valid_slice_size_accepted(self, tmp_path):
        if not os.path.exists(_NGINX):
            pytest.skip(f"nginx binary not built at {_NGINX}")
        proc = self._nginx_t(tmp_path, "128m")
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode == 0, f"valid 128m slice rejected:\n{out}"
        assert "successful" in out

    def test_non_multiple_slice_size_rejected(self, tmp_path):
        if not os.path.exists(_NGINX):
            pytest.skip(f"nginx binary not built at {_NGINX}")
        proc = self._nginx_t(tmp_path, "100k")
        out = proc.stdout.decode(errors="replace")
        assert proc.returncode != 0, "non-multiple-of-1m slice must be rejected"
        assert "multiple of 1m" in out


# ---------------------------------------------------------------------------
# Integration coverage — executable spec.  The stream slice path (open + read)
# is implemented (slice_read.c); these end-to-end cases need a live XRootD
# origin + cache, which the current OOM-constrained test host cannot sustain,
# so they remain skipped until a healthy env is available.
# ---------------------------------------------------------------------------

_PENDING = "needs a live XRootD origin + cache env (stream slice serving)"


@pytest.mark.skip(reason=_PENDING)
class TestSliceCacheIntegration:

    # --- WebDAV plane ---

    def test_slice_cache_hit(self):
        """Seed slice 0; GET bytes 0-50MiB -> 206 served from cache, no origin call."""

    def test_slice_cache_miss_then_fill(self):
        """Cold cache; GET bytes 0-50MiB on 128MiB slice -> fill triggered, body correct."""

    def test_slice_cache_prefetch(self):
        """GET slice 0 -> slice 1 fill scheduled (a .__xrds_*_1 file appears)."""

    def test_slice_etag_mismatch_invalidates(self):
        """Cache slice 0; change file at origin (new etag); GET -> old slices evicted, fresh data."""

    def test_slice_range_spanning_two_slices(self):
        """GET Range bytes=100m-300m on 128MiB slices -> data stitched correctly."""

    # --- Stream plane ---

    def test_kxr_read_slice_cache_hit(self):
        """Open file; kXR_read in a cached slice -> pread from cache, no kXR_wait."""

    def test_kxr_read_slice_cache_miss_wait(self):
        """Cold cache; kXR_read -> kXR_wait with seconds > 0."""

    def test_kxr_read_resumes_after_fill(self):
        """Cold cache; kXR_read -> kXR_wait; after fill, retry returns correct data."""

    # --- Eviction + security ---

    def test_evict_removes_whole_slice_set(self):
        """Cache several slices; trigger eviction -> all .__xrds_* files removed as a unit."""

    def test_slice_path_cannot_escape_cache_root(self):
        """Path traversal in the slice path stays confined to cache_root."""
