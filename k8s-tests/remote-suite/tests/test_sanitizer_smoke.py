# brix-remote-skip
# tests/test_sanitizer_smoke.py
"""Sanitizer smoke lane: drive a minimal read round-trip through a SANITIZE=1
fleet then assert no ASan/UBSan report files were emitted during the transfer.

Skip unless BRIX_SANITIZER_LANE=1 (set by the CI lane after the sanitizer
build, not by the default test run).

Lane workflow (run by CI, not inside this test):

    # 1. Build the module and client with ASan+UBSan
    tests/build_sanitizer.sh

    # 2. Start the fleet under ASan instrumentation (ASAN_OPTIONS log_path set
    #    by manage_test_servers.sh when SANITIZE=1)
    SANITIZE=1 tests/manage_test_servers.sh restart

    # 3. Run this test — conftest.py attaches to the running fleet without
    #    restarting it (_external_fleet_attached() returns True)
    BRIX_SANITIZER_LANE=1 \\
        SANITIZE_LOG_DIR=/tmp/xrd-test/sanitize \\
        pytest tests/test_sanitizer_smoke.py -v

    # 4. Stop the fleet; LSan fires at process exit and writes asan.<pid> files
    SANITIZE=1 tests/manage_test_servers.sh stop
    ls "${SANITIZE_LOG_DIR:-/tmp/xrd-test/sanitize}/asan.*"

ASan heap-error and UBSan reports are written immediately when detected (not only
at exit), so this test catches open/read path errors during the live transfer.
LSan leak reports fire at step 4 and are checked by the lane script after stop.
"""

import glob
import hashlib
import os
import pathlib
import shutil
import subprocess

import pytest

from settings import DATA_ROOT, HOST, NGINX_ANON_PORT, XRDCP_BIN

pytestmark = pytest.mark.skipif(
    os.environ.get("BRIX_SANITIZER_LANE") != "1",
    reason="sanitizer lane only — set BRIX_SANITIZER_LANE=1",
)

# Must match the log_path written by manage_test_servers.sh when SANITIZE=1.
# manage_test_servers.sh: log_path=${SANITIZE_LOG_DIR}/asan  → files are asan.<pid>
SANITIZE_LOG_DIR = os.environ.get("SANITIZE_LOG_DIR", "/tmp/xrd-test/sanitize")

_ANON_BASE = f"root://{HOST}:{NGINX_ANON_PORT}"


def test_no_sanitizer_reports_after_basic_io(tmp_path):
    """Write a small payload to the server's export root, xrdcp-download it
    through the running SANITIZE=1 fleet via kXR_open + kXR_read, verify
    byte-exact content, then assert that no ASan/UBSan report files were
    emitted during the transfer.

    The file is placed directly on the server's POSIX export root (DATA_ROOT)
    so no authenticated write-open is needed; any xrdcp binary on PATH suffices
    for the download leg.  A unique per-PID name avoids collisions with
    parallel sessions.
    """
    xrdcp = shutil.which(XRDCP_BIN)
    if xrdcp is None:
        pytest.skip(
            f"xrdcp not found on PATH (XRDCP_BIN={XRDCP_BIN!r}); "
            "install xrootd-client or build client/ first"
        )

    # Place a uniquely named file in the server's export root so xrdcp can
    # pull it without needing write authentication.
    fname = f"sanitizer_smoke_{os.getpid()}.bin"
    src_path = pathlib.Path(DATA_ROOT) / fname
    payload = b"xrootd-sanitizer-smoke\n" + os.urandom(64)
    src_path.write_bytes(payload)

    try:
        # Remove reports that pre-date this test (e.g. written during fleet
        # startup) so the final assertion catches only errors triggered by our
        # transfer, not earlier noise.
        for stale in glob.glob(os.path.join(SANITIZE_LOG_DIR, "asan.*")):
            os.remove(stale)

        # Drive bytes through the sanitized nginx module on the root:// path.
        # This exercises: TCP accept → XRootD handshake → login → kXR_open →
        # kXR_read → kXR_close on the ASan-instrumented server.
        out = tmp_path / "got.bin"
        url = f"{_ANON_BASE}//{fname}"
        result = subprocess.run(
            [xrdcp, "-f", url, str(out)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"xrdcp exited {result.returncode} — transfer failed\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        # Verify byte identity; confirms real data traversed the module, not
        # just that the handshake succeeded and xrdcp returned 0.
        expected_md5 = hashlib.md5(payload).hexdigest()
        got_md5 = hashlib.md5(out.read_bytes()).hexdigest()
        assert expected_md5 == got_md5, (
            f"content mismatch after transfer — "
            f"expected md5={expected_md5}, got {got_md5}"
        )

        # The primary CI assertion: no asan.<pid> report files were written
        # during the transfer.  A file here means the instrumented server hit a
        # heap error or undefined behaviour on the open/read path.
        reports = sorted(glob.glob(os.path.join(SANITIZE_LOG_DIR, "asan.*")))
        assert not reports, (
            "ASan/UBSan reports written during basic I/O — "
            "the sanitized server detected memory or undefined-behaviour errors:\n"
            + "\n".join(
                f"  {p}:\n{pathlib.Path(p).read_text(errors='replace')[:1000]}"
                for p in reports
            )
        )
    finally:
        src_path.unlink(missing_ok=True)
