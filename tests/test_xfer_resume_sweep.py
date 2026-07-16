"""Phase 6 housekeeping — TTL sweep of abandoned upload-resume partials.

The worker-0 sweeper removes `*.xrdresume.part` files in the configured stage dir
once they are older than $BRIX_UPLOAD_RESUME_TTL, while preserving fresh ones
(an in-progress / recently-interrupted upload must never be disturbed) and
ignoring non-resume files.

Throwaway nginx comes from the registry lifecycle harness.
"""
import os
import time

import pytest

from settings import NGINX_BIN, BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness


@pytest.fixture
def sweep_server(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")

    stage = tmp_path / "stage"; stage.mkdir()

    # An abandoned partial (old mtime) → must be swept.
    old = stage / "deadbeef.xrdresume.part"
    old.write_bytes(b"abandoned")
    past = time.time() - 3600
    os.utime(old, (past, past))
    # A fresh partial (now) → must survive (TTL=600).
    fresh = stage / "cafef00d.xrdresume.part"
    fresh.write_bytes(b"in-progress")
    # A non-resume file (old) → must be ignored.
    keep = stage / "keepme.txt"
    keep.write_bytes(b"not a partial")
    os.utime(keep, (past, past))

    lifecycle.start(NginxInstanceSpec(
        name="lc-resume-sweep",
        template="nginx_xfer_resume_sweep.conf",
        template_values={"BIND_HOST": BIND_HOST, "STAGE_DIR": str(stage)},
        env={"BRIX_UPLOAD_RESUME_TTL": "600"},
        reason="upload-resume partial TTL sweep coverage"))

    class S:
        pass
    s = S()
    s.old, s.fresh, s.keep = str(old), str(fresh), str(keep)
    return s


def test_ttl_sweep_removes_only_stale_partials(sweep_server):
    # Sweep fires ~5s after worker start; poll for the abandoned partial to go.
    deadline = time.time() + 15
    while time.time() < deadline and os.path.exists(sweep_server.old):
        time.sleep(0.3)

    assert not os.path.exists(sweep_server.old), \
        "abandoned (old) resume partial was not swept"
    assert os.path.exists(sweep_server.fresh), \
        "fresh resume partial (age < TTL) must be preserved"
    assert os.path.exists(sweep_server.keep), \
        "non-resume file must never be swept"
