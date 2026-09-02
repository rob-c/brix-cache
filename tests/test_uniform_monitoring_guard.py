"""The uniform-monitoring surface is wired on EVERY plane (phase-110 guard).

The $brix_* monitoring variables are meaningful only if the request/session
actually populates a brix_io_monitor_t. Registering the variables (guarded by
check_directive_registry R11) is half the contract; the other half is that each
data plane BINDS the monitor onto the VFS ctx it serves through, and that the
VFS layer FOLDS into it. Those bindings are one-line calls scattered across the
protocol handlers — nothing structural stops a refactor from dropping the S3
one and silently making every S3 $brix_* value "-", with no test failing
(there is no S3 fleet node with a brix log_format; the S3 data path shares its
whole fold mechanism with the WebDAV path that IS runtime-tested). This guard
pins the wiring so that cannot happen unnoticed.

  * success   — every HTTP data-plane serve/write ctx builder binds the monitor,
                and the VFS observer folds op/latency + cache into it
  * error     — the detector really requires the bind call (non-vacuous)
  * security  — the cache-status vocabulary lives in the SHARED metrics header,
                not an HTTP header, so no plane can spell it privately (rule 2)

Run:
    PYTHONPATH=tests pytest tests/test_uniform_monitoring_guard.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.xdist_group("uniform-monitoring-guard")]

SRC = Path(__file__).resolve().parent.parent / "src"


def _text(rel):
    return (SRC / rel).read_text()


def _strip(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


# Each HTTP data-plane ctx builder that serves or writes client bytes must bind
# the request's monitor, so $brix_* reports on that plane exactly as on WebDAV.
BIND_SITES = {
    "protocols/webdav/access_vfs_ctx.c": "brix_http_monitor_bind",  # GET/PUT/COPY
    "protocols/s3/object.c": "brix_http_monitor_bind",              # S3 GET
    "protocols/s3/util.c": "brix_http_monitor_bind",                # S3 PUT/multipart
}


def test_every_http_data_plane_binds_the_monitor():
    """(success) WebDAV and S3 both bind the per-request monitor — so S3 $brix_*
    is populated by the same mechanism the WebDAV runtime tests exercise."""
    for rel, call in BIND_SITES.items():
        assert call + "(r, vctx)" in _strip(_text(rel)) \
            or call + "(r, vctx);" in _strip(_text(rel)), (
            f"{rel} no longer binds the I/O monitor — its plane's $brix_* "
            "values would silently go to '-'")


def test_root_plane_binds_the_session_monitor():
    """(success) The root:// plane points every VFS ctx at the session monitor
    through its one per-session hook (all 14 ctx-build sites route here)."""
    text = _strip(_text("protocols/root/path/op_path.c"))
    assert "vctx->io_monitor = &ctx->io_monitor" in text, (
        "brix_root_vfs_bind_session no longer binds the session monitor — the "
        "stream $brix_* surface would go dark")


def test_observer_folds_op_latency_and_cache():
    """(success) The VFS layer folds into the monitor: the post-op observer
    records op/latency, and the cache decision records HIT/MISS."""
    obs = _strip(_text("fs/vfs/vfs_internal.h"))
    assert "brix_io_monitor_record_op(ctx->io_monitor" in obs, "op fold gone"
    assert "brix_io_monitor_add_latency(ctx->io_monitor" in obs, "latency fold gone"
    cache = _strip(_text("fs/vfs/vfs_open.c"))
    assert "brix_io_monitor_record_cache" in cache, "cache fold gone"


def test_cache_vocabulary_is_in_the_shared_header_not_http():
    """(security-neg / rule 2) The cache-status enum and name function live in
    the SHARED metrics header, so the variable, the JSON key and the metric
    label all render the SAME word — no plane can spell the vocabulary
    privately. An HTTP header owning it would let a plane drift."""
    unified = _text("observability/metrics/unified.h")
    assert "brix_cache_status_e" in unified, "cache enum not in unified.h"
    assert "brix_metric_cache_status_name" in unified, "name fn not in unified.h"
    # And the HTTP variables header must NOT redefine the enum (it was moved).
    hv = _text("core/http/http_variables.h")
    assert "BRIX_CACHE_STATUS_HIT" not in hv, (
        "http_variables.h redefines the cache vocabulary — it must include "
        "unified.h, not own the enum")


def test_bind_detector_is_not_vacuous():
    """(error) The bind check really requires the call, not just the file."""
    fake = "webdav_vfs_ctx_build_data(r, conf, path, vctx);"  # no bind call
    assert "brix_http_monitor_bind(r, vctx)" not in fake
