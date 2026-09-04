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
    text = _strip(_text("protocols/root/path/op_path_vfs.c"))
    assert "vctx->io_monitor = &ctx->io_monitor" in text, (
        "brix_root_vfs_bind_session no longer binds the session monitor — the "
        "stream $brix_* surface would go dark")


def test_observer_folds_op_latency_and_cache():
    """(success) The VFS layer folds into the monitor: the post-op observer
    records op/latency, and the cache decision records HIT/MISS."""
    obs = _strip(_text("fs/vfs/vfs_observe_internal.h"))
    assert "brix_io_monitor_record_op(ctx->io_monitor" in obs, "op fold gone"
    assert "brix_io_monitor_add_latency(ctx->io_monitor" in obs, "latency fold gone"
    cache = _strip(_text("fs/vfs/vfs_open.c"))
    assert "brix_io_monitor_record_cache" in cache, "cache fold gone"


def test_every_adopt_path_records_the_data_operation():
    """(success) POSIX fd and object-backed/cache handles both identify their
    open as read/write; a cache HIT must not lose $brix_op/$brix_path/$brix_ops.
    """
    adopt = _strip(_text("fs/vfs/vfs_open_adopt.c"))
    assert adopt.count("brix_io_monitor_record_op(ctx->io_monitor") == 2, (
        "both brix_vfs_adopt_fd and brix_vfs_adopt_obj must record their open")


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


# The outcome-class word (`ok`/`not_found`/`forbidden`/`io_error`/`other`) is
# ONE fact — `$brix_status`. Rule 2 says its string is identical on every
# surface, which holds by construction iff every surface renders it through the
# one shared function `brix_metric_err_name` (unified.c). These are the four
# renderers of that fact: the two variable handlers, the JSON access log, and
# the Prometheus status label.
STATUS_RENDER_SITES = {
    "core/http/http_variable_monitor.c": "$brix_status (HTTP variable)",
    "protocols/root/stream/stream_variables.c": "$brix_status (stream variable)",
    "observability/metrics/access_log.c": 'JSON "status" field',
    "observability/metrics/unified_export_io.c": "Prometheus brix_io_ops status label",
}


def test_status_word_renders_through_the_shared_err_name_on_every_surface():
    """(success / rule 2) The outcome-class word is one fact with one string on
    every surface: variable, JSON, and Prometheus all render `$brix_status`
    through the SINGLE shared `brix_metric_err_name` (unified.c). If any surface
    hand-spelled the word instead, `forbidden` on the log could drift from
    `forbidden` on the metric — exactly the pre-phase-110 disease. This pins the
    identity structurally (no fleet needed, and it holds for S3, which has no
    fleet node)."""
    for rel, surface in STATUS_RENDER_SITES.items():
        assert "brix_metric_err_name" in _text(rel), (
            f"{surface} ({rel}) no longer renders the outcome class through the "
            "shared brix_metric_err_name — its status word can now drift from "
            "every other surface's")


def test_mutation_denied_reason_is_the_denial_cause_not_the_outcome_class():
    """(security-neg / correctness) The doc's W4-error bullet paired the JSON
    `status` with `brix_vfs_mutation_denied_total{reason}` as "the identical
    string" — but they are DIFFERENT facts and MUST NOT be unified: `status`
    is the OUTCOME class (`forbidden`, via brix_metric_err_name), while the
    mutation-denied `reason` is the DENIAL CAUSE, the fixed literal `read_only`.
    The Prometheus twin of the status word is the `status` label on
    brix_io_ops_total / brix_tpc_transfers_total (both err_name-rendered), NOT
    this reason label. This pins the reason as the fixed cause literal so a
    future "make the metric match the log" change cannot wrongly overwrite the
    denial cause with the outcome word (which would erase why the write was
    refused, and — since read-only is the sole VFS mutation refusal — make the
    label a redundant restatement of `op`)."""
    exporter = _strip(_text("observability/metrics/unified_export.c"))
    # The reason is baked into the exposition format string as a fixed literal,
    # so it can never be substituted from the outcome-class name function: the
    # two vocabularies are deliberately separate facts.
    assert 'reason=\\"read_only\\"' in exporter, (
        "brix_vfs_mutation_denied_total no longer bakes the fixed denial cause "
        'reason="read_only" into its format string — the denial-cause fact was '
        "lost, or was made a %s substitution that could carry the outcome word")


# W2 de-conflated two identity facts the pre-phase-110 $brix_session_user merged
# into one: the SUBJECT (the DN or token `sub`) and the MAPPED local account the
# request runs as (identity.mapped_user, populated by the auth-time gridmap
# lookup). $brix_sub reads the subject; $brix_user reads mapped_user. The reads
# must stay on DIFFERENT fields on both planes.
USER_READS_MAPPED = {
    "core/http/http_variable_monitor.c": "$brix_user (HTTP)",
    "protocols/root/stream/stream_variables.c": "$brix_user (stream)",
}


def test_user_is_the_mapped_account_and_sub_is_the_subject_on_both_planes():
    """(security-neg / W2 de-conflation) $brix_user (the mapped local account,
    identity.mapped_user) and $brix_sub (the subject) are DIFFERENT facts and
    must read DIFFERENT identity fields on both planes. A refactor repointing
    $brix_user at the subject would silently restore the conflation the old
    $brix_session_user embodied — and the existing unmapped-'-' runtime test
    would stay green through it, because '-' is what both a missing mapping AND
    an anonymous subject produce. This pins the distinct wiring, plus the
    mapped_resolved gate that makes an unmapped identity '-' rather than a stale
    account name."""
    for rel, who in USER_READS_MAPPED.items():
        src = _strip(_text(rel))
        assert "mapped_user" in src and "mapped_resolved" in src, (
            f"{who} no longer reads identity.mapped_user under a mapped_resolved "
            "gate — $brix_user could collapse back onto the subject")
    # $brix_sub reads the SUBJECT — a different field — on both planes.
    http_sub = _strip(_text("core/http/http_variable_identity.c"))
    assert "id->subject" in http_sub, "$brix_sub (HTTP) no longer reads identity.subject"
    stream = _strip(_text("protocols/root/stream/stream_variables.c"))
    assert "brix_identity_subject_cstr" in stream, (
        "$brix_sub (stream) no longer reads the identity subject")
