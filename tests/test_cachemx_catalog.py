"""Full metric-catalogue conformance: every exported family's TYPE pinned.

WHAT: One /metrics scrape of the matrix instance, then a per-family
      parametrized pin of the complete compile-time catalogue (family name ->
      Prometheus type) plus structural exposition rules: HELP presence, no
      duplicate TYPE lines, histogram sample shape, and the suffix
      conventions (with the one calibrated `_total`-gauge exception).

WHY:  The exposition catalogue is compile-time — all families render
      HELP/TYPE regardless of configuration — so a single instance pins the
      whole board.  A silent type flip (counter -> gauge), a renamed family,
      or a family added without registration breaks recording rules and
      dashboards downstream; a per-family pin names the exact family in the
      failing test id.
"""

import pytest

import _cachemx as cx
from _cachemx import mx  # noqa: F401

def _check_test_total_suffix_families_are_counters_1(offenders):
    assert offenders == set()

def _check_test_total_suffix_families_are_counters_2(types, f):
    assert types[f] == ["gauge"]


pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cachemx")]

# The complete catalogue, calibrated live (215 families).  A drift in either
# direction fails test_catalogue_complete_no_drift with the offending names.
CATALOG = {
    "brix_acc_dns_breaker_open_total": "counter",
    "brix_acc_nss_breaker_open_total": "counter",
    "brix_auth_l1_hits_total": "counter",
    "brix_auth_l1_misses_total": "counter",
    "brix_auth_total": "counter",
    "brix_budget_waits_total": "counter",
    "brix_bytes_root_rx_total": "counter",
    "brix_bytes_root_tx_total": "counter",
    "brix_bytes_rx_ipv4_total": "counter",
    "brix_bytes_rx_ipv6_total": "counter",
    "brix_bytes_rx_total": "counter",
    "brix_bytes_tx_ipv4_total": "counter",
    "brix_bytes_tx_ipv6_total": "counter",
    "brix_bytes_tx_total": "counter",
    "brix_cache_bytes": "gauge",
    "brix_cache_bytes_evicted_total": "counter",
    "brix_cache_dirty_reaped_total": "counter",
    "brix_cache_evicted_bytes_total": "counter",
    "brix_cache_eviction_errors_total": "counter",
    "brix_cache_eviction_threshold_ratio": "gauge",
    "brix_cache_evictions_total": "counter",
    "brix_cache_hits_total": "counter",
    "brix_cache_misses_total": "counter",
    "brix_cache_requests_total": "counter",
    "brix_cache_occupancy_ratio": "gauge",
    "brix_cache_prefetch_blocks_total": "counter",
    "brix_cache_prefetch_failures_total": "counter",
    "brix_cache_prefetch_jobs_total": "counter",
    "brix_cache_usage_ratio": "gauge",
    "brix_cache_watermark_evicted_bytes_total": "counter",
    "brix_cache_watermark_evicted_files_total": "counter",
    "brix_cache_watermark_purges_total": "counter",
    "brix_cluster_servers_registered": "gauge",
    "brix_cms_cap_rejections_total": "counter",
    "brix_cms_frame_yields_total": "counter",
    "brix_cms_idle_closes_total": "counter",
    "brix_cms_login_timeouts_total": "counter",
    "brix_cms_logins_total": "counter",
    "brix_cms_connect_failures_total": "counter",
    "brix_cms_registered_links": "gauge",
    "brix_cms_read_timeouts_total": "counter",
    "brix_config_generation": "gauge",
    "brix_connections_active": "gauge",
    "brix_connections_total": "counter",
    "brix_cred_deleg_fail_total": "counter",
    "brix_cred_deleg_total": "counter",
    "brix_cred_select_deny_total": "counter",
    "brix_cred_select_fallback_total": "counter",
    "brix_cred_select_user_total": "counter",
    "brix_csi_scrub_mismatch_total": "counter",
    "brix_cvmfs_bytes_served_total": "counter",
    "brix_cvmfs_fill_failures_total": "counter",
    "brix_cvmfs_fills_total": "counter",
    "brix_cvmfs_negative_hits_total": "counter",
    "brix_cvmfs_origin_bytes_total": "counter",
    "brix_cvmfs_origin_failovers_total": "counter",
    "brix_cvmfs_repo_bytes_served_total": "counter",
    "brix_cvmfs_repo_cache_hits_total": "counter",
    "brix_cvmfs_repo_cache_misses_total": "counter",
    "brix_cvmfs_repo_files_accessed_total": "counter",
    "brix_cvmfs_repo_fill_failures_total": "counter",
    "brix_cvmfs_repo_fills_total": "counter",
    "brix_cvmfs_repo_negative_hits_total": "counter",
    "brix_cvmfs_repo_origin_bytes_total": "counter",
    "brix_cvmfs_repo_requests_total": "counter",
    "brix_cvmfs_repo_verify_failures_total": "counter",
    "brix_cvmfs_requests_total": "counter",
    "brix_cvmfs_upstream_failovers_total": "counter",
    "brix_cvmfs_upstream_fill_duration_seconds": "histogram",
    "brix_cvmfs_upstream_fill_failures_total": "counter",
    "brix_cvmfs_upstream_fills_total": "counter",
    "brix_cvmfs_upstream_origin_bytes_total": "counter",
    "brix_cvmfs_upstream_requests_total": "counter",
    "brix_cvmfs_verify_failures_total": "counter",
    "brix_frm_asynresp_total": "counter",
    "brix_frm_cmsd_have_total": "counter",
    "brix_frm_dedup_hits_total": "counter",
    "brix_frm_evict_total": "counter",
    "brix_frm_in_flight": "gauge",
    "brix_frm_migrate_total": "counter",
    "brix_frm_purge_total": "counter",
    "brix_frm_reject_inflight_total": "counter",
    "brix_frm_requests_total": "counter",
    "brix_frm_stage_fail_total": "counter",
    "brix_frm_stage_latency_seconds": "histogram",
    "brix_frm_stage_success_total": "counter",
    "brix_frm_waitresp_total": "counter",
    "brix_io_bytes_read": "counter",
    "brix_io_bytes_written": "counter",
    "brix_io_latency_seconds": "histogram",
    "brix_io_latency_usec": "histogram",
    "brix_io_offload_total": "counter",
    "brix_io_ops_total": "counter",
    "brix_io_slowop_threshold_usec": "gauge",
    "brix_io_slowop_total": "counter",
    "brix_mirror_divergence_total": "counter",
    "brix_mirror_dropped_total": "counter",
    "brix_mirror_errors_total": "counter",
    "brix_mirror_requests_total": "counter",
    "brix_oci_delegate_total": "counter",
    "brix_oci_fill_bytes_total": "counter",
    "brix_oci_requests_total": "counter",
    "brix_oci_token_fetch_total": "counter",
    "brix_oci_upstream_errors_total": "counter",
    "brix_oci_verify_fail_total": "counter",
    "brix_ocsp_timeouts_total": "counter",
    "brix_path_depth_violations_total": "counter",
    "brix_pmark_firefly_dropped_total": "counter",
    "brix_pmark_firefly_sent_total": "counter",
    "brix_pmark_flowlabel_failed_total": "counter",
    "brix_pmark_flowlabel_set_total": "counter",
    "brix_pmark_flows_ended_total": "counter",
    "brix_pmark_flows_started_total": "counter",
    "brix_pmark_map_unresolved_total": "counter",
    "brix_proxy_abandoned_handles_total": "counter",
    "brix_proxy_closes_total": "counter",
    "brix_proxy_open_errors_total": "counter",
    "brix_proxy_opens_total": "counter",
    "brix_proxy_path_op_errors_total": "counter",
    "brix_proxy_path_ops_total": "counter",
    "brix_proxy_read_bytes_total": "counter",
    "brix_proxy_reads_total": "counter",
    "brix_proxy_reconnects_total": "counter",
    "brix_proxy_upstream_auth_errors_total": "counter",
    "brix_proxy_upstream_connect_errors_total": "counter",
    "brix_proxy_upstream_connects_total": "counter",
    "brix_proxy_wait_responses_total": "counter",
    "brix_proxy_write_bytes_total": "counter",
    "brix_proxy_writes_total": "counter",
    "brix_rate_limit_eviction_total": "counter",
    "brix_rate_limit_throttled_total": "counter",
    "brix_rate_limit_zone_full_errors_total": "counter",
    "brix_registry_full_total": "counter",
    "brix_requests_total": "counter",
    "brix_rpm_prefetch_fail_total": "counter",
    "brix_rpm_prefetch_total": "counter",
    "brix_rpm_requests_total": "counter",
    "brix_rpm_verify_fail_total": "counter",
    "brix_s3_auth_total": "counter",
    "brix_s3_bytes_rx_ipv4_total": "counter",
    "brix_s3_bytes_rx_ipv6_total": "counter",
    "brix_s3_bytes_rx_total": "counter",
    "brix_s3_bytes_tx_ipv4_total": "counter",
    "brix_s3_bytes_tx_ipv6_total": "counter",
    "brix_s3_bytes_tx_total": "counter",
    "brix_s3_events_total": "counter",
    "brix_s3_list_common_prefixes_total": "counter",
    "brix_s3_list_contents_total": "counter",
    "brix_s3_list_truncated_total": "counter",
    "brix_s3_put_bodies_total": "counter",
    "brix_s3_range_requests_total": "counter",
    "brix_s3_requests_total": "counter",
    "brix_s3_responses_total": "counter",
    "brix_scvmfs_requests_total": "counter",
    "brix_session_evict_total": "counter",
    "brix_session_registry_full_total": "counter",
    "brix_session_src_cap_evict_total": "counter",
    "brix_ssi_alerts_pushed_total": "counter",
    "brix_ssi_attn_push_failures_total": "counter",
    "brix_ssi_errors_total": "counter",
    "brix_ssi_requests_total": "counter",
    "brix_storage_backend_info": "gauge",
    "brix_storage_bytes_available": "gauge",
    "brix_storage_bytes_total": "gauge",
    "brix_storage_bytes_used": "gauge",
    "brix_storage_io_bytes_read": "counter",
    "brix_storage_io_bytes_written": "counter",
    "brix_storage_occupancy_ratio": "gauge",
    "brix_stream_connections_rejected_total": "counter",
    "brix_stream_handshake_timeouts_total": "counter",
    "brix_stream_io_uring_active": "gauge",
    "brix_stream_io_uring_fallback_total": "counter",
    "brix_stream_io_uring_ops_total": "counter",
    "brix_stream_oversized_payloads_total": "counter",
    "brix_stream_read_pdu_timeouts_total": "counter",
    "brix_stream_request_frames_total": "counter",
    "brix_stream_request_payload_bytes_total": "counter",
    "brix_stream_response_frames_total": "counter",
    "brix_stream_response_write_errors_total": "counter",
    "brix_stream_response_write_stalls_total": "counter",
    "brix_stream_send_drain_timeouts_total": "counter",
    "brix_stream_tpc_egress_refused_total": "counter",
    "brix_tpc_bytes_total": "counter",
    "brix_tpc_gsi_delegated_total": "counter",
    "brix_tpc_transfers_total": "counter",
    "brix_unique_users_current": "gauge",
    "brix_unique_users_total": "counter",
    "brix_user_evictions_total": "counter",
    "brix_user_sessions_total": "gauge",
    "brix_vfs_bulk_delete_batches_total": "counter",
    "brix_vfs_bulk_delete_keys_total": "counter",
    "brix_vfs_evict_bytes_total": "counter",
    "brix_vfs_lock_refused_total": "counter",
    "brix_vfs_mutation_denied_total": "counter",
    "brix_vfs_precond_advisory_total": "counter",
    "brix_vfs_precond_failed_total": "counter",
    "brix_vfs_recall_total": "counter",
    "brix_vfs_spill_active": "gauge",
    "brix_vfs_spill_bytes_total": "counter",
    "brix_vfs_spill_refused_total": "counter",
    "brix_vo_bytes_rx_total": "counter",
    "brix_vo_bytes_tx_total": "counter",
    "brix_vo_overflow_total": "counter",
    "brix_vo_requests_total": "counter",
    "brix_webdav_auth_total": "counter",
    "brix_webdav_bytes_rx_ipv4_total": "counter",
    "brix_webdav_bytes_rx_ipv6_total": "counter",
    "brix_webdav_bytes_rx_total": "counter",
    "brix_webdav_bytes_tx_ipv4_total": "counter",
    "brix_webdav_bytes_tx_ipv6_total": "counter",
    "brix_webdav_bytes_tx_total": "counter",
    "brix_webdav_cors_total": "counter",
    "brix_webdav_propfind_depth_total": "counter",
    "brix_webdav_propfind_entries_total": "counter",
    "brix_webdav_put_bodies_total": "counter",
    "brix_webdav_range_requests_total": "counter",
    "brix_webdav_requests_total": "counter",
    "brix_webdav_responses_total": "counter",
    "brix_webdav_tpc_cred_total": "counter",
    "brix_webdav_tpc_total": "counter",
    "brix_wire_bytes_rx_total": "counter",
    "brix_wire_bytes_tx_total": "counter",
    "brix_wt_dirty_handles": "gauge",
    "brix_wt_flush_bytes_total": "counter",
    "brix_wt_flush_pending": "gauge",
    "brix_wt_flushes_total": "counter",
    "brix_wt_stage_throttled_total": "counter",
    "brix_wt_stage_usage_ratio": "gauge",
    "brix_xfer_heap_bytes": "gauge",
    "brix_xfer_heap_high_water_bytes": "gauge",
}

# The _total-suffixed gauges, calibrated live: a point-in-time session census
# and a capacity figure ("total bytes of storage"), not monotone counters.
# Any new entrant here is a naming bug.
TOTAL_SUFFIX_GAUGES = {"brix_user_sessions_total", "brix_storage_bytes_total"}

HISTOGRAMS = sorted(f for f, t in CATALOG.items() if t == "histogram")


@pytest.fixture(scope="module")
def expo(mx):
    """One parsed exposition: raw text + {family: type} from # TYPE lines."""
    text = cx.mfetch(mx.metrics)
    types = {}
    for line in text.splitlines():
        if line.startswith("# TYPE "):
            _, _, fam, typ = line.split(" ", 3)
            types.setdefault(fam, []).append(typ)
    return text, types


@pytest.mark.parametrize("family", sorted(CATALOG))
def test_family_type_pinned(expo, family):
    """The family renders exactly one # TYPE line with the pinned type."""
    _, types = expo
    assert types.get(family) == [CATALOG[family]]


def test_catalogue_complete_no_drift(expo):
    """The exported family set matches the calibrated catalogue exactly, in
    both directions — an unregistered new family and a silently dropped one
    are equally reportable."""
    _, types = expo
    assert set(types) == set(CATALOG)


def test_every_family_has_help(expo):
    """Every # TYPE'd family carries a # HELP line."""
    text, types = expo
    helped = {line.split(" ", 3)[2] for line in text.splitlines()
              if line.startswith("# HELP ")}
    assert set(types) <= helped


def test_no_duplicate_type_lines(expo):
    """No family emits its # TYPE header twice (double registration)."""
    _, types = expo
    dupes = {f: t for f, t in types.items() if len(t) != 1}
    assert dupes == {}


def test_histogram_samples_use_component_suffixes(expo):
    """Histogram families expose only _bucket/_sum/_count samples — a bare
    `family value` sample under a histogram TYPE is malformed exposition."""
    text, _ = expo
    for fam in HISTOGRAMS:
        bare = [l for l in text.splitlines()
                if l.startswith(fam + " ") or l.startswith(fam + "{")]
        assert bare == [], f"bare sample under histogram {fam}"


def test_total_suffix_families_are_counters(expo):
    """`_total` means counter, with the single calibrated gauge exception."""
    _, types = expo
    offenders = {f for f, t in types.items()
                 if f.endswith("_total") and t != ["counter"]
                 and f not in TOTAL_SUFFIX_GAUGES}
    _check_test_total_suffix_families_are_counters_1(offenders)
    for f in TOTAL_SUFFIX_GAUGES:
        _check_test_total_suffix_families_are_counters_2(types, f)


def test_ratio_families_are_gauges(expo):
    """`_ratio` families are gauges — a ratio counter is meaningless."""
    _, types = expo
    offenders = {f for f, t in types.items()
                 if f.endswith("_ratio") and t != ["gauge"]}
    assert offenders == set()
