"""Calibrated catalogue snapshot: HELP text per family.

Generated from a live matrix-stack scrape (scratchpad/gen_catalog_data.py);
regenerate the same way after intentionally changing exporter text.
"""

HELP = {
    'brix_acc_dns_breaker_open_total':
        'Times the XrdAcc reverse-DNS circuit breaker tripped open.',
    'brix_acc_nss_breaker_open_total':
        'Times the XrdAcc NSS group-lookup circuit breaker tripped open.',
    'brix_auth_l1_hits_total':
        'Auth-gate verdicts served from the per-worker L1 cache (no SHM lock).',
    'brix_auth_l1_misses_total':
        'Auth-gate L1 misses that fell through to the SHM L2 or full evaluation.',
    'brix_auth_total':
        'Authentication attempts by protocol, method, and status.',
    'brix_budget_waits_total':
        'Reads deferred with kXR_wait because they would exceed brix_memory_budget.',
    'brix_bytes_root_rx_total':
        'Bytes received from clients via the native XRootD root:// protocol.',
    'brix_bytes_root_tx_total':
        'Bytes sent to clients via the native XRootD root:// protocol.',
    'brix_bytes_rx_ipv4_total':
        'Bytes received from IPv4 clients (stream layer).',
    'brix_bytes_rx_ipv6_total':
        'Bytes received from IPv6 clients (stream layer).',
    'brix_bytes_rx_total':
        'Bytes received from clients (write payloads).',
    'brix_bytes_tx_ipv4_total':
        'Bytes sent to IPv4 clients (stream layer).',
    'brix_bytes_tx_ipv6_total':
        'Bytes sent to IPv6 clients (stream layer).',
    'brix_bytes_tx_total':
        'Bytes sent to clients (read data).',
    'brix_cache_bytes':
        'Cache filesystem bytes by state.',
    'brix_cache_bytes_evicted_total':
        'Cache bytes evicted, by protocol.',
    'brix_cache_dirty_reaped_total':
        'Cache files reaped by the stale-dirty reaper, by reason (abandoned/incomplete = write-back discarded; completed = finished staging reclaimed).',
    'brix_cache_evicted_bytes_total':
        'Bytes reclaimed by cache eviction.',
    'brix_cache_eviction_errors_total':
        'Cache eviction maintenance errors.',
    'brix_cache_eviction_threshold_ratio':
        'Configured cache eviction high-water occupancy ratio.',
    'brix_cache_evictions_total':
        'Files evicted from brix_cache_export.',
    'brix_cache_hits_total':
        'Cache hits by protocol.',
    'brix_cache_misses_total':
        'Cache misses by protocol.',
    'brix_cache_occupancy_ratio':
        'Filesystem occupancy ratio for brix_cache_export.',
    'brix_cache_prefetch_blocks_total':
        'Cache blocks filled by background prefetch.',
    'brix_cache_prefetch_failures_total':
        'Background cache prefetch jobs that failed.',
    'brix_cache_prefetch_jobs_total':
        'Background cache prefetch jobs posted.',
    'brix_cache_usage_ratio':
        'Cache filesystem occupancy (0-1).',
    'brix_cache_watermark_evicted_bytes_total':
        'Bytes reaped by the watermark reaper.',
    'brix_cache_watermark_evicted_files_total':
        'Files reaped by the watermark reaper.',
    'brix_cache_watermark_purges_total':
        'Watermark reaper purge runs that reclaimed space.',
    'brix_cluster_servers_registered':
        'Number of data servers currently in the cluster registry.',
    'brix_cms_cap_rejections_total':
        'CMS server connections refused by the global or per-IP admission cap.',
    'brix_cms_frame_yields_total':
        'CMS read loops that yielded the worker after the per-wakeup frame cap.',
    'brix_cms_idle_closes_total':
        'CMS server connections reaped by the post-login idle watchdog.',
    'brix_cms_login_timeouts_total':
        'CMS server connections closed for not completing LOGIN before the deadline.',
    'brix_cms_logins_total':
        'CMS LOGIN frames this node sent to its upstream manager (federation joins).',
    'brix_cms_connect_failures_total':
        'Upward CMS dials that never became a logged-in link (refused/unreachable/deadline).',
    'brix_cms_registered_links':
        'Upward CMS links currently logged in (0 = this node is OUT of the cluster).',
    'brix_cms_read_timeouts_total':
        'CMS client reconnects after the manager went silent past the read timeout.',
    'brix_config_generation':
        'Config loads since master start (steps on each reload).',
    'brix_connections_active':
        'Currently open XRootD connections.',
    'brix_connections_total':
        'Total TCP connections accepted since process start.',
    'brix_cred_deleg_fail_total':
        'Delegation-gate failures by protocol and reason (closed vocabulary).',
    'brix_cred_deleg_total':
        'Delegation-gate terminal outcomes, by protocol, configured delegation mode, and outcome.',
    'brix_cred_select_deny_total':
        'Request rejected at the credential gate (EACCES; fallback_deny=1), by protocol.',
    'brix_cred_select_fallback_total':
        'Service-credential fallback allowed (no/expired user cred or driver incapable; fallback_deny=0), by protocol.',
    'brix_cred_select_user_total':
        'Per-user backend credential selected and used, by protocol.',
    'brix_csi_scrub_mismatch_total':
        'At-rest data blocks whose on-disk bytes failed CRC32c re-verification during the background CSI scrub (brix_csi_scrub_interval). A rising value is silent storage rot; 0 unless a scrub is armed.',
    'brix_cvmfs_bytes_served_total':
        'bytes served to clients by cache disposition',
    'brix_cvmfs_fill_failures_total':
        'fills that failed definitively',
    'brix_cvmfs_fills_total':
        'origin fills published to the cache',
    'brix_cvmfs_negative_hits_total':
        '404s absorbed by the per-worker negative cache',
    'brix_cvmfs_origin_bytes_total':
        'bytes pulled from the Stratum-1 origins (WAN in)',
    'brix_cvmfs_origin_failovers_total':
        'read attempts that failed over to the next-ranked origin',
    'brix_cvmfs_repo_bytes_served_total':
        'bytes served per repository by cache disposition',
    'brix_cvmfs_repo_cache_hits_total':
        'requests served from the local store per repository',
    'brix_cvmfs_repo_cache_misses_total':
        'requests that needed an origin fill per repository',
    'brix_cvmfs_repo_files_accessed_total':
        'CAS objects served (hit or fill) per repository',
    'brix_cvmfs_repo_fill_failures_total':
        'fills that failed definitively per repository',
    'brix_cvmfs_repo_fills_total':
        'origin fills published per repository',
    'brix_cvmfs_repo_negative_hits_total':
        '404s absorbed by the negative cache per repository',
    'brix_cvmfs_repo_origin_bytes_total':
        'bytes pulled from the Stratum-1 origins per repository (WAN in)',
    'brix_cvmfs_repo_requests_total':
        'requests per repository by traffic class',
    'brix_cvmfs_repo_verify_failures_total':
        'CAS verify mismatches per repository',
    'brix_cvmfs_requests_total':
        'CVMFS requests by traffic class',
    'brix_cvmfs_upstream_failovers_total':
        'fills served by a non-primary endpoint per upstream Stratum-1',
    'brix_cvmfs_upstream_fill_duration_seconds':
        'origin fill duration per upstream',
    'brix_cvmfs_upstream_fill_failures_total':
        'origin fill attempts that failed per upstream Stratum-1',
    'brix_cvmfs_upstream_fills_total':
        'origin fills that published per upstream Stratum-1',
    'brix_cvmfs_upstream_origin_bytes_total':
        'bytes pulled per upstream Stratum-1 (WAN in)',
    'brix_cvmfs_upstream_requests_total':
        'origin fill attempts per upstream Stratum-1',
    'brix_cvmfs_verify_failures_total':
        'CAS verify mismatches (fill quarantined, never admitted)',
    'brix_frm_asynresp_total':
        'Async stage completions delivered via kXR_attn(asynresp).',
    'brix_frm_cmsd_have_total':
        'Now-resident paths registered with the manager (cmsd Have).',
    'brix_frm_dedup_hits_total':
        'Stage opens collapsed onto an already in-flight recall.',
    'brix_frm_evict_total':
        'kXR_evict / Tape-REST release marks applied.',
    'brix_frm_in_flight':
        'Stage requests currently QUEUED or STAGING.',
    'brix_frm_migrate_total':
        'Category-2 migrate-out attempts (scaffolding).',
    'brix_frm_purge_total':
        'Category-2 purge decisions logged (scaffolding).',
    'brix_frm_reject_inflight_total':
        'Stage requests refused because the queue was at max_inflight.',
    'brix_frm_requests_total':
        'Tape stage requests admitted to the FRM durable queue.',
    'brix_frm_stage_fail_total':
        'Recalls that failed, by coarse reason.',
    'brix_frm_stage_latency_seconds':
        'Tape recall latency in seconds.',
    'brix_frm_stage_success_total':
        'Recalls that completed and brought the file online.',
    'brix_frm_waitresp_total':
        'Async stalled opens parked with kXR_waitresp.',
    'brix_io_bytes_read':
        'Total bytes read from storage, by protocol.',
    'brix_io_bytes_written':
        'Total bytes written to storage, by protocol.',
    'brix_io_latency_usec':
        'I/O operation latency in microseconds.',
    'brix_io_ops_total':
        'I/O operations completed, by protocol, operation, and status.',
    'brix_mirror_divergence_total':
        'Shadow status differed from the primary.',
    'brix_mirror_dropped_total':
        'Requests skipped by the mirror sampling/filter.',
    'brix_mirror_errors_total':
        'Mirror requests that failed to reach the shadow.',
    'brix_mirror_requests_total':
        'Mirror requests the shadow answered.',
    'brix_ocsp_timeouts_total':
        'OCSP fetches that hit the socket deadline (connect/handshake/read).',
    'brix_path_depth_violations_total':
        'Requests rejected because path depth exceeded BRIX_MAX_WALK_DEPTH. Prevents CPU exhaustion from malicious symlink traversal chains or deep nesting.',
    'brix_pmark_firefly_dropped_total':
        'Firefly UDP datagrams dropped on sendto error (fail-open).',
    'brix_pmark_firefly_sent_total':
        'Firefly UDP datagrams sent successfully.',
    'brix_pmark_flowlabel_failed_total':
        'IPv6 flow-label setsockopt refusals (kernel/permission; fail-open).',
    'brix_pmark_flowlabel_set_total':
        'IPv6 flow labels stamped on connections.',
    'brix_pmark_flows_ended_total':
        'SciTags flows that emitted an end firefly.',
    'brix_pmark_flows_started_total':
        'SciTags flows that mapped to (experiment,activity) and were marked.',
    'brix_pmark_map_unresolved_total':
        'Opens with packet marking enabled but no (experiment,activity) mapping.',
    'brix_proxy_abandoned_handles_total':
        'Upstream file handles freed on client disconnect without an explicit close.',
    'brix_proxy_closes_total':
        'kXR_close requests forwarded to upstream.',
    'brix_proxy_open_errors_total':
        'kXR_open requests forwarded to upstream that failed.',
    'brix_proxy_opens_total':
        'kXR_open requests forwarded to upstream that succeeded.',
    'brix_proxy_path_op_errors_total':
        'Path-based mutation operations that received an error from upstream.',
    'brix_proxy_path_ops_total':
        'Path-based mutation operations (rm/mkdir/rmdir/mv/chmod/truncate) that succeeded.',
    'brix_proxy_read_bytes_total':
        'Bytes relayed from upstream to client via proxy.',
    'brix_proxy_reads_total':
        'kXR_read/pgread/readv requests forwarded to upstream.',
    'brix_proxy_reconnects_total':
        'Upstream reconnect attempts after idle connection drop.',
    'brix_proxy_upstream_auth_errors_total':
        'Upstream login or token authentication failures.',
    'brix_proxy_upstream_connect_errors_total':
        'Upstream TCP connect or TLS handshake failures.',
    'brix_proxy_upstream_connects_total':
        'Successful upstream TCP (or TLS) connects.',
    'brix_proxy_wait_responses_total':
        'kXR_wait responses from upstream that were absorbed and retried transparently.',
    'brix_proxy_write_bytes_total':
        'Bytes forwarded from client to upstream via proxy.',
    'brix_proxy_writes_total':
        'kXR_write/pgwrite/writev requests forwarded to upstream.',
    'brix_rate_limit_eviction_total':
        'LRU node evictions from rate-limit shared-memory zones.',
    'brix_rate_limit_throttled_total':
        'Requests throttled by the advanced rate limiter.',
    'brix_rate_limit_zone_full_errors_total':
        'Allocation failures in rate-limit shared-memory zones.',
    'brix_registry_full_total':
        'Server registrations dropped because the registry was at capacity.',
    'brix_requests_total':
        'XRootD requests completed, by operation and status.',
    'brix_s3_auth_total':
        'S3 SigV4 or anonymous authentication outcomes.',
    'brix_s3_bytes_rx_ipv4_total':
        'Bytes received from IPv4 clients via S3-compatible PUT.',
    'brix_s3_bytes_rx_total':
        'Bytes accepted into successful S3-compatible PUT writes.',
    'brix_s3_bytes_tx_ipv4_total':
        'Bytes sent to IPv4 clients via S3-compatible GET.',
    'brix_s3_bytes_tx_total':
        'Bytes emitted by S3-compatible GET, LIST, and XML error responses.',
    'brix_s3_events_total':
        'Low-cardinality S3-compatible endpoint diagnostic events.',
    'brix_s3_list_common_prefixes_total':
        'S3 ListObjectsV2 CommonPrefixes entries emitted.',
    'brix_s3_list_contents_total':
        'S3 ListObjectsV2 Contents entries emitted.',
    'brix_s3_list_truncated_total':
        'S3 ListObjectsV2 responses that returned a continuation token.',
    'brix_s3_put_bodies_total':
        'S3-compatible PUT body storage modes observed after successful writes.',
    'brix_s3_range_requests_total':
        'S3-compatible GET range handling outcomes.',
    'brix_s3_requests_total':
        'S3-compatible endpoint requests received, by operation.',
    'brix_s3_responses_total':
        'S3-compatible endpoint responses by operation and HTTP status class.',
    'brix_scvmfs_requests_total':
        'requests admitted by the scvmfs security preamble (EXPERIMENTAL)',
    'brix_session_evict_total':
        'Idle sessions reaped (LRU) to admit a new login under table pressure.',
    'brix_session_registry_full_total':
        'Logins rejected because the session table was full and nothing was reapable.',
    'brix_session_src_cap_evict_total':
        'Own-LRU sessions recycled because one identity hit the per-source soft cap.',
    'brix_ssi_alerts_pushed_total':
        'XrdSsi out-of-band alerts pushed to clients.',
    'brix_ssi_attn_push_failures_total':
        'XrdSsi kXR_attn pushes that failed to queue.',
    'brix_ssi_errors_total':
        'XrdSsi error responses.',
    'brix_ssi_requests_total':
        'XrdSsi requests dispatched.',
    'brix_storage_backend_info':
        'Composed storage stack per export (source backend, origin, auth, stage); value always 1.',
    'brix_storage_bytes_available':
        'Backend export filesystem bytes available.',
    'brix_storage_bytes_total':
        'Backend export filesystem size in bytes (local backends).',
    'brix_storage_bytes_used':
        'Backend export filesystem bytes used.',
    'brix_storage_io_bytes_read':
        'Bytes read by each storage backend driver.',
    'brix_storage_io_bytes_written':
        'Bytes written by each storage backend driver.',
    'brix_storage_occupancy_ratio':
        'Backend export filesystem occupancy (0-1).',
    'brix_stream_connections_rejected_total':
        'Connections refused at accept because the listener was at brix_max_connections.',
    'brix_stream_handshake_timeouts_total':
        'Connections dropped because the pre-auth handshake stalled past brix_handshake_timeout.',
    'brix_stream_io_uring_active':
        '1 if a worker fronting this listener has used the io_uring backend.',
    'brix_stream_io_uring_fallback_total':
        'Mapped disk ops that fell back to the thread pool because io_uring was full or runtime-disabled.',
    'brix_stream_io_uring_ops_total':
        'Mapped disk ops (read/write/single-group readv/writev) submitted via the io_uring backend.',
    'brix_stream_oversized_payloads_total':
        'Native XRootD requests rejected because their payload was too large.',
    'brix_stream_read_pdu_timeouts_total':
        'Connections dropped because an incomplete request PDU stalled past brix_read_timeout.',
    'brix_stream_request_frames_total':
        'Native XRootD request headers parsed by the stream module.',
    'brix_stream_request_payload_bytes_total':
        'Declared native XRootD request payload bytes parsed by the stream module.',
    'brix_stream_response_frames_total':
        'Native XRootD response send attempts.',
    'brix_stream_response_write_errors_total':
        'Native XRootD response send or send_chain failures.',
    'brix_stream_response_write_stalls_total':
        'Native XRootD response sends that had to wait for socket writability.',
    'brix_stream_send_drain_timeouts_total':
        'Connections dropped because the response drain stalled past brix_send_timeout.',
    'brix_stream_tpc_egress_refused_total':
        'TPC pulls refused because the requested source host was not on brix_tpc_source_allow (server-side request-forgery control). 0 unless brix_tpc_source_guard is on.',
    'brix_tpc_bytes_total':
        'Successful third-party-copy bytes.',
    'brix_tpc_gsi_delegated_total':
        'Outbound TPC GSI proxy-delegation credential-selection outcomes.',
    'brix_tpc_transfers_total':
        'Third-party-copy transfer outcomes.',
    'brix_unique_users_current':
        'Currently tracked unique user identities (bounded LRU, max 1024). Users are identified by DN or token sub via FNV-1a hash.',
    'brix_unique_users_total':
        'Lifetime unique user identities seen since process start. Never decremented.',
    'brix_user_evictions_total':
        'User identity slots evicted from the tracking table.',
    'brix_user_sessions_total':
        'Sessions per tracked user identity. Sum across all entries equals total authenticated sessions.',
    'brix_vo_bytes_rx_total':
        'Bytes received from clients grouped by virtual organisation. VO names are truncated to 15 characters.',
    'brix_vo_bytes_tx_total':
        'Bytes sent to clients grouped by virtual organisation. VO names are truncated to 15 characters; the metric family has one entry per VO.',
    'brix_vo_overflow_total':
        'VO entries that exceeded the tracking limit and were evicted.',
    'brix_vo_requests_total':
        'Requests grouped by virtual organisation. VO names are truncated.',
    'brix_webdav_auth_total':
        'WebDAV authentication outcomes.',
    'brix_webdav_bytes_rx_ipv4_total':
        'Bytes received from IPv4 clients via WebDAV PUT.',
    'brix_webdav_bytes_rx_ipv6_total':
        'Bytes received from IPv6 clients via WebDAV PUT.',
    'brix_webdav_bytes_rx_total':
        'Bytes received into WebDAV storage writes.',
    'brix_webdav_bytes_tx_ipv4_total':
        'Bytes sent to IPv4 clients via WebDAV GET and PROPFIND.',
    'brix_webdav_bytes_tx_ipv6_total':
        'Bytes sent to IPv6 clients via WebDAV GET and PROPFIND.',
    'brix_webdav_bytes_tx_total':
        'Bytes sent from WebDAV GET and PROPFIND responses.',
    'brix_webdav_cors_total':
        'WebDAV CORS request/header decisions.',
    'brix_webdav_propfind_depth_total':
        'WebDAV PROPFIND requests by Depth header bucket.',
    'brix_webdav_propfind_entries_total':
        'WebDAV PROPFIND response entries emitted.',
    'brix_webdav_put_bodies_total':
        'WebDAV PUT body storage modes.',
    'brix_webdav_range_requests_total':
        'WebDAV GET range handling outcomes.',
    'brix_webdav_requests_total':
        'WebDAV requests received, by HTTP/WebDAV method.',
    'brix_webdav_responses_total':
        'WebDAV responses by method and HTTP status class.',
    'brix_webdav_tpc_cred_total':
        'WebDAV HTTP-TPC OAuth2/OIDC credential delegation events.',
    'brix_webdav_tpc_total':
        'WebDAV HTTP-TPC COPY pull, push, and helper events.',
    'brix_wire_bytes_rx_total':
        'Raw socket bytes received from native XRootD clients.',
    'brix_wire_bytes_tx_total':
        'Raw socket bytes sent to native XRootD clients.',
    'brix_wt_dirty_handles':
        'Open write-through handles with unflushed dirty data.',
    'brix_wt_flush_bytes_total':
        'Bytes mirrored to origin by successful write-through flushes.',
    'brix_wt_flush_pending':
        'Write-through flush tasks currently pending completion.',
    'brix_wt_flushes_total':
        'Write-through flush completions by result.',
    'brix_wt_stage_throttled_total':
        'Writes shed by staging backpressure, by action.',
    'brix_wt_stage_usage_ratio':
        'Write-back staging filesystem occupancy (0-1).',
    'brix_xfer_heap_bytes':
        'Bytes currently held in per-connection transfer scratch buffers.',
    'brix_xfer_heap_high_water_bytes':
        'Peak transfer-heap bytes observed since start.',
}
