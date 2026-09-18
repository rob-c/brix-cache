# Configuration directive reference

Reference for the most commonly-used `brix_*` directives — name, context, type, default, and what each one actually does. For a single-table summary of the most-used directives, see [quick-reference.md](quick-reference.md). Some advanced features are summarized in their subsystem docs first; for example, health checks live in [`src/net/upstream/README.md`](../../src/net/upstream/README.md), traffic mirroring in [`src/net/mirror/README.md`](../../src/net/mirror/README.md), and advanced rate/bandwidth/concurrency limits in [`src/net/ratelimit/README.md`](../../src/net/ratelimit/README.md).

[← Configuration overview](config-reference.md)

## Directives

<!-- BEGIN GENERATED DIRECTIVE REGISTRY -->

### Complete directive registry (generated)

This table is generated from the live `ngx_command_t` registrations, including directive fragments and X-macro families. Context and argument shape are authoritative; exact defaults and validation constraints remain in the curated sections below and in the linked registration owner. Run `cmake --build build --target docs-directives` after changing the surface.

| Directive | Plane | Arguments | Registration owner |
|---|---|---|---|
| `brix_acc_audit` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_authdb` | http | `<value>` | `src/core/config/http_directives_auth.h` |
| `brix_acc_encoding` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_format` | http | `<value>` | `src/core/config/http_directives_auth.h` |
| `brix_acc_gidlifetime` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_gidretran` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_nisdomain` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_pgo` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_refresh` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_resolve_hosts` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_acc_spacechar` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_access_log` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_admin_allow` | http | `<value>...` | `src/observability/dashboard/module.c` |
| `brix_admin_proxy_allow` | http | `<value>...` | `src/observability/dashboard/module.c` |
| `brix_admin_rate_limit` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_admin_require_both` | http | `on|off` | `src/observability/dashboard/module.c` |
| `brix_admin_secret` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_admin_socket` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_allow_write` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_auth` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_auth_cache` | stream | `<value>` | `src/protocols/root/stream/directives_zones.h` |
| `brix_auth_maxfail` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_authdb` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_authdb_engine` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_authz_backstop` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_backend_async` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_async_batch` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_async_wait` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_ca_dir` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_backend_delegation` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_krb5_forwardable` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_access_key` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_endpoint` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_flavor` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_region` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_role` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_secret_key` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_s3_sts_ttl` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_sss_keytab` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_backend_token_audience_ok` | http | `<value>...` | `src/core/config/http_directives_core.h` |
| `brix_backend_token_exchange_client_id` | http | `<value>` | `src/core/config/http_directives_core.h` |
| `brix_backend_token_exchange_client_secret` | http | `<value>` | `src/core/config/http_directives_core.h` |
| `brix_backend_token_exchange_endpoint` | http | `<value>` | `src/core/config/http_directives_core.h` |
| `brix_bandwidth_limit` | http, stream | `<value> <value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_cache` | stream | `on|off` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise` | stream | `on|off` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_data_url` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_federation` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_interval` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_issuer` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_key` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_namespace` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_advertise_web_url` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_allow_prefix` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_cold_max_age` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_cold_store` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_deny_prefix` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_dirty_max_age` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_evict_at` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_evict_to` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_eviction_threshold` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_export` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_global_cas` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_high_watermark` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_include_regex` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_index_cache` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_lock_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_low_watermark` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_max_bytes` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_max_file_size` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_max_object` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_meta` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_only_if_cached` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_origin_family` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_passthrough` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_passthrough_max` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_peers` | http | `<value>...` | `src/core/config/http_directives_core.h` |
| `brix_cache_prefetch` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_prefetch_window` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_reap_interval` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_root` | http | `<value>` | `src/core/config/http_directives_core.h` |
| `brix_cache_serve_while_filling` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_slice_size` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_state_root` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_cache_store` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_store_endpoint` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_cache_urlcgi` | http, stream | `<value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_uvkeep` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_cache_verify` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_cache.h` |
| `brix_cache_verify_digest` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_cache.h` |
| `brix_certificate` | stream | `<value>` | `src/core/config/stream_common.c` |
| `brix_certificate_key` | stream | `<value>` | `src/core/config/stream_common.c` |
| `brix_checksum_default` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_checksum_plugin` | http, stream | `<value> <value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_chkpnt_maxsz` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_ckscan_depth` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_ckscan_max_files` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_client_ca_store` | http | `<value>` | `src/core/config/http_directives_ops.h` |
| `brix_client_certificate_folder` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_cms_admin_socket` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_affinity` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_altds` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_altds_interval` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_blacklist_file` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_coalesce` | stream | `on|off` | `src/protocols/root/stream/directives_caps.h` |
| `brix_cms_connect_retry` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_delay_hold` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_delay_servers` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_dfs` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_emptylife` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_fanout` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_fanout_window` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_fsxeq` | stream | `<value> <value>...` | `src/protocols/root/stream/directives_cms_fsxeq.h` |
| `brix_cms_fsxeq_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms_fsxeq.h` |
| `brix_cms_fxhold` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_initial_delay` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_interval` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_load_weight` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_locate_multi` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_locate_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_locate_window` | stream | `<value>` | `src/protocols/root/stream/directives_caps.h` |
| `brix_cms_manager` | stream | `<value>...` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_min_free` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_paths` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_perf_interval` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_perf_pgm` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_read_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_response` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_role` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_sched` | stream | `<value>...` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_send_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_server` | stream | `on|off` | `src/net/cms/server_module.c` |
| `brix_cms_server_allow` | stream | `<value>...` | `src/net/cms/server_module.c` |
| `brix_cms_server_idle_timeout` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_interval` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_login_timeout` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_max_connections` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_max_connections_per_ip` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_max_direct` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_sss_keytab` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_server_tcp_keepalive` | stream | `on|off` | `src/net/cms/server_module.c` |
| `brix_cms_server_tcp_user_timeout` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cms_space_enforce` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_space_hwm` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_stage_select` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_state_fanout` | stream | `<value>` | `src/protocols/root/stream/directives_caps.h` |
| `brix_cms_state_relay` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_tcp_keepalive` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_tcp_user_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_vnid` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_cms_whitelist_file` | stream | `<value>` | `src/net/cms/server_module.c` |
| `brix_cns` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_collapse_redir` | stream | `on|off` | `src/protocols/root/stream/directives_caps.h` |
| `brix_collapse_redir_ttl` | stream | `<value>` | `src/protocols/root/stream/directives_caps.h` |
| `brix_compress` | http | `on|off` | `src/core/config/http_directives_core.h` |
| `brix_concurrency_limit` | http, stream | `<value> <value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_credential` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/module.c` |
| `brix_crl` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_crl_mode` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_crl_reload` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_crl_scope` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_csi` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_csi_block` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_csi_require` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_csi_scrub_interval` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_csi_trust_fs` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_cvmfs` | http | `on|off` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_attest` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_bundle` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_client_hold` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_delta` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_dict` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_fill_max_life` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_fill_retry_policy` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_geo_answer` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_geo_cache_ttl` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_geo_max_servers` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_here` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_learn` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_manifest_ttl` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_negative_ttl` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_offline_ttl` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_origin_attempt_timeout` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_connect_timeout` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_coords` | http | `<value> <value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_http_version` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_reuse_conn` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_select` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_stall_bytes` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_origin_stall_timeout` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_qos` | http | `<value> <value> <value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_quarantine_dir` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_repo_authz` | http | `<value> <value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_rtt_interval` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_scrub` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_scrub_interval` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_scrub_rate` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_shared_cache` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_stratum0_root` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_swarm` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_swarm_interval` | http | `<value>` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_trace` | http | `on|off` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_unified_origin` | http | `on|off` | `src/protocols/cvmfs/directives_resilience.h` |
| `brix_cvmfs_upstream_allow` | http | `<value>...` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_upstream_max` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_verify_manifest` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_cvmfs_virtual_repo` | http | `<value> <value>...` | `src/protocols/cvmfs/directives_core.h` |
| `brix_dashboard` | http | `on|off` | `src/observability/dashboard/module.c` |
| `brix_dashboard_anonymous` | http | `on|off` | `src/observability/dashboard/module.c` |
| `brix_dashboard_browse_root` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_cluster_stale_after` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_cookie_path` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_idle_threshold` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_password` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_scan_max_files` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_scan_root` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_session_ttl` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_stalled_threshold` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_users` | http | `<value>` | `src/observability/dashboard/module.c` |
| `brix_dashboard_vfs_browse` | http | `on|off` | `src/observability/dashboard/module.c` |
| `brix_data_substreams` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_delegation_endpoint` | http | `on|off` | `src/core/config/http_directives_ops.h` |
| `brix_dirstats` | stream | `on|off` | `src/protocols/root/stream/directives_cache.h` |
| `brix_dns_cache_max` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/core/config/stream_common.c` |
| `brix_dns_retry` | http, stream | `<value> <value>` | `src/core/config/http_directives_ops.h`<br>`src/core/config/stream_common.c` |
| `brix_dns_status_zone` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/core/config/stream_common.c` |
| `brix_durable_commit` | stream | `on|off` | `src/core/config/stream_common.c` |
| `brix_durable_publish` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_export` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_frm` | stream | `on|off` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_async_recall` | stream | `on|off` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_control_dir` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_copy_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_copymax` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_fail_backoff` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_fail_retries` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_max_inflight` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_purge_interval` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_purge_max_bytes` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_purge_policy` | stream | `<value> <value> <value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_purge_polprog` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_purge_watermark` | stream | `<value> <value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_queue_path` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_stage_ttl` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_stage_wait` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_stagecmd` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_frm_stagemsg` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_fsoverload_redirect` | stream | `<value> <value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_fsoverload_stall` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_gridftp` | stream | `on|off` | `src/protocols/gridftp/ftp_module.c` |
| `brix_gridftp_gsi` | stream | `on|off` | `src/protocols/gridftp/ftp_module.c` |
| `brix_gridftp_pasv_port_range` | stream | `<value> <value>` | `src/protocols/gridftp/ftp_module.c` |
| `brix_gridftp_require_allo_size` | stream | `on|off` | `src/protocols/gridftp/ftp_module.c` |
| `brix_gsi_ciphers` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_gsi_legacy_proxy` | http, stream | `off|on|full-only` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_gsi_keypool_seed` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_gsi_keypool_size` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_gsi_max_inflight_handshakes` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_gsi_signed_dh` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_guard` | http | `on|off` | `src/net/httpguard/module.c` |
| `brix_guard_audit_log` | http | `<value>` | `src/net/httpguard/module.c` |
| `brix_guard_bounce_status` | http | `<value>` | `src/net/httpguard/module.c` |
| `brix_guard_default_signatures` | http | `on|off` | `src/net/httpguard/module.c` |
| `brix_guard_profile` | http | `<value>` | `src/net/httpguard/module.c` |
| `brix_guard_signature` | http | `<value>` | `src/net/httpguard/module.c` |
| `brix_guard_stream` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_guard_valid_method` | http | `<value>...` | `src/net/httpguard/module.c` |
| `brix_guard_valid_prefix` | http | `<value>` | `src/net/httpguard/module.c` |
| `brix_handshake_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_health` | http | `on|off` | `src/observability/metrics/module.c` |
| `brix_health_check` | stream | `on|off` | `src/protocols/root/stream/directives_net.h` |
| `brix_health_check_blacklist` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_health_check_interval` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_health_check_threshold` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_health_check_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_health_check_type` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_host_allow` | stream | `<value>...` | `src/protocols/root/stream/directives_auth.h` |
| `brix_http_handoff` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_idmap` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_broker_user` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_cache_ttl` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_default_user` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_export` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_forbidden_groups` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_forbidden_users` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_gridmap` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_min_uid` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_socket` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_idmap_user` | stream | `<value>` | `src/protocols/root/stream/directives_tier.h` |
| `brix_inherit_parent_group` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_io_uring` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_io_uring_admin` | stream | `on|off` | `src/protocols/root/stream/directives_cache.h` |
| `brix_io_uring_panic_file` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_io_uring_queue_depth` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_io_uring_restrict` | stream | `on|off` | `src/protocols/root/stream/directives_cache.h` |
| `brix_krb5_delegate` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_krb5_ip_check` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_krb5_keytab` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_krb5_principal` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_ktls` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_kv_zone` | http, stream | `<value> <value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_zones.h` |
| `brix_listen_port` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_lock_enforcement` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_macaroon_secret` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_macaroon_secret_old` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_manager_map` | stream | `<value> <value>` | `src/protocols/root/stream/module.c` |
| `brix_manager_mode` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_manager_stale_after` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_max_connections` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_max_delay` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_cms.h` |
| `brix_memory_budget` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_metadata_only` | stream | `on|off` | `src/protocols/root/stream/directives_caps.h` |
| `brix_metrics` | http | `on|off` | `src/observability/metrics/module.c` |
| `brix_metrics_slowop` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_min_sec_level` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_mirror_exclude_opcodes` | stream | `<value>...` | `src/protocols/root/stream/directives_net.h` |
| `brix_mirror_log_diverge` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_mirror_methods` | http | `<value>...` | `src/core/config/http_directives_ops.h` |
| `brix_mirror_opcodes` | stream | `<value>...` | `src/protocols/root/stream/directives_net.h` |
| `brix_mirror_sample` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_mirror_strip_auth` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_mirror_timeout` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_mirror_token` | http | `<value>` | `src/core/config/http_directives_ops.h` |
| `brix_mirror_url` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_mirror_writes` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_n2n_pool` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_n2n_prefix` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_n2n_scheme` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_negcache_backoff` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_oci_delegate_insecure` | http | `on|off` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_delegate_proof_ttl` | http | `<value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_delegate_realm` | http | `<value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_gc_grace` | http | `<value>` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_gc_interval` | http | `<value>` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_manifest_ttl` | http | `<value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_max_blob_size` | http | `<value>` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_mirror` | http | `<value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_mirror_auth` | http | `<value> <value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_mirror_delegate` | http | `on|off` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_mirror_insecure` | http | `on|off` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_registry` | http | `on|off` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_registry_allow_anonymous` | http | `on|off` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_registry_root` | http | `<value>` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_token_issuers` | http | `<value>` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_token_zone` | http | `<value> <value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_upload_grace` | http | `<value>` | `src/protocols/oci/directives_registry.h` |
| `brix_oci_upstream_auth_realm` | http | `<value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_oci_upstream_namespace` | http | `<value>` | `src/protocols/oci/directives_mirror.h` |
| `brix_ocsp` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_ocsp_require_nonce` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_ocsp_soft_fail` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_ocsp_stapling` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_opaque_strict` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_oss_cgroup` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_oss_maxsize` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_oss_quota` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_oss_quota_enforce` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_oss_space` | stream | `<value> <value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_pblock_block_size` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/module.c` |
| `brix_pipeline_depth` | stream | `<value>` | `src/protocols/root/stream/module.c` |
| `brix_pmark` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_appname` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_defsfile` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_domain` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_echo` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_firefly` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_firefly_dest` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_firefly_origin` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_flowlabel` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_http_plain` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_map_activity` | http, stream | `<value> <value> <value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_map_experiment` | http, stream | `<value> <value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_pmark_scitag_cgi` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_pmark.h` |
| `brix_posc_persist` | stream | `<value>` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_prepare_command` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_protbind` | http, stream | `<value> <value>...` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_pwd_file` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_rate_limit` | http, stream | `<value> <value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_zones.h` |
| `brix_rate_limit_rule` | http, stream | `<value> <value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_rate_limit_zone` | http, stream | `<value>...` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_net.h` |
| `brix_read_compress` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_read_only` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_read_only_public` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_read_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_readv_segment_size` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_recover_writes` | stream | `on|off` | `src/protocols/root/stream/directives_caps.h` |
| `brix_redir_cache_slots` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_registry_slots` | stream | `<value>` | `src/protocols/root/stream/directives_caps.h` |
| `brix_require_pgwrite` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_require_vo` | http, stream | `<value> <value>` | `src/core/config/http_directives_auth.h`<br>`src/core/config/stream_common.c` |
| `brix_resolver` | http, stream | `<value>...` | `src/core/config/http_directives_ops.h`<br>`src/core/config/stream_common.c` |
| `brix_root` | stream | `on|off` | `src/protocols/root/stream/module.c` |
| `brix_rpm_metadata_ttl` | http | `<value>` | `src/protocols/rpm/rpm_module.c` |
| `brix_rpm_mirror` | http | `<value>` | `src/protocols/rpm/rpm_module.c` |
| `brix_rpm_mirror_insecure` | http | `on|off` | `src/protocols/rpm/rpm_module.c` |
| `brix_rpm_prefetch` | http | `on|off` | `src/protocols/rpm/rpm_module.c` |
| `brix_s3` | http | `on|off` | `src/protocols/s3/module.c` |
| `brix_s3_access_key` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_allow_unsigned_session_token` | http | `on|off` | `src/protocols/s3/module.c` |
| `brix_s3_bucket` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_list_cache` | http | `on|off` | `src/protocols/s3/module.c` |
| `brix_s3_list_cache_ttl` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_max_keys` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_mpu_max_age` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_region` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_secret_key` | http | `<value>` | `src/protocols/s3/module.c` |
| `brix_s3_token` | http | `on|off` | `src/protocols/s3/module.c` |
| `brix_s3_verify_chunk_signatures` | http | `on|off` | `src/protocols/s3/module.c` |
| `brix_scvmfs` | http | `on|off` | `src/protocols/cvmfs/directives_core.h` |
| `brix_scvmfs_authz` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_scvmfs_token_issuers` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_scvmfs_voms` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_scvmfs_voms_cert_dir` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_scvmfs_vomsdir` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_scvmfs_x509_dn` | http | `<value>` | `src/protocols/cvmfs/directives_core.h` |
| `brix_seccomp` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_seccomp_allow_exec` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_security_level` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_send_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_session_log` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_session_slots` | stream | `<value>` | `src/protocols/root/stream/module.c` |
| `brix_signing_policy` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_signing_required` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_sitename` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_socket_rcvbuf` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_socket_sndbuf` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_srr` | http | `on|off` | `src/protocols/srr/module.c` |
| `brix_srr_endpoint` | http | `<value> <value> <value>` | `src/protocols/srr/module.c` |
| `brix_srr_id` | http | `<value>` | `src/protocols/srr/module.c` |
| `brix_srr_name` | http | `<value>` | `src/protocols/srr/module.c` |
| `brix_srr_quality` | http | `<value>` | `src/protocols/srr/module.c` |
| `brix_srr_share` | http | `<value> <value>` | `src/protocols/srr/module.c` |
| `brix_srr_version` | http | `<value>` | `src/protocols/srr/module.c` |
| `brix_ssi` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_ssi_cta_executor` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_ssi_cta_journal` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_ssi_max_inflight` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_ssi_request_max` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_ssi_response_max` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_ssi_service` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_sss_getcreds` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_sss_keytab` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_stage` | http, stream | `on|off` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_stage_dir` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_caps.h` |
| `brix_stage_flush` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_stage_store` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_storage_backend` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_storage_credential` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_storage_credential_dir` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_storage_credential_fallback` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_storage_credential_mint_ca` | http, stream | `<value> <value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_storage_credential_mint_ttl` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/module.c` |
| `brix_strict_security` | http | `on|off` | `src/core/config/http_directives_core.h` |
| `brix_supervisor` | stream | `on|off` | `src/protocols/root/stream/directives_caps.h` |
| `brix_tap_proxy` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_audit_log` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_auth` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_login_user` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_path_rewrite` | stream | `<value> <value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_sss_identity` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_tap_proxy_upstream` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_upstream_tls` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_upstream_tls_ca` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_upstream_tls_name` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tap_proxy_upstream_tls_verify` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tcp_congestion` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_cms.h` |
| `brix_tcp_keepalive` | stream | `on|off` | `src/protocols/root/stream/directives_cms.h` |
| `brix_tcp_user_timeout` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_thread_pool` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_cms.h` |
| `brix_throttle_bandwidth_budget` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_throttle_bandwidth_zone` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_throttle_max_open_files` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_throttle_zone` | stream | `<value>` | `src/protocols/root/stream/directives_auth.h` |
| `brix_tls` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_tls_ciphers` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_tls_ciphersuites` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_tls_require` | http, stream | `<value>...` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_tls_reuse` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_tls_verify_log` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_token_audience` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_token_cache` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_zones.h` |
| `brix_token_clock_skew` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_token_config` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_token_introspect_fail_open` | http | `on|off` | `src/core/config/http_directives_auth.h` |
| `brix_token_introspect_loc` | http | `<value>` | `src/core/config/http_directives_auth.h` |
| `brix_token_introspect_ttl` | http | `<value>` | `src/core/config/http_directives_auth.h` |
| `brix_token_introspect_url` | http | `<value>` | `src/core/config/http_directives_auth.h` |
| `brix_token_issuer` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_token_jwks` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_token_jwks_refresh_interval` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_tpc_allow_identity` | http, stream | `<value> <value>...` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_allow_local` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_allow_private` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_delegate` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_key_ttl` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_max_hops` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_max_transfer_secs` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_oids` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_outbound_bearer_file` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_outbound_client_id` | http, stream | `<value>` | `src/protocols/root/stream/directives_tpc.h`<br>`src/protocols/webdav/directives_tpc.h` |
| `brix_tpc_outbound_client_secret` | http, stream | `<value>` | `src/protocols/root/stream/directives_tpc.h`<br>`src/protocols/webdav/directives_tpc.h` |
| `brix_tpc_outbound_passthrough` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_outbound_renew_lead` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_outbound_renew_strict` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_outbound_scope` | http, stream | `<value>` | `src/protocols/root/stream/directives_tpc.h`<br>`src/protocols/webdav/directives_tpc.h` |
| `brix_tpc_outbound_tls` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_outbound_token_endpoint` | http, stream | `<value>` | `src/protocols/root/stream/directives_tpc.h`<br>`src/protocols/webdav/directives_tpc.h` |
| `brix_tpc_push` | stream | `on|off` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_require` | http, stream | `<value> <value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_require_source_size` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_restrict` | http, stream | `<value>...` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_source_allow` | http, stream | `<value>...` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_source_guard` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_streams` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_transfer_max_age` | stream | `<value>` | `src/protocols/root/stream/directives_tpc.h` |
| `brix_tpc_verify_checksum` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_tpc.h` |
| `brix_transparent_proxy` | stream | `<value>` | `src/protocols/root/stream/directives_cms.h` |
| `brix_trusted_ca` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/core/config/stream_common.c` |
| `brix_trusted_ca_dir` | http | `<value>` | `src/core/config/http_directives_ops.h` |
| `brix_unix_trust_remote` | stream | `on|off` | `src/protocols/root/stream/directives_auth.h` |
| `brix_upload_resume` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_caps.h` |
| `brix_upstream` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_tls` | stream | `on|off` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_tls_ca` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_tls_name` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_tls_verify` | stream | `on|off` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_token_file` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_x509_key` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_upstream_x509_proxy` | stream | `<value>` | `src/protocols/root/stream/directives_net.h` |
| `brix_verify_depth` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_auth.h` |
| `brix_verify_write` | http, stream | `on|off` | `src/core/config/http_directives_core.h`<br>`src/core/config/stream_common.c` |
| `brix_vfs_spill_max` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_vfs_spill_path` | http, stream | `<value>` | `src/core/config/http_directives_ops.h`<br>`src/protocols/root/stream/directives_tier.h` |
| `brix_virtual_redirector` | stream | `on|off` | `src/protocols/root/stream/directives_caps.h` |
| `brix_voms_cert_dir` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/core/config/stream_common.c` |
| `brix_vomsdir` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/core/config/stream_common.c` |
| `brix_webdav` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_accel_redirect` | http | `<value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_auth` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_authz` | http | `on|off` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_checksum_on_write` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_checksum_xattr_format` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_cors_credentials` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_cors_max_age` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_cors_origin` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_dig` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_dig_auth` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_dig_export` | http | `<value> <value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_header2cgi` | http | `<value> <value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_html_listing` | http | `on|off` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_listing_redirect` | http | `<value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_lock_startup_sweep` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_lock_timeout` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_macaroon_location` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_macaroon_max_validity` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_open_file_cache` | http | `[value ...]` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_open_file_cache_errors` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_open_file_cache_events` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_open_file_cache_min_uses` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_open_file_cache_valid` | http | `<value>` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_proxy_certs` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_query_token` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_redirect_dataserver` | http | `on|off` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_redirect_port` | http | `<value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_redirect_scheme` | http | `<value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_redirect_window` | http | `<value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_require_digest` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_revoke_cache` | http | `<value>` | `src/protocols/webdav/directives_zones.h` |
| `brix_webdav_secretkey` | http | `<value>` | `src/protocols/webdav/directives_net.h` |
| `brix_webdav_storage_staging` | http | `on|off` | `src/protocols/webdav/directives_storage.h` |
| `brix_webdav_tape_rest` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_tpc` | http | `on|off` | `src/protocols/webdav/module_commands.c` |
| `brix_webdav_tpc_cadir` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_cafile` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_cert` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_credential_forward` | http | `on|off` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_curl` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_key` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_low_speed_bytes` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_low_speed_secs` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_marker_interval` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_max_streams` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_timeout` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_webdav_tpc_xfr` | http | `<value>` | `src/protocols/webdav/directives_tpc.h` |
| `brix_worker_user` | http, stream | `<value>` | `src/core/config/http_directives_core.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_write_compress` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_write_through` | stream | `on|off` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_wt_allow_prefix` | stream | `<value>` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_wt_credential` | stream | `<value>` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_wt_deny_prefix` | stream | `<value>` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_wt_mode` | stream | `<value>` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_wt_origin` | stream | `<value>` | `src/protocols/root/stream/directives_writethrough.h` |
| `brix_wt_stage_backend` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_wt_stage_block_size` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_wt_stage_high_watermark` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_wt_stage_low_watermark` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_wt_stage_root` | stream | `<value>` | `src/protocols/root/stream/directives_cache.h` |
| `brix_zip_access` | http, stream | `on|off` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_zip_cd_max_bytes` | http, stream | `<value>` | `src/core/config/http_directives_auth.h`<br>`src/protocols/root/stream/directives_security.h` |
| `brix_zip_force_scratch` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_zip_stage_dir` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_zip_stage_max_bytes` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |
| `brix_ztn_cleartext` | stream | `on|off` | `src/protocols/root/stream/directives_security.h` |
| `brix_ztn_maxsz` | stream | `<value>` | `src/protocols/root/stream/directives_security.h` |

<!-- END GENERATED DIRECTIVE REGISTRY -->

## Unified storage grammar

Three rules cover all four protocols (`brix_root`, `brix_webdav`, `brix_s3`, `brix_cvmfs`):

- **`brix_<proto> on;`** — per-location enable. One directive activates the protocol handler.
  Only one protocol may be enabled per location or per port.
- **Unified storage directives** — registered once by `ngx_http_brix_common_module` (HTTP
  plane) and by the stream module (stream plane); valid at `http|server|location` (or
  stream `main|server`); merged main→srv→loc so a `server{}` block can configure storage
  once and every brix location inherits it: `brix_export`, `brix_storage_backend`,
  `brix_cache_store`, `brix_cache_root`, `brix_cache_verify`, `brix_cache_max_object`,
  `brix_cache_evict_at`, `brix_cache_evict_to`, `brix_cache_index_cache`, `brix_cache_meta`,
  `brix_cache_slice_size`, `brix_cache_prefetch`, `brix_cache_prefetch_window`,
  `brix_cache_urlcgi`, `brix_cache_only_if_cached`, `brix_cache_uvkeep`, `brix_cache_max_bytes`,
  `brix_stage`, `brix_stage_store`, `brix_stage_flush`, `brix_thread_pool`.
- **Bare `brix_*` cross-protocol directives** — one spelling that works identically on
  every plane (registered once by the common owner and adopted into each protocol conf).
  Storage/lifecycle: `brix_allow_write`, `brix_read_only`,
  `brix_read_only_public` (stream only), `brix_compress`, `brix_ktls`,
  `brix_metrics`, `brix_health`, `brix_credential`, `brix_upload_resume`, `brix_stage_dir`,
  `brix_vfs_spill_path`, `brix_vfs_spill_max`, `brix_durable_publish`,
  `brix_lock_enforcement`, `brix_authz_backstop`, `brix_zip_access`,
  `brix_pblock_block_size`. Authorization / trust (phase-101 W4):
  `brix_require_vo`, `brix_protbind`, `brix_pwd_file`, `brix_macaroon_secret`,
  `brix_token_jwks`, `brix_token_issuer`, `brix_token_audience`, `brix_token_clock_skew`,
  `brix_token_config`, `brix_trusted_ca`, `brix_trusted_ca_dir`, `brix_crl`, `brix_crl_mode`,
  `brix_signing_policy`, `brix_vomsdir`, `brix_voms_cert_dir`. HTTP-TPC SSRF policy:
  `brix_tpc_allow_local`, `brix_tpc_allow_private`, `brix_tpc_source_guard`,
  `brix_tpc_source_allow`, `brix_tpc_require_source_size`, `brix_tpc_verify_checksum`.
  Native root:// pull shape (2.0 F7): `brix_tpc_max_hops`, `brix_tpc_streams`;
  the push dialect (2.0 F16): `brix_tpc_push`.
  Per-request identity (phase-101 W6): the `brix_idmap*` family.

The only remaining per-protocol directive families are behavior specific to one protocol
(`brix_cvmfs_*`, `brix_scvmfs_*`, `brix_s3_*` auth, `brix_webdav_*` TPC-transport/CORS, …).

> **Renamed a prefixed directive?** Every phase-101 old→new spelling (the de-prefixings
> above plus the W6 role renames — `brix_ocsp`, `brix_dashboard_scan_*`, `brix_idmap*`,
> the CA/trust quartet) is listed in
> [migration-unified-grammar.md](migration-unified-grammar.md). Old names are hard-removed:
> nginx reports a stock `unknown directive`, never a silent alias.

---

### `brix_storage_backend ftp://…|gsiftp://…` — outbound FTP/GridFTP origin

An export may use a remote FTP/GridFTP namespace as its primary storage without
changing the client-facing protocol:

```nginx
# Anonymous RFC 959 origin; default port 21.
brix_storage_backend ftp://ftp.example.org/archive;

# GSI-authenticated GridFTP origin; default port 2811.
brix_credential atlas_origin {
    x509_proxy /run/credentials/atlas-proxy.pem;
    ca_dir /etc/grid-security/certificates;
}
brix_storage_backend gsiftp://grid.example.org/store;
brix_storage_credential atlas_origin;
```

The URL requires a host and an absolute base path (omitting the path means
`/`). Bracketed IPv6 authorities are accepted. Query strings, fragments,
userinfo, `.`/`..` path components, control bytes and backslashes are rejected
at `nginx -t`; the driver repeats logical-path confinement before emitting an
FTP command.

`ftp://` performs anonymous login. `gsiftp://` requires an X.509 proxy selected
from `brix_storage_credential` or the existing per-user backend-credential
machinery. A VOMS proxy is forwarded as the same certificate chain, preserving
its attributes. The default data plane uses passive MODE S and `PROT C`/`DCAU N`;
EPSV/PASV ports are always connected on the established control peer, so a
malicious PASV address cannot redirect BriX. Kerberos, username/password and
session pooling are not enabled by this URL.

#### Data-channel parameters

Three trailing parameters select the data channel. The first two are
**requirements**: an origin that cannot honour one fails the transfer rather
than moving the bytes under weaker terms. The third is a **ceiling**, and does
degrade — see below.

| Parameter | Effect | An origin that refuses |
| --- | --- | --- |
| `mode=e` | GFD.020 §3.4 extended block mode — offset-addressed blocks instead of "the close is the end" | `504`; the read or write fails, and is **not** retried in stream mode |
| `prot=p` | TLS on the data socket (`DCAU A` + `PROT P`), presenting the control channel's proxy, with the data peer's leaf DN pinned to the control identity | `534`; the transfer fails, never downgraded to cleartext |
| `streams=<n>` | ceiling on the data connections one read may open with GFD.020 §5.1 `SPAS` striping; `1`–`16`, default `1` (never ask). Requires `mode=e` | any refusal, and the same bytes arrive over one connection |

```nginx
brix_storage_backend gsiftp://grid.example.org/store mode=e prot=p streams=4;
```

`prot=p` is rejected at `nginx -t` on an `ftp://` origin. The protection's value
is the DN pin, and an anonymous control channel authenticates no identity to pin
to — an unpinned TLS data channel is encrypted to whoever answered the PASV
address, which is not what the parameter promises.

`streams=<n>` above `1` requires `mode=e` and is rejected at `nginx -t`
without it: a striped transfer is reassembled from blocks that carry their own
offsets, and stream mode has none. The check runs on the whole store line, so
`streams=4 mode=e` and `mode=e streams=4` behave identically.

Unlike its two neighbours, `streams=` **degrades**, because it is a statement
about speed rather than about what the bytes are. An origin that does not
advertise `SPAS`, refuses it, answers with more stripes than the ceiling, or
returns a reply that will not parse is served over the single connection, with
identical bytes. One refusal is not negotiable: **every stripe address must be
the control channel's own peer.** A `SPAS` reply is the only place in this
protocol where an origin hands the driver a list of addresses, and following
one elsewhere would make the storage backend dial arbitrary hosts inside your
network on the origin's instruction. A single foreign stripe abandons the whole
striped attempt before any socket is opened. A genuinely multi-host striped
door is therefore read over one connection — a speed limit, not a failure.
`SPOR` (the client offering the addresses) is not implemented: the driver never
listens.

**`ERET` is used automatically, and is not a parameter.** With `mode=e`, a
bounded read asks the origin for its window with `ERET P <offset> <length>`
(GFD.020 §5.3) when the origin advertises `ERET` in `FEAT`, instead of `REST`
followed by a transfer that runs to EOF. An origin that advertises it and then
refuses it is served from the positioned `REST`+`RETR` path. It is deliberately
never sent outside `mode=e`: a door that ignored the window and answered with
the whole file from offset 0 would be undetectable in stream mode, whereas an
extended block carries the absolute offset that gives it away.

Available operations are range/full read, stat/list, MKCOL, MOVE, DELETE,
whole-object staged PUT with origin-side temporary-name promotion, and
same-origin `COPY`. A typed read-only export rejects mutations in the VFS
before any FTP command reaches the origin.

**`COPY` between two paths of one export is served by the gateway**, not by the
client. FTP has no server-side copy verb, so the bytes still move — but only on
the gateway↔origin link, over one control session: the source is sized, read
into a local scratch file, stored under a random temporary name and promoted
with `RNFR`/`RNTO`. The destination therefore appears whole or not at all; a
failed copy renames nothing and removes its own temporary. A transfer shorter
than the size the origin itself reported is refused rather than published,
because a bounded read that stops early is not an error the origin reports.
Copying a path onto itself is refused: it would work, and it would rewrite a
healthy object for no gain.

**`sshftp://` is not a supported scheme.** GridFTP-over-SSH requires the
control transport to terminate on the storage host, which means a child process
per session; nginx workers may not fork. An `ssh -L` tunnel is not a
substitute, because the data channel connects to the control channel's own
peer — which through a tunnel is `127.0.0.1`, not the origin.

---

### `brix_storage_backend forward://<protocols> permit=<host|.suffix>…` — forwarding proxy (client-named origins)

**Roles:** `brix_storage_backend` only (an export origin; refused on every
`brix_cache_store` / `brix_stage_store` / `brix_cold_store` line) ·
**Driver:** `xroot_fwd` · **Since:** 2.0 (F5, XrdPss forwarding mode:
`pss.origin = *` + `pss.permit`)

A fixed `root://host:port` origin makes the export a proxy for **one**
server. A `forward://` origin makes it a proxy for whichever server the
client names *inside the path it opens*, the XrdPss forwarding convention:

```text
xrdcp root://proxy.example.org//root://origin.example.org:1094//data/f.bin .
xrdcp root://proxy.example.org//roots://tape.example.org//data/f.bin .
```

The key `/root://origin.example.org:1094//data/f.bin` is split into
`{scheme, host, port (default 1094), remote path}`; one origin child (the
ordinary `root://` driver, so `verify_pages`, `nearline`, `credential=`,
the `_cred` identity plane and the cache/stage decorators all apply per
origin) is created on first use for each distinct admitted `host:port` and
reused after that. Every namespace and data verb is relayed to that child;
`rename` and `server_copy` refuse `EXDEV` (`kXR_NotAuthorized`) unless both
keys land on the same origin — an origin cannot move a file it does not
hold.

Two operator gates decide what the proxy will dial on a client's say-so.
Both are mandatory:

- `forward://<protocols>` — a comma list of `root` and/or `roots`, in any
  order: the schemes a client may name. A key whose scheme is outside the
  list is `kXR_Unsupported`; an empty list, an unknown scheme or a dangling
  comma is a configuration error.
- `permit=<host|.suffix>` — repeatable; the hosts the proxy may dial. An
  entry is an exact host or a leading-dot domain suffix (`.example.org`
  permits hosts *under* that domain and nothing that merely contains it).
  The match rule is the TPC source-egress guard's, so a forwarded open and
  a TPC pull agree on what `.example.org` permits. A host outside the list
  is `kXR_NotAuthorized` **before any resolve or connect** and is logged as
  a refusal. A `forward://` line with **no** `permit=` is refused at
  `nginx -t`: an empty list would relay to any origin a client names.

A key that names no origin (`/data/f.bin` on a forwarding export) is
`kXR_NotFound` — there is no default origin to fall back to. `permit=` is
accepted only on a `forward://` backend line; on a fixed `root://` origin
or on any store tier it is a configuration error, so a permit list is never
written where nothing honours it.

```nginx
# Forward root:// and roots:// to any host under two site domains.
brix_storage_backend forward://root,roots permit=.example.org permit=.cern.ch;

# One named origin only, every page verified as it arrives.
brix_storage_backend forward://root permit=origin.example.org verify_pages=require;
```

Pinned by `tests/test_release20_forward_proxy.py` (grammar accept/reject,
a byte-exact forwarded read and stat, the three refusals — unsupported
scheme, no origin named, host outside the permit list answered without a
dial — the anchored suffix rule, a permitted-but-dead origin failing
promptly, and the fs_list / build / slot-matrix census) and by
`tests/test_sd_xroot_fwd_key.py` (the key parser and the permit verdict as
a standalone C unit suite).

---

### `brix_root on|off`

**Required (stream).** Enables the XRootD (`root://`) protocol handler for this server block.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;       # ← this activates the module
        brix_export /data;
    }
}
```

Without `brix_root on`, nginx ignores all other `brix_*` directives in the block.

---

#### Advertised node identity (`XRDNET_IDENTITY`)

The name a server publishes wherever a client may dial it back — the
`kXR_locate` token when the client sets `kXR_prefname` (stock `xrdfs
spaceinfo`, `locate -h`) and the `cms.d` registration `<host>:<port>` — is
`gethostname(2)`, unless the environment variable `XRDNET_IDENTITY` names a
syntactically valid host name (letters, digits, `.`, `-`, `:`; at most 255
bytes). It is the same short-circuit stock XRootD honours, read once by the
master at configuration time, so it needs no `env` whitelist in `nginx.conf`
and every worker advertises the same name. Use it on a host whose
`gethostname(2)` has no DNS record (a laptop, a container without a FQDN):
clients would otherwise be handed a name they cannot resolve.

---

### `brix_export <path>`

**Default:** `/`

The filesystem directory that clients see as their root (`/`). Every path a client requests is resolved relative to this directory. Paths that try to escape using `..` or symlinks are rejected.

```nginx
brix_export /data/store;   # clients see /data/store as "/"
```

A client requesting `/mc/sample.root` gets `/data/store/mc/sample.root` on disk.

---

### `brix_allow_write on|off`

**Default:** `off`

Whether clients may write, delete, rename, or create directories. Off by default so read-only servers are safe without any extra configuration.

Write operations that require this flag: `kXR_pgwrite`, `kXR_write`, `kXR_sync`, `kXR_truncate`, `kXR_mkdir`, `kXR_rmdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`. A write request to a server where this is `off` returns `kXR_fsReadOnly`.

```nginx
brix_allow_write on;   # allow uploads and deletes
```

---

### `brix_read_only on|off`

**Default:** `off`

Forces the server read-only. Unlike leaving `brix_allow_write` off, this is
applied at **config-merge time** by `brix_shared_apply_read_only()`: it sets
`allow_write` off *before* any token scope is consulted, so a write scope in a
WLCG token, a `brix_allow_write on` later in the same block, or a directive
inherited from an enclosing scope cannot re-open the surface. The override is
announced in the error log at startup rather than applied silently.

Mutually exclusive with [`brix_manager_mode`](#brix_manager_mode-onoff): a
manager redirects path mutations to a data node *before* the local write gate
runs, so the pair would not produce a read-only endpoint. `nginx -t` refuses it
at `[emerg]`.

```nginx
brix_read_only on;     # nothing on this listener can be mutated
```

See [Read-Only Public `root://` Gateway](read-only-root-gateway.md) for the
opcode-by-opcode evidence.

---

### `brix_read_only_public on|off`

**Default:** `off` · **stream (`root://`) plane only**

The public-gateway posture. **Implies `brix_read_only`** — the finaliser turns
it on, so every write gate keyed on `allow_write` covers a public gateway
without knowing this directive exists — and *additionally* refuses the
`kXR_query` infotypes that describe the **server** rather than a path the client
may already read:

| Refused (`kXR_NotAuthorized`) | Still answered |
|---|---|
| `kXR_QStats` (1), `kXR_Qspace` (5), `kXR_Qvisa` (8), `kXR_QFSinfo` (10) | `kXR_QPrep` (2), `kXR_Qcksum` (3), `kXR_Qxattr` (4), `kXR_Qckscan` (6), `kXR_QFinfo` (9) |

Listing, stat, open, read and streaming are untouched, so an anonymous client
can still browse and stream data.

`kXR_Qconfig` (7) is **filtered per key** rather than refused: the protocol's own
capability list and limits (`chksum`, `readv`, `readv_ior_max`, `readv_iov_max`,
`pio_max`, `bind_max`, `fattr`, `tpc`, `tpcdlg`, `cmpread`, `cmpwrite`,
`xrdfs.ext`, `brix.substreams`) still answer, so `xrdcp` capability negotiation
and vector-read tuning work exactly as on a plain `brix_read_only` gateway. The
keys that describe the **deployment** — `version` and `role` — are withheld and
echoed like an unknown key. The `public_safe` column in the descriptor table
defaults to withheld, so a key added later fails closed. See
[§6.3 of the gateway page](read-only-root-gateway.md#63-kxr_qconfig-deployment-identity-withheld-protocol-capability-kept).

```nginx
brix_read_only_public on;   # read-only AND non-disclosing
```

---

### `brix_upload_resume on|off`

**Default:** `on`

Controls upload staging. When on, a fresh write open (`kXR_new`/overwrite) is
**not** written to its final path — the server streams the bytes to a
deterministic, identity-keyed **staging partial file** and **atomically renames
it onto the destination on a clean `kXR_close`**. Readers never observe a
half-written file, and a client that disconnects mid-transfer can reconnect and
**resume in place** (the partial is preserved, not discarded). With it `off`,
fresh uploads are still staged when the client sets POSC (`kXR_posc`) but are not
resumable. A pure in-place update (`kXR_open_updt` with no create) always writes
directly, never through a staging file.

```nginx
brix_upload_resume on;   # stage + atomically move uploads into place (default)
```

---

### `brix_stage_dir <path>`

**Default:** unset (stage alongside the destination file)

Directory for upload staging partials. By default the staging file is created in
the **same directory** as the destination, so the commit `rename(2)` is atomic on
the same filesystem. Point this at a dedicated fast device (e.g. NVMe) to absorb
in-flight uploads there; when the stage dir is on a *different* filesystem than
the storage, the commit transparently falls back to copy-then-rename (still
atomic at the destination). Must resolve within a path the worker can write.

```nginx
brix_stage_dir /srv/fast/upload-staging;
```

---

### `brix_vfs_spill_path <path>`

**Default:** unset (fall back to `brix_stage_dir`; with neither set, reordered
uploads on a staged-only backend are refused)

Scratch root for the VFS writer's **reorder spill** (phase-107 C1). A backend
without random-write capability (an `http://` or `s3://` storage origin) can
only accept an upload as a strictly sequential staged stream; when a client
writes out-of-order (multi-stream `xrdcp`, GridFTP mode E), the writer absorbs
the out-of-order extents into an owned-temp scratch file under this directory
and drains them sequentially into the staged session at close. The path must be
**absolute**, an existing writable directory, and **outside every export root**
— all three are `nginx -t` errors. The directory is registered with the
owned-temp reaper, so a crashed worker's spill scratch is reclaimed at startup.
Telemetry: `brix_vfs_spill_bytes_total`, `brix_vfs_spill_refused_total`,
`brix_vfs_spill_active`.

```nginx
brix_vfs_spill_path /srv/fast/vfs-spill;
```

---

### `brix_vfs_spill_max <size>`

**Default:** `0` (unlimited — the scratch filesystem decides)

Caps the **span** of a single reorder spill (highest absorbed offset, i.e. the
scratch file's apparent size — see `brix_vfs_spill_path`). An upload whose
out-of-order extents would exceed the cap is refused with the same errno a full
scratch device would produce (`ENOSPC`), and nothing is published. Values other
than `0` must be at least `1m` (`nginx -t` error otherwise) — a smaller spill
cannot hold even one typical reordered block, so a tiny value is always a
configuration mistake.

```nginx
brix_vfs_spill_max 2g;   # refuse any single spill spanning more than 2 GiB
```

---

### `brix_durable_publish <on|off>`

**Default:** `on`

The **durable-publish barrier** (phase-107 C3). Every publish that makes a name
visible in the export — a staged-upload commit, a rename — is followed by an
`fsync` of the destination's **parent directory**, so the name itself survives a
crash or power loss (the file *data* was already flushed before the rename; the
directory entry was not). A failed barrier fails the operation: the name is
visible but reporting success would claim durability the store does not have —
the client sees `EIO` and the failure is logged at `crit`. On non-POSIX
backends the barrier dispatches the driver's `sync_publish` slot (a no-op where
the far end's publish is already atomic-and-durable).

`off` trades crash-durability of the *name* for one less fsync per publish —
defensible on a cache/scratch export whose contents are rebuildable, wrong for
an origin. Fails safe: an export with no explicit `off` is always durable.

```nginx
brix_durable_publish off;   # scratch export: rebuildable, skip the dirsync
```

---

### `brix_lock_enforcement <strict|advisory|off>`

**Default:** `strict`

**Cross-protocol lock enforcement** (phase-107 C7). A WebDAV `LOCK` persists as
an xattr on the resource, so the lock state is already visible to every
protocol sharing the export — this directive decides whether it *binds* them.
The VFS lock gate (`brix_vfs_require_unlocked`) runs on every path mutation —
write-open, staged open, delete, rename (both names), copy destination, mkdir,
xattr write — after the read-only policy check (`EROFS` always precedes
`EBUSY`) and walks target → export root, honouring `Depth: infinity` on
ancestor collection locks. A WebDAV client defeats its own lock by presenting
the token in an `If:` header; no other plane can present one, which is what
holding a lock means.

- `strict` — a live foreign lock refuses the mutation on **every** plane:
  `root://` answers `kXR_FileLocked`, HTTP/WebDAV `423 Locked`, S3
  `409 Conflict` + `OperationAborted`, GridFTP `450` (transient). Probe
  failures fail toward enforcement.
- `advisory` — WebDAV refuses as always (its edge check is untouched); the
  other planes log a warning, book the metric, and proceed. One release of
  migration cover for a deployment that discovers stale locks on upgrade.
- `off` — today's behaviour exactly: locks bind WebDAV clients only.

An **expired** lock is treated as absent but never reaped by the gate —
read-time cleanup stays with the writable WebDAV edge, so a read-only export
answers correctly without mutating. Run `tools/diag/lock_scan.py` before
upgrading an export with long-lived locks; watch
`brix_vfs_lock_refused_total{proto}` during an `advisory` window — its rate is
exactly the traffic `strict` will start refusing.

```nginx
brix_lock_enforcement advisory;   # migration window: warn, count, allow
```

---

### `brix_authz_backstop <off|observe|enforce>`

**Default:** `observe`

Re-evaluates the export's native or XrdAcc rules, VO ACL and token scope at the
VFS boundary. Protocol handlers still perform the primary authorization check
and compose their own wire error. The backstop exists so a new or refactored
handler cannot accidentally reach a storage driver without an equivalent
decision.

- `off` — skip the VFS re-evaluation.
- `observe` — allow the operation, but count and warn when the VFS would deny
  it or when a VFS context was not bound to its export's rules.
- `enforce` — return `EACCES` on a disagreement or unbound context. An export
  with no configured rules remains allow-all and is reported separately.

For mutations, the read-only policy always runs first, so `EROFS` continues to
take precedence over `EACCES` and reveals no authorization detail. Watch
`brix_vfs_authz_backstop_total{proto,result}`, where `result` is one of
`agree`, `edge_missing`, `no_rules`, or `unbound`. Both `edge_missing` and
`unbound` must remain zero across real traffic before a deployment opts into
`enforce`.

```nginx
brix_authz_backstop observe;  # rollout-safe coverage audit
```

---

### `brix_posc_persist <auto|manual|off> [hold <time>]`

**Default:** `auto` (no grace period)

The XRootD `ofs.persist` analog. A hard crash (SIGKILL, power loss) during a
non-staged write leaves a `<final>.xrd-tmp.<pid>.<rand>` temp orphaned in the
export tree. At worker startup BriX reaps such orphans whose owner process is
**dead**, while keeping any whose owner is still **alive** (an in-flight write of
a draining worker during a reload). This directive governs that recovery:

- **`auto`** — reap dead-owner orphans (the historical, default behaviour).
- **`manual`** / **`off`** — **keep** orphans in place for an operator to inspect
  or recover manually. (BriX POSC is temp+fsync+rename with no separate tracked
  POSC-state database, so `manual` and `off` both mean "do not auto-reap".)
- **`hold <time>`** — a grace period. Under `auto`, an orphan is reaped only once
  it has been idle at least `<time>` (measured from its mtime), so a temp whose
  writer is about to reconnect and resume is not removed out from under it. A
  temp with a future mtime (clock skew) is treated as fresh and kept.

The reaper runs once at worker-0 startup, so the policy is **node-global**: the
last `brix_posc_persist` in the configuration wins, and a server block without
the directive never overrides one that has it. Changing a running node's policy
requires an explicit directive — a reload that *removes* it keeps the last
explicit value until the next full restart (the fail-safe direction: orphans are
kept, never wrongly deleted).

```nginx
brix_posc_persist manual;              # keep crash orphans for manual recovery
brix_posc_persist auto hold 1h;        # reap, but spare orphans younger than 1h
```

---

### `brix_n2n_scheme identity|ral|cephfs_path`, `brix_n2n_pool <name>`, `brix_n2n_prefix <path>`

**Default:** derived from the backend origin (unset)

Override the export's **name translation** — the map from a wire logical path
(LFN) to the physical name a backend addresses (PFN), and back for directory
listing. Every scheme first canonicalizes the LFN (folds `.` and `//`, and
**rejects** any `..` component) and only then composes the physical name; the
translation runs only *after* the path has been confined to the export, so it
maps an already-legal name and never widens access.

- `identity` — the physical name is the canonicalized LFN.
- `cephfs_path` — `<brix_n2n_prefix><lfn>`; the RADOS/CephFS convention where the
  object/path is a prefix (localroot / key prefix) prepended to the LFN.
- `ral` — `<brix_n2n_pool>:<brix_n2n_prefix><lfn>`; the RAL/Glasgow `XrdCeph`
  object convention where the pool is a `:`-prefix in the name. Requires
  `brix_n2n_pool`.

Left unset, the translation is **derived from `brix_storage_backend`**: a `ceph:`
/ `rados://` origin defaults to `cephfs_path` with the origin's key prefix (the
RADOS pool is bound at the ioctx, so it is *not* named — `ral` is rejected for
the `ceph` backend); every other backend defaults to `identity`. These
directives only override that default.

Validated at `nginx -t`: an unknown scheme, `ral` without `brix_n2n_pool`, `ral`
on the `ceph` backend, a `brix_n2n_pool` over 127 bytes, or a `brix_n2n_prefix`
over 255 bytes is a configuration error (never a silent runtime truncation to a
different physical name). Available on the `root://` (stream), WebDAV and S3
export planes; GridFTP exports take the derived default.

```nginx
brix_storage_backend ceph:xrdtest?/store/;   # → cephfs_path, prefix "/store/"
brix_n2n_prefix /site/atlas/;                # override just the prefix
```

---

### `brix_auth none|gsi|token|both`

**Default:** `none`

Authentication mode:

- `none` — accept any username, no credentials required
- `gsi` — require a valid x509 proxy certificate (see [Authentication](../06-authentication/auth-overview.md))
- `token` — require a valid WLCG/JWT bearer token using the `ztn` security protocol
- `both` — accept either GSI or bearer-token credentials on the same listener

```nginx
brix_auth gsi;
```

---

### `brix_authdb <path>` — native identity authorization

**Context:** stream `server{}` (`brix_root`) · HTTP `location` (`brix_webdav`)

Path to a native authorization-rule file. On the stream (`root://`) plane this is
the engine entry; the runtime engine is chosen by `brix_authdb_engine`
(`native` default / `xrdacc`). On the **HTTP** plane bare `brix_authdb` is the
**native** engine, enforced by the WebDAV access phase for READ methods — reach
the XrdAcc engine on HTTP via `brix_acc_authdb` instead (phase-101 W5). See
[XrdAcc authorization](../06-authentication/authorization-xrdacc.md) and the
[migration guide](migration-unified-grammar.md#phase-101-authdb-engine-split-2026-08--w5).

```nginx
# stream: engine chosen by brix_authdb_engine
brix_authdb        /etc/brix/authdb;
brix_authdb_engine xrdacc;           # stream-only tuner spelling

# HTTP (WebDAV): bare name = native u/g/p engine
location /dav/ { brix_webdav on; brix_authdb /etc/brix/authdb; }
```

#### File grammar

One rule per line, four whitespace-separated fields; `#` starts a comment and
blank lines are ignored:

```
<selectors> <id> <path-prefix> <privileges>
```

**Field 1 — identity selectors.** A *set* of one to six **distinct** letters,
all of which must match (they are AND-ed, so a compound rule is always
**narrower** than any of its selectors alone):

| Letter | Matches | Compared against |
|---|---|---|
| `u` | the authenticated user | GSI DN / SSS user; `*` = any |
| `g` | VO / group membership | the VO-name list (`$brix_vo`); `*` matches even an empty list |
| `p` | the peer address | IP or CIDR string match — **no reverse DNS** in this engine |
| `a` | any identity | takes the id `*`; **may not be combined** with another selector |
| `v` | the VOMS virtual organisation | the vorg CSV derived from the credential's FQANs; `*` = any non-empty |
| `l` | the VOMS role | the role CSV derived from the same FQANs; `*` = any non-empty |

**Field 2 — the id.** A rule with **one** selector takes its id **verbatim** —
a DN is full of punctuation, so nothing is split. A rule with **two or more**
selectors splits its id on `|` into exactly one non-empty component per
selector, positionally: `ug atlasuser|atlas /data rl` means DN `atlasuser`
**and** VO `atlas`.

`v` and `l` together are matched as a **positional pair**: the vorg and the role
must come from the *same* FQAN. A proxy holding `/cms/Role=NULL` **and**
`/atlas/Role=production` therefore does **not** satisfy `vl cms|production`,
which is what an independent match of the two lists would have granted.

**Field 3 — the path prefix.** Longest matching prefix wins among the rules that
carry *enough* privileges; a later rule of equal length overrides an earlier one.

**Field 4 — privileges.** One or more of:

| Letter | Grants |
|---|---|
| `r` | read (implies lookup) |
| `l` | lookup / stat |
| `w`, `a` | update (write; `a` = append, same FS permission) |
| `d` | delete |
| `m` | mkdir |
| `k` | admin |
| `x` | **stage/recall** — `xrdfs prepare -s` / `-e`, and the VFS stage/evict mutations |

There is **no deny record**: a request is denied when no rule with sufficient
privileges matches its path. `x` is its own privilege — granting `w` does *not*
grant staging.

```
# a single-selector rule takes its id verbatim
u /DC=org/DC=example/OU=People/CN=Alice   /data/alice   rlwd
g atlas                                    /data/atlas   rl
p 10.1.0.0/16                              /scratch      rlw
a *                                        /public       rl

# compound rules: one '|'-separated id component per selector, AND-ed
ug alice|atlas                             /data/joint   rl
vl atlas|production                        /data/prod    rlx
```

#### Unparseable lines are refused, not narrowed

An unknown selector or privilege letter, a repeated selector, `a` combined with
another selector, a wrong number of id components or an empty one all **refuse
the whole configuration** at `nginx -t`, naming the file, the line number and
the offending byte:

```
brix_authdb "/etc/brix/authdb" line 7: unknown privilege letter 'z' (the native
authdb engine refuses a line it cannot parse rather than silently dropping part
of it; use `brix_authdb_engine xrdacc` for XrdAcc-format files)
```

Dropping the character instead would hand out a rule the operator never wrote —
usually a **wider** one. An XrdAcc-format file is unaffected: the same file is
read by both engines' parsers, so a native-grammar defect is only raised once
the engine has settled on `native`.

---

### `brix_acc_authdb <path>` — XrdAcc engine (HTTP)

**Context:** HTTP `location`/`server{}`/`http{}` (all brix HTTP protocols)

The XrdAcc-engine entry point on the HTTP planes (WebDAV/S3/cvmfs), with tuners
`brix_acc_format` (`native|xrdacc`), `brix_acc_audit`
(`none|deny|grant|all`), `brix_acc_refresh <secs>`, and the OS/host resolution
family (`brix_acc_gidlifetime`, `brix_acc_pgo`, `brix_acc_resolve_hosts`, …).
On the stream reference plane the equivalents keep the `brix_authdb_*` spellings
(phase-101 W5: prefix names the engine on HTTP).

```nginx
location /s3/ { brix_s3 on; brix_s3_bucket b;
    brix_acc_authdb /etc/brix/authdb;
    brix_acc_format xrdacc;
    brix_acc_audit  all;
    brix_acc_refresh 60;
}
```

---

### `brix_verify_depth <n>`

**Default:** `0` (unlimited)

Cap the maximum X.509 chain depth accepted when verifying a client's GSI
proxy/certificate at `root://` login — the `xrd.tlsca verdepth` analog. `<n>` is
passed to `X509_STORE_CTX_set_depth`, so a client presenting a chain with more
than `<n>` intermediate CAs is rejected. `0` (the default) imposes no limit from
BriX's side (OpenSSL's built-in ceiling still applies), byte-identical to a
server without the directive. Use it to bound absurdly deep proxy/intermediate
chains on a GSI listener.

```nginx
brix_verify_depth 4;
```

---

### `brix_protbind <host-template> [none | [only] <protocol>...]`

**Default:** none (every peer gets the `brix_auth` set)
**Context:** `stream { server { … } }`

Per-host authentication policy — the BriX equivalent of XRootD's
`sec.protbind`. Each occurrence appends one rule; at connection time the
**first** rule whose template matches the peer wins, so specific templates must
come before the `*` catch-all. Protocol names are `gsi`, `ztn` (alias `token`),
`sss`, `unix`, `krb5`, `host` and `pwd`.

- `<protocol>...` — offer these protocols first, then the remaining protocols of
  the `brix_auth` base set
- `only <protocol>...` — offer exactly these and nothing else
- `none` — this peer authenticates anonymously

Host templates follow XRootD's `XrdOucNList` rules: at most one `*`, matched
case-insensitively against the peer's reverse-DNS name, falling back to its IP
literal. Reverse DNS is only performed when at least one rule has a non-`*`
template, and the result is cached for the life of the connection.

The resolved set drives all three stages consistently: the `kXR_protocol`
capability reply, the `&P=…` blocks of the `kXR_login` security token (emitted
in the rule's order — an arbitrary ordered multi-protocol token, not just the
`both` composition), and the `kXR_auth` credential-type gate, which re-checks
membership because a client may offer any credtype regardless of what was
advertised.

Naming a protocol in a rule pulls the listener into that protocol's startup
configuration, so its prerequisites (`brix_certificate`, `brix_token_jwks`,
`brix_sss_keytab`, …) are validated at config time rather than failing the
first handshake.

```nginx
brix_protbind mon.example.org none;          # monitoring probes: anonymous
brix_protbind *.farm.local only unix;        # on-site: unix only
brix_protbind * gsi ztn;                     # everyone else: GSI, then tokens
```

See [`brix_protbind`](#brix_protbind-host-template-none--only-protocol)
for the HTTP/WebDAV face of the same policy.

---

### `brix_sss_getcreds on|off`

**Default:** `off`

Keeps the proxied credential an SSS client may carry inside its credential (the
`CRED` field of the entity). With `off` the parser wipes the blob and the
session's credential stays empty, which is what an endpoint that only needs a
name, a VO and a role wants. Turn it on where something downstream actually
replays the forwarded credential — a gateway hop, a proxy that must present the
user's own token upstream. The blob is opaque to the server: it is never
logged, never parsed, and only its length appears on the accept line.

The keytab still decides how much of the rest is believed. A key that pins the
identity (no `anybody`/`allusers` option) drops the client-asserted VO, role and
endorsements before they reach any authorization decision, logging
`SSS entity fields dropped: keytab pins the identity`; a key that defers lets
them through into the connection's VO/role attributes. Every field has a hard
receiver cap (name/VO/role 256, groups 512, endorsements 1024, credential
4096 bytes) and an over-cap value fails the credential — nothing is truncated.

```nginx
brix_auth         sss;
brix_sss_keytab   /etc/brix/sss.keytab;
brix_sss_getcreds on;      # keep a forwarded credential for the next hop
```

Accepted credentials log one line:
`brix: SSS auth OK user="…" group="…" vorg="…" role="…" endo=<n> creds=<n>`.

### `brix_tls on|off`

**Default:** `off`

Enables XRootD's in-protocol TLS upgrade on a normal `root://` listener. When a
client advertises `kXR_ableTLS`, the server replies with `kXR_haveTLS` and
upgrades the same TCP connection to TLS before `kXR_login` / `kXR_auth`
continue.

Requires `brix_certificate` and `brix_certificate_key`.

Use this on a plain `listen 1094;` style listener. Do not combine it with
`listen ... ssl` on the same stream server; that `roots://` mode is already
encrypted from the first byte. Full details: [tls.md](tls-config.md).

```nginx
server {
    listen 1095;
    brix_root on;
    brix_export /data;
    brix_auth gsi;
    brix_certificate     /etc/grid-security/hostcert.pem;
    brix_certificate_key /etc/grid-security/hostkey.pem;
    brix_trusted_ca      /etc/grid-security/certificates/ca.pem;
    brix_tls on;
}
```

---

### `brix_tls_ciphers <list>`

**Default:** empty (OpenSSL defaults)

Pin the OpenSSL cipher list on the `root://` in-protocol TLS context — the
`xrd.tlsciphers` analog, with the same scope and semantics as nginx's own
`ssl_ciphers` directive (`SSL_CTX_set_cipher_list`, governing TLSv1.2 and below;
TLSv1.3 cipher suites stay OpenSSL's defaults). Empty (the default) leaves the
OpenSSL defaults untouched.

A list that matches **no** ciphers this build can offer is a hard configuration
error (`nginx -t` fails) rather than a silent fallback to the OpenSSL defaults —
so a typo can never leave the listener quietly more permissive than intended.

```nginx
brix_tls on;
brix_tls_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
```

Governs only the TLSv1.2-and-below cipher list. To restrict the **TLSv1.3**
suites — which is where a modern connection actually negotiates — use
`brix_tls_ciphersuites`.

---

### `brix_tls_ciphersuites <list>`

**Default:** empty (OpenSSL defaults)

Pin the **TLSv1.3** cipher-suite list on the `root://` in-protocol TLS context
(`SSL_CTX_set_ciphersuites`) — the companion to `brix_tls_ciphers`, which governs
only TLSv1.2 and below. Because TLSv1.3 is the default protocol on any modern
client/OpenSSL, this is the knob that actually restricts a present-day
connection's ciphers. Suite names use the TLSv1.3 spelling
(`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, …). Empty (the
default) leaves OpenSSL's defaults untouched.

As with `brix_tls_ciphers`, a list matching **no** suites this build can offer is
a hard configuration error (`nginx -t` fails), never a silent fallback.

```nginx
brix_tls on;
brix_tls_ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
```

---

### `brix_tls_reuse on|off`

**Default:** `on`

Controls TLS session resumption on the `root://` in-protocol TLS context — the
`xrootd.tlsreuse` analog. `on` (the default) leaves the OpenSSL/nginx behaviour
untouched. `off` disables **both** the server session cache and TLS session
tickets, so every connection performs a full handshake — use it where
per-connection forward secrecy matters and no resumption state should be
retained (or replayable). Governs only the root:// TLS context; the HTTP side is
controlled by nginx's own `ssl_session_cache` / `ssl_session_tickets`.

```nginx
brix_tls on;
brix_tls_reuse off;
```

---

### `brix_tls_require none|[all|login|session|data|tpc|-<cap>]...`

**Default:** `none`

Per-capability TLS gating (the stock `xrootd.tls` policy). Each named
capability must arrive over a TLS-encrypted connection; a cleartext request
that exercises a required capability is refused with `kXR_TLSRequired`
(`root://`) or `403` (WebDAV / S3):

- `login` — `kXR_login` / `kXR_auth` themselves
- `session` — every post-login operation (locks the whole session, like stock)
- `data` — data-plane transfers (read/readv/pgread/write/writev/pgwrite;
  HTTP GET/PUT bodies)
- `tpc` — third-party-copy opens (native `tpc.*` opens and WebDAV `COPY`)
- `all` — all four; `-<cap>` subtracts one (e.g. `all -tpc`); `none` (alone)
  disables gating

Tokens fold left-to-right. The enforced mask is advertised to `root://`
clients as `kXR_tlsLogin`/`kXR_tlsSess`/`kXR_tlsData`/`kXR_tlsTPC` bits in
the `kXR_protocol` reply, so conformant clients upgrade pre-emptively instead
of eating a refusal. Available on the stream server and every HTTP plane
(WebDAV, S3). Finer-grained than the `brix_min_sec_level` session floor: a
`data`-only mask leaves cleartext metadata (stat/dirlist) untouched.

```nginx
brix_tls_require session data;   # cleartext may login; nothing else
```

---

### `brix_signing_required on|off`

**Default:** `off`

Makes `brix_security_level` **fail-closed** on a session that cannot sign
requests at all.

`brix_security_level` (`none|compatible|standard|intense|pedantic`) says which
opcodes must arrive wrapped in a `kXR_sigver` envelope. Producing that
signature needs a session key, and **only GSI establishes one** — an `sss`,
`ztn`, `krb5`, `unix`, `host` or anonymous session has no key material to sign
with. Historically such a session skipped the level check entirely and was
served unsigned, silently: an operator who set `brix_security_level intense`
on a token listener got *no* tamper protection and nothing in the log said so.

That gap is now always **visible** and optionally **closed**:

- **off** (default) — the request is still served unsigned, but the session
  logs one `WARN` naming the configured level and stating that requests are
  being `accepted UNSIGNED`. One line per session, not per request.
- **on** — the request is refused with `kXR_NotAuthorized`
  (`"request signing required but this session cannot sign"`), so the
  directive means what it reads like it means.

Off by default because turning it on rejects **every** client whose auth
protocol does not sign — including stock clients using `sss`/`ztn`/`krb5` —
which is a deployment decision, not a safe default. Turn it on when the
listener is GSI-only and you want the signing level to be load-bearing.

Session state-machine opcodes (`login`, `protocol`, `auth`, `endsess`, `ping`,
`sigver`, `bind`) stay exempt at every level, exactly as they do for a
signing-capable session — so this can never lock out the handshake itself.

> **Note:** this closes the *silent-bypass* half of the gap. Actually deriving
> a signing key for `sss`/`krb5` (both carry key material, and stock signs
> `sss`) is a wire change requiring matched client and server derivation, and
> is tracked separately in the parity audit §5.2.

```nginx
brix_auth             gsi;
brix_security_level   intense;
brix_signing_required on;      # unsignable sessions are refused, not waved through
```

---

### `brix_ztn_cleartext on|off`

**Default:** `off`

Stock XRootD refuses `ztn` (bearer-token) authentication over a cleartext
connection: a bearer token is replayable by any on-path observer. BriX
matches that default — a cleartext `kXR_login` on a token listener drops the
`ztn` offer (refusing the login outright when no other protocol remains), and
a cleartext `kXR_auth` with a `ztn` credential is refused with
`kXR_TLSRequired`. `brix_ztn_cleartext on` opts a listener back into
cleartext ztn for lab and test rigs that drive the raw wire without TLS.
Never enable it on a production listener.

```nginx
brix_ztn_cleartext on;   # lab only: raw cleartext ztn drivers
```

---

### `brix_certificate <path>`

Path to the server's PEM certificate file. Required when `brix_auth gsi` or `brix_auth both`.

```nginx
brix_certificate /etc/grid-security/hostcert.pem;
```

---

### `brix_certificate_key <path>`

Path to the server's PEM private key file. Required when `brix_auth gsi` or `brix_auth both`.

```nginx
brix_certificate_key /etc/grid-security/hostkey.pem;
```

---

### `brix_trusted_ca <path>`

Path to a PEM file containing the CA certificate (or bundle of CA certificates) that the server trusts for verifying client proxy certificates. Required when `brix_auth gsi` or `brix_auth both`.

It also anchors some outbound legs — the native TPC source's TLS handshake and the Pelican origin — but **not** the `root://` storage backend. That leg (`brix_storage_backend root://…`) is built on a synthetic server config that inherits nothing from this directive: its trust store comes only from `ca_dir` inside the `brix_credential` block named by `brix_storage_credential`. With no `ca_dir` there, the origin's certificate is not verified at all (a silent operator opt-out) and the `root://` TLS upgrade falls back to the system CA bundle. Put the anchor in the credential block:

```nginx
brix_credential origin { x509_proxy /run/proxy.pem; ca_dir /etc/grid-security/certificates; }
brix_storage_credential origin;
```

See [pki.md](../06-authentication/pki-config.md) for CA bundle layout and hash symlink setup.

```nginx
brix_trusted_ca /etc/grid-security/certificates/ca.pem;
```

---

### `brix_crl <path>`

Path to a PEM CRL file or a directory containing CRLs. Directory mode scans `*.pem` and grid-style `*.r0` through `*.r9` files. When configured, GSI verification enables OpenSSL CRL checks for the full certificate chain.

See [pki.md](../06-authentication/pki-config.md) for CRL distribution point conventions and hash symlinks.

```nginx
brix_crl /etc/grid-security/certificates;
```

---

### `brix_crl_reload <seconds>`

**Default:** `0` (disabled)

How often each worker reloads `brix_crl` and rebuilds its GSI trust store. A failed reload keeps the previous store in place.

```nginx
brix_crl_reload 300;  # reload CRLs every five minutes
```

---

### `brix_token_jwks <path>`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation. Used when `brix_auth token` or `brix_auth both` is configured.

```nginx
brix_token_jwks /etc/tokens/jwks.json;
```

---

### `brix_token_issuer <string>`

Expected JWT `iss` claim. Tokens from other issuers are rejected.

```nginx
brix_token_issuer "https://idp.example.com";
```

---

### `brix_token_audience <string>`

Expected JWT `aud` claim. Tokens for other services are rejected.

```nginx
brix_token_audience "my-storage";
```

---

### `brix_access_log <path>|off`

**Context:** stream `server`, HTTP `main`/`server`/`location`

**Default:** `off`

File path for the brix access log. Stream root:// locations write the legacy
per-operation access lines here. HTTP WebDAV/S3/CVMFS locations use the same
file handle for correlated `SESS` lifecycle audit lines when
`brix_session_log` is enabled. See [Metrics & logging](../08-metrics-monitoring/monitoring-guide.md) for the log format and examples.

```nginx
brix_access_log /var/log/nginx/brix_access.log;
```

The file is opened `O_APPEND` so it is safe to share across multiple nginx worker processes. Rotate with `kill -USR1 $(cat /run/nginx.pid)`.

---

### `brix_session_log on|off`

**Context:** stream `server`, HTTP `main`/`server`/`location`

**Default:** `on`

Controls correlated `SESS` lifecycle audit lines. When enabled, sessions write
CONNECT/AUTH/ATTEMPT/RESULT/XFER/END records into the existing
`brix_access_log` stream with a per-session ID.

```nginx
brix_session_log on;
```

Disable this only when the extra lifecycle lines are not wanted; the regular
per-operation access log is controlled separately by `brix_access_log`.

---

### `brix_dashboard on|off`

**Context:** HTTP `location`

**Default:** `off`

Enables the HTTPS monitoring dashboard on the HTTP `/brix/` location. The
dashboard serves an embedded browser page and a JSON snapshot endpoint. Use it
for live operator checks; keep Prometheus scraping `/metrics` for long-term
metrics storage.

```nginx
server {
    listen 8443 ssl;

    location /brix/ {
        brix_dashboard on;
        brix_dashboard_password "change-me";
    }
}
```

The page is available at `/brix/`, the login form at `/brix/login`, and the
compatibility JSON endpoint at `/brix/transfers`. Versioned JSON is available
under `/brix/api/v1/`, including `/snapshot`, `/transfers`, `/events`,
`/history`, `/cache`, and `/cluster`. Serve this location only over TLS and
restrict it to an admin network because it exposes active file paths, client
addresses, and authenticated identities. See
[Metrics & logging](../08-metrics-monitoring/monitoring-guide.md#https-monitoring-dashboard)
for the full dashboard setup.

---

### `brix_dashboard_password <string>`

**Context:** HTTP `location`

**Default:** unset

Password required by the HTTPS monitoring dashboard login form.

```nginx
brix_dashboard_password "change-me";
```

Always set this directive in production. If it is omitted, the dashboard
location is treated as unauthenticated. The session cookie is marked `Secure`,
`HttpOnly`, and `SameSite=Strict`.

---

### `brix_dashboard_session_ttl <time>`

**Context:** HTTP `location`

**Default:** `8h`

Controls the signed dashboard session cookie lifetime. Values use nginx time
syntax.

```nginx
brix_dashboard_session_ttl 4h;
```

---

### `brix_dashboard_cookie_path <path>`

**Context:** HTTP `location`

**Default:** `/brix`

Sets the `Path` attribute on the dashboard session cookie. The value must be a
non-empty absolute path and cannot contain control characters or semicolons.

```nginx
brix_dashboard_cookie_path /brix;
```

---

### `brix_dashboard_idle_threshold <time>`

**Context:** HTTP `location`

**Default:** `5s`

Marks an active dashboard row as `idle` when no bytes have moved for this
duration.

```nginx
brix_dashboard_idle_threshold 5s;
```

---

### `brix_dashboard_stalled_threshold <time>`

**Context:** HTTP `location`

**Default:** `60s`

Marks an active dashboard row as `stalled` when no bytes have moved for this
duration. The value must be greater than or equal to
`brix_dashboard_idle_threshold`.

```nginx
brix_dashboard_stalled_threshold 60s;
```

---

### `brix_dashboard_cluster_stale_after <time>`

**Context:** HTTP `location`

**Default:** `90s`

Marks manager registry entries as stale in `/brix/api/v1/cluster` and the
dashboard cluster panel when their heartbeat age exceeds this duration.

```nginx
brix_dashboard_cluster_stale_after 90s;
```

---

### `brix_dashboard_users <path>`

**Context:** HTTP `location`

**Default:** unset

Loads an htpasswd-like users file for named dashboard operators. Each readable,
non-comment line has the form `username:password-hash`; system `crypt(3)` hashes
are accepted, and plaintext entries are supported for development fixtures. This
directive cannot be used together with `brix_dashboard_password`.

```nginx
brix_dashboard_users /etc/nginx/brix-dashboard.htpasswd;
```

The file is read during nginx config validation/startup. Dashboard audit events
record login success and failure by username, but never record passwords or
cookie values.

---

### `brix_thread_pool <name>`

**Default:** `default`

Name of the nginx thread pool used for async file I/O (reads and writes). Must match a `thread_pool` directive at the main config level (outside `stream {}`).

If the named pool does not exist, the module falls back to synchronous I/O and logs a notice. Synchronous I/O means a slow read blocks all other connections on the same worker process — fine for development, not for production. Read-through cache mode is stricter: `brix_cache on` requires a working thread pool because cache fills perform network and disk I/O.

```nginx
# At the top of nginx.conf, outside stream {}
thread_pool brix_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;
        brix_thread_pool brix_io;
    }
}
```

How many threads to use: a good starting point is one thread per disk spindle, or 4–8 for NVMe/SSD. The `max_queue` value caps how many pending I/O tasks can queue up before new requests start returning errors.

---

### `brix_ckscan_depth <n>`

**Default:** `32`

Maximum directory recursion depth for a single `kXR_Qckscan` request. Entries
below this depth are skipped without failing the scan.

```nginx
brix_ckscan_depth 64;  # Updated: was 32, actual default is 64
```

---

### `brix_ckscan_max_files <n>`

**Default:** `100000`

Maximum number of regular files returned by a single `kXR_Qckscan` request.
Additional files are skipped once the limit is reached.

```nginx
brix_ckscan_max_files 50000;  # Updated: was 100000, actual default is 50000
```

---

### `brix_oss_maxsize <size>`

**Default:** `0` (no cap)

The `oss.maxsize` create-size cap: refuse a root:// data write whose **end**
offset (offset + length) would push the file past this. Enforced across the
whole native write plane (`kXR_write` / `kXR_pgwrite` / `kXR_writev`), so a
client that omits or understates its `oss.asize` hint is still stopped at the
byte that would cross the limit; a refused write commits nothing. `0` keeps the
historical behaviour (no cap).

```nginx
brix_oss_maxsize 10g;
```

---

### `brix_oss_cgroup <name>`

**Default:** `default`

The space-group name the `kXR_Qspace` report advertises as `oss.cgroup` — the
label accounting tools key on. A single-partition site can name its group here;
the value is emitted verbatim into the `&`-joined `oss.*` report, so the name
may not contain a CGI-structural byte (`&`, `=`, space, or a control char) — a
name that does is refused at config parse. This directive names the **default**
group — the one that owns every path no `brix_oss_space` prefix claims. For a
multi-partition site, declare the partitions with
[`brix_oss_space`](#brix_oss_space-group-prefix-quotasize-quota-1), which also
implements the create-time `?oss.cgroup=<name>` selector on write opens.

```nginx
brix_oss_cgroup atlas-datadisk;
```

---

### `brix_oss_quota <size>`

**Default:** `-1` (unlimited)

The space quota the `kXR_Qspace` report advertises as `oss.quota` — the number
`xrdfs query space` and accounting tools display. A site migrating from a stock
`xrootd` server can restore its configured quota here so those tools see the same
value; unset, the report keeps the stock `-1` (unlimited). Accepts the usual size
suffixes (`k`/`m`/`g`); a malformed or negative value is refused at config parse.

On its own this is **advertisement only** — the value is reported but nothing
rejects a write that crosses it. Set
[`brix_oss_quota_enforce on`](#brix_oss_quota_enforce-onoff) to make it
load-bearing for the default group, and declare
[`brix_oss_space`](#brix_oss_space-group-prefix-quotasize-quota-1) groups to
give individual path prefixes their own enforced quotas.

```nginx
brix_oss_quota 500g;
```

### `brix_oss_quota_enforce on|off`

**Default:** `off`

Makes `brix_oss_quota` load-bearing: a `kXR_write`/`writev`/`pgwrite` whose
length would push the export's usage past the quota is refused `kXR_overQuota`.
Usage comes from the same probe the `kXR_Qspace` report advertises — a backend
with a space slot (e.g. `pblock` with `?quota=`) answers from its catalog;
plain POSIX falls back to `statvfs` of the export's filesystem, which is
**conservative on a shared mount** (other tenants' usage counts against the
quota) and exact on a dedicated volume. The probe is cached for 5 seconds per
worker, so enforcement lags a fresh write by at most that much; a probe failure
never blocks writes. Off (the default), the quota stays advertisement-only.

```nginx
brix_oss_quota 500g;
brix_oss_quota_enforce on;
```

---

### `brix_oss_space <group> <prefix> [quota=<size>|quota=-1]`

**Context:** stream server, repeatable. **Default:** no groups — the whole
export is the one default group named by `brix_oss_cgroup` and capped by
`brix_oss_quota`.

Phase-115 W3.3 (2026-09-06, setter `src/core/config/space_group_conf.c`).
Declares a named space group that owns one export-relative path prefix; the
longest matching prefix wins, so nested groups nest naturally. A group's
usage is the sum of the regular files below its prefix (a confined VFS
walk, cached for 5 s per worker and bumped by every admitted write) and its
`quota=` is the cap; `quota=-1` or no `quota=` means accounting only.

- With `brix_oss_quota_enforce on`, the group's quota governs every
  `kXR_write`/`writev`/`pgwrite` under its prefix (`kXR_overQuota` when the
  write would push the group past it), and `brix_oss_quota` then governs
  only paths outside every group.
- `kXR_Qspace` reports the group that owns the queried path, or the one a
  `?oss.cgroup=<name>` selector names, as `oss.cgroup` with the group's own
  used/quota/headroom; an unknown name is the caller's error
  (`kXR_ArgInvalid`, "unknown space group").
- A write open carrying `?oss.cgroup=<name>` must name the group whose
  prefix owns the path (or the default group for a path no prefix owns);
  a mismatch or unknown name is refused `kXR_ArgInvalid` rather than
  silently re-homed. Read opens ignore the key.

`nginx -t` refuses an empty or CGI-unsafe group name (`&`, `=`, space,
control bytes), a prefix that is not an absolute export-relative path or
carries an empty or dot segment or a trailing slash (the bare `/` is
refused: that is the default group), a `quota=` that is not a
non-negative size or `-1`, a group declared twice, and a prefix that
already belongs to another group.

```nginx
brix_oss_cgroup default;
brix_oss_quota 500g;
brix_oss_quota_enforce on;
brix_oss_space atlas-datadisk /atlas/datadisk quota=200g;
brix_oss_space atlas-scratch  /atlas/scratch  quota=-1;
```

---

### `brix_sitename <name>`

**Default:** unset

The human-readable site/node identity for this server — the `all.sitename`
analog. A client reads it via `xrdfs query config sitename` (kXR_Qconfig), and it also
fills the `site="…"` attribute of the kXR_QStats `<statistics>` summary-
monitoring document that federation dashboards read. When unset, the Qconfig
`sitename` query echoes the key (stock's default-config behaviour) and the QStats
`site` attribute is empty, so leaving it out changes nothing.

```nginx
brix_sitename WLCG-Cache-AMS-01;
```

---

### `brix_checksum_default <algo>`

**Default:** `adler32`

The checksum algorithm used when a `kXR_Qcksum` request selects none of its own
(no `<algo>:` prefix and no `?cks.type=<algo>` opaque), and the algorithm
advertised **first** in the `xrdfs query config chksum` list — the entry clients
take as this server's preference when intersecting checksum preference lists.
The `xrootd.chksum` default analog: WLCG sites typically prefer `crc32c`, cloud
deployments `sha256`. Must be one of the built-ins
`adler32`/`crc32`/`crc32c`/`crc64`/`crc64nvme`/`md5`/`sha1`/`sha256`/`sha512`
or a name registered by [`brix_checksum_plugin`](#brix_checksum_plugin-name-path-parms);
alias spellings (`crc64xz` for `crc64`, `zcrc32` for `crc32`) are accepted and
advertised as written. An unrecognized value degrades to `adler32` at use
rather than failing checksums, and is dropped from the advertised list
entirely — the server never offers a name it cannot answer, so a typo costs
you your preference, never a client's transfer. An explicit per-request
algorithm always overrides it.

```nginx
brix_checksum_default crc32c;
```

---

### `brix_checksum_plugin <name> <path> [parms]`

**Context:** `stream` main level or `http` main level (one process-wide
registry, filled by either table) · **Default:** none · **Since:** 2.0

Registers a site checksum algorithm from a shared object, the
`xrootd.chksum <name> <path> [parms]` plugin analog. Once registered the name
behaves exactly like a built-in everywhere an algorithm is named: a
`kXR_Qcksum` with `<name>:` or `?cks.type=<name>`, `brix_checksum_default <name>`,
the `xrdfs query config chksum` list (built-ins first, then plugins, the
configured default at the head), and WebDAV `Want-Digest: <name>` →
`Digest: <name>=<hex>`. No per-protocol configuration is involved.

`<path>` must be an **absolute** path to a **regular file** that is **not
group- or world-writable**. It is `dlopen`ed at configuration time
(`RTLD_NOW | RTLD_LOCAL`), must export one symbol `brix_cks_plugin` of type
`brix_cks_plugin_t` (see `src/core/compat/checksum_plugin_abi.h`, a plain C99
header with no server dependency), and is put through a self-test — `init`
with the `parms` string, an empty `update`, `final` — before the configuration
is accepted. `parms` is optional, at most 255 bytes, and is passed verbatim to
every `init`; a plugin that rejects it fails the self-test. `nginx -t` refuses
every malformed registration with a message naming the cause: relative or
missing path, not a regular file, writable, `dlopen` failure, no
`brix_cks_plugin` symbol, ABI version other than `1`, a plugin `name` that
differs from the directive's, a digest longer than 64 bytes, a state larger
than 4096 bytes, a missing `init`/`update`/`final`, a failed self-test, a name
that is not 1..15 lowercase letters or digits, a name that collides with a
built-in (`crc32` and `crc32c` included) or with an earlier plugin, and a
ninth plugin. A reload rebuilds the registry from the new configuration and
closes the previous objects.

The host owns everything but the arithmetic: it walks the object (any storage
backend, the same reader the built-ins use), calls `update` per chunk on a
per-request stack state, and hex-encodes the digest itself (INVARIANT 9 —
encode at the edge; a plugin never sees the wire). One worker process calls
one plugin's `update` sequence at a time per request, so a plugin needs no
locking but must keep all state inside the `state` block it is handed.

```nginx
stream {
    brix_checksum_plugin fnv1a64 /usr/lib64/brix/brix_cks_fnv1a64.so;
    brix_checksum_plugin sitehash /usr/lib64/brix/brix_cks_site.so "seed=42";
    server { ... brix_checksum_default fnv1a64; }
}
```

`contrib/checksum-plugins/` carries a worked example (FNV-1a 64, with a
`basis=<16 hex>` parm), the build recipe (`cc -shared -fPIC`) and the ABI
contract; `docs/09-developer-guide/checksum-plugins/README.md`.

---

### `brix_admin_socket <path>`

**Default:** unset (no admin socket)

Opens a runtime admin unix socket (the `XrdXrootdAdmin` analog) for inspecting
and controlling live sessions without restarting the server. The socket speaks a
line-based text protocol (a documented divergence — stock's admin wire grammar is
unpublished):

| command | effect |
|---|---|
| `list` | `ok <n>` then one `<sessid-hex> <peer\|-> <dn\|->` line per connection on the worker |
| `disc <sessid-hex>` | disconnect that session gracefully (FIN — the client sees EOF) |
| `msg <sessid-hex> <text>` | deliver `<text>` to that client as an unsolicited `kXR_attn`/asyncms |
| `pause <sessid-hex> [<secs>]` | stop reading that session's requests (they back up via TCP backpressure; in-flight replies still drain); with `<secs>`, auto-resume after that many seconds |
| `cont <sessid-hex>` | resume a paused session and serve whatever backed up |
| `abort <sessid-hex>` | disconnect without ceremony (RST — the client sees `ECONNRESET`) |

Replies are `ok[ <detail>]` or `err <reason>`. The socket files are created mode
`0600` — **filesystem permission on the path is the entire privilege boundary**
(exactly like stock's `adminpath`), so place them in a root/operator-owned
directory. **Every worker serves its own socket**: worker 0 at the configured
`<path>`, worker *n* at `<path>.<n>` — each lists and controls exactly the
sessions its worker owns (a session lives on one worker), so an admin tool
sweeps the socket set; a targeted verb on the wrong worker's socket answers
`err unknown-or-not-local`. With `worker_processes 1` there is just the one
socket. Sessions are listed from connection setup (including mid-login),
matching the stock admin view. Note `pause` does not suspend any armed
read/idle deadlines — a session paused longer than `brix_read_timeout` (when
configured) is still reaped by it.

```nginx
brix_admin_socket /run/brix/admin.sock;
```

---

### `brix_webdav_html_listing on|off`

**Default:** `off`

Render an HTML directory index when a WebDAV `GET` targets a directory (the
XrdHttp *Listing* analog). Off — the stock *listingdeny* posture — returns
`403`. On enumerates the directory through the same impersonation-aware VFS
readdir seam PROPFIND uses (dotfiles and internal sidecars hidden, every name
HTML-escaped) and serves a `text/html` index of name / size / mtime.

```nginx
brix_webdav_html_listing on;
```

---

### `brix_webdav_listing_redirect <url>`

**Default:** unset

The *listingredir* analog: a `GET` on a directory `301`-redirects to
`<url>` with the request path appended, instead of listing. Checked **before**
`brix_webdav_html_listing`, so it wins when both are set.

```nginx
brix_webdav_listing_redirect https://browse.example.org/;
```

---

### `brix_max_delay <time>`

**Default:** `0` (off — the built-in 10 s staging poll interval)

The XrdHttp `http.maxdelay` analog. When a `GET` hits an object that is not yet
online — a nearline (tape) recall is in flight — BriX answers `202` "staging"
with a `Retry-After` telling the client how long to wait before polling again.
That interval is 10 seconds by default; this directive **caps** it, so a
deployment can tighten the recall poll cadence.

It only ever tightens: a value **≥ 10 s is a no-op** (the server never tells a
client to wait *longer* than it already intends), and `0` keeps the 10 s default.
Set it below 10 s when a fast-staging backend or an impatient client fleet wants
snappier polling.

```nginx
brix_max_delay 3s;   # poll every 3 s during a tape recall, not every 10 s
```

---

### `brix_resolver auto|off [path=<file>] [valid=<time>] [min_ttl=<time>] [max_ttl=<time>] [negative_ttl=<time>] [ipv4=on|off] [ipv6=on|off] [search=on|off]`

**Context:** http, server, location, stream, stream server. **Default:** `off`.

Runtime DNS (phase 116). `auto` reads the `resolv.conf` visible to the server
(`path=`, default `/etc/resolv.conf`) at configuration-parse time, seeds the
enclosing block's core `resolver` slot with its nameservers when the operator
wrote no explicit `resolver`, and switches every BriX hostname directive in the
block to runtime resolution: `brix_cms_manager`, `brix_upstream`,
`brix_mirror_url`, `brix_http_handoff` and `brix_transparent_proxy` accept a
name that does not resolve at start-up, the server starts, and the worker
resolves the name from its event loop, re-resolving on TTL expiry. `search=on`
(default) applies the file's `search`/`domain` list and `ndots`. `valid=` pins a
TTL (whole seconds; nginx's resolver has no sub-second unit), `min_ttl`/`max_ttl`
clamp the answer's TTL, `negative_ttl` caches NXDOMAIN. With `off` hostnames are
resolved once at parse time as stock nginx does. Write an explicit `resolver`
*before* `brix_resolver auto` in the same block, never after it.

`path=` must be **absolute**: a relative name would be read against the process
working directory, which differs between `nginx -t` and the master, so the
directive is refused at parse time. The file is re-read on every configuration
load, so a reload picks up a rewritten `resolv.conf` (a container's DNS moving
under the process) without a restart.

What is honoured from the file:

| Line | Honoured | Notes |
|---|---|---|
| `nameserver <ip>` | yes, first 3 | IPv4/IPv6 **literals only** — a name here is ignored, exactly as glibc ignores it. BriX also accepts the `ip:port` / `[v6]:port` form (an extension; glibc has no port syntax) so a test or a sidecar resolver on a non-53 port can be pointed at |
| `search a b …` / `domain a` | yes, first 6 | the **last** such line wins (glibc); a trailing dot is dropped |
| `options ndots:N` | yes | clamped to 15 |
| `options timeout:N` | yes | clamped to 30 s (`0` → 1, as glibc does) |
| `options attempts:N` | yes | clamped to 5 |
| `options rotate` | parsed, **no-op** | accepted so a stock file is not rejected; nginx's resolver already round-robins its nameserver list |
| any other keyword/option | ignored | unknown tokens never fail the parse |
| `$LOCALDOMAIN`, `$RES_OPTIONS` | yes | applied over the file, as glibc does |

A file that cannot be read, or whose `nameserver` lines are **all** unparseable,
is not fatal: BriX logs a warning and falls back to resolution through the libc
resolver on the thread pool — the server still starts, and names still resolve.
That fallback is the whole point of the phase: **no hostname, and no broken DNS,
may keep the server from starting.**

Observability (the `dns` panel of the dashboard snapshot carries the same rows
with the resolver's error text):

* `brix_dns_targets{state="resolving|resolved|failed"}`
* `brix_dns_resolutions_total`, `brix_dns_failures_total`
* `brix_dns_lookups_total{result="ok|nxdomain|timeout|error"}`
* `brix_dns_cache_{entries,hits_total,misses_total,negative_hits_total}`
* `brix_dns_reverse_cache_{entries,hits_total,misses_total,negative_hits_total}`
* `brix_dns_bridge_{requests_total,timeouts_total}` — blocking resolutions
  that crossed from a thread pool into the worker's own resolver, and how
  many of those crossings timed out and fell back to libc

### `brix_dns_retry <initial> <max>`

**Context:** http, server, location, stream, stream server. **Default:** `1s 30s`.

Exponential back-off between failed runtime resolutions of a registered target:
the first retry after `<initial>`, doubling up to `<max>`.

A target whose address is *resolved but unreachable* is re-resolved out of band,
independent of this back-off: when a mirror, CMS or proxy connect fails, the
registry rotates to the next answer for that name and re-resolves it within
~0.5 s instead of waiting out the TTL. IP literals are never re-resolved.

### `brix_dns_cache_max <n>`

**Context:** http, server, location, stream, stream server. **Default:** `4096`.

Upper bound on entries in the per-worker positive/negative answer cache; the
least recently used entry is evicted first. The reverse (PTR) cache uses the
same bound.

### `brix_dns_status_zone <name>`

**Context:** http, server, location, stream, stream server. **Default:** none.

Label reported in the dashboard `dns` panel for targets registered in this
block, so one snapshot can be read per edge/site. The Prometheus gauge
`brix_dns_targets{state="resolving|resolved|failed"}` never carries this label
(low-cardinality rule).

### `brix_ztn_maxsz <size>`

**Default:** `0` (no extra cap)

The ztn `-maxsz` analog: refuse a bearer credential longer than this **before**
any parse/JWKS/crypto work — an unauthenticated peer must not get to choose how
much validation CPU a single `kXR_auth` burns. `0` keeps the historical
behaviour (only the auth frame limit applies).

```nginx
brix_ztn_maxsz 64k;
```

---

### `brix_max_delay <time>`

**Default:** `60s` (stock `ofs.maxdelay`)

Clamp on the seconds any `kXR_wait` may tell a client to stall — staging
recalls, CMS SUPCount floor holds, memory backpressure. Enforced at the single
emission choke point (`brix_send_wait`), so every wait the server can produce
is covered. `0` disables the clamp (an explicitly configured long hold is
answered in full).

```nginx
brix_max_delay 60s;
```

---

### `brix_fsoverload_stall <time>`

**Default:** `1s`

The seconds a read or `readv` deferred by `brix_memory_budget` tells the client
to back off before retrying — the `xrootd.fsoverload` *stall* analog. `1s` is
the historical hardcoded value, so an unconfigured server is unchanged; raise
it to shed load harder under memory pressure. Still clamped by
`brix_max_delay` at the emission choke point.

```nginx
brix_fsoverload_stall 5s;
```

---

### `brix_fsoverload_redirect <host> <port>`

**Default:** unset (off — a memory overload *stalls* per `brix_fsoverload_stall`)

The `xrootd.fsoverload` *redirect* action. When a read or `readv` is deferred by
`brix_memory_budget`, instead of telling the client to back off and retry **here**
(the stall), redirect it to another server — offloading the read to a sibling that
has headroom. Set it to the host and port of another cache/data server in the
mesh; leaving it unset keeps the stall behaviour.

Both overload responses share one choke point, so `brix_max_delay` still bounds
any stall this server does emit. The grammar is two tokens — `<host> <port>`,
**not** `host:port` — a deliberate BriX spelling.

The redirect is only handed to a client that advertised the `kXR_readrdok` login
ability (it can follow a redirect that arrives *during* a read). A client that
did not — an older client, or BriX's own client, whose async engine does not
chase read redirects — instead gets the `brix_fsoverload_stall` back-off even
when this directive is set, so it is never handed a redirect it would mishandle.
The read is simply deferred here until the budget frees.

```nginx
brix_memory_budget       512m;
brix_fsoverload_redirect  cache-b.example.org 1094;   # offload, don't stall
```

---

### `brix_metrics_slowop <usec>`

**Default:** `0` (disabled)

Arm the OssStats-style **slow-op classifier**: any I/O operation whose measured
latency meets or exceeds `<usec>` **microseconds** is booked into the
`brix_io_slowop_total{proto,op}` counter on `/metrics`, and the armed threshold
is exported as the `brix_io_slowop_threshold_usec` gauge. `0` (the default)
disables classification entirely — no counter movement, byte-identical to a
server without the directive.

The threshold is stamped into the metrics shared-memory zone once per config
load, so it applies process-wide to every protocol's latency-sampled ops (the
same completions the `brix_io_latency_seconds` histogram bins). The unit is
microseconds — not a time token — so a fine threshold is expressible. Requires
the metrics zone (an enabled server block). Only ops that file a latency sample
(the AIO data-plane completions) are eligible, matching the histogram's scope.

```nginx
brix_metrics_slowop 500000;   # book ops slower than 500 ms
```

---

### `brix_chkpnt_maxsz <size>`

**Default:** `104857604` (the protocol minimum `kXR_ckpMinMax`)

Largest file `kXR_chkpoint` `ckpBegin` will snapshot — the `ofs.chkpnt maxsz`
analog. `ckpBegin` refuses larger files with `kXR_overQuota`, and `ckpQuery`
reports the cap as `maxCkpSize`. A value below the protocol minimum is raised
to it at merge: `kXR_ckpMinMax` is the "minimum maximum" every server must
accept, so honoring a lower cap would refuse checkpoints a spec-conforming
client is entitled to.

```nginx
brix_chkpnt_maxsz 200m;
```

---

### `brix_vomsdir <path>`

Path to the directory containing VOMS server information (`vomsdir/<vo>/<host>.lsc` files — subject DN then issuer DN of the VOMS signing certificate — or legacy PEM copies of that certificate), one subdirectory per VO. Required when `brix_require_vo` is used. VOMS attribute certificates are verified natively by the module; no VOMS library is needed on the host.

```nginx
brix_vomsdir /etc/voms;
```

---

### `brix_voms_cert_dir <path>`

Path to the hashed CA certificate directory used to chain the VOMS signing certificate embedded in each attribute certificate, with the same CRL and `signing_policy` handling as the GSI identity chain. Required when `brix_require_vo` is used.

```nginx
brix_voms_cert_dir /etc/grid-security/certificates;
```

---

### `brix_require_vo <path> <vo>`

Restricts access to `<path>` (and all descendants) to clients whose VO list includes `<vo>`. For GSI, the VO list comes from VOMS proxy attributes. For token authentication, `wlcg.groups` claims are mapped into the same VO list. Can be specified multiple times for different paths.

`brix_auth gsi`, `brix_auth token`, or `brix_auth both` must be enabled. The directive also requires `brix_vomsdir` and `brix_voms_cert_dir` because the same ACL machinery is used for GSI and token groups.

```nginx
brix_require_vo /atlas atlas;   # only ATLAS members can access /atlas
brix_require_vo /cms   cms;     # only CMS members can access /cms
```

If a GSI client has no VOMS extensions, or a token client has no matching `wlcg.groups`, the VO list is empty and access to protected paths is denied.

---

### `brix_inherit_parent_group <path>`

When a file or directory is created under `<path>`, nginx automatically adjusts its GID and group permission bits to match the parent directory. This mimics the Linux `setgid` bit at the application layer, which is useful when the backing filesystem (e.g. CephFS) does not reliably propagate `setgid` across mounts.

```nginx
brix_inherit_parent_group /cms;   # keep /cms/* group-owned by cms group
```

What happens on each create:
- **File**: GID set to parent GID; group read/write bits copied from parent; group execute preserved if already set.
- **Directory**: GID set to parent GID; group rwx bits copied from parent; `S_ISGID` added if the parent has it.
- **Recursive mkdir (`kXR_mkdirpath`)**: policy applied to each newly created directory level.

---

### `brix_manager_map /prefix host:port`

Map requests for a path prefix to an external manager/redirector endpoint. When a `locate` or `open` request matches a configured prefix the server replies with an XRootD `kXR_redirect` (status `4004`). The redirect body format is a 4-byte big-endian port followed by the host name bytes (ASCII). Lookups use longest-prefix matching; prefixes are normalized by the module before comparison.

The `host:port` value may be an IPv4 address or an IPv6 literal using bracket notation (for example: `[::1]:1234`). See [Manager Mode](../05-operations/manager-mode.md) for full semantics and examples.

```nginx
brix_manager_map /maps backend.example.org:54321;
```

---

### `brix_upstream host:port`

Configures an upstream XRootD redirector to forward requests to when no local `brix_manager_map` prefix matches. The module connects to the specified host:port, performs a minimal XRootD handshake, and relays the client request (currently `kXR_locate`, `kXR_open`, and `kXR_stat`). Upstream responses are forwarded verbatim:

- `kXR_redirect` — forwarded to the client as-is
- `kXR_wait` — timer is scheduled; the request is retried after the specified delay (capped at 60 s)
- `kXR_waitresp` — forwarded to the client; the upstream sends an unsolicited reply when ready
- `kXR_ok` / `kXR_error` — forwarded to the client

Used together with `brix_manager_map` to build a two-tier topology: static prefix rules handle known paths, and the catch-all upstream handles anything else.

When the upstream demands authentication, its `kXR_login` reply carries a security advert (`&P=gsi,…&P=ztn,…`) and the connector answers with the credential that matches it: `brix_upstream_x509_proxy` when the advert offers `gsi`, otherwise `brix_upstream_token_file` when it offers `ztn` (or names nothing the connector recognises); with neither configured the connection is aborted with `upstream requires auth; set brix_upstream_token_file (ztn) or brix_upstream_x509_proxy (gsi) to match its advert`. On the GSI path the upstream's server certificate is verified against `brix_trusted_ca` when that is set; without `brix_trusted_ca` the front logs `brix: upstream gsi: no brix_trusted_ca configured; upstream server certificate not verified` once per handshake and proceeds — the same opt-out the cache origin has.

```nginx
brix_upstream redirector.example.org:1094;
```

#### `brix_upstream_token_file <path>`

**Context:** stream server. **Default:** unset.

File holding the bearer token the transparent upstream connector presents as a `ztn` credential when the upstream's login advert offers `ztn` (or offers nothing the connector recognises). Read synchronously at each authenticated bootstrap, so a rotated token is picked up without a reload. Registered in `src/protocols/root/stream/directives_net.h`; consumed in `src/net/upstream/auth.c` and `src/net/upstream/bootstrap.c`.

#### `brix_upstream_x509_proxy <path>`

**Context:** stream server. **Default:** unset.

X.509 proxy (or plain certificate) PEM the transparent upstream connector presents when the upstream's login advert offers `gsi`. Preferred over `brix_upstream_token_file` whenever both are set and the advert offers `gsi`; the two-round `XrdSecgsi` client handshake is the same kernel the cache origin and the TPC destination use. Registered in `src/protocols/root/stream/directives_net.h`, merged in `src/core/config/server_conf_merge_proxy_net.c`, consumed in `src/net/upstream/auth_gsi.c` (phase-115 W2.4).

#### `brix_upstream_x509_key <path>`

**Context:** stream server. **Default:** the `brix_upstream_x509_proxy` file itself (a proxy carries its private key concatenated, the usual case).

Separate private-key file for a plain-certificate credential given to `brix_upstream_x509_proxy`. Ignored unless `brix_upstream_x509_proxy` is set.

---

### `brix_cache on|off`

**Default:** `off`

Enables read-through cache mode for native `root://` opens. In this mode, read opens are served from `brix_cache_export`. If the requested file is missing, nginx fetches the whole file from the export's `brix_storage_backend root://…` origin into a temporary part file, atomically renames it into place, and then opens the cached copy for the client.

Cache mode is currently direct-mode and defaults to read-only:
- A working nginx thread pool is required.
- The origin fetch is anonymous **unless the export carries a credential**: attach one with `brix_storage_credential <name>` (defined by `brix_credential`) and the in-process origin login presents it — a bearer token over `ztn`, an X.509 proxy over `gsi`, an SSS keytab, or a delegated krb5 TGT, whichever the origin's login advert offers. (Before 2.0 this said authenticated origin fetches were not implemented; that stopped being true in phase-64 §14.)
- The origin must be a **data server**: a `kXR_redirect` from the origin fails the fill with `kXR_Unsupported` rather than being followed. Point `brix_storage_backend` at the data server, not at a manager/redirector.
- By default files are cached as whole files. Set `brix_cache_slice_size` to enable fixed-size partial/range slice caching.
- Cache eviction is best-effort and runs during cache fills when filesystem occupancy is above `brix_cache_eviction_threshold`.
- **Write-through mode** (optional): When enabled via `brix_write_through on`, dirty write handles are mirrored to an origin data server on `kXR_sync` or `kXR_close`.

### `brix_cache_slice_size <size>|off`

**Default:** `off`

Enables fixed-size slice caching for cache reads when `brix_cache on` is also
enabled. A read that touches a missing slice schedules a bounded origin fetch for
that slice and asks the client to retry with `kXR_wait`; later reads can serve
ready slices without fetching the whole origin object. The size must be `off`/`0`
or a positive multiple of 1 MiB.

```nginx
brix_cache_slice_size 128m;
```

### `brix_cache_prefetch <n>` / `brix_cache_prefetch_window <size>`

**Default:** `0` (off) / `8m`

Background block prefetch for the **unified slice cache** (`brix_cache_store` +
`brix_cache_slice_size`, any protocol plane). When a client reads a slice-cached
object sequentially, the serving engine issues a WILLNEED hint through the
storage-driver `read_advise` slot and the cache decorator fills the *absent
successor blocks* on a worker thread — so the next blocks are already local when
the reader gets there, instead of costing one synchronous origin round-trip
each (XrdPfc `pfc.prefetch` parity).

- `brix_cache_prefetch <n>` — max in-flight background fill jobs per worker
  (`0`–`64`; `0` disables the feature entirely: hints are discarded and no
  speculative origin read ever happens).
- `brix_cache_prefetch_window <size>` — how far speculation may run ahead of
  the read cursor (`0` = unbounded to end of object, otherwise ≥ `64k`). The
  window is a *rolling runway*: each handle keeps a prefetch frontier, so a
  long sequential stream is continuously topped up to at most `window` bytes
  ahead of the reader — never burst-then-starve, never re-posted.

Sequential detection lives in the engines: the `root://` read path suppresses
the hint on random access (disable-on-random parity), and the HTTP
memory-backed serve loop only speculates for requests of at least 1 MiB, so
small metadata GETs never amplify origin traffic. Jobs authenticate to the
origin with the credential captured at open, need the `default` nginx thread
pool, and skip blocks the foreground filled meanwhile. Observability:
`brix_cache_prefetch_jobs_total`, `brix_cache_prefetch_blocks_total`,
`brix_cache_prefetch_failures_total` on `/metrics`.

```nginx
brix_cache_store       posix:/var/cache/brix;
brix_cache_slice_size  1m;
brix_cache_prefetch    4;
brix_cache_prefetch_window 16m;
```

### `brix_cache_urlcgi [blocksize {ignore|<min> <max>}] [prefetch {ignore|<min> <max>}]`

**Default:** absent — both hints ignored

Per-open cache hints for the **unified slice cache** (XrdPfc `pfc.urlcgi`
parity, 2.0 F5). An XRootD client may append `pfc.blocksize=<bytes>` and/or
`pfc.prefetch=<blocks>` to the path it opens, exactly as it would against
an XrdPfc proxy. By default the server ignores both. Each clause of this
directive *arms* one hint and bounds it — the client's value is clamped
into `[min, max]`, never refused, so a client can tune the cache for its
access pattern but cannot dictate a geometry the operator did not allow.

- `blocksize <min> <max>` — a **new** slice-cache object opened with
  `pfc.blocksize=` gets that block size, clamped into the bounds and
  rounded down to the 1 MiB slice granule; without a hint the object gets
  `brix_cache_slice_size`. Both bounds are positive multiples of `1m`,
  `min <= max`. An object the cache already holds keeps the geometry its
  cinfo records — a later hinted open adopts it, so two handles never race
  two block maps over one file. A whole-file export (no
  `brix_cache_slice_size`) ignores the hint: it cannot switch an export
  into slice mode.
- `prefetch <min> <max>` — a handle opened with `pfc.prefetch=` gets its own
  speculation runway of that many blocks (× the object's block size),
  clamped into the bounds, in place of `brix_cache_prefetch_window` for
  that handle only; `max` is at least 1, `min` may be 0, and a clamped 0
  switches speculation off for the handle. The engine itself must be on
  (`brix_cache_prefetch > 0`); the hint never starts it.
- `ignore` names a clause explicitly ignored. Naming the directive without
  a clause leaves that clause ignored in this block (it is not inherited
  from the enclosing block); an absent directive inherits the enclosing
  block's, and each clause inherits as a `min max` pair.

The hints ride the `root://` open opaque only (`kXR_open`, read opens; a
write open drops them; an HTTP query string does not carry them). Under
`brix_opaque_strict on` both keys are typed unsigned integers — `pfc.blocksize=abc`
or a negative count is refused pre-handler with `kXR_ArgInvalid`; with
strict off a malformed value is simply dropped, so stock clients that
append junk keep working. The `pfc.` namespace is recognized by the schema
either way.

```nginx
brix_cache_store       posix:/var/cache/brix;
brix_cache_slice_size  1m;
brix_cache_prefetch    4;
brix_cache_prefetch_window 16m;
brix_cache_urlcgi      blocksize 1m 16m prefetch 0 32;
```

Pinned by `tests/test_release20_cache_urlcgi.py` (grammar, strict-schema
typing, and the live clamp: honoured, clamped at `max`, raised to `min`,
rounded, ignored when unarmed, existing geometry wins, whole-file mode
untouched, runway narrowed / switched off / clamped / ignored).

### `brix_cache_only_if_cached on|off`

**Default:** `off`

Serve **only** what this cache already holds. A read whose object is not a
cache hit is refused with `kXR_NotFound` instead of being filled from the
origin (XrdPfc `pfc.onlyifcached` parity).

The point is topology, not policy hygiene: a node in this mode contributes the
copies it has and never becomes an origin puller, so a client that asks for
something it does not hold gets a clean "not here" and fails over to another
replica — rather than making this node fetch across the WAN on its behalf.
The refusal is deliberately `kXR_NotFound` and not a server error, because a
client retries a server error against the *same* node but moves on from a
not-found.

Placement of the gate matters and is fixed:

- **after** the cache-hit test — an object that IS cached still serves normally;
- **before** the admission filter and before the fill / nearline-recall paths —
  otherwise a path the admission policy declined would still reach the source,
  which is exactly the bypass this mode exists to prevent.

Writes are never gated; they pass through as usual. A *partial* (slice) hit
counts as a miss — upstream's `minsize` / `minfrac` partial-hit thresholds are
not implemented.

### `brix_cache_uvkeep <time>`

**Default:** `0` (off — a never-verified entry is trusted until its normal TTL)

Bound how long a cached entry whose contents were **never verified** against the
origin may be trusted (XrdPfc `pfc.uvkeep` parity). Some fills carry no origin
digest to check against — a TLS-trusted whole-file or slice fill, for example —
and are committed with the cinfo `F_VERIFIED` flag clear. With `uvkeep` set, such
an entry that is older than `<time>` (measured from when the fill published it) is
treated as a **miss** on the next open, so the cache revalidates it against the
source before serving.

The knob only ever **adds** revalidation:

- a **verified** entry (contents checked against the origin digest) is never aged
  out by `uvkeep`;
- an unverified entry still **inside** the window serves from cache as usual;
- an entry with no recorded fill time (legacy) is exempt.

So the fail-safe direction is "revalidate more", never "serve something staler".
BriX's revalidation is a full refill through the miss path — stronger than a
conditional `HEAD` — so an origin unreachable at that point fails the open rather
than serving the unverified copy.

```nginx
brix_cache_uvkeep 30m;   # re-check a never-verified entry at least every 30 min
```

```nginx
brix_cache_store          posix:/var/cache/brix;
brix_cache_only_if_cached on;
```

### `brix_cache_serve_while_filling <time>`

**Default:** `0` (off — a reader waits for the whole-file fill to commit)

Let a reader that arrives during another reader's **whole-file fill** follow that
fill instead of serialising behind it (XrdPfc serve-while-filling parity). The
follower reads the staged, not-yet-committed bytes up to the **fill frontier**;
a read at the frontier is answered `kXR_wait`, so the client streams at the
origin's pace rather than paying the whole object's transfer time before its
first byte. `<time>` is the **no-progress deadline**: if the frontier has not
advanced for that long the follower gives up (the filler died without cleaning
up) rather than waiting forever.

Slice mode (`brix_cache_slice_size`) already serves partial content on demand
and is unaffected — this knob is the whole-file equivalent.

Bounds worth knowing before enabling it:

- It applies only to a **local** cache store (`posix:`); a remote store has no
  staged file for a follower to open.
- It applies only when **`brix_cache_verify` is `off`**. Under any verifying
  mode the staged bytes are provisional — the digest or signature check runs at
  commit and may still reject them — so following them would mean serving bytes
  that were never verified.
- A followed object is never sent with `sendfile`: the file is still growing, so
  the follower is served from memory-backed buffers only.
- If the fill **aborts**, every follower's next read fails `kXR_IOError`; the
  staged file is unlinked before the coordination marker is, so a follower can
  never mistake a truncated fill for a clean end of file.
- A large read already streaming when it reaches the frontier ends **short**
  (a normal `kXR_read` outcome) and the client re-reads from there; only a read
  that has not yet put bytes on the wire receives `kXR_wait`.

```nginx
brix_cache_store               posix:/var/cache/brix;
brix_cache_serve_while_filling 30s;   # follow an in-flight fill; give up after
                                      # 30s with no frontier progress
```

### `brix_cache_cold_max_age <time>`

**Default:** `0` (off)

Age-based purge of **clean read-through fills**: a cached object nothing has
touched for longer than this is removed regardless of occupancy (XrdPfc
`pfc.purgecoldfiles` parity).

The watermark reaper (`brix_cache_high_watermark`) only runs once the
filesystem crosses its high-water mark, so on a roomy cache an object nobody
reads is kept forever. This horizon releases it. Losing it costs nothing: a
clean read-fill is re-fetchable from the origin, which is why only *clean*
fills are eligible — dirty write-back staging is bounded separately by
`brix_cache_dirty_max_age`, and a finished write-back copy by that same
horizon.

Age is measured from the **later of atime and mtime**. atime alone is not
trustworthy — `relatime` coarsens it and `noatime` freezes it entirely, which
would make every file look ancient and purge a hot cache. Taking the later of
the two degrades safely: on a `noatime` mount the age is effectively measured
from the fill instead of the last read, so the purge can only ever be too slow,
never too eager.

Off by default, deliberately: unlike the dirty horizon (which bounds a leak)
this one **discards otherwise-serviceable cache**, so it is only ever an
explicit operator choice. It runs on the same per-worker maintenance timer as
the stale-dirty reaper — that timer is now armed by *either* horizon.
Observability: `brix_cache_dirty_reaped_total{reason="cold"}` on `/metrics`.

```nginx
brix_cache_store        posix:/var/cache/brix;
brix_cache_cold_max_age 7d;
```

### `brix_cache_max_bytes <size>`

**Default:** `0` (off)

Cap the cache's **own total bytes** (XrdPfc `pfc.diskusage files` parity). This is
a second, independent reaper arm alongside the ppm filesystem-occupancy watermark
(`brix_cache_high_watermark`): when the sum of what this cache holds exceeds the
cap, the watermark reaper evicts oldest-first until it is back within it.

It exists because occupancy and footprint are not the same thing on a **shared
filesystem**. `statvfs` reports the whole mount's fullness — everyone's data — so
the ppm watermark either never fires (a huge mount the cache never fills) or
thrashes (a noisy neighbour fills the disk and the cache reaps itself to nothing).
A byte cap bounds the cache by what it actually owns, regardless of the neighbours.

The two arms compose: with both set, each tick reaps down to the FS low-water
mark *and* down to the byte cap. The byte arm uses the same LRU candidate set and
the same eviction (cold-tier demote, manager-unregister, sidecar cleanup) as the
occupancy arm — only the stop condition differs. The reaper timer is armed by
*either* arm, so a byte cap works even with no FS watermark configured.

Notes: eviction is **down to** the cap (there is no separate low mark; the reaper
cadence, `brix_cache_reap_interval`, rate-limits re-eviction). The owned-bytes sum
includes each object's small `.cinfo`/`.meta` sidecars, so it slightly over-counts
and evicts marginally sooner than a data-only measure.

```nginx
brix_cache_store     posix:/var/cache/brix;   # shares the mount with other data
brix_cache_max_bytes 200g;                    # keep our footprint under 200 GiB
```

### `brix_cache_store ram:<size>` — the in-memory cache store

**Since:** Phase 115

A cache store URL of the form `ram:<size>` puts the hot cache in memory instead
of on a filesystem. The whole location is the byte cap — there is no path:

```nginx
brix_cache_store ram:2g;    # 2 GiB of cache, per worker
```

**The size is PER WORKER.** The store is a per-worker heap object table, matching
how the stock in-memory caches it mirrors are scoped, so `ram:8g` on a server
with 16 workers is up to 128 GiB of resident memory. nginx logs the resolved
capacity at NOTICE on startup with `PER WORKER` spelled out; check it there
before sizing.

The cap is HARD, not a watermark. A fill reserves its declared size when it
opens, so two concurrent fills cannot both be told there is room for the same
bytes, and the store evicts its own coldest entries (LRU, skipping objects a
client currently has open) to make room. The shared eviction reaper —
`brix_cache_eviction_threshold`, `brix_cache_max_bytes`, `brix_cache_reap_interval`
— does not apply: those take a lock file inside a physical cache root, which a
memory store does not have. There is nothing to configure; the cap *is* the
policy.

When the store cannot fit an object at all (it is larger than the whole cap, or
every resident object is currently open), the fill is refused and the read is
served straight from the source. A full memory cache is a slower server, never a
failing one.

`ram:` is accepted **only** as `brix_cache_store`, the hot cache:

| Directive | `ram:<size>` | Why |
|---|---|---|
| `brix_cache_store` | accepted | losing the store costs a refill and nothing else |
| `brix_stage_store` | refused at config time | a staged write would be ACKed to the client and then lost on restart |
| `brix_storage_backend` | refused at config time | it would be the only copy of every byte |
| `brix_cache_cold_store` | refused at config time | the demotion target must not be costlier and more volatile than the tier demoting into it |

A size of `0`, or one nginx's size grammar cannot parse, is refused: an
unbounded memory store is an out-of-memory kill, not a configuration.

**Observability:** every export with a `brix_cache_store` counts as a cache
for `/metrics` (since 2.0; before, only `brix_cache on` did and the tier grammar
emitted no cache rows at all). `brix_cache_occupancy_ratio` and
`brix_cache_bytes` are rendered from the store's own capacity report
(`brix_cstore_freespace`) — for `ram:` that is the configured size as `total`
and resident bytes plus in-flight fill reservations as `used` — and fall back
to a `statvfs` of the legacy `brix_cache_export` root only when the store has
no report of its own. The store is per worker, so the row describes the worker
that served the scrape, and the rows appear once the export has accepted its
first TCP connection (the slot is published at accept time, before any
handshake). `brix_cache_eviction_threshold_ratio` still reports
`brix_cache_eviction_threshold`, which is the legacy reaper's setting, not the
`ram:` LRU's. Pinned by `tests/test_release20_ram_cache_metrics.py`.

### `brix_write_through on|off`

**Default:** `off`

Enables write-through behavior for native XRootD writes. When this is `on`, write-mode `kXR_open` requests are evaluated by the WT decision policy and eligible handles are mirrored to an origin server.

In this mode:
1.  **Open**: The module opens the local file and caches the WT allow/deny decision on the handle.
2.  **Write**: `kXR_write`, `kXR_pgwrite`, `kXR_writev`, and handle-based `kXR_truncate` update the local file and mark the handle dirty.
3.  **Sync**: `kXR_sync` mirrors the full local file to the WT origin, then sends origin truncate and sync. Origin failures are returned to the client.
4.  **Close**: Dirty handles are flushed on close. `sync` mode blocks during close; `async` mode posts the flush to the configured nginx thread pool. Close-time origin failures are logged but do not fail the close response.

> **Note:** Write-through mode uses whole-file replacement at sync/close, not per-write dual dispatch. It is a good fit for ingest-style workflows and less suitable for very large random-write workloads.

```nginx
thread_pool brix_cache_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;                # namespace used for ACL matching
        brix_storage_backend root://origin.example.org:1094;
        brix_cache_store     posix:/var/cache/brix;
        brix_cache_export    /;
        brix_cache_eviction_threshold 0.9;
        brix_thread_pool brix_cache_io;

        brix_write_through on;
        brix_wt_mode sync;                  # sync | async
        brix_wt_origin origin.example.org:1094;
        brix_wt_allow_prefix /data/ingest/;
        brix_wt_deny_prefix /data/private/;
    }
}
```

### `brix_wt_mode sync|async`

**Default:** `sync`

Controls close-time WT flush behavior. `sync` mirrors dirty data before
`kXR_close` completes. `async` posts the mirror operation to the configured
thread pool and releases the handle immediately. Explicit `kXR_sync` requests
always flush synchronously.

### `brix_wt_origin <host:port>`

Sets the WT origin data server. **Required** for write-through: with no
`brix_wt_origin` the write-back stage is not built and `brix_wt_mode` has no
effect. (Before 2.0 this said write-through fell back to `brix_cache_origin` —
that family was retired in phase-64 and the fallback read a field no directive
could write, so it never fired.) The value is a bare `host:port`; a write-through
leg to a TLS origin is not supported in 2.0.

### `brix_wt_allow_prefix <path>` / `brix_wt_deny_prefix <path>`

Repeatable WT policy filters. Deny prefixes take precedence over allow
prefixes. If one or more allow prefixes are configured, paths that match none
of them are treated as local-only writes.

---

### `brix_cache_export <path>`

Local directory used to store cached files. Client paths map directly under this directory, so a request for `/store/a.root` becomes `/var/cache/brix/store/a.root` when `brix_cache_export /var/cache/brix;` is configured. The directory must exist and be readable, writable, and searchable by nginx at startup.

```nginx
brix_cache_export /var/cache/brix;
```

---

### Cache origin — `brix_storage_backend root://host:port`

The legacy `brix_cache_origin*` family is retired (phase-64 §14). A cache's source is the export's `brix_storage_backend` (`root://` or `roots://` for TLS from the first byte), its identity a named `brix_credential` attached with `brix_storage_credential`, and the physical cache is `brix_cache_store`.

```nginx
brix_storage_backend roots://origin.example.org:1095;
brix_cache_store     posix:/var/cache/brix;
brix_cache_export    /;
```

When outbound TLS is enabled, nginx verifies the origin certificate using `brix_trusted_ca` if configured, otherwise OpenSSL's default trust paths.

---

### `brix_cache_lock_timeout <time>`

**Default:** `300s`

How long a worker waits for another worker's in-progress fill of the same file. Cache fills use per-file `O_EXCL` lock files under the cache directory, so concurrent opens of the same missing path collapse to one origin transfer.

```nginx
brix_cache_lock_timeout 600s;  # Updated: was 120s, actual default is 600s
```

---

### `brix_cache_eviction_threshold <ratio|percent>`

**Default:** `0.9`

High-water filesystem occupancy threshold for cache eviction. When a cache fill sees `brix_cache_export` above this ratio, one worker takes a cache-wide eviction lock and unlinks the oldest regular cached files until occupancy drops back to the threshold or no candidates remain.

The value may be written as a ratio (`0.85`) or a percent (`85` or `85%`). Temporary part files, fill lock files, the eviction lock, files on a different filesystem, and the file currently being filled are skipped.

```nginx
brix_cache_eviction_threshold 0.85;
```

---

### `brix_cache_store_endpoint on|off`

**Default:** `off` — valid on the HTTP planes (`http|server|location`) and, since the root:// plane gained it, on `stream server`.

Declares this server the **trusted remote cache-STORE surface** for a cache node whose `brix_cache_store` points at it. Internal reserved names — `<key>.cinfo`, `<key>.meta`, stage markers — are answered as absent on every ordinary export (a client must not be able to read or create one). A cache node running `brix_cache_meta sidecar` against a remote store writes exactly such a name beside each object, so without this switch the sidecar `kXR_open` is refused `kXR_NotFound` (3011), every cinfo store fails, and the tier silently refills on every read.

```nginx
stream {
    server {                       # the store node
        listen 1096;
        brix_root on;
        brix_export /srv/cachestore;
        brix_allow_write on;
        brix_cache_store_endpoint on;
    }
}
```

The switch lifts the reserved-name guard for `kXR_open`/`kXR_stat`/`kXR_statx` **only**. Directory listings still skip internal names (a cache addresses its sidecars by exact name, so nothing needs them enumerated), and export confinement is untouched. Leave it `off` on every client-facing export.

---

### `brix_cache_verify off|best-effort|require`

**Default:** `best-effort` on a standalone `brix_cache` read-through cache; `off` on a composed `brix_storage_backend cache:…` tier.

Checksum-on-fill integrity for the read-through cache. A completed fill is hashed in its `.part` staging file — **before** the atomic rename that publishes it — and compared to the digest the origin advertised. A mismatch discards the part, so a truncated or corrupted transfer never becomes a served cache entry; a match records the verified digest in the entry's `.cinfo`.

| Value | Meaning |
|---|---|
| `off` | Never verify. |
| `best-effort` | Verify whenever the origin supplies a digest this build can compute; publish flagged *unverified* when it cannot. Never publishes a proven-bad file. |
| `require` | A usable digest is mandatory — a fill whose origin advertises none fails instead of publishing. |

The HTTP planes (`http|server|location`) accept `off` plus the three **self-verifying** grammars, where the cache key itself names the digest and no origin round-trip is needed: `cvmfs-cas` (the CVMFS object name is a SHA-1), `oci-digest` (an OCI blob key names a SHA-256) and `rpm-repodata` (createrepo names each metadata file `<checksum>-<name>`). `best-effort`/`require` are stream-plane (`root://`) values.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_cache on;
        brix_cache_export /var/cache/brix;
        brix_storage_backend root://origin.example.org:1094;
        brix_cache_verify require;          # publish nothing we cannot prove
    }
}
```

The two defaults differ on purpose and are load-bearing: a standalone cache has verified best-effort since the feature shipped, and 2.0 keeps that; a composed tier treats an unset policy as `off` so adding a cache decorator to a chain never silently adds origin checksum round-trips. Set the directive explicitly whenever the distinction matters.

> **2.0 fix.** Before 2.0 the standalone spine read an internal field that no directive could write, so `brix_cache_verify off` and `brix_cache_verify require` parsed but did nothing there — every standalone cache verified best-effort whatever the configuration said. Both values are now honoured on both spines.

---

### `brix_cache_verify_digest <algorithm>`

**Default:** unset — the origin picks.

Names the checksum algorithm a **non-`root://`** origin is asked for when `brix_cache_verify` is armed. An `xroot://` origin is asked with `kXR_Qcksum` and answers with whatever it holds, so this directive does not apply to it; an HTTP/Pelican origin is asked with `Want-Digest`, and an object store is asked for a stored checksum, and both need to be told *which* digest to return.

The value must be an algorithm this build can compute locally — the same names `brix_checksum_default` accepts (`adler32`, `crc32`, `crc32c`, `md5`, `sha1`, `sha256`, `sha512`, `crc64`, `crc64nvme`, plus any name added by `brix_checksum_plugin`). An unknown name fails `nginx -t`; the directive may appear once per scope. Valid on `stream server` and on `http|server|location`.

```nginx
brix_cache_verify        best-effort;
brix_cache_verify_digest sha256;        # ask the HTTPS origin for Want-Digest: sha-256
```

With `brix_cache_verify require` and no digest the origin can produce, the fill fails rather than publishing — naming an algorithm the origin does not support is therefore a fail-closed configuration, not a silent downgrade.

---

### Pelican federation cache advertisement — `brix_cache_advertise*`

A cache node can publish itself to a [Pelican](https://pelicanplatform.org/) federation Director so the Director redirects clients to it. Each advertisement is a signed `OriginAdvertiseV2` document POSTed to the Director's `/api/v1.0/director/registerCache`, carrying a short-lived ES256 JWT (`scope: pelican.advertise`) signed with the cache's own key. A per-worker timer re-advertises on the configured cadence; the Director expires ads that stop arriving.

The Director's address is not configured directly: the advertiser fetches `https://<federation>/.well-known/pelican-configuration` from the authority named by `brix_cache_advertise_federation` and POSTs to the Director that document names. **Without a federation the advertiser never arms** — see the 2.0 note at the end of this section.

The cache's **public key must already be registered with the federation registry** — that handshake is an out-of-band operator step and is not performed by this module.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_cache on;
        brix_cache_export /var/cache/brix;
        brix_storage_backend https://origin.example.org;

        brix_sitename                    ral-cache-01;
        brix_cache_advertise             on;
        brix_cache_advertise_federation  osg-htc.org;
        brix_cache_advertise_key         /etc/brix/pelican-ec-p256.pem;
        brix_cache_advertise_data_url    https://cache01.example.org:8443;
        brix_cache_advertise_web_url     https://cache01.example.org;
        brix_cache_advertise_issuer      https://issuer.example.org;
        brix_cache_advertise_interval    60s;
        brix_cache_advertise_namespace   /cms;
        brix_cache_advertise_namespace   /atlas;
    }
}
```

| Directive | Default | Meaning |
|---|---|---|
| `brix_cache_advertise on\|off` | `off` | Arm the per-worker advertisement timer. A no-op unless a signing key and a data URL are also configured. |
| `brix_cache_advertise_federation <host[:port]>` | unset | The federation's discovery authority, e.g. `osg-htc.org`. An **authority only** — a scheme or a path is a parse error — fetched as `https://<host>:<port>/.well-known/pelican-configuration` to find the Director. Port defaults to 443. Unset, nothing is ever advertised. The name is resolved at advertise time, not at parse time, so a federation that is briefly unresolvable does not block start-up. |
| `brix_cache_advertise_key <path>` | unset | PEM EC (P-256) private key that signs the advertise JWT. Loaded once per worker at start-up; a key that fails to load disables advertising with a logged error, it does not stop the server. |
| `brix_cache_advertise_data_url <url>` | unset | The public URL clients are redirected to for data. Required. |
| `brix_cache_advertise_web_url <url>` | unset | The node's public web/UI URL, published for operators. |
| `brix_cache_advertise_issuer <url>` | unset | Token issuer advertised to the federation. |
| `brix_cache_advertise_interval <time>` | `60s` | Re-advertisement period. Clamped **up** to the federation minimum of 60s. |
| `brix_cache_advertise_namespace <prefix>` | none | A namespace prefix this cache serves. Repeatable; an advertisement with no namespace advertises none. |

The site name comes from the existing [`brix_sitename`](#brix_sitename-name) — the same label `xrdfs query config sitename` answers with — and becomes the registry prefix `/caches/<sitename>`. Unset, the advertisement falls back to `nginx-xrootd-cache`.

> **2.0 fix (two layers).** The advertiser, its timer and its document builders shipped before 2.0, but no `ngx_command_t` registered seven of the directives above: every one was an “unknown directive”, so the feature could not be turned on from a configuration file at all. Registering them exposed the second layer — the scheduler read its federation authority from the host of the long-retired `brix_cache_origin`, a field no directive could write, so the advertiser was still permanently disarmed. `brix_cache_advertise_federation` is the eighth name, added in 2.0 to close that. Both layers are pinned by `tests/test_release20_registered_nowhere.py` and `tests/test_release20_never_armed.py`.

---

### `brix_cms_manager host:port [host:port ...]`

Registers this data server with one or more XRootD CMS managers and starts a
heartbeat connection to EVERY one of them concurrently (stock `all.manager`
parity: a node joins the whole redundant manager set, not just the first).
Manager addresses are resolved during config parsing.

Accepts multiple endpoints on one directive and/or repeated directives — the
entries accumulate, capped at 15 (stock `XrdCmsFinder MaxMan`).  A duplicate
endpoint (same resolved address) is rejected at parse time: stock managers
blacklist a second login from the same node identity, so a duplicate would
break the node's cluster membership rather than add redundancy.

Registry-miss lookups (`kXR_locate`, manager-mode open/stat/query paths)
rotate round-robin over the logged-in links (stock `ClientMan` rotation) and
fail over automatically when a manager drops; CNS namespace events fan out to
every live link so each redundant manager keeps a complete inventory.

```nginx
brix_cms_manager cms-a.example.org:1213 cms-b.example.org:1213;
brix_cms_paths /store;
brix_cms_interval 30s;
```

### `brix_cms_paths <string>`

**Default:** `brix_export`

Path string advertised in the CMS login packet. Use this when the exported CMS
namespace differs from the local filesystem root.

### `brix_cms_interval <time>`

**Default:** `30s`

How often each worker sends CMS load/availability heartbeats after registration.

### `brix_cms_vnid <string>`

**Default:** unset

Virtual network id advertised in the CMS login envCGI string (`vnid=`), matching
stock `cmsd` semantics. The manager records it per registered server and shows it
in the dashboard cluster rows. *(Phase-89 W9.)*

---

### CMS manager tuning (phase-89 CMS parity — all default to pre-phase behaviour)

These flags extend manager-mode selection and mutation handling. Every default
preserves the previous behaviour, so leaving them unset is a provable no-op.

#### `brix_cms_load_weight <0–100>`

**Default:** `0`

Blends the real machine-load vector from node heartbeats (`/proc`-sourced
cpu/net/mem/pagefault meter) into selection scoring. Read selection scores
`((100-w)·util + w·load)/100`; write selection scales `free_mb` down by
`w·load/10000`. `0` keeps the byte-identical space/util-only scoring.

#### `brix_cms_locate_window <time>`

**Default:** `0` (off)

Dynamic location: on a locate miss in the SHM location cache, park the client,
fan `kYR_state` probes out to logged-in node connections whose exports cover the
path, and redirect to the first `kYR_have` answer (which is then cached with a
30 s TTL). On window expiry the client gets `kXR_wait` and selection falls back
to the static registry chain. `0` = static prefix selection only.

#### `brix_cms_state_fanout <n>`

**Default:** `8`

Cap on how many node connections one dynamic-locate window probes.

#### `brix_cms_coalesce on|off`

**Default:** `off`

Request coalescing for dynamic locate. Without it, N clients that miss on the
*same* path inside one `brix_cms_locate_window` each open their own window and
each fan `kYR_state` out to the same nodes — N identical probe storms for one
answer. With it on, a locate whose path already has a window in flight **on this
worker** parks without probing, and the single `kYR_have` that settles the
leader redirects every follower to the same target. A `kXR_refresh` locate never
coalesces: refresh exists precisely to bypass a cached or in-flight answer.
Coalescing is per worker, because waking a parked session resolves its
connection in the waker's own process. Counted by
`brix_cms_locate_coalesced_total`.

#### `brix_cms_affinity on|off`

**Default:** `off`

Sticky selection: among the fresh (non-stale, non-blacklisted) candidate set, a
path hash — not the load metric — picks the server, so repeat opens of the same
path land on the same node. A drained or blacklisted host is never sticky.

#### `brix_cms_locate_multi on|off`

**Default:** `off`

`kXR_locate` answers `kXR_ok` with the full live `<type><r|w>host:port` server
set (lateral redirect) instead of a single `kXR_redirect`. An empty set falls
through to the single-server path unchanged.

`<type>` is `S` for a data server and `M` for a manager or supervisor (registry
role `M`/`R`), lowercased to `s`/`m` when `brix_manager_stale_after` is set and
the entry has not been heard from inside that window — the stock
`kXR_locate` vocabulary, where lowercase means "known but not currently
confirmed". Every entry used to be published as `S` regardless of role, which
told a client to open data against a manager; brix's own `xcp` source selector
(`client/lib/xfer/copy_xcp_sources.c`) skips `M`/`m` entries, so it was the
first thing the mislabel broke.

#### `brix_cms_fanout on|off` / `brix_cms_fanout_window <time>`

**Defaults:** `off` / `500ms`

Multi-replica mutation fan-out: with `brix_cms_fanout on`, a client
`kXR_rm`/`kXR_rmdir` whose path has ≥2 registered holders (all connected to this
worker) is forwarded to *every* holder instead of redirecting to one. The node
executor is silent on success, so aggregation is a deadline window: no
`kYR_error` inside `brix_cms_fanout_window` ⇒ `kXR_ok`; any node error ⇒
`kXR_error` with that node's text. Single-holder paths keep the redirect path.
**Gotcha:** the window is a msec slot — write `600ms`; a bare `600` parses as
600 *seconds*.

---

### CMS parity wave (2026-08-09 — stock `cms.*` selection/topology parity)

Every directive below defaults to the previous behaviour; leaving them unset is
a no-op. Covered by `tests/test_cms_parity_wave.py`.

#### `brix_cms_delay_servers <n>` / `brix_cms_delay_hold <secs>`

**Defaults:** `0` (off) / `5`

SUPCount floor (stock `cms.delay servers`). While fewer than `n` **data
servers** (roles `S`/proxy-server `PS`) are registered, the manager answers
every `kXR_locate`/`kXR_open`/`kXR_stat` with `kXR_wait <delay_hold>` instead of
redirecting — a fresh manager with 1 of 20 nodes up must not funnel the whole
grid onto that one node. Managers, supervisors and peers do not count toward the
floor.

#### `brix_cms_sched cpu N io N runq N mem N pag N space N fuzz N maxload N`

**Default:** all `0` (legacy `brix_cms_load_weight` scoring)

Component-weighted selection (stock `cms.sched`). Any non-zero weight switches
read scoring to the weighted mean of the five heartbeat `theLoad` bytes (cpu,
net/io, xeq/runq, mem, pag) plus the disk-utilisation `space` component; write
scoring keeps `free_mb` as the base, discounted by machine load. `fuzz N` (0–100)
treats two read candidates whose blended metric differs by ≤N% as equal and
rotates round-robin between them; `maxload N` demotes a node whose blended
machine load exceeds N to a last-resort tier below stale-but-live nodes
(graceful degradation, never a hard refusal — the SUPCount floor covers the
not-ready case). Each value is 0–100; unknown keys fail `nginx -t`.

#### `brix_cms_stage_select on|off`

**Default:** `off`

Stage-aware selection (stock two-phase select). A read of a file no node holds
(loc-cache miss, or a `brix_cms_emptylife` negative entry) is routed to the
roomiest **stage-capable** node (one that advertised the `kYR_status` stage bit)
instead of the least-utilised node — the recall lands on the node with the most
free space. Requires `brix_cms_locate_window` (or the negative cache) to know a
path has no live holder.

#### `brix_cms_fxhold <time>` / `brix_cms_emptylife <time>`

**Defaults:** unset (30 s legacy TTL) / `0` (off)

`brix_cms_fxhold` sets the positive location-cache TTL (stock `cms.fxhold`
defaults to 8 h; BriX keeps the legacy 30 s unless set). `brix_cms_emptylife`
enables a **negative** location cache: a `kYR_state` fan-out that expires with no
`kYR_have` records "no node holds this path" for the given TTL, so a client's
retry answers `kXR_NotFound` immediately instead of re-parking through another
full window. Both are msec slots — write `8h`, `30s`.

#### `brix_cms_dfs on|off`

**Default:** `off`

Shared-filesystem mode (stock `cms.dfs`). Every node sees every file, so the
per-file `kYR_state` fan-out is pure overhead — with `on`, locate skips the
probe entirely and selects by load among all registered nodes exporting the
path.

#### `brix_cms_server_max_direct <n>` *(CMS-server block)*

**Default:** `0` (off)

ManTree-style login offload. Once `n` direct data servers (`S`) are registered,
a **new** server login is answered `kYR_try` naming the least-utilised
registered supervisor (`R`) and closed; the node re-dials the supervisor,
forming the tree. Supervisors, managers, peers and reconnecting known members
are never offloaded. The node honours an unsolicited login `kYR_try`
(re-targeting its heartbeat link, reverting to the configured manager after
repeated failures or a redirect chain >4 deep). Full stock ManTree tree
*negotiation* (superport self-instantiation, ClustID dedup) is a documented
divergence.

#### `brix_cms_perf_pgm <cmd>` / `brix_cms_perf_interval <time>`

**Defaults:** unset (off) / `30s`

External machine-load feed (stock `cms.perf pgm`). A long-lived child process is
spawned once per CMS-client worker; each stdout line `cpu net xeq mem pag` (five
0–100 integers) overrides the `/proc` meter's figures in the `kYR_load`
heartbeat while fresher than `2×interval`. A dead feed is respawned with backoff;
a stale or missing feed silently falls back to `/proc` — the heartbeat is never
blocked.

#### `brix_cms_altds <port> [monitor]` / `brix_cms_altds_interval <time>`

**Defaults:** off / `10s`

Alternate (foreign) data server (stock `cms.altds`). The CMS login advertises
`<port>` as this node's data port, so clients selected here are redirected to a
co-located foreign data server (e.g. a stock `xrootd` on the same host — the
manager records the connection's peer address, so only the port is
advertisable). With `monitor`, a periodic non-blocking loopback probe of the
port drives `kYR_status` suspend/resume on every manager link when the foreign DS
dies or returns.

#### `brix_cms_fsxeq <op>... <program> [<arg>...]` / `brix_cms_fsxeq_timeout <time>`

**Defaults:** no program (the built-in leg runs) / `10s`

Run an operator program **in place of** a namespace operation a CMS manager
forwards down to this data node (stock `cms.fsxeq`). `<op>` is one or more of
`chmod`, `mkdir`, `mkpath`, `mv`, `rm`, `rmdir`, `trunc`; `<program>` must be an
absolute path. This is how a site whose namespace does not live in the local
filesystem — a database, an archive workflow, a tape front-end — takes over the
ops a manager forwards, instead of having them applied with `chmod(2)` and
friends.

The program **replaces** the built-in leg: it is not a hook that runs beside it,
and nothing else touches the filesystem for that op. Ops you do not name keep
the built-in leg, so a line may cover exactly the operations your namespace owns.

Arguments follow stock `XrdOucProg`: the op's own arguments are **appended** to
the command line you configured, and the op name is **not** injected.

| op | appended arguments |
| --- | --- |
| `chmod`, `mkdir`, `mkpath` | `<mode>` (four octal digits) `<path>` |
| `trunc` | `<size>` (decimal bytes) `<path>` |
| `mv` | `<path>` `<path2>` |
| `rm`, `rmdir` | `<path>` |

`<path>` is the **physical** path (the export root joined to the forwarded
name), not the LFN. Pointing several ops at one program is normal — stock
disambiguates by baking a literal argument into each line:

```nginx
thread_pool default threads=4 max_queue=256;

stream {
    server {
        # ...
        brix_cms_fsxeq mkdir mkpath /usr/local/libexec/ns-tool create;
        brix_cms_fsxeq rm rmdir     /usr/local/libexec/ns-tool remove;
        brix_cms_fsxeq_timeout 30s;
    }
}
```

Exit `0` is success and the node answers the manager the way the built-in leg
would — **silently**. Any other exit, a program that cannot be executed, and a
program still running at `brix_cms_fsxeq_timeout` all fail the op with the same
`kYR_error` shape stock cmsd uses, carrying `fsxeq program exited <n>`,
`fsxeq program could not be run` or `fsxeq program timed out`. A timed-out
program's whole process group is `SIGKILL`ed.

The run happens on an nginx **thread pool**, so a slow or wedged program costs
one pool slot and one forwarded op — never the worker's event loop. A
configuration with a program but **no `thread_pool` directive** has nowhere to
post the run, and every configured op is refused (`fsxeq program not runnable`)
rather than quietly falling back to the leg you replaced.

What the feature does **not** relax:

- **Confinement.** The built-in leg runs under `openat2`/`RESOLVE_BENEATH` on
  the export root, so a hostile manager's `..` never escapes; an external
  program has no such floor. A forwarded path is therefore gated **before the
  fork** — absolute, bounded, and free of `..` anywhere — and a path that fails
  is answered `fsxeq path denied` with the program never run. For `mv`, both
  paths are gated.
- **The read-only posture.** `brix_allow_write off` refuses the forwarded op
  with `Read-only file system` *before* anything is forked, so a program can
  never be the way a forbidden posture gets written through.
- **Program ownership.** A program that is group- or world-writable is refused
  at `nginx -t`, like `brix_frm_stagecmd` — it runs with the worker's
  credentials, so anyone who can rewrite it inherits them.
- **What the program is handed.** Exactly the arguments above: no worker listen
  socket, client connection, epoll instance or export root descriptor, and no
  credential material in its argv or environment.

Each op may name exactly one program; a second line for the same op is refused
at `nginx -t`. A `brix_cms_fsxeq` at `stream` level is inherited by every server
that does not claim that op itself.

#### `brix_cms_min_free <MB>`

**Default:** `100`

The **mSpace** policy floor (in MB) this data node advertises in its CMS
`kYR_login` payload (stock `cms.space [min ...]`). It is the free-space level
below which the manager should stop selecting this node for **writes** — a
static policy figure, not a live measurement (the live free space rides the
`fSpace` field / periodic `kYR_load` heartbeat). Was a hardcoded 100 MB; the
default is unchanged, so existing meshes see no difference. Absolute megabytes
only — the stock percentage form (`min 2%`) is not accepted.

#### `brix_cms_space_enforce on|off` / `brix_cms_space_hwm <MB>` *(manager)*

**Defaults:** `off` / `0` (= each node's own advertised floor)

The manager-side half of `cms.space`. Every node already advertises its
`brix_cms_min_free` floor in the **mSpace** field of its `kYR_login`; the
manager parsed that field and discarded it, so the floor was enforced nowhere
and a node could be selected for writes all the way to `ENOSPC`. With
`brix_cms_space_enforce on` the manager remembers each node's advertised floor
and stops offering that node for **writes** once its live `fSpace` (from the
`kYR_load` heartbeat) drops below it.

Degradation, not refusal: a space-blocked node falls to the same last-resort
tier as an over-`maxload` node (§2.3), so a mesh where *every* node is below its
floor still selects — badly, and visibly — rather than answering "no servers".
Reads and the `brix_cms_stage_select` staging selector ignore the block
entirely: a full disk is a reason not to write to a node, never a reason to stop
reading the data it already holds.

The block is sticky with hysteresis. It latches when free space falls below the
floor and clears only at `brix_cms_space_hwm`, which is clamped **up** to the
node's own floor — so a hwm below the floor cannot make a node oscillate in and
out of the write set on every heartbeat. `0` means "clear at the floor" (latch
still applies: recovery must reach the floor, not merely approach it).

A node's advertised floor is scoped to itself. An absurd mSpace can only remove
its own advertiser from write selection; there is no field by which one node can
raise the bar for another. Per-entry state is visible in the dashboard snapshot
as `min_free_mb` and `space_blocked`.

#### `brix_cms_whitelist_file <path>` *(CMS-server block)*

**Default:** unset

Inverse of `brix_cms_blacklist_file`: **only** hosts matching an entry may
register — a login from any other host is refused at admission and closed. Same
line grammar (host, `host:port`, IPv4 CIDR, `*` patterns), same mtime-poll +
re-assert cadence. Mutually exclusive with `brix_cms_blacklist_file`.

The blacklist file additionally accepts (2026-08-09) `*` host **patterns**
(XrdOucNList rules — at most one `*`) and a per-entry `redirect <host:port>`
action that answers a matching node's login with `kYR_try` naming the alternate
manager (instead of only draining it).

#### `brix_cms_role peer|proxy` (added to `auto|server|manager|supervisor`)

`peer` logs in with the `kYR_peer` Mode bit (no `kYR_server`): the manager
registers it as an overflow cluster consulted only as a last resort before
`kXR_NotFound`, never in normal selection. `proxy` logs in `kYR_proxy|kYR_server`
— a proxy data server selectable like any other.

---

### `brix_manager_mode on|off`

**Default:** `off`

Cannot be combined with [`brix_read_only`](#brix_read_only-onoff) or
`brix_read_only_public`: a manager redirects `mkdir`/`rm`/`rmdir`/`mv`/`chmod`/
`truncate` to a data node before the local read-only gate runs, so the endpoint
would not be read-only. `nginx -t` refuses the pair at `[emerg]`.

Enables dynamic server registry queries on this XRootD listener. When on, `kXR_locate` and `kXR_open` requests are answered with `kXR_redirect` to whichever registered data server best matches the requested path (lowest utilisation for reads, most free space for writes). The server also advertises the `kXR_isManager` capability bit in `kXR_protocol` responses.

Requires a companion `brix_cms_server on;` listener (typically on port 1213) to receive data server registrations. The registry is a 128-slot shared-memory table populated by the CMS server when data servers connect and send login frames.

See [cluster-mode.md](../05-operations/cluster-management.md) for the full two-tier and three-tier cluster configuration.

```nginx
stream {
    server {
        listen 1213;
        brix_cms_server on;
    }
    server {
        listen 1094;
        brix_root on;
        brix_export /dev/null;      # redirector has no local storage
        brix_manager_mode on;
    }
}
```

---

### `brix_cms_server on|off`

**Default:** `off`

Enables a CMS management-protocol server on this stream listener. When on, the listener accepts incoming TCP connections from data servers, parses CMS login and heartbeat frames, and maintains the shared server registry used by `brix_manager_mode`.

This directive is used on a dedicated management port (default 1213), not on the XRootD data port.

| CMS frame | Action |
|---|---|
| `kYR_login` | Register server: host, port, path list, free space, utilisation (+ `vnid=` from envCGI) |
| `kYR_avail` / `kYR_load` / `kYR_space` | Update load metrics (incl. the phase-89 machine-load vector) |
| `kYR_usage` / `kYR_stats` | Answer aggregate free-space (`kYR_load` 13-byte form) / size form |
| `kYR_status` | Reset / suspend / resume / stage-state transitions |
| `kYR_have` | Cache a node's dynamic location assertion (export-confined, drained/blacklisted refused) |
| `kYR_pong` | Update last-seen timestamp |
| Disconnect | Unregister server from registry |

```nginx
stream {
    server {
        listen 1213;
        brix_cms_server on;
    }
}
```

#### `brix_cms_blacklist_file <path>` (CMS-server block)

**Default:** unset

Operator-driven blacklist file for the CMS-server block: one `host`,
`host:port`, or IPv4 `a.b.c.d/n` CIDR per line (bare/bracketed IPv6 host text
matches exactly; malformed lines are warned and skipped, never fatal; 128
entries / 64 KB caps). The file is mtime-polled from the per-connection ping
tick and re-asserted after every registration, so **the file wins over an admin
`undrain`** — a file-listed host stays excluded until the file changes, while
removing a line lifts the ban within ≤3 ping intervals. *(Phase-89 W6′; see the
admin cluster API for runtime drain/undrain.)*

---

## CSI block-checksum integrity directives

At-rest integrity on the unified per-file metadata record ("xmeta"): one
CRC32C per block (default 1MiB), stored in the file's own `user.xrd.cinfo`
xattr (or a stock-readable `<file>.cinfo` sidecar when the xattr doesn't
fit). Reads verify the blocks they fully span; writes fold fresh CRCs and
merge them into the record at close. **On by default** — set `brix_csi off`
to opt out, or keep it on and set `brix_csi_trust_fs on` where the
filesystem already checksums end-to-end. All directives are stream
server-block scoped.

| Directive | Default | Meaning |
|---|---|---|
| `brix_csi on\|off` | `on` | Enable block-checksum integrity for this server |
| `brix_csi_block <size>` | `1m` | CRC granule for NEW records (existing records keep their own) |
| `brix_csi_require on\|off` | `off` | Refuse read-opens of files with no verifiable record |
| `brix_csi_trust_fs on\|off` | `off` | Trust the backing filesystem: skip read-verify |
| `brix_csi_scrub_interval <time>` | `0` (off) | Paced at-rest scrub cadence: re-verify every recorded block CRC under the export root every `<time>` |

### `brix_csi_trust_fs on|off`

**Default:** `off`

Declares the backing filesystem self-checksumming (ZFS, CephFS, RADOS, Btrfs)
and skips CSI verification on the read path: pure read handles don't load the
record at all, and reads through a read-write handle skip the block check.
The write side is untouched — writes keep folding block CRCs into the record
at close, and pgwrite wire-CRC validation stays on — so records remain fresh
for scrubbing and for switching back to `off` later.

Only enable this on storage that provides its own end-to-end data checksums;
on a plain filesystem it silently disables at-rest corruption detection for
reads. While trusting, `brix_csi_require` is not enforced on read opens.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /zpool/data;      # ZFS: checksummed end-to-end already
        brix_csi on;                # keep recording block CRCs on write
        brix_csi_trust_fs on;       # but don't re-verify reads
    }
}
```

Semantics worth knowing: a read verifies only the blocks it FULLY covers
(partial-edge blocks are skipped on the hot path); a CRC slot of zero means
"not computed" and never fails a read; a crash between writing and close
leaves stale CRCs, so reads of a torn upload fail with `kXR_ChkSumErr` until
the file is rewritten (fail-closed).

### `brix_csi_scrub_interval <time>`

**Default:** `0` (off)

Arms a paced background **at-rest scrub**. Because a read only verifies the
blocks it fully covers, a corrupt block in cold data is never noticed until an
unlucky client happens to read across it. When set, a per-server maintenance
timer walks the export root once every `<time>` and re-verifies **every**
recorded block CRC of every tagged file against its bytes on disk — surfacing
silent storage rot proactively rather than on the read path.

The interval is the pacing: one full sweep per interval, never a self-rearming
hot poll (it is a `cancelable` timer, so it never delays a graceful shutdown).
A block whose CRC slot is unset ("not computed") or whose recorded range runs
past the file on disk is skipped (fail-open on coverage gaps); the scrub only
reports a genuine CRC difference. Each corrupt block increments the
`brix_csi_scrub_mismatch_total` metric and emits an `error.log` diagnostic
naming the file, block index, and recorded-vs-on-disk CRC. The scrub is
read-only — it never repairs or quarantines; restore the affected file from a
good replica.

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_export /data;
        brix_csi on;
        brix_csi_scrub_interval 6h;   # sweep the whole export every 6 hours
    }
}
```

Leave it at `0` on filesystems that already scrub themselves (ZFS/CephFS/RADOS
with periodic `scrub`), pairing with `brix_csi_trust_fs on` — the storage layer
does the at-rest verification there.

---

## Proxy mode directives

These directives configure transparent XRootD proxy mode, in which a stream
listener forwards `root://` client requests to one or more upstream XRootD data
servers or redirectors. All proxy directives are `server`-context (stream
`server {}` block). Defaults below match `src/protocols/root/stream/module.c`.

### `brix_tap_proxy on|off`

**Default:** `off`

Enables transparent XRootD proxy mode for this stream server. Requires at least
one `brix_tap_proxy_upstream`.

### `brix_tap_proxy_upstream host[:port] [auth]`

Upstream XRootD data server or redirector. May appear multiple times for
round-robin load balancing. The optional second argument overrides
`brix_tap_proxy_auth` for this upstream only.

### `brix_tap_proxy_upstream_tls on|off`

**Default:** `off`

Wraps the outbound upstream connection in TLS from the first byte.

### `brix_tap_proxy_upstream_tls_ca <path>`

PEM CA bundle used to verify the upstream TLS certificate (enables peer
verification).

### `brix_tap_proxy_upstream_tls_name <host>`

SNI hostname presented on the upstream TLS connection. Defaults to the
`brix_tap_proxy_upstream` host.

### `brix_tap_proxy_auth <mode>`

**Default:** `anonymous`

Auth bridging mode for upstream connections (for example `anonymous`, `forward`,
or `sss`). `forward` replays the client bearer token; `sss` builds an SSS
credential from the configured key.

### `brix_tap_proxy_login_user <string>`

Overrides the username placed in the upstream `kXR_login` frame.

### `brix_tap_proxy_sss_identity keytab|client`

**Default:** `keytab`

Chooses whose identity the tap proxy puts in the SSS credential it presents to
its upstream. `keytab` — the 1.x behaviour — sends the local keytab key's own
user, so every client reaches the upstream as one service account. `client`
mints the authenticated front-side client's full entity instead: name, VO,
role, groups, endorsements, and the proxied credential when
`brix_sss_getcreds` kept one.

`client` refuses to open the upstream connection at all when the front-side
session is not authenticated, so the upstream is never told about an identity
this hop did not verify — the refusal is per attempt, not one-shot, and no
bytes reach the origin. The upstream's own keytab still decides whether to
believe the forwarded VO and role, exactly as it does for a direct client.

```nginx
brix_tap_proxy              on;
brix_tap_proxy_upstream     se.example.org:1094;
brix_tap_proxy_auth         sss;
brix_sss_keytab             /etc/brix/sss.keytab;
brix_tap_proxy_sss_identity client;
```

### `brix_proxy_audit_log <path>|off`

**Default:** `off`

Writes one JSON line per closed or abandoned upstream file handle.

### `brix_proxy_reconnect_attempts <n>`

**Default:** `0`

Reconnect budget per client session when an idle upstream connection drops with
no open handles.

### `brix_proxy_connect_timeout <ms>`

**Default:** `10000`

Milliseconds allowed for the TCP connect to the upstream. `0` disables the
limit.

### `brix_proxy_read_timeout <ms>`

**Default:** `60000`

Milliseconds allowed between upstream response bytes. `0` disables the limit.

### `brix_proxy_keepalive_interval <ms>`

Idle keepalive interval for upstream connections.

### `brix_tap_proxy_path_rewrite <strip> <add>`

Strips a leading prefix from open/path requests, then prepends `add` (for
example `brix_tap_proxy_path_rewrite /brix /data`).

---

## CVMFS site-cache directives

These directives configure the `cvmfs://` protocol handler
(`ngx_http_brix_cvmfs_module`), which turns an nginx location into a
Squid-replacement CVMFS forward-proxy or reverse-proxy site cache. The cache is
read-only by construction — `brix_allow_write`, `brix_stage`, and
`brix_cache_slice_size` are rejected with a config error under a cvmfs location.

Unified storage directives (`brix_cache_store`, `brix_cache_verify`,
`brix_cache_evict_at`, `brix_cache_evict_to`, `brix_storage_backend`,
`brix_thread_pool`, …) apply to cvmfs locations exactly as they do to WebDAV and
S3. The tables below cover the cvmfs-specific knobs only.

### Core enable and manifest/negative cache

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs on\|off` | flag | `off` | Activate the cvmfs handler for this location (one protocol per location) |
| `brix_cvmfs_manifest_ttl <sec>` | seconds | `61` | How long `.cvmfspublished` manifests are held before revalidation |
| `brix_cvmfs_negative_ttl <sec>` | seconds | `10` | How long a known-missing object answer is cached |
| `brix_cvmfs_quarantine_dir <path>` | path | unset | Directory for CAS-verify failures; each quarantined file is evidence of a corrupt transfer |
| `brix_cvmfs_trace on\|off` | flag | `off` | Promote upstream-request lines to INFO in the error log (process-wide) |

### Upstream allow-list and fill policy

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_upstream_allow <host> …` | 1+ hosts | required | Stratum-1 hostname(s) this cache is allowed to fetch from; multi-host and multi-directive both work |
| `brix_cvmfs_upstream_max <n>` | integer | `8` | Maximum concurrent fill connections to any single upstream endpoint |
| `brix_cvmfs_client_hold <sec>` | seconds | `25` | Maximum time a waiting client is held while the cache retries origins before returning `504 Retry-After` |
| `brix_cvmfs_fill_max_life <sec>` | seconds | `300` | Maximum lifetime of a single fill; fill is abandoned and a fresh one started after this |

### Origin selection

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_origin_select static\|geo\|rtt` | enum | `rtt` | Strategy for ordering origins: `rtt` probes connect latency every `rtt_interval` and prefers the fastest; `geo` ranks by great-circle distance from `brix_cvmfs_here`; `static` uses declaration order |
| `brix_cvmfs_rtt_interval <sec>` | seconds | `60` | How often RTT probes run (only when `origin_select rtt`) |
| `brix_cvmfs_here <lat>:<lon>` | lat:lon | required for `geo` | Geographic coordinates of this cache node (e.g. `55.95:-3.19`) |
| `brix_cvmfs_origin_coords <host[:port]> <lat>:<lon>` | host lat:lon | required for `geo` | Coordinates of one Stratum-1; repeat for each origin |

`brix_cvmfs_origin_select geo` without `brix_cvmfs_here` is a config error. A `brix_cvmfs_origin_coords` entry not matched to a configured origin is also a config error. `geo` (and `rtt`) require origins registered via `brix_storage_backend` (an http/https URL or pipe-separated list); `brix_cvmfs_upstream_allow` alone does not register endpoints for geo ranking.

### Upstream stall detection

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_origin_connect_timeout <sec>` | seconds | `2` | TCP connect timeout per upstream attempt |
| `brix_cvmfs_origin_stall_timeout <sec>` | seconds | `4` | Seconds at the low-speed threshold before the connection is declared stalled |
| `brix_cvmfs_origin_stall_bytes <n>` | bytes | `1` | Low-speed threshold in bytes/second used with `origin_stall_timeout` |
| `brix_cvmfs_origin_attempt_timeout <sec>` | seconds | `0` (off) | Hard per-attempt time ceiling; `0` disables |
| `brix_cvmfs_origin_reuse_conn on\|off` | flag | `on` | Reuse HTTP keep-alive connections to origins |
| `brix_cvmfs_fill_retry_policy failover\|force-primary` | enum | `failover` | After a stall: `failover` tries the next endpoint; `force-primary` retries the ranked-first endpoint |
| `brix_cvmfs_shared_cache on\|off` | flag | `off` | Allow multiple cache processes to share the same cache directory |
| `brix_cvmfs_unified_origin on\|off` | flag | `off` | Serve every proxy request (including repository endpoints) from a single configured `brix_storage_backend` http(s) origin set |

### Server-side geo answering

These directives configure nginx's response to CVMFS geo-API requests
(`/cvmfs/<fqrn>/api/v1.0/geo/…`), so that clients rank Stratum-1s by distance
from this cache rather than making their own geo queries.

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_geo_answer off\|rtt` | enum | `off` | `rtt` answers geo requests using RTT-derived rankings; `off` passes them upstream |
| `brix_cvmfs_geo_cache_ttl <sec>` | seconds | `60` | How long geo-answer results are cached |
| `brix_cvmfs_geo_max_servers <n>` | integer | `16` | Maximum servers returned in one geo-answer response |

### Secure cvmfs (scvmfs, EXPERIMENTAL)

`brix_scvmfs on` layers TLS and bearer-token authorization on top of a cvmfs
location. Requires `brix_cvmfs on` in the same location and a TLS listener
(`listen … ssl` with certificates). Plain HTTP is refused.

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_scvmfs on\|off` | flag | `off` | Enable secure cvmfs on this location |
| `brix_scvmfs_authz none\|bearer` | enum | `none` | `bearer` gates clients on a WLCG/SciTokens read scope |
| `brix_scvmfs_token_issuers <path>` | path | required for `bearer` | SciTokens configuration file listing trusted issuers |

### Cache storage knobs (unified — apply to cvmfs)

These are the unified storage directives most commonly tuned for a cvmfs site cache.
See the unified grammar section at the top of this page for the complete list.

| Directive | Default | Purpose |
|---|---|---|
| `brix_cache_store posix:<path>` | required | Local cache directory (XFS recommended; the cache engine owns the volume) |
| `brix_cache_verify off\|cvmfs-cas` | **`cvmfs-cas`** for cvmfs (other protocols: `off`) | Verify every fill against its SHA-1 content address; quarantines corrupt objects |
| `brix_cache_evict_at <pct>` | `90` | Percent-full that triggers eviction. On the `root://` stream read cache this pair seeds the proactive watermark LRU reaper (percent → ppm; an explicit `brix_cache_high_watermark`/`brix_cache_low_watermark` pair takes precedence). On the cvmfs/HTTP plane occupancy eviction is not wired to it yet — cache growth there is bounded by `brix_cache_max_object` and DELETE/overwrite eviction. |
| `brix_cache_evict_to <pct>` | `80` | Percent-full target the reaper evicts down to (hysteresis partner of `brix_cache_evict_at`; must be lower). Same plane caveat as above. |
| `brix_storage_backend <url>` | unset | Reverse-proxy origin(s) — pipe-separated `http://` URL list for failover; use instead of `brix_cvmfs_upstream_allow` in reverse mode |
| `brix_thread_pool <name>` | `default` | nginx thread pool for fill I/O |

### Repo serving, composition and manifest trust

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_stratum0_root <path>` | path | unset | Serve a published Stratum-0 repo tree from `<path>` (explicit alias for `brix_export` — the merge refuses cache-fill upstream grammar in the same block, and the gate answers `/.cvmfs_master_replica` so a real Stratum-1 `cvmfs_server add-replica` recognizes it as a replication source) |
| `brix_cvmfs_virtual_repo <name> <member>…` | 2+ args | unset | Compose a virtual repo `<name>` from one or more member repos |
| `brix_cvmfs_repo_authz <repo> <scitokens.cfg>` | 2 args | unset | Token-gate one repo — clients need a WLCG/SciTokens read scope per the config (phase-85 F3) |
| `brix_cvmfs_verify_manifest <pubkey>` | path | unset | Master public-key file used to verify `.cvmfspublished` manifest signatures |

### Integrity scrubbing, QoS and provenance

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_scrub on\|off` | flag | `off` | Background CAS integrity scrubber — re-verifies cached objects against their content address (phase-87 G17) |
| `brix_cvmfs_scrub_interval <sec>` | seconds | `60` | Scrub cycle period |
| `brix_cvmfs_scrub_rate <n>` | integer | `20` | Scrub throttle — objects checked per cycle tick |
| `brix_cvmfs_attest <arg>` | takes 1 | unset | Runtime provenance attestation of served content (phase-87 G15) |
| `brix_cvmfs_qos <vo> <a> <b>` | 3 args | unset | Per-VO / per-job QoS fill throttling (phase-85 F9) |

### Content-transfer optimizations (phase-87, opt-in)

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_bundle on\|off` | flag | `off` | Chunk-bundle batch fetch — coalesce many small CAS fetches into one origin request (G2) |
| `brix_cvmfs_delta on\|off` | flag | `off` | Cross-revision delta transfer (G10) |
| `brix_cvmfs_dict on\|off` | flag | `off` | Trained shared-dictionary coding (G3) |
| `brix_cvmfs_learn on\|off` | flag | `off` | Workload-learned predictive prewarm (G11) |
| `brix_cvmfs_swarm on\|off` | flag | `off` | P2P swarm cold-start — peer caches seed each other (G12) |
| `brix_cvmfs_swarm_interval <sec>` | seconds | `3` | Swarm peer-refresh interval |

### Additional origin / TTL knobs

| Directive | Args | Default | Purpose |
|---|---|---|---|
| `brix_cvmfs_offline_ttl <sec>` | seconds | `0` (off) | Keep serving stale cached content for this long when every origin is unreachable |
| `brix_cvmfs_origin_http_version <ver>` | enum | auto | Force the HTTP version for origin fills (requires a libcurl that supports it) |
### Origin query options

An origin URL in `brix_storage_backend` may carry query options after the path.
They are read from the whole spec and applied to the **primary** endpoint; a
value ends at `&` or at the `|` that separates failover origins.

| Option | Origins | Effect |
|---|---|---|
| `?put_checksum=1` | `http`, `s3` | Sign and send a body checksum on every upload so the origin rejects a wire-corrupted PUT with `400 BadDigest` |
| `?tape_api=<abs path>` | `http` | The origin fronts an HSM and speaks the [WLCG Tape REST API](https://twiki.cern.ch/twiki/bin/view/LCG/TapeRESTAPI) at that base (e.g. `/api/v1`). Non-empty is what arms tape awareness — `residency` reports staged/on-tape and `recall` submits the stage request. |
| `?nearline=1` | `s3` | The bucket is archive-backed (GLACIER / DEEP_ARCHIVE / an INTELLIGENT_TIERING archive tier): `residency` reads the storage class and `recall` issues RestoreObject |
| `?restore_days=N` | `s3` | How long a restored copy stays readable. `0` (the default) leaves the S3 layer's own default. |

```nginx
brix_storage_backend https://tape.example.org/data?tape_api=/api/v1;
brix_storage_backend s3://s3.example.org/bucket?nearline=1&restore_days=7;
```

A tape-aware origin **must** have a cache tier configured — the cache is what a
recall stages into — and composing one without `brix_cache_store` is a config
error rather than a runtime surprise. `?tape_api=` is refused (leaving the export
plain HTTP) unless it is an absolute path made only of unreserved URL bytes, so a
typo cannot end up spliced into a request line. The `root://` equivalent is a
scheme rather than an option: `root+tape://` / `roots+tape://`.

### Store-line parameters

Everything **after the URL** on a tier line (`brix_storage_backend`,
`brix_cache_store`, `brix_cache_stage_store`, `brix_cache_cold_store`) is a
space-separated parameter, parsed by `src/fs/tier/tier_config_args.c`. They are
not query options: a query option belongs to the URL and travels with it, a
parameter says what BriX should do with the store the URL names. An
unrecognised token is refused (`[emerg] … unknown store param "…"`) rather than
ignored, so a misspelled parameter fails `nginx -t` instead of leaving a
deployment believing it configured something.

| Parameter | Roles | Effect |
|---|---|---|
| `credential=<name>` | any | Bind the store to a declared `brix_credential` block. An undeclared name is refused. |
| `block_size=<size>` | any | Origin read/fetch stride in nginx size syntax (`1m`, `512k`). |
| `nearline` | backend | The origin fronts tape/an MSS: reads recall asynchronously instead of blocking. Refused on a cache/stage/cold tier — that tier **is** the recall target. |
| `verify_pages[=require\|best-effort]` | backend, `root://` and `forward://` only | Verify every 4 KiB page arriving from the origin against its CRC32c (below). |
| `permit=<host\|.suffix>` | backend, `forward://` only | Repeatable. The hosts a forwarding proxy may dial on a client's say-so: an exact host or a leading-dot domain suffix (the TPC egress guard's match rule). Mandatory on a `forward://` line; refused anywhere else. |

#### `verify_pages` — per-page origin verification

**Roles:** `brix_storage_backend` only · **Schemes:** `root://`, `roots://`, `forward://` (applied to every admitted origin) ·
**Default:** off (plain `kXR_read`)

With `verify_pages` a `root://` origin read is issued as **`kXR_pgread`**
instead of `kXR_read`: the origin returns each 4 KiB page prefixed by its
CRC32c, and BriX recomputes and compares every page before a byte of it reaches
the cache or the client. A page that does not match is a hard failure — the
read is refused, nothing partial is committed, and the mismatch is logged with
the file offset.

```nginx
brix_storage_backend root://origin.example.org:1094//data verify_pages;
brix_storage_backend root://legacy.example.org:1094//data verify_pages=best-effort;
```

This closes the half of the integrity story that `brix_cache_verify` cannot
reach. `brix_cache_verify` hashes a **completed fill** against a whole-file
digest, so it is blind to a partial or ranged read (there is no whole file to
hash) and to an origin that publishes no digest at all. `verify_pages` verifies
the bytes **as they arrive**, per page, with no digest and no complete file
required. Over cleartext `root://` this is the only integrity BriX has: TCP's
16-bit checksum is a corruption hint, not a guarantee.

**The bare token means `require`.** An operator who writes `verify_pages` is
asking for verified bytes, so an origin that cannot deliver them must say so:

| Spelling | Origin speaks `kXR_pgread` | Origin does not (pre-5.x, or refuses) |
|---|---|---|
| `verify_pages` / `verify_pages=require` | every page verified | read refused, `kXR_Unsupported`, `[error] refusing to read from origin … unverified` |
| `verify_pages=best-effort` | every page verified | one `[warn]`, then falls back to unverified `kXR_read` |

`best-effort` is the explicit opt-in for a federation of mixed-vintage origins.
Corruption is refused under **both** spellings — `best-effort` relaxes what
happens when an origin *cannot* verify, never what happens when a page *fails*
verification.

Support is read from the origin's `kXR_protocol` reply (`kXR_suppgrw`) and
remembered on the connection, so a pre-5.x origin costs no wasted round trip.
An origin that advertises the capability and then refuses the request is
handled once per object and, under `require`, still fails closed. A refusal
that arrives **mid-train** — after pages have already been accepted — is
treated as a protocol error, not as a fallback opportunity.

Refused at parse time (all of these fail `nginx -t`): the parameter on a
cache/stage/cold tier (it verifies bytes *arriving from* an origin), on a
non-`root://` driver (no per-page checksum exists on the wire), and any value
other than `require` or `best-effort`.

Implemented in `src/fs/cache/origin_pgread.c` (the wire kernel) and dispatched
in `src/fs/backend/xroot/sd_xroot_io.c`; phase-115 W4.3.

## Network / TCP tuning directives

Per-connection socket options applied once at accept on the `root://` stream
plane. All are **best-effort and non-fatal** — a kernel that rejects the option
(missing feature, value above a sysctl cap) leaves its default and the connection
proceeds. All default to the kernel default, so a stock deployment is unchanged.

### `brix_socket_sndbuf <size>`

**Default:** `0` (kernel autotuning) · **Context:** `stream {}`, `server {}`

Sets `SO_SNDBUF` (send-buffer bytes) on each accepted connection. On a high
bandwidth-delay-product link (long-RTT WAN transfers) the kernel's send
autotuning can lag the true BDP, capping a single download stream below line
rate; pinning the send buffer to the deployment BDP (`bandwidth × RTT`) lets the
server keep the pipe full. Setting it disables send autotuning for that socket,
so leave it `0` unless you have **measured** the BDP. The kernel doubles the
requested value for bookkeeping and clamps it to `net.core.wmem_max`. Phase-33
P3-B3. Download (server→client) is the dominant `root://` read direction, so this
is the primary throughput knob of the pair.

### `brix_socket_rcvbuf <size>`

**Default:** `0` (kernel autotuning) · **Context:** `stream {}`, `server {}`

Sets `SO_RCVBUF` (receive-buffer bytes) on each accepted connection — the
symmetric knob for the upload/PUT direction. Same BDP guidance and
`net.core.rmem_max` clamp as `brix_socket_sndbuf`.

**Example** — a 10 Gbps path with a 30 ms RTT (BDP ≈ 37.5 MiB):

```nginx
stream {
    server {
        listen 1094;
        brix_root on;
        brix_storage_backend posix:/data;
        brix_socket_sndbuf 40m;   # requires: sysctl -w net.core.wmem_max=41943040
        brix_socket_rcvbuf 40m;   # requires: sysctl -w net.core.rmem_max=41943040
    }
}
```

## Backend credential delegation directives

Control how the gateway re-presents a client's proven identity to a downstream
backend/origin (the phase-70 "full credential delegation" work). All default to
**off / disabled**, so a stock deployment forwards nothing.

### `brix_backend_krb5_forwardable on|off`

**Default:** `off` · **Context:** `http {}`, `server {}`, `location {}` and
`stream {}`, `server {}`

Arms the Kerberos (krb5) origin leg. When a client authenticates over `root://`
with a **forwardable** TGT (`GSS_C_DELEG_FLAG`), turning this on lets the gateway
capture the delegated ticket and re-delegate it — via a fresh GSSAPI context — to
a Kerberised origin backend, so the origin sees the *client's* identity rather
than the gateway's. Left `off`, no forwarded credential is ever captured and the
gateway falls back to SELECT (its own service identity).

The origin service principal is **derived** as `host/<backend-fqdn>@<REALM>`,
taking the realm from the gateway's own configured principal — there is no
separate directive for the origin principal, and a backend host string is
rejected if it tries to smuggle a realm (`@`) or principal component (`/`).

Available on **both** request planes: the HTTP plane and the `root://` stream
plane (krb5 auth runs on the stream plane). The value is validated at `nginx -t`
— any token other than `on`/`off` is a hard load error, never a silent no-op.

> **Status (2026-07-28):** the cryptographic core (capture + forward + principal
> derivation) is landed and LIVE-verified against a real MIT KDC; the inbound
> two-round wire state machine and the outbound multi-leg drive are the remaining
> runtime pieces, blocked on live krb5 peers. See
> `docs/refactor/phase-70-full-credential-delegation.md` §5.7 / §5.7.1.

### S3 STS (`brix_backend_s3_sts_endpoint` / `brix_backend_s3_sts_flavor`)

The sibling S3 delegation directives (SigV4 `AssumeRole` against an STS endpoint;
`aws` or `minio` dialect) are documented in
`docs/refactor/phase-70-full-credential-delegation.md` §5.5. `…_endpoint` is
load-validated at `nginx -t` (must be a well-formed `http(s)://` URL).

## Phase-105 — unified cross-protocol directives (wave 2)

All registered once on the common module; set at `http{}`/`server{}`/location
scope and inherited by every brix HTTP protocol (WebDAV, S3, cvmfs) unless a
narrower scope is stated. Hard-renamed old spellings are listed in
`migration-unified-grammar.md`.

| Directive | Args | What it does |
|---|---|---|
| `brix_kv_zone` | `zone=name:size key=N val=N` (http main) | declare a shared-memory KV zone (token cache, rate-limit state) |
| `brix_token_cache` | `zone=<name>` | cross-worker verified-JWT cache; amortizes bearer validation on webdav AND s3. Only positive verdicts are stored; entries re-check `exp` and are TTL-capped at 5 min |
| `brix_rate_limit` | `zone= rate=<N>r/s burst=<N> [key=dn\|ip]` | per-client-IP token-bucket admission, enforced BEFORE the auth burden on webdav, s3 and cvmfs (`key=dn` is stream-plane semantics; HTTP keys by IP) |
| `brix_rate_limit_zone` / `brix_rate_limit_rule` / `brix_bandwidth_limit` / `brix_concurrency_limit` | see phase-25 docs | traffic-shaping rules; rules now inherit into nested locations like every other preamble rule array |
| `brix_max_delay` | `<time>` | cap on the client wait/Retry-After a response may advertise (xrootd maxdelay analog). HTTP default 0=off; stream default 60 |
| `brix_verify_depth` | `<n>` | accepted client proxy-chain depth cap in the auth path (VOMS proxies + delegation re-verify on HTTP; GSI login on stream). HTTP default 10; stream 0=unlimited |
| `brix_trusted_ca` / `brix_trusted_ca_dir` | `<file>` / `<dir>` | auth-layer verify-source CA material for GSI/VOMS cert auth. **Consumed by webdav today** — inert on protocols without cert auth (s3 SigV4/bearer) |
| `brix_client_ca_store` | `<dir>` (srv/loc) | hashed CA dir loaded into the SERVER SSL_CTX client-verify store at postconfiguration (server-wide by construction) |
| `brix_delegation_endpoint` | `on\|off` | opt-in GSI proxy-upload delegation well-known endpoint. **Served by the webdav dispatch** — enabling it elsewhere has no endpoint to serve |
| `brix_tcp_congestion` | `<alg>` | sender-side TCP congestion algorithm (e.g. `bbr`) applied by the shared file-serve path to EVERY HTTP download (webdav GET, S3 GetObject, cvmfs) |
| `brix_mirror_url` + `_methods`/`_sample`/`_strip_auth`/`_writes`/`_log_diverge`/`_timeout`/`_token` | see phase-24 docs | traffic-mirror settings; the mirror handlers are global, so one `http{}`-level target mirrors every brix HTTP protocol |
| `brix_token_introspect_url` / `_loc` / `_ttl` / `_fail_open` | str / str / `<time>` / flag | OIDC introspection (revocation): `_loc` names the internal location that proxy_passes to the IdP; consulted for any brix request carrying a Bearer token. `_ttl` accepts time units (default 30s); `_fail_open` default on |
| `brix_webdav_query_token` | `on\|off` (webdav) | accept `?authz=`/`?access_token=` query-string tokens (default on) — webdav auth surface, renamed from `brix_http_query_token` |
| `brix_webdav_secretkey` | `<key>` (webdav) | redirect-CGI HMAC key (pairs with `brix_webdav_redirect_*`) — renamed from `brix_http_secretkey` |

Stream-plane spellings unified in the same wave: `brix_authdb_engine`
(`native|xrdacc`, was `brix_authdb_format`), `brix_acc_audit` /
`brix_acc_refresh` (were `brix_authdb_audit`/`_refresh`),
`brix_wt_stage_root`/`_backend`/`_block_size` (were `brix_cache_wt_stage_*`),
and the HTTP TPC outbound-token quartet now spelled
`brix_tpc_outbound_{token_endpoint,client_id,client_secret,scope}`.

---

## Release 2.0 — directives that had no prose before 2.0

Every directive below was registered and consumed (or, where stated,
accepted for compatibility only) but appeared nowhere outside the generated
registry table until the 2.0 readiness audit
([register](../10-reference/release-2.0-readiness.md)). The entries are
grouped by family; each states context, default and what the knob drives.
No 2.0 directive is accepted without effect: the last such set, thirteen
`brix_frm_*` knobs, was wired or removed by the audit's F1 (ADR-3b,
2026-09-08). A future knob that parses but drives nothing must carry the
label "Accepted, no effect" in its own section and be declared in the
register — that is what `tests/test_release20_surface_pins.py` enforces.

### Stream connection limits and timeouts (phase 39)

#### `brix_handshake_timeout <time>`

**Context:** stream server. **Default:** `0` (off). Deadline for a client to
complete the initial handshake + protocol/login exchange after connecting; a
connection still unauthenticated when it expires is closed. Guards the
per-connection state a slow-loris client would otherwise pin.

#### `brix_send_timeout <time>`

**Context:** stream server. **Default:** `0` (off). Deadline for the client to
drain a pending response write; a client that stops reading for longer than
this is disconnected. Complements `brix_read_timeout`.

#### `brix_tcp_user_timeout <time>`

**Context:** stream server. **Default:** `0` (kernel default). Sets
`TCP_USER_TIMEOUT` on the accepted socket: how long transmitted data may
remain unacknowledged before the kernel aborts the connection. Makes a
half-dead peer fail in a bounded time instead of at the kernel's retransmit
ceiling.

#### `brix_tcp_keepalive on|off`

**Context:** stream server. **Default:** `off`. Enables `SO_KEEPALIVE` on
accepted client sockets so idle-but-alive sessions survive middlebox timeouts
and dead peers are detected.

#### `brix_max_connections <n>`

**Context:** stream server. **Default:** `0` (unlimited). Cap on concurrent
client connections per worker for this server block; a connection beyond the
cap is refused at accept time. (The CMS control plane has its own
`brix_cms_server_max_connections`, default 4096.)

#### `brix_manager_stale_after <time>`

**Context:** stream server (manager role). **Default:** `0` (off).
Process-wide staleness threshold for data-server registrations held by a
manager: a data server that has not refreshed within this window is treated
as gone for selection. Set on the manager, not on data servers.

#### `brix_redir_cache_slots <n>`

**Context:** stream server. **Default:** compile-time
`BRIX_REDIR_CACHE_SLOTS`. Size of the shared redirect cache that remembers
which data server answered a path so a repeat `open` skips the CMS round
trip. Larger sites with many hot paths raise it; the slot count is fixed at
start-up.

### Backend health checks (phase 22)

Active probing of the data servers a manager or proxy forwards to. All six
live in `src/protocols/root/stream/directives_net.h`.

#### `brix_health_check on|off`

**Context:** stream server. **Default:** `off`. Enable the periodic probe
loop for this server's upstream/data-server set.

#### `brix_health_check_interval <time>` / `brix_health_check_timeout <time>`

**Defaults:** `30s` / `5s`. How often each target is probed and how long one
probe may take before it counts as a failure.

#### `brix_health_check_threshold <n>` / `brix_health_check_blacklist <time>`

**Defaults:** `3` / `60s`. Consecutive failures before a target is removed
from selection, and how long it stays removed before the next probe may
readmit it.

#### `brix_health_check_type ping|stat`

**Default:** `ping`. `ping` performs the protocol handshake only; `stat`
additionally issues a `kXR_stat` of the export root so a server whose
storage is unmounted is also marked down.

### Backend async queue

Applies to the write path of remote storage backends (root://, davs://, s3://).

#### `brix_backend_async on|off`

**Context:** stream server; http, server, location. **Default:** `off`.
Queue backend writes instead of issuing each one synchronously in the request
thread; a queued batch is flushed by the backend worker.

#### `brix_backend_async_batch <n>` / `brix_backend_async_wait <time>`

**Defaults:** `64` (minimum 1) / `200ms`. Maximum operations per flushed
batch, and how long a partial batch waits for more work before it is flushed
anyway.

### Backend credential material

#### `brix_backend_s3_sts_role <arn>` / `brix_backend_s3_sts_access_key <key>` / `brix_backend_s3_sts_secret_key <key>` / `brix_backend_s3_sts_region <region>`

**Context:** stream server; http, server, location. **Default:** unset.
Together with the already documented `brix_backend_s3_sts_endpoint` and
`brix_backend_s3_sts_ttl`, configure AWS STS `AssumeRole`: the access/secret
pair authenticates the `AssumeRole` call, `role` names the role to assume
per mapped user, `region` selects the signing region. The temporary
credentials returned are used for the S3 backend on that user's behalf and
refreshed before `ttl` expires. Secret material belongs in a root-only
include file.

#### `brix_backend_token_exchange_client_id <id>` / `brix_backend_token_exchange_client_secret <secret>`

**Context:** stream server; http, server, location. **Default:** unset.
Client credentials for the RFC 8693 token exchange named by
`brix_backend_token_exchange_endpoint`: the inbound bearer is exchanged for
one the backend accepts before the backend request is issued.

#### `brix_backend_token_audience_ok <aud> [aud …]`

**Context:** stream server; http, server, location. **Default:** unset
(no audience check on the delegated token). Audience values the exchanged
or forwarded backend token is allowed to carry; a token whose `aud` matches
none of them is not sent to the backend (`src/protocols/shared/deleg_wire.c`).

### Read cache admission, families, peers and tiers

#### `brix_cache_allow_prefix <path>` / `brix_cache_deny_prefix <path>`

**Context:** stream server; http, server, location. **Default:** none (admit
everything the size/regex rules admit). Path-prefix admission for the
read-through cache. When any `allow_prefix` is set only objects under one of
the prefixes are cached; `deny_prefix` excludes a subtree even when a wider
prefix admits it. Denied objects are still served, uncached.

#### `brix_cache_origin_family auto|inet|inet6`

**Context:** stream server; http, server, location. **Default:** `auto`.
Address family the cache uses for origin fills: `auto` follows the
resolver's answer order, `inet`/`inet6` forces IPv4 or IPv6 (a dual-stack
origin whose IPv6 path is broken is the usual reason).

#### `brix_cache_peers <host:port> [host:port …] self=<host:port>`

**Context:** http, server, location. **Default:** none. Phase-85 sibling
cache mesh: at least two members, exactly one of them tagged `self=`. On a
miss the cache asks its siblings before the origin, so a site with several
caches fills each object from the origin once.

#### `brix_cache_cold_store <url>`

**Context:** stream server; http, server, location. **Default:** none.
Second, slower cache tier behind `brix_cache_store` (which is required —
the configuration is refused otherwise). Objects evicted from the hot tier
are demoted here rather than deleted, and a hot miss checks the cold tier
before the origin.

#### `brix_cache_passthrough on|off` / `brix_cache_passthrough_max <size>`

**Context:** stream server; http, server, location. **Defaults:** `off` /
`0` (= `brix_cache_max_object`). Phase 92: when an object is declined by
admission but several HTTP clients are already waiting on the same fill,
`on` spools it once so the coalesced waiters are served a transient hit,
then evicts it immediately. `_max` caps the spool size for such a fill.

### Cluster (CMS) and namespace

#### `brix_cms_state_relay on|off`

**Context:** stream server. **Default:** `off`. Phase-61 W7 multi-tier
clustering: a mid-tier manager relays `kYR_state` notifications it receives
from its data servers up to its own manager, so a top-level redirector
learns of file arrivals two tiers down. Leave off in a flat cluster.

#### `brix_cns off|emit|collect`

**Context:** stream server. **Default:** `off`. Composite Name Space
inventory: `emit` makes a data server announce namespace changes to its
manager; `collect` makes a manager gather them so a `kXR_stat`/`dirlist`
against the manager can answer from inventory. A cluster typically runs
`emit` on data servers and `collect` on the manager.

#### `brix_cms_admin_socket <path>`

**Context:** stream server (CMS manager or data server). **Default:** none.
The CMS runtime admin socket — the stock `cmsd` admin-interface analog. A
unix-domain line server at `<path>` accepting `nodes`, `drain <host> <port>`,
`undrain <host> <port>`, `forget <host> <port>` and `reset`, so a manager that
runs no dashboard still has cluster control. It reaches the same registry
helpers as the HTTP admin API, and because the node registry lives in shared
memory the effect is **node-wide**, not per-worker (contrast
`brix_admin_socket`, which administers `root://` sessions and is therefore
per-worker).

`nodes` lists one line per registered node as
`<host>:<port> role=… free_mb=… util_pct=… state=…`, where state is one of
`up`, `drained` or `space-blocked`. A drain survives the node's heartbeats —
a load update never re-creates or un-blacklists an entry — so only a fresh
`kYR_login` from that node clears it. `forget` on an unregistered node answers
`ok`, not an error; `undrain` on one answers `err not-found`.

**Security:** the socket is chmod 0600 and carries no in-band authentication —
filesystem permission on the path *is* the privilege boundary, exactly as with
stock's `adminpath`. Place it somewhere only the operator can open. Worker 0
serves `<path>` and worker *n* serves `<path>.<n>`, so the path must be short
enough for `sun_path` (107 bytes) with that suffix. The directive is node-global
(parse-time static, last one wins).

### CMS manager response mode

#### `brix_cms_response redirect|proxy`

**Context:** stream server (CMS manager). **Default:** `redirect`. How a CMS
manager answers a client whose path a registered data server holds.
`redirect` issues the stock `kXR_redirect` to the selected node. `proxy` pins
the client's session to the selected node and relays its requests through the
manager (select-then-proxy); `kXR_locate` is then answered with the manager's
own address, so clients that cannot reach data servers directly still work.
Registered in `src/protocols/root/stream/directives_cms.h` (phase-115 W2.1).

### Dashboard

#### `brix_dashboard_vfs_browse on|off`

**Context:** location (dashboard). **Default:** `off`. Enables the read-only
VFS export browser under `/api/v1/vfs*` (census, listing, download through
`brix_vfs_*`). It requires the dashboard's admin authentication; with `off`
those routes answer 404.

### Tape / FRM

Twenty-two `brix_frm_*` directives are registered in
`src/protocols/root/stream/directives_net.h`; **nine drive behaviour and
thirteen are accepted, no effect in 2.0.** The in-process FRM engine the
thirteen configured (durable queue file, copy runners, fail/back-off policy,
migration) was dissolved in phase 64; the purge pair regained an engine in
phase-115 W3.2 (below); tape recall now goes through
the `tape://` VFS adapter (`src/fs/backend/frm/`), whose stage command and
library dialects are configured by the `BRIX_FRM_STAGECMD`,
`BRIX_FRM_{HPSS,CTA}_STAGECMD`, `BRIX_FRM_LIB` and `BRIX_FRM_{HPSS,CTA}_LIB`
environment variables (see `k8s-tests/remote-suite/tests/test_frm_scratch.py`
and `src/fs/backend/frm/sd_frm_adapter.c`), and the stage request registry
lives in shared memory. The thirteen names stay registered on purpose
(phase-89 ADR-3, ratified 2026-07-27: grammar retained so existing
configurations load; pinned by `tests/test_frm_directive_pin.py`), and they
are listed in the [2.0 readiness register](../10-reference/release-2.0-readiness.md).

#### `brix_frm on|off`

**Context:** stream server. **Default:** `off`. Enables the stage request
registry behind `kXR_prepare` / `kXR_query prepare` and the nearline-open
recall path; with `off` a nearline open is served from the backend as-is.

#### `brix_frm_max_inflight <n>`

**Context:** stream server. **Default:** `128`. Capacity of the shared-memory
stage request registry (`postconfiguration.c`); a `kXR_prepare` beyond it is
refused.

#### `brix_frm_stage_ttl <time>`

**Context:** stream server. **Default:** `300s`. How long a parked nearline
open (and its `kXR_prepare` record) stays live before it is reaped
(`open_request_resolve.c`, `prepare_recall.c`).

#### `brix_frm_stage_wait <seconds>`

**Context:** stream server. **Default:** `30`. The `kXR_wait` interval
returned to a client whose `open` triggered a stage-in: the client retries
after this many seconds while the recall runs.

#### `brix_frm_async_recall on|off`

**Context:** stream server. **Default:** `off`. Park the nearline open with
`kXR_waitresp` and complete it in place through `kXR_attn(asynresp)` when the
recall lands, instead of the `kXR_wait` retry loop.

#### `brix_frm_control_dir <path>`

**Context:** stream server. **Default:** unset. Directory the stage registry
publishes its control state into when `brix_frm on`; read at worker start
(`process_server_init.c`).

#### Nearline export — `brix_storage_backend tape://<adapter>/<base>[?arc=<depth>]`

`tape://<adapter>/<base-path>` (alias `frm://`) selects the MSS adapter
(`stub` = the built-in local-directory simulation used by the tests; `exec`
/ `hpss` / `cta` drive `BRIX_FRM_*_STAGECMD`; `lib` / `libhpss` / `libcta`
`dlopen` `BRIX_FRM_*_LIB`) and the online buffer's base path, which must be
absolute (`[emerg] brix_storage_backend: tape://|frm:// needs
"//<adapter>/<base-path>[?arc=<depth>]"`). The same URL form is accepted by
the tier store directives (`brix_cache_store`, `brix_cache_cold_store`,
`brix_stage_store`).

**Dataset archiver (phase-115 W3.1, 2026-09-06).** `?arc=<depth>`, depth
`1..8`, wraps the selected adapter in `src/fs/backend/frm/sd_frm_arc.c`: a
*dataset* is the first `<depth>` path components of a key, and its members
stay in the online buffer (per-key migration deferred) until the completion
marker `.brix-dataset-complete` is written into the dataset. Sealing packs
every regular file below the dataset into one stored (uncompressed) ZIP,
`<dataset>.brixarc.zip`, migrates it to tape, writes the member index to the
sidecar `<base>/.arcidx/<dataset>.idx` and migrates the marker; the archive
is a plain ZIP readable by `unzip` or Python `zipfile`. Sealing is
synchronous inside the marker's staged commit — there is no background
backup queue. Afterwards a member read recalls the archive and extracts that
member only; `stat` and directory listings answer from the sidecar with no
recall. A sealed dataset is immutable: a new member is refused with `EPERM`
(`kXR_NotAuthorized`), republishing the marker with `EEXIST` (`kXR_ItExists`),
and `*.brixarc.zip` is a reserved key (`EINVAL`, `kXR_ArgInvalid`). Member
names are validated on extract — `..`, absolute paths and control bytes are
skipped, never created, and counted in `brix: tape archive "…": skipped N
unsafe member name(s)`. Any other query is refused at `nginx -t`:
`brix_storage_backend: tape:// query "<q>" is not "arc=<1..8>"` on the
export, `tape store opts "?<q>": expected "arc=<1..8>"` on a tier store.
Pinned by `tests/test_phase115_tape_arc.py`.

#### Tape-buffer purge engine

Phase-115 W3.2 (2026-09-05) gave the `tape://` tier's online buffer
(`<base>/.online`) an in-process LRU reaper,
`src/fs/backend/frm/sd_frm_purge.c`, paced by a worker-0 timer in
`src/core/config/process_frm_purge.c`. It arms when the export's driver chain
carries a `tape://` tier and at least one of the two arms below is
configured; with the directives set but no tape tier in the chain the worker
logs `brix: brix_frm_purge_* configured but export "…" has no tape:// tier;
purge engine not armed` and nothing runs. Each pass takes a non-blocking
`flock` on `<online>/.brix-purge.lock` (a concurrent pass, or an operator's
manual run, makes it skip with an INFO line), walks the buffer without
following symlinks, and releases the coldest copies first until every armed
target is met. Only copies whose MSS adapter reports a durable tape copy are
released — the tape side is never touched — and copies younger than 30 s,
copies pinned by an in-flight `prepare`/stage request, and symlinks are
skipped. Releases count in `brix_frm_purge_total` and
`brix_vfs_evict_bytes_total{driver="frm"}`. Pinned by
`tests/test_phase115_tape_purge.py`.

2.0 F4 (2026-09-08) added `frm_purged`'s per-space policy surface on top of
the two export-wide arms: `brix_frm_purge_policy` gives a `brix_oss_space`
group its own owned-bytes arm, hold and, with `brix_frm_purge_polprog`, an
external program that chooses which of the group's eligible copies go. A
rule alone arms the engine. Pinned by `tests/test_release20_purge_policy.py`.

#### `brix_frm_purge_watermark <hi> <lo>`

**Context:** stream server. **Default:** unset (filesystem arm off).

Filesystem-occupancy arm. `hi` and `lo` are fractions (`0.90`) or
percentages (`90%`) with `0 < hi < 1` and `lo ≤ hi`; a `lo` above `hi` is
refused at `nginx -t`. When a pass finds the online buffer's filesystem above
`hi`, it releases cold copies until occupancy is back down to `lo`.

#### `brix_frm_purge_max_bytes <size>`

**Context:** stream server. **Default:** `0` (cap arm off).

Owned-bytes cap arm: when the bytes the online buffer owns exceed the cap,
the pass releases cold copies down to it. Independent of filesystem
occupancy; either arm on its own arms the engine.

#### `brix_frm_purge_interval <time>`

**Context:** stream server. **Default:** `5m`.

Re-arm interval between passes; values under `1s` are raised to `1s`. The
first pass runs 5 s after the worker starts.

#### `brix_frm_purge_policy {*|<group>} <hi> <lo> [hold <time>] [polprog]`

**Context:** stream server. **Default:** none (2.0 F4, 2026-09-08).

One rule per `brix_oss_space` group, or `*` for every key whose group has no
rule of its own and for keys under no group at all (a nested group is its own
space: a key of a group without a rule never inherits an enclosing group's
rule). A rule is an owned-bytes arm of the group alone: when the bytes the
group holds in the online buffer exceed `<hi>`, the pass releases the group's
coldest eligible copies until they are under `<lo>`. Thresholds are sizes
(`2g`, `500m`) or, for a named group with a positive `quota=`, percentages of
that quota (`90%` `70%`); both must be of one kind and `<lo>` may not exceed
`<hi>`. `hold <time>` keeps copies touched more recently than that (the
engine's 30 s floor applies when it is shorter or absent). `polprog` marks the
group's releases as needing the approval of `brix_frm_purge_polprog`, which
must then be configured. The export-wide arms (`brix_frm_purge_watermark`,
`brix_frm_purge_max_bytes`) still reach into every group; a rule alone arms
the engine. Every group named must be a `brix_oss_space` of the same server
and may carry one rule; the merge refuses anything else. The pass logs one
`tape purge "…" policy "<group>": owned A -> B bytes (hi=… lo=… hold=… s[,
polprog]), released N file(s), M bytes` line per rule and one `policy pass:
rules=… held=… unapproved=… polprog=idle|ok|failed approved=… ignored=…`
line per pass. The `frm_purged` analog is `purge.policy {*|sname} min max
[hold] [polprog]`.

#### `brix_frm_purge_polprog <program>`

**Context:** stream server. **Default:** none (2.0 F4, 2026-09-08).

The external policy program the purge engine runs once per pass whenever a
`polprog` rule's group is under pressure (its own arm or an export-wide one):
`<program> <candidates-file> <decision-file>`, no shell, with the worker's
credentials, under the `brix_frm_copy_timeout` deadline (30 s when that is
unset; a hung program is SIGKILLed). The candidates file lists every online
copy of every `polprog` group, one `<group> <touched-epoch> <size> <key>` line
each, `<key>` being the export path of the copy (leading `/`). The program
must create the decision file with one key per line naming the copies that
may go (empty = none); the engine then releases, in LRU order and within the
group's need, only the candidates it named. It chooses among eligible copies
and can never add one: a line naming anything that is not one of its
candidates (another group's key, a traversal, an absolute path, a symlink, an
unmigrated copy) is counted as `ignored` and never touched. Any failure —
cannot spawn, non-zero exit, deadline, no decision file — is fail-closed: the
`polprog` groups release nothing this pass and the error log says why
(`policy program "…" failed (<why>); its groups release nothing this pass`);
rules without `polprog` still release. Both files live under the online root
as `.brix-purge.candidates` / `.brix-purge.decision` and are removed after the
run; every `.brix-purge.*` name under the buffer is reserved for the engine.
The program must be an absolute path and, like `brix_frm_stagecmd`, may not
be group- or world-writable. Setting it without any `polprog` rule is a
warning: the program never runs. Pinned by
`tests/test_release20_purge_policy.py`.

#### `brix_frm_queue_path <path>`

**Context:** stream server. **Default:** none — `brix_frm on` refuses to
load without it (`[emerg] brix_frm on requires brix_frm_queue_path`) and the
path must be absolute. The durable stage journal (2.0 F1): every staged
write-through flush and recall request is persisted here as a `<reqid>.req`
record, replayed on worker start and swept by `brix_frm_fail_backoff`;
records that exhaust `brix_frm_fail_retries` move to `<path>/deadletter/`.
Worker 0 creates the directory (mode 0700) at start; when that fails the
worker logs `brix_frm_queue_path "<path>": mkdir failed; the stage journal
is in-memory only (no restart recovery)` and keeps serving. Before 2.0 the
journal directory came only from the `BRIX_STAGE_JOURNAL_DIR` environment
variable, which is still honoured on servers without `brix_frm on`.

**OssArc backup queue (2.0 F3).** Behind `tape://<adapter>/<base>?arc=<depth>`
the dataset seal is an `archive` journal record, not part of the client's
close: the `.brix-dataset-complete` marker's commit freezes the dataset
(members refused `kXR_NotAuthorized`, a second marker `kXR_ItExists`) and
queues the seal, which the engine runs off the event loop — compose the
stored ZIP, ship it, write the sidecar, migrate the marker — with the same
`brix_frm_fail_backoff` re-drive, restart replay and `brix_frm_fail_retries`
dead-letter discipline as a flush. Members stay readable from the online
buffer throughout. A dead-lettered seal is recovered by moving
`deadletter/<reqid>.req` back into the journal directory and reloading or
restarting, or withdrawn by deleting the marker's online copy
(`<base>/.online/<dataset>/.brix-dataset-complete`), after which the next
re-drive drops the record (`reason=not-online`) and the dataset accepts
members again. A replayed record is refused unless its export still
resolves to that tape tier and its key is a completion marker
(`not-anchored` / `no-tape-tier` / `not-a-marker`), so a crafted record can
never seal anything. Without `brix_frm on` there is no journal and the seal
runs inline in the marker's commit, as before 2.0.

#### `brix_frm_stagecmd <program>`

**Context:** stream server. **Default:** none. The program the `tape://exec`
MSS adapter runs as `<program> <verb> <key> <online-buffer>` for the `recall`,
`migrate`, `exists`, `purge`, `rcreate` and `dread` verbs. It must be an absolute path and, when
it exists at load time, must not be group- or world-writable (`[emerg] …
is group- or world-writable; refusing to run a program anyone else can
rewrite`). The directive takes precedence over `BRIX_FRM_STAGECMD` and the
per-dialect `BRIX_FRM_{HPSS,CTA}_STAGECMD` variables, which stay the fallback
when it is unset; it no longer inherits `brix_prepare_command`. The program
runs in a session of its own with only standard input, output and error
open: no worker descriptor (listen socket, client connection, log) reaches
it, and a `brix_frm_copy_timeout` kill takes its whole process group.

#### `brix_frm_copymax <n>`

**Context:** stream server. **Default:** `8`. Upper bound on stage-engine
transfers dispatched to the thread pool at once; further requests wait in
the scheduler queue. Must be at least 1.

#### `brix_frm_fail_retries <n>`

**Context:** stream server. **Default:** `5`. Attempts a journal record may
accumulate — a permanent deny from the origin, or a transient failure
re-driven by the retry sweep or a restart replay — before it is dead-lettered
to `<queue_path>/deadletter/<reqid>.req` with its stage copy retained for
operator recovery (`[error] … DEAD-LETTERED (reqid=… attempts=…)`). Must be
at least 1.

#### `brix_frm_fail_backoff <time>`

**Context:** stream server. **Default:** `60s`; values under `1s` are raised
to `1s`. Period of worker 0's retry sweep, which re-drives every `FAILED`
journal record older than the backoff without waiting for a restart
(`[notice] stage retry sweep armed (…)` at start, one `retry sweep - …`
summary per pass that re-drove something). Armed only when a `brix_frm on`
server publishes a `brix_frm_queue_path`; an environment-only journal keeps
its restart-only replay.

#### `brix_frm_copy_timeout <time>`

**Context:** stream server. **Default:** `0` (no deadline). Wall-clock limit
for one `brix_frm_stagecmd` invocation (`recall`, `migrate`, `exists`, `purge`, `rcreate`): a
child still running at the deadline is killed with `SIGKILL` — its whole
process group, so a shebang script's children die with it — the operation
fails with `ETIMEDOUT`, and the worker logs `stage command "<program> <verb>
<key>" exceeded brix_frm_copy_timeout (<n> ms) and was killed`. Directory
listing (`dread`) is not subject to the deadline.

#### `brix_frm_stagemsg <file>`

**Context:** stream server. **Default:** none (no feed). The StageEvents
notification file — the analogue of xrootd's `oss.stagemsg` /
`XRDOFSEVENTS` hand-off to an external stager (2.0 F2). Every worker opens
it once at start (created `0600`, append-only) and writes one line per
stage transition, so a site hook, tape monitor or external stager tails one
file instead of parsing `error.log` or the journal directory:

```
<utc-iso8601> <source> <event> <reqid|-> <key|-> [name=value ...]
```

The key and every value are `%`-escaped as a URI (space, `%`, `#`, `?`,
`"`, control and non-ASCII bytes), so a line always splits on spaces and a
pair on its first `=`. Sources and events:

| Source | Events | Pairs |
|---|---|---|
| `engine` — the durable stage engine (`brix_frm_queue_path`) | `queued`, `started`, `done`, `failed`, `deadletter`, `replayed`, `dropped` | `kind=` (`flush`, `recall`, `upload`, `multipart`, `archive`), `errno=`, `attempts=`, `reason=` (`denied`, `unreachable`, `corrupt`, `not-a-flush`; for an `archive` record `not-anchored`, `no-tape-tier`, `not-a-marker`, `not-online`, `no-archiver`) |
| `prepare` — the `kXR_prepare` / Tape REST request registry (`brix_frm_control_dir`) | `queued`, `staging`, `online`, `failed`, `cancelled`, `deleted`, `expired` | `principal=` (the requester DN, `-` when anonymous) |
| `frm` — the `tape://` MSS adapter (no request id) | `recall-begin`, `recall-online`, `recall-failed`, `migrate-done`, `migrate-failed`, `seal-done`, `seal-failed` | `errno=` |

The path must be absolute and, if the file already exists at load time, it
must be a regular file that is not group- or world-writable (`[emerg]
brix_frm_stagemsg "<file>" is group- or world-writable; refusing to feed a
file anyone else can append to` — a feed anyone can append to is a forged
tape-event stream for whatever tails it). The feed is best-effort: a failed
open or write logs one `[error] brix_frm_stagemsg "<file>": open failed;
stage notifications are off in this worker until the file is writable again
(staging itself is unaffected)` and the next transition re-opens the file,
so repairing the directory needs no reload. Nothing in the file is a
credential: keys, principals, kinds and numbers only. An asynchronous MSS
whose recall completes on a later poll reports that completion through the
`prepare online` line of the request that asked for it, not through a second
`frm` line. Start-up announces the feed with `[notice] stage engine:
StageEvents feed "<file>"`. Pinned by `tests/test_release20_frm_stagemsg.py`.

The seven knobs configure one process-wide stage engine: every `brix_frm on`
server must publish the same values, and a second server that disagrees is
refused at load (`[emerg] brix_frm_copymax 5 differs from the value another
brix_frm server published (4): the stage engine is process-wide`). Any of
them on a server without `brix_frm on` is accepted with `[warn] … is
ignored: brix_frm is off in this server`. Seven further names of the
in-process engine dissolved in phase 64 left the grammar in 2.0 and are
refused as `unknown directive`; the
[2.0 readiness register](../10-reference/release-2.0-readiness.md) §(c.1)
lists them. Pinned by `tests/test_release20_frm_knobs.py` and
`tests/test_release20_frm_stagemsg.py`.

### HTTP guard and stream relay guard

The HTTP knobs are described with examples in
[`src/net/httpguard/README.md`](../../src/net/httpguard/README.md).

#### `brix_guard_default_signatures on|off`

**Context:** http, server, location. **Default:** `on`. Whether the built-in
junk-scanner signature set (`.php`, `.asp`, `wp-`, `.git`, `.env`, …) is
applied when `brix_guard on`.

#### `brix_guard_signature <substring>`

**Context:** http, server, location. Repeatable. Extra blocklist substring
matched against the request line in addition to the default set.

#### `brix_guard_valid_prefix <prefix>` / `brix_guard_valid_method <method> [method …]`

**Context:** http, server, location. **Default:** taken from
`brix_guard_profile`. Narrow the legitimate namespace and the allowed HTTP
methods; a request outside either is bounced with `brix_guard_bounce_status`
and audited to `brix_guard_audit_log`.

#### `brix_guard_stream on|off`

**Context:** stream server. **Default:** `off`. The `root://` equivalent of
the HTTP guard for the stream relay sink: a connection that does not present
a valid XRootD handshake within the relay is dropped
(`src/protocols/root/relay/relay_guard.c`).

### Kerberos and packet marking

#### `brix_krb5_delegate on|off`

**Context:** stream server; http, server, location. **Default:** `off`.
Phase-70 §5.7: accept a forwardable TGT from a krb5-authenticated client and
use it for the backend connection made on that client's behalf. Requires a
build with Kerberos support.

#### `brix_pmark_domain any|local|remote`

**Context:** stream server; http, server, location. **Default:** `any`.
Which address class receives SciTag packet marking: `local` marks only
traffic to site-local peers, `remote` only off-site, `any` both.

#### `brix_pmark_firefly_origin on|off`

**Context:** stream server; http, server, location. **Default:** `off`.
Also send the flow-lifecycle firefly UDP report to the client's origin
address, in addition to the collector named by `brix_pmark_firefly_dest`.

### SSI (Scalable Service Interface)

Opt-in request/response service on the stream plane; the CTA (CERN Tape
Archive) bridge is its first service.

#### `brix_ssi_service <name>`

**Context:** stream server. **Default:** none (SSI disabled). Names the
service handled by `kXR_ssi` requests on this server; `cta` enables the
tape-archive bridge.

#### `brix_ssi_max_inflight <n>` / `brix_ssi_request_max <size>` / `brix_ssi_response_max <size>`

**Defaults:** `8` / `1m` / `1m`. Concurrent SSI requests per session and
the largest request and response body the server will buffer.

#### `brix_ssi_cta_journal <path>` / `brix_ssi_cta_executor test|prod`

**Defaults:** none / `test`. Where the CTA bridge journals accepted requests
(so a restart can replay them), and whether the request is handed to the
production executor or to the in-tree test executor that only records it.

### Throttling and bandwidth reservation

#### `brix_throttle_zone <name>`

**Context:** stream server. **Default:** none. Binds the server's
`brix_throttle_*` limits to a declared rate-limit zone so the counters are
shared across workers; the name must be declared with `brix_rate_limit_zone`
or the configuration is refused.

#### `brix_throttle_bandwidth_zone <name>` / `brix_throttle_bandwidth_budget <size>`

**Context:** stream server. **Default:** off. Phase-92 XrdBwm-style read
reservation: a read reserves its size against the per-zone budget and is
answered `kXR_Overloaded` when the budget is exhausted, instead of queuing
until the link saturates.

### Third-party copy

#### `brix_tpc_outbound_passthrough on|off`

**Context:** stream server; http, server, location. **Default:** `on`.
Forward the inbound bearer token to the TPC source when the client presented
one and no `brix_tpc_outbound_*` exchange is configured. Turn off when the
source must never see the client's own credential.

#### `brix_tpc_outbound_tls on|off`

**Context:** stream server; http, server, location. **Default:** `off`.
Phase-57 §F5: require TLS on the outbound `root://` source connection of a
native TPC pull (`roots://`), refusing a source that cannot upgrade.

#### `brix_tpc_outbound_renew_lead <time>`

**Context:** stream server. **Default:** `0` (renewal disabled). Renew the
delegated credential this long before it expires, on the live outbound
connection, so a long copy can outlive the token that launched it. A copy that
would otherwise die mid-stream when its bearer aged out instead re-mints and
continues.

Only the **issuer-facing** token modes can act on this — `oidc-agent` and
RFC 8693 token exchange (`brix_tpc_outbound_token_endpoint`) — because renewal
means asking an issuer for a fresh credential. A credential merely *forwarded*
from the client (`brix_tpc_outbound_passthrough`) cannot be re-minted by this
server, and configuring a lead time does not change that.

Set the lead comfortably longer than one mint round-trip; `0` keeps the
pre-renewal behaviour, where a copy simply runs on the credential it started
with.

#### `brix_tpc_outbound_renew_strict on|off`

**Context:** stream server. **Default:** `off`. Fail a pull whose delegated
credential has genuinely expired and could not be renewed, instead of streaming
on with it.

It is off by default so that turning renewal on with
`brix_tpc_outbound_renew_lead` can never introduce a denial by itself: a site
that enables renewal gets the benefit without a new failure mode. Turn it on
where an expired credential must stop the transfer rather than be tolerated.

Note the one case this flag does **not** govern: a mint that fails against an
*already-expired* credential is fatal either way, because there is nothing left
to renew from.

#### `brix_tpc_max_hops <n>`

**Context:** stream server. **Default:** `4`. **Range:** `0`–`16`. How many
`kXR_redirect` answers a native TPC pull follows from its source before giving
up. Each hop re-bootstraps on the redirect target (handshake, protocol, login
and the same ztn/GSI/token leg as the first source), passes the target through
`brix_tpc_source_guard` / `brix_tpc_source_allow` exactly as the host the
client named, and is logged as `TPC hop N: from -> to for <lfn>`. `0` refuses
the first redirect (`kXR_NotAuthorized`, "brix_tpc_max_hops is 0"). A redirect
back to the host being read, or one with a malformed body, fails the pull
regardless of the budget. A hop the allowlist refuses counts on
`brix_stream_tpc_egress_refused_total`.

#### `brix_tpc_streams <n>`

**Context:** stream server. **Default:** `1`. **Range:** `1`–`15`. Upper bound
on the number of parallel source connections a native TPC pull may use when
the client asks for them with `tpc.str=<n>` in the destination open (the
`ofs.tpc streams` analogue; BriX's `xrdcp -S <n>` sends the key, stock XrdCl
5.9 does not). The destination opens `min(n, brix_tpc_streams) - 1` extra
connections to the source, binds each to the primary session with `kXR_bind`,
and reads the file as rounds of one 1 MiB read per stream. With the default of
`1`, for a hint that does not parse, for a source that refuses `kXR_bind`, or
for one that returned no session id, the pull is the ordinary single-stream
loop — the degradation is logged, never an error.

#### `brix_tpc_push on|off`

**Context:** stream server. **Default:** `off`. Opt this listener into the
BriX native-TPC **push** dialect (`tpc.stage=push`). Stock native TPC is
destination-side *pull* only — the destination dials the source and reads — so
a site whose storage may make only **outbound** connections cannot be the source
of a native copy at all. A push inverts who dials: the source connects to the
destination and writes.

One flag arms both roles on the listener, because an operator opts into both
postures at once: a source may originate a push, and a destination may accept
bytes from a server rather than a client. Three legs, all carrying
`tpc.stage=push` so a stock peer never mistakes one for a pull:

1. **client → destination** — write-open `<dst-lfn>?tpc.key=K&tpc.stage=push`.
   Registers `K` in the rendezvous registry and **creates** the file. Nothing is
   dialled.
2. **client → source** — read-open
   `<src-lfn>?tpc.key=K&tpc.dst=<host[:port]>&tpc.dlfn=</dst/path>&tpc.stage=push`
   (optionally `&tpc.str=<n>`). The two `kXR_sync`s that arm and fire a pull arm
   and fire the push.
3. **source → destination** — write-open
   `</dst/path>?tpc.key=K&tpc.org=<client>&tpc.stage=push`. **Consumes** `K`
   (single-use) and writes; `kXR_open_updt` only, so a push can only write where
   a client already registered a key.

With the flag off, either leg is refused `kXR_Unsupported` at the open — before
path resolution, authorization and the write gate — so the answer names the
posture, not the path.

What the dialect does **not** relax:

- The destination the source is told to dial goes through the same
  `brix_tpc_source_guard` / `brix_tpc_source_allow` allowlist and the same
  `brix_tpc_allow_local` / `brix_tpc_allow_private` SSRF policy as a pull
  source, including the per-resolved-address recheck at connect. A refused
  destination is refused at the **open**, with `signal=tpc_egress` in the guard
  audit and no socket dialled; it counts on
  `brix_stream_tpc_egress_refused_total`.
- `tpc.str=<n>` is clamped by `brix_tpc_streams`, exactly as on a pull.
- **The source export stays read-only.** A push source writes nothing locally —
  it reads its own file and streams it out. The two arm/fire `kXR_sync`s are the
  only thing exempted from `brix_allow_write`; a `kXR_sync` on any other handle,
  a sync after the transfer finishes, and every other write opcode still answer
  `kXR_fsReadOnly`. Turning this on therefore grants a client no mutation
  privilege on the export.
- A failed push never removes the source file. (The failure-path unlink that
  removes a half-written *destination* copy on a pull is suppressed on a push,
  where the same path names the operator's own data.)

The destination still needs `brix_allow_write on`: it is the side that writes.

#### `brix_webdav_tpc_credential_forward on|off`

**Context:** http, server, location. **Default:** `on`. Present the
requester's per-user proxy certificate or bearer to the HTTP-TPC source.
Opportunistic: when no per-user credential is available the configured
`brix_webdav_tpc_cert`/`_key` are used.

### WebDAV

#### `brix_webdav_checksum_on_write <alg>[,<alg>]`

**Context:** http, server, location. **Default:** none. Compute and persist
the named checksums as the body of a `PUT` streams in (§8.3), so a later
`Want-Digest` or `RFC-3230` query is answered from the stored value without
re-reading the file.

#### `brix_webdav_checksum_xattr_format text|xrdcks`

**Context:** http, server, location. **Default:** `text`. Layout of the
persisted checksum extended attribute: plain text, or the binary `XrdCks`
record an xrootd data server writes, for a namespace shared with stock
xrootd.

#### `brix_webdav_dig_export <name> <dir>` / `brix_webdav_dig_auth <file>`

**Context:** http, server, location. **Default:** none. The xrootd
`/dig/` diagnostic namespace: `dig_export` publishes `<dir>` (resolved with
`realpath` at configuration time) under the name; `dig_auth` names a
principal→export allow-file and is fail-closed — with the export configured
but no allow-file, or a principal absent from it, the request is refused.

#### `brix_webdav_header2cgi <Header> <cgikey>`

**Context:** http, server, location. **Default:** none. Repeatable. Copies
the value of the named request header into the opaque CGI string under
`cgikey` before authorization, the `XrdHttp` `header2cgi` behaviour; the
usual use is `authz` so a proxy that carries the token in a custom header
still authorizes.

#### `brix_webdav_revoke_cache zone=<name>`

**Context:** http, server, location. **Default:** none. Shared-memory zone
(declared with `brix_kv_zone`) in which token-introspection verdicts are
cached across workers, so a revoked token is refused everywhere once the
introspection endpoint has said so and unrevoked tokens are not
re-introspected on every request.

### Write-back (write-through stage)

#### `brix_wt_credential <name>`

**Context:** stream server; http, server, location. **Default:** `""`
(anonymous). Name of a `brix_credential` the write-back flusher presents to
the backend when replaying staged writes.

#### `brix_wt_stage_high_watermark <ratio|percent>` / `brix_wt_stage_low_watermark <ratio|percent>`

**Defaults:** `0` (off) / high − 5 % (or half of high). Occupancy of the
write-back stage area at which new writes are shed: between low and high
the client is told to wait (`kXR_wait` / `503`), at or above high it is
refused (`kXR_Overloaded` / `429`). Accepts `0.9` or `90%`.

### ZIP archive member access

#### `brix_zip_stage_dir <path>` / `brix_zip_force_scratch on|off` / `brix_zip_stage_max_bytes <size>`

**Context:** stream server. **Defaults:** unset / `off` / `512m`. Where a
compressed ZIP member is extracted before it is served, whether extraction
is forced through scratch even when the member is stored uncompressed, and
the largest member that will be staged (a larger one is refused).

### Miscellaneous stream-plane knobs

#### `brix_auth_maxfail <n>`

**Context:** stream server. **Default:** `0` = built-in `10`. Number of
failed authentication attempts a session may make before it is disconnected
(brute-force and GSI CPU-amplification guard, §5.7).

#### `brix_dirstats on|off`

**Context:** stream server. **Default:** `off`. A `kXR_stat` of a directory
reports the recursive byte size of its subtree (an on-demand `du` through
the VFS walk) instead of the directory inode size, matching xrootd's
`dirstats`.

#### `brix_durable_commit on|off`

**Context:** stream server (adopted by the http plane). **Default:** `on`.
Whether a staged write is `fsync`ed before it is published at its final
path. `off` skips the pre-publish data sync — faster on battery-backed
storage, at the cost of a torn file if the host loses power between publish
and the next writeback.

#### `brix_oci_delegate_realm <name>`

**Context:** location (OCI registry). **Default:** `brix-oci`. The realm
string carried in the `WWW-Authenticate` challenge the OCI mirror issues
when a pull must be delegated to the client's own registry credential.

#### `brix_mirror_exclude_opcodes <op> [op …]`

**Context:** stream server. **Default:** none. When a stream mirror target
is configured without `brix_mirror_opcodes`, every request is replayed to
the shadow server; this de-selects the named opcodes from that set (write
opcodes additionally require `brix_mirror_writes on`). Ignored when
`brix_mirror_opcodes` lists opcodes explicitly.

**Vocabulary** (both directives): `all stat locate open dirlist statx query
mkdir rm rmdir mv truncate chmod write`. `read` and `readv` are **refused at
`nginx -t`** since 2.0: a read addresses an open handle that only the primary
session holds, so the one-shot mirror can never replay it, and before 2.0 the
names were accepted and then silently skipped — `all` no longer expands to
them either. Delete them from a mask that still lists them.
