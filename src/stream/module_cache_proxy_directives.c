#include "ngx_xrootd_module.h"
/*
 * Read-through cache, write-through mode, CMS manager registration, and
 * transparent proxy directives.
 *
 * WHAT: Defines the nginx configuration directives that control caching behaviour,
 *       write-through mirroring to origin servers, CMS manager heartbeat registration,
 *       and transparent XRootD proxy operation. These directives populate the second
 *       block of the ngx_command_t array (the first block is in module.c).
 *
 * WHY:  Standalone XRootD servers need local read-through caching for hot data
 *       (reducing origin traffic), write-through mirroring for durability, and CMS
 *       manager heartbeat for cluster-aware redirect. Transparent proxy mode lets
 *       nginx terminate auth/TLS at the perimeter while relaying opcodes to a backend.
 *
 * HOW:  Each directive entry is an ngx_command_t struct with: the directive name,
 *       access flags (NGX_STREAM_SRV_CONF), argument count, setter function or slot,
 *       offset into srv_conf struct. Setter functions handle multi-argument parsing
 *       and validation; NGX_CONF_TAKE1 slots store a single string value directly.
 */

#include "proxy/proxy.h"
#include "proxy/proxy_internal.h"

    /* Read-through cache mode: serve from a local cache_root and fill misses. */
    { ngx_string("xrootd_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache),
      NULL },

    { ngx_string("xrootd_cache_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_root),
      NULL },

    { ngx_string("xrootd_cache_origin"),
    /* Sets the cache fill origin host:port. Accepts multiple origins for redundancy;
     * nginx selects the first reachable upstream during cache miss resolution. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_origin,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cache_origin_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_origin_tls),
      NULL },

    { ngx_string("xrootd_cache_lock_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cache_lock_timeout),
      NULL },

    { ngx_string("xrootd_cache_eviction_threshold"),
    /* Sets the cache eviction threshold as a ratio (0.0-1.0) or percentage string.
     * When cache usage exceeds this level, oldest entries are evicted to make room. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_eviction_threshold,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Files larger than this are not cached unless their basename matches the
     * include regex below.  Accepts bytes with optional k/m/g suffix.  0 = no limit. */
    { ngx_string("xrootd_cache_max_file_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_max_file_size,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* POSIX extended regular expression matched against the path basename.
     * Matching files are admitted to cache even if they exceed the size limit. */
    { ngx_string("xrootd_cache_include_regex"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cache_include_regex,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* ---- write-through mode directives (mirrors XrdPfc configuration from
     * /tmp/xrootd-src/src/XrdPfc/README) ---- */

    { ngx_string("xrootd_write_through"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      xrootd_conf_set_wt_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_wt_mode"),
    /* Sets write-through mode: 'direct' mirrors every kXR_write/kXR_pgwrite to
     * origin immediately; 'lazy' defers mirroring until kXR_sync or kXR_close. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_mode,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_wt_origin"),
    /* Sets the write-through origin host:port. Separate from cache_origin — this
     * is where mirrored writes go, regardless of what serves reads from cache. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_origin,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Repeatable: path prefix that is NEVER write-through (deny list). */
    { ngx_string("xrootd_wt_deny_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_deny_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Repeatable: path prefix that is ALWAYS write-through (allow list). */
    { ngx_string("xrootd_wt_allow_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_wt_allow_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Optional CMS manager registration/heartbeat. */
    { ngx_string("xrootd_cms_manager"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_cms_manager,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_cms_paths"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_paths),
      NULL },

    { ngx_string("xrootd_cms_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_interval),
      NULL },

    { ngx_string("xrootd_cms_locate_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, cms_locate_timeout),
      NULL },

    { ngx_string("xrootd_listen_port"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, listen_port),
      NULL },

    /*
     * Async pread/pwrite support is only compiled when nginx itself was built
     * with thread-pool support.
     */
    { ngx_string("xrootd_thread_pool"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      /* Names an nginx thread_pool block to service async disk I/O. */
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, common.thread_pool_name),
      NULL },

    /* ---- transparent proxy mode ---- */

    { ngx_string("xrootd_proxy"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_enable),
      NULL },

    { ngx_string("xrootd_proxy_upstream"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE12,
      xrootd_conf_set_proxy_upstream,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_proxy_upstream_tls"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls),
      NULL },

    { ngx_string("xrootd_proxy_auth"),
    /* Sets proxy auth mode: 'none' (pass-through), 'gsi', 'token', or 'both'.
     * Determines whether nginx authenticates the client before relaying to upstream. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_auth,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_proxy_login_user"),
    /* Sets the proxy login user identity forwarded to the backend XRootD server.
     * Used when proxy_auth=none or token — nginx presents this user to upstream. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      xrootd_conf_set_proxy_login_user,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("xrootd_proxy_audit_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_audit_log),
      NULL },

    { ngx_string("xrootd_proxy_upstream_tls_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls_ca),
      NULL },

    { ngx_string("xrootd_proxy_upstream_tls_name"),
    /* Sets the TLS CA PEM file path for verifying the upstream XRootD server's
     * certificate during proxy mode TLS connections. Required when proxy_upstream_tls=on. */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_upstream_tls_name),
      NULL },

    { ngx_string("xrootd_proxy_reconnect_attempts"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_reconnect_attempts),
      NULL },

    { ngx_string("xrootd_proxy_connect_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_connect_timeout),
      NULL },

    { ngx_string("xrootd_proxy_read_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_read_timeout),
      NULL },

    { ngx_string("xrootd_proxy_keepalive_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, proxy_keepalive_interval),
      NULL },

    { ngx_string("xrootd_proxy_path_rewrite"),
    /* Sets a path rewrite rule: two arguments — source prefix and replacement.
     * Rewrites client paths before forwarding to upstream (e.g., /data -> /store). */
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE2,
      xrootd_conf_set_proxy_path_rewrite,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Required terminator so nginx knows where the directive table ends. */
    ngx_null_command
};

