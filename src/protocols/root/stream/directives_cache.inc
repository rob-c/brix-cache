/*
 * directives_cache.inc — read-through cache directives (cache mode, cache_root/store, admission, transfer-heap budget)
 * #included into ngx_stream_brix_commands[] in module.c (compiler concatenates;
 * setters/enum tables from module_enums.h stay visible). Not a standalone TU.
 */
    /* cache/proxy directives (merged into ngx_stream_brix_commands[]) */
    /* Read-through cache mode: serve from a local cache_root and fill misses. */
    { ngx_string("brix_cache"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache),
      NULL },

    { ngx_string("brix_cache_export"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_root),
      NULL },

    /* §14 (phase-64): the legacy cache-origin config model is RETIRED. The
     * directives brix_cache_origin{,_tls,_proxy,_cadir,_client,_token_file,
     * _forward_token,_s3_*} are deleted — a cache's source is the export's
     * brix_storage_backend, its identity a named brix_credential attached
     * via brix_storage_credential (x509_proxy/ca_dir, token, s3_access_key/
     * s3_secret_key/s3_region, sss_keytab), and the physical cache is
     * brix_cache_store. cache_origin_family survives below: it is the connect
     * address-family policy for the tier root:// backend, not an origin knob. */

    { ngx_string("brix_cache_origin_family"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_origin_family,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cache_lock_timeout"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_lock_timeout),
      NULL },

    { ngx_string("brix_cache_eviction_threshold"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_eviction_threshold,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Files larger than this are not cached unless their basename matches the
     * include regex below.  Accepts bytes with optional k/m/g suffix.  0 = no limit. */
    { ngx_string("brix_cache_max_file_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_max_file_size,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* Unified cache-state engine: where .cinfo persistence records live ("" ⇒
     * cache_root), how long a dirty write-back staging file may sit before the
     * reaper removes it (secs; 0 = off), and read-cache admission prefixes (parity
     * with brix_wt_{allow,deny}_prefix). */
    { ngx_string("brix_cache_state_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_state_root),
      NULL },

    { ngx_string("brix_cache_dirty_max_age"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_dirty_max_age),
      NULL },

    /* Watermark-driven LRU reaper: a background timer purges the read cache
     * oldest-first when filesystem occupancy crosses the HIGH watermark, down to
     * the LOW watermark (hysteresis). Watermarks accept 0.9 or 90%; the interval
     * is in seconds. cache_eviction_threshold remains the on-fill safety net and
     * the default for HIGH when these are unset. */
    { ngx_string("brix_cache_high_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, reaper.high_watermark),
      NULL },

    { ngx_string("brix_cache_low_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, reaper.low_watermark),
      NULL },

    { ngx_string("brix_cache_reap_interval"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, reaper.reap_interval),
      NULL },

    { ngx_string("brix_cache_deny_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_deny_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("brix_cache_allow_prefix"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_allow_prefix,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    /* §14 (phase-64): brix_cache_storage_backend/_block_size are RETIRED —
     * a driver-backed cache is the tier grammar's brix_cache_store
     * ("pblock:<dir> block_size=<n>", any driver), cinfo carried in-store. */

    { ngx_string("brix_cache_wt_stage_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_wt_stage_root),
      NULL },

    { ngx_string("brix_cache_wt_stage_backend"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_wt_stage_backend),
      NULL },

    { ngx_string("brix_cache_wt_stage_block_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_wt_stage_block_size),
      NULL },

    /* Two-tier write-back-staging backpressure: occupancy of the staging
     * filesystem in [low,high) delays new write-opens/PUTs (kXR_wait/503); at/
     * above high they are rejected (kXR_Overloaded/429) until it drains below
     * low. Reads are never throttled. Accepts 0.9 or 90%. No-op unless a staging
     * root is configured. */
    { ngx_string("brix_wt_stage_high_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_wt_stage_high_watermark),
      NULL },

    { ngx_string("brix_wt_stage_low_watermark"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_watermark,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, cache_wt_stage_low_watermark),
      NULL },

    /* Phase 31 W4: SHM-global transfer-heap budget.  A read that would push the
     * live transfer-buffer total past this is deferred with kXR_wait.  Accepts
     * bytes with optional k/m/g suffix.  0 = no cap.  Default 768m. */
    { ngx_string("brix_memory_budget"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, memory_budget),
      NULL },

    /* Max bytes served per kXR_readv element (the official "maxReadv_ior"). A
     * segment requesting more is capped to this and the client re-reads the tail.
     * Accepts bytes with optional k/m/g suffix. Default 2097136 (stock XRootD:
     * maxBuffsz 2 MiB - 16-byte readahead_list). */
    { ngx_string("brix_readv_segment_size"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, readv_segment_size),
      NULL },

    /* Phase 44: optional io_uring disk-I/O backend (off/auto/on; default auto).
     * `on` requires the backend — startup fails if it is not compiled in or the
     * runtime probe fails (brix_uring_validate_conf, §32 fail-fast). */
    { ngx_string("brix_io_uring"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, io_uring),
      &brix_io_uring_modes },

    { ngx_string("brix_io_uring_queue_depth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, io_uring_queue_depth),
      NULL },

    { ngx_string("brix_io_uring_panic_file"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, io_uring_panic_file),
      NULL },

    { ngx_string("brix_io_uring_admin"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, io_uring_admin),
      NULL },

    { ngx_string("brix_io_uring_restrict"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_brix_srv_conf_t, io_uring_restrict),
      NULL },

    /* §14 (phase-64): the legacy brix_cache_slice is RETIRED — slice/partial
     * caching is the tier grammar's brix_cache_slice_size (same 1 MiB-multiple
     * validation), served by the composed sd_cache partial path (§6.5). */

    /* POSIX extended regular expression matched against the path basename.
     * Matching files are admitted to cache even if they exceed the size limit. */
    { ngx_string("brix_cache_include_regex"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      brix_conf_set_cache_include_regex,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
