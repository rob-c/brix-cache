/*
 * srv_conf_fields_cache.inc: Pelican register, unified cache-state engine, LRU reaper, VFS cache storage, checksum-on-fill, io_uring restrictions — a field-declaration fragment of ngx_stream_brix_srv_conf_t, split
 * (phase-79 file-size burndown) out of config.h via the repo's established .inc
 * struct-fragment pattern (cf. module_commands.c / directives_*.inc). Included
 * INSIDE the struct body in config.h — the struct assembles byte-identically, so
 * ZERO ABI change and every `conf->field` access is unchanged. Not a standalone
 * TU; do not #include anywhere but the srv_conf struct body. */

    /* ---- Pelican cache registration / advertisement (origin/pelican_register.c) ---- */
    brix_cache_advertise_conf_t  advertise;  /* [brix_cache_advertise, ..._key,
                                                ..._data_url, ..._sitename, ...]
                                                — see brix_cache_advertise_conf_t. */
    time_t      cache_lock_timeout; /* [brix_cache_lock_timeout 30] — how long to
                                       wait for another worker's fill before giving up */
    ngx_uint_t  cache_eviction_threshold; /* [brix_cache_eviction_threshold 0.9]
                                             filesystem occupancy ratio in ppm */
    off_t       cache_max_file_size;      /* [brix_cache_max_file_size 1g]
                                             Files larger than this are not admitted
                                             to cache unless their basename matches
                                             cache_include_regex.  0 = no limit. */
    off_t       memory_budget;            /* [brix_memory_budget 768m] Phase 31 W4
                                             SHM-global cap on transfer-heap bytes;
                                             a read that would exceed it is deferred
                                             with kXR_wait.  0 = no cap. */
    size_t      readv_segment_size;       /* [brix_readv_segment_size 2097136]
                                             max bytes served per kXR_readv element
                                             (the official "maxReadv_ior"); a segment
                                             requesting more is capped to this and the
                                             client re-reads the tail. Default matches
                                             stock XRootD: maxBuffsz(2MiB) - 16. */
    brix_cache_include_regex_conf_t  include_regex;  /* [brix_cache_include_regex]
                                                        — see brix_cache_include_regex_conf_t. */

    /* ---- unified cache-state engine (src/cache/cinfo.h v3) ----
     * cache_state_root: where the per-file .cinfo persistence records live; "" ⇒
     * default to cache_root. cache_dirty_max_age: a write-back staging file dirty
     * for longer than this (secs) is reaped (default 7 days; 0 = off). The
     * cache_{deny,allow}_prefixes mirror the write-through lists for read-cache
     * admission parity (consumed via the shared filter, cache_admit.h). */
    ngx_str_t    cache_state_root;        /* [brix_cache_state_root] */
    time_t       cache_dirty_max_age;     /* [brix_cache_dirty_max_age] secs; 0=off */
    ngx_event_t *cache_reap_timer;        /* per-worker stale-dirty reaper; NULL if off */
    ngx_array_t *cache_deny_prefixes;     /* brix_wt_prefix_entry_t[] — read admission */
    ngx_array_t *cache_allow_prefixes;    /* same; whitelist when non-empty */

    /* ---- watermark-driven LRU reaper (src/cache/reap_watermark.h) ----
     * A background per-worker timer purges the read cache oldest-first when
     * occupancy crosses cache_high_watermark, down to cache_low_watermark
     * (hysteresis). Watermarks are filesystem occupancy in ppm (0-1000000), the
     * same unit as cache_eviction_threshold (which maps to high for back-compat).
     * cache_reap_interval is the timer period in seconds. */
    brix_cache_reaper_conf_t  reaper;  /* [brix_cache_high_watermark, ..._low_watermark,
                                          ..._reap_interval] — see brix_cache_reaper_conf_t. */

    /* ---- exclusively-VFS cache storage (src/cache/cache_storage.h) ----
     * The cache does ALL disk byte-I/O through an SD driver instance per role
     * (read cache, sidecar/state, write-back staging) — the POSIX driver bound to
     * a per-worker O_PATH rootfd by default, or a configured driver (pblock).
     * Built once at worker init (brix_cache_storage_init), torn down at exit.
     * The *_inst pointers are brix_sd_instance_t* (void* here to keep config.h
     * free of the sd.h include). _backend "" ⇒ POSIX on the role's rootfd. */
    /* §14: cache_storage_backend/_block_size deleted (tier brix_cache_store). */
    ngx_str_t  cache_wt_stage_root;       /* [brix_cache_wt_stage_root] */
    ngx_str_t  cache_wt_stage_backend;    /* [brix_cache_wt_stage_backend] */
    size_t     cache_wt_stage_block_size; /* [brix_cache_wt_stage_block_size] */
    /* Two-tier write-back-staging backpressure: when the staging filesystem
     * (cache_wt_stage_root) occupancy enters [low,high) new write-opens/PUTs are
     * delayed (kXR_wait / 503); at/above high they are rejected (kXR_Overloaded /
     * 429) until it drains below low. Reads are never throttled. ppm (0-1e6);
     * 0 = unset/off (no staging backpressure). */
    ngx_uint_t cache_wt_stage_high_watermark; /* [brix_wt_stage_high_watermark] ppm */
    ngx_uint_t cache_wt_stage_low_watermark;  /* [brix_wt_stage_low_watermark] ppm */
    int        cache_rootfd;              /* O_PATH on cache_root; -1 until init */
    int        cache_state_rootfd;        /* O_PATH on cache_state_root (or cache_root) */
    int        cache_wt_stage_rootfd;     /* O_PATH on cache_wt_stage_root; -1 if none */
    void      *cache_storage_inst;        /* read-cache brix_sd_instance_t* */
    void      *cache_state_inst;          /* sidecar/state instance (POSIX) */
    void      *cache_wt_stage_inst;       /* write-back staging instance; NULL if none */
    /* Policy-layer cstore adapter built over cache_storage_inst at config time
     * (eviction / reaper / free-space drive the store through this, never the
     * bare driver — phase-64 P3/G5). NULL when the read cache is off. */
    void      *cache_storage_cstore;      /* brix_cstore_t* */
    /* Whole-file cache SOURCE built from the legacy cache_origin config (xroot/s3),
     * so every fill runs through the one brix_cache_fill_from_source spine
     * (phase-64 §6.5 fold). NULL for http/pelican (libcurl) or no legacy origin. */
    void      *cache_source_inst;         /* brix_sd_instance_t* (bare origin) */
    /* Write-through as one mechanism (Option A): sd_stage(source=wt_origin,
     * store=export backend). A write-open routes through this so a write buffers on
     * the local store and flushes to the origin on close — replacing run_flush. NULL
     * when write-through is off or the store backend is unavailable. */
    void      *cache_wt_stage_sd_inst;    /* brix_sd_instance_t* (sd_stage) */
    int        cache_wt_store_rootfd;     /* O_PATH fd for a posix-export wt store; -1 */

    /* ---- checksum-on-fill integrity (src/cache/verify.h) ----
     * After a fill downloads a file into its .part staging file, recompute its
     * content checksum and compare against the digest the origin advertised
     * (kXR_Qcksum for root://, a Digest header for HTTP/Pelican). A mismatch
     * discards the part so a corrupted transfer never becomes a cache entry. */
    ngx_uint_t  cache_verify;          /* [brix_cache_verify off|best-effort|require]
                                          brix_cache_verify_mode_e; default
                                          best-effort. 0=off, 1=best-effort, 2=require. */
    ngx_str_t   cache_verify_digest;   /* [brix_cache_verify_digest crc32c]
                                          preferred algorithm to request from an
                                          HTTP origin (Want-Digest); empty = take
                                          whatever the origin reports. */

    /* §14: the legacy cache_slice_size field is deleted — slice/partial caching
     * is common.cache_slice_size (brix_cache_slice_size, tier grammar). */

    /* ---- write-through mode ----
     *
     * On a write-mode open, if wt_enable is set the decision callback evaluates
     * whether writes should be propagated back to an origin XRootD server. The
     * cached decision (wt_policy) is applied at close time: sync flush blocks
     * until complete; async flush schedules a background task and returns
     * immediately to the client.
     *
     * Mirrors XrdPfc's two-mode design: full-file prefetch vs block-based mode
     * is replaced here by sync-close-flush vs async-thread-pool-flush.
     */

    /* ---- write-through mode ---- */
    brix_wt_conf_t  wt;  /* [brix_write_through, brix_wt_mode, brix_wt_origin,
                            brix_wt_credential, ...] — see brix_wt_conf_t. */

    /* ---- request signing / security level ---- */
    ngx_uint_t  security_level;  /* [brix_security_level none|compatible|standard|intense|pedantic]
                                     kXR_secNone=0 .. kXR_secPedantic=4; 0 = no enforcement */

    /* ---- in-protocol TLS upgrade (kXR_ableTLS) ---- */
    ngx_flag_t  tls;      /* [brix_tls on|off] — advertise kXR_haveTLS */
    ngx_flag_t  tls_ktls; /* [brix_ktls on|off] — SSL_OP_ENABLE_KTLS so TLS reads
                           * can sendfile (Phase 29). Default off: only a win with
                           * hardware TLS-offload NICs — software kTLS is SLOWER than
                           * userspace OpenSSL on AES-NI CPUs (measured 2-5x). */
    ngx_ssl_t  *tls_ctx;  /* SSL_CTX built from certificate/key at postconfiguration */

    /* ---- root:// inline read compression (phase-42 W4) ----
     * [brix_read_compress on|off] — opt-in, off by default and invisible to
     * stock XRootD peers.  When on, the server advertises available codecs via
     * kXR_Qconfig "cmpread" and honours a client open opaque
     * "?xrootd.compress=<codec>" by compressing each kXR_read response with that
     * codec (pgread/readv stay plaintext — the CRC32c invariant is preserved).
     * A stock client never sends the opaque, so the uncompressed path is
     * byte-identical. */
    ngx_flag_t  read_compress;

    /* ---- root:// inline write decompression (phase-42 W5) ----
     * [brix_write_compress on|off] — opt-in, off by default and invisible to
     * stock peers.  When on, the server advertises codecs via kXR_Qconfig
     * "cmpwrite" and honours a client WRITE open opaque "?xrootd.compress=<codec>"
     * by decompressing each kXR_write payload (bomb-guarded) before storing it
     * plaintext on disk.  pgwrite stays plaintext.  A stock client never sends the
     * opaque, so the uncompressed write path is byte-identical. */
    ngx_flag_t  write_compress;

    /* ---- ZIP member access (phase-57 W2) ----
     * [brix_zip_access on|off] — opt-in, off by default.  When on, a read
     * open whose opaque carries "?xrdcl.unzip=<member>" serves that member of
     * the archive as a standalone read-only file (stored + deflate), matching
     * XrdZip.  zip_cd_max_bytes caps the central-directory read (bomb guard;
     * default 16 MiB). */
    ngx_flag_t  zip_access;
    size_t      zip_cd_max_bytes;
    /* Materialize-to-scratch for ZIP member access: zip serves a member by
     * random-access pread (+ sendfile for stored members) over the archive fd,
     * which a backend with no kernel fd cannot provide.  When staging is in
     * effect, the archive is copied into a local POSIX scratch and read there.
     * Off by default (a POSIX export reads the confined fd in place). */
    ngx_str_t   zip_stage_dir;        /* [brix_zip_stage_dir <path>]          */
    ngx_flag_t  zip_force_scratch;    /* [brix_zip_force_scratch on|off]      */
    size_t      zip_stage_max_bytes;  /* [brix_zip_stage_max_bytes <size>]    */

    /* ---- cluster / redirector mode ---- */
    ngx_flag_t  manager_mode;  /* [brix_manager_mode on|off] — query the
                                   server registry in kXR_open and kXR_locate
                                   before attempting local resolution */
    ngx_uint_t  pipeline_depth; /* [brix_pipeline_depth N] — per-connection
                                    in-flight response/read window (out_ring +
                                    rd_pool slots).  A deeper pipeline absorbs more
                                    wire latency/jitter (packet reordering, high-BDP
                                    links) at a per-slot memory cost.  Default
                                    BRIX_PIPELINE_DEPTH_DEFAULT; clamped to
                                    [MIN, MAX]. */
    ngx_uint_t  registry_slots; /* [brix_registry_slots N] — shared-memory
                                    registry capacity; default 128 */
    ngx_uint_t  session_slots;  /* [brix_session_slots N] — session registry
                                    capacity; default BRIX_SESSION_REGISTRY_SLOTS */
    ngx_uint_t  redir_cache_slots; /* [brix_redir_cache_slots N] — manager
                                    redirect-collapse cache capacity;
                                    default BRIX_REDIR_CACHE_SLOTS */

    /* ---- Phase 22: active health checks (off by default) ---- */
    brix_hc_conf_t  hc;  /* [brix_health_check, brix_health_check_*] — see brix_hc_conf_t. */

    /* ---- CMS manager heartbeat + client network-fault resilience ---- */
    brix_cms_conf_t  cms;  /* [brix_cms_manager, brix_cms_paths, brix_cms_interval,
                              brix_cms_*_timeout, ...] — see brix_cms_conf_t. */
    ngx_int_t        listen_port;  /* [brix_listen_port 1094] — port advertised to CMS manager */

    /* ---- bounded recursive query walks ---- */
    ngx_uint_t  ckscan_max_depth; /* [brix_ckscan_depth N] — maximum
                                      recursive directory depth for kXR_Qckscan */
    ngx_uint_t  ckscan_max_files; /* [brix_ckscan_max_files N] — maximum
                                      regular files emitted by one kXR_Qckscan */

    /* ---- single-port protocol handoff ---- */
    /* [brix_http_handoff host:port] — when a non-XRootD (HTTP/TLS) client
     * lands on this stream port, splice it to this local HTTP/WebDAV listener.
     * Lets a single registered port serve both root:// and WebDAV so a stock
     * XrdHttp redirector (which redirects HTTP to the data port) can reach an
     * nginx data node.  NULL = off (legacy: a non-XRootD client is closed). */
    ngx_addr_t *http_handoff_addr;
    ngx_str_t   http_handoff_name;

    /* [brix_transparent_proxy host:port] — relay every connection on this port
     * verbatim to an upstream XRootD server (auth handshake travels end-to-end)
     * while a tap decodes the cleartext frames (src/relay/relay.c). NULL = off. */
    ngx_addr_t *relay_addr;
    ngx_str_t   relay_name;

    /* [brix_guard_stream on|off] — bad-actor guard on the transparent relay:
     * classify each tapped frame (src/net/guard/), drop the connection on junk
     * signatures / grammar violations, audit notfound/authfail responses. */
    ngx_flag_t  relay_guard_enable;

    /* ---- transparent proxy mode ---- */
    brix_proxy_conf_t  proxy;  /* [brix_proxy, brix_proxy_upstream, brix_proxy_auth,
                                  brix_proxy_login_user, brix_proxy_*_timeout, ...]
                                  — see brix_proxy_conf_t. */

    /* ---- node topology + behavioral capability flags (Phase 2/3) ---- */
    brix_node_caps_conf_t  caps;  /* [brix_metadata_only, brix_supervisor,
                                     brix_virtual_redirector, brix_collapse_redir,
                                     brix_collapse_redir_ttl, brix_recover_writes]
                                     — see brix_node_caps_conf_t. */
    ngx_str_t   upload_stage_dir;   /* [brix_stage_dir <path>] optional fast-cache
                                       staging device; empty = stage adjacent to the
                                       destination.  Canonicalized into
                                       upload_stage_dir_canon at config time. */
    char        upload_stage_dir_canon[PATH_MAX];
    ngx_flag_t  upload_resume;      /* [brix_upload_resume on|off] default ON.
                                       When on, writable opens stage to a
                                       DETERMINISTIC identity-keyed partial that
                                       survives a disconnect/restart, so a
                                       reconnecting client resumes the upload from
                                       its offset; commit (rename->final) happens
                                       only on a clean kXR_close.  See
                                       src/compat/tmp_path.c brix_make_resume_path. */

    /* ---- OCSP certificate revocation checking (Feature 8e) ---- */
    brix_ocsp_conf_t  ocsp;  /* [brix_ocsp_enable, brix_ocsp_soft_fail,
                                brix_ocsp_stapling] revocation + stapling state;
                                staple_data/len populated at init_process. */

    /* ---- Phase 24: traffic mirroring (off by default) ---- */
    brix_mirror_conf_t  mirror;  /* [brix_stream_mirror_url, brix_mirror_*]
                                      fire-and-forget read-request replay to a
                                      shadow XRootD server; enabled == 0 = no-op */

    /* ---- Phase 25: advanced rate limiting (off by default) ---- */
    ngx_array_t  *rl_rules;        /* brix_rl_rule_t[] from
                                      [brix_rate_limit_rule / _bandwidth_limit];
                                      NULL = no limits */

    /* ---- Phase 39: network-fault resilience (all OFF by default) ----
     * Steady-state per-connection deadlines on root:// — armed/disarmed only at
     * PDU/drain boundaries (src/connection/recv.c, send.c), never per-byte and
     * never inside the Phase-29 pipelining keep-reading branches.  0 = disabled
     * (byte-for-byte current behaviour); a half-open / slowloris / silently-
     * stalled peer is otherwise never timed out on the steady-state path.
     * Exceeds official XRootD, which arms no steady-state read/write deadline. */
    ngx_msec_t  read_timeout;       /* [brix_read_timeout 0] per-incomplete-PDU
                                       receive deadline (also bounds a slow write/
                                       auth/prepare payload drain). 0 = off. */
    ngx_msec_t  handshake_timeout;  /* [brix_handshake_timeout 0] tighter pre-auth
                                       deadline so an unauthenticated stall cannot
                                       squat a connection slot. 0 = off. */
    ngx_msec_t  send_timeout;       /* [brix_send_timeout 0] response-drain
                                       deadline: sheds a slow/half-open consumer
                                       holding parked out_ring slots. 0 = off. */
    ngx_msec_t  tcp_user_timeout;   /* [brix_tcp_user_timeout 0] setsockopt
                                       TCP_USER_TIMEOUT (ms) at accept — kernel
                                       reaps a silently-dropped peer with unacked
                                       in-flight data even during a parked
                                       AIO/SENDING window.  MUST be >> send_timeout.
                                       0 = leave the kernel default. */
    ngx_flag_t  tcp_keepalive;      /* [brix_tcp_keepalive off] SO_KEEPALIVE +
                                       tight TCP_KEEPIDLE/INTVL/CNT at accept for
                                       seconds-scale dead-peer detection.  off =
                                       leave the kernel default (2h first probe). */
    ngx_str_t   tcp_congestion;     /* [brix_tcp_congestion ""] setsockopt
                                       TCP_CONGESTION at accept (e.g. "bbr") — the
                                       sender's congestion control governs download
                                       throughput, and BBR ignores the spurious
                                       loss signals packet reordering induces.
                                       Empty = leave the kernel default. */
    ngx_msec_t  manager_stale_after; /* [brix_manager_stale_after 0] WS7: ms with
                                       no heartbeat after which a registered data
                                       server is de-preferred in cluster selection
                                       (brix_srv_select falls back to it only if
                                       every replica is stale).  Applied to the
                                       shared registry via brix_srv_set_stale_after.
                                       0 = disabled.  Recommended ~3x cms_interval. */
    ngx_uint_t  max_connections;    /* [brix_max_connections 0] WS9: pre-identity
                                       admission cap checked at accept against the
                                       per-listener connections_active gauge.  Over
                                       the cap the connection is refused with a plain
                                       TCP close (no streamid exists pre-login for a
                                       framed kXR_wait).  0 = unlimited (no change).
                                       Requires the metrics zone (where the gauge
                                       lives). */

    /* ---- Phase 44: optional io_uring disk-I/O backend ----
     * All off by default.  The data path is byte-for-byte identical to the
     * thread-pool tier; only the syscall location differs.  See src/aio/uring.c
     * and docs/refactor/phase-44-io-uring-backend.md. */
    ngx_uint_t  io_uring;            /* [brix_io_uring auto] enum: OFF/ON/AUTO.
                                        ON makes startup fail (nginx -t error,
                                        master exits non-zero) if io_uring is not
                                        compiled in or the runtime probe fails. */
    ngx_int_t   io_uring_queue_depth;/* [brix_io_uring_queue_depth 256] per-worker
                                        ring SQ/CQ entries = max in-flight SQEs. */
    ngx_str_t   io_uring_panic_file; /* [brix_io_uring_panic_file ""] kill switch:
                                        when this file exists every worker treats
                                        io_uring as disabled and falls back on the
                                        next op (polled, no reload). "" = unset. */
    ngx_flag_t  io_uring_admin;      /* [brix_io_uring_admin off] expose
                                        POST /xrootd/api/v1/admin/io_uring to flip
                                        the cross-worker SHM disable flag. */
    ngx_flag_t  io_uring_restrict;   /* [brix_io_uring_restrict on] lock each ring
                                        to fd-only data opcodes via
                                        io_uring_register_restrictions() (>=5.10). */
