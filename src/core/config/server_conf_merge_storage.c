/*
 * server_conf_merge_storage.c — server-block merge for the storage plane
 * (compression/ZIP, read-through cache origin/sizing/eviction/verify, memory
 * budget, readv sizing, io_uring).  Split from server_conf_merge_security.c at
 * phase-103 to hold the 600-line file cap; brix_merge_srv_storage() stays the
 * non-static entry point (declared in server_conf_internal.h) and every
 * sub-helper file-local.  No behaviour change.
 */

#include "config.h"
#include "server_conf_internal.h"
#include "auth/crypto/store_policy.h"   /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* defaults */
#include "core/compat/crypto.h"         /* brix_secret_page_guard (F3) */
#include "core/compat/af_policy.h"      /* BRIX_AF_AUTO default for origin family */
#include "fs/cache/verify.h"          /* brix_cache_verify_mode_e default */
#include "net/ratelimit/ratelimit.h"   /* phase-59 W3a: throttle zone lookup */
#include "protocols/root/protocol/flags.h"  /* kXR_ckpMinMax — chkpnt_maxsz floor */

/*
 * WHAT: merge the compression + ZIP-access group and the write-through staging
 *       roots/backends + backpressure watermarks + dirty-reaper age + cache
 *       allow/deny prefix inheritance.
 * WHY:  the staging LOW watermark auto-derives from the just-merged HIGH; keeping
 *       them adjacent makes the hysteresis default explicit.
 * HOW:  inherit the compression/ZIP scalars, then the staging roots and the
 *       HIGH/LOW watermark pair (LOW = HIGH − 5% when only HIGH is set), and
 *       inherit the prefix arrays when the child left them NULL.
 */
static void
brix_merge_srv_zip_stage(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_value(conf->read_compress,   prev->read_compress,   0);
    ngx_conf_merge_value(conf->write_compress,  prev->write_compress,  0);
    ngx_conf_merge_value(conf->zip_access,      prev->zip_access,      0);
    ngx_conf_merge_size_value(conf->zip_cd_max_bytes, prev->zip_cd_max_bytes,
                              16 * 1024 * 1024);
    ngx_conf_merge_str_value(conf->zip_stage_dir, prev->zip_stage_dir, "");
    ngx_conf_merge_value(conf->zip_force_scratch, prev->zip_force_scratch, 0);
    ngx_conf_merge_size_value(conf->zip_stage_max_bytes,
                              prev->zip_stage_max_bytes, 512 * 1024 * 1024);
    /* ofs.chkpnt maxsz analog: default = the protocol minimum, and an
     * explicitly configured smaller value is raised to it — kXR_ckpMinMax is
     * the "minimum maximum" every server must accept, so honoring a lower cap
     * would refuse checkpoints a spec-conforming client is entitled to. */
    ngx_conf_merge_size_value(conf->chkpnt_maxsz,
                              prev->chkpnt_maxsz, (size_t) kXR_ckpMinMax);
    if (conf->chkpnt_maxsz < (size_t) kXR_ckpMinMax) {
        conf->chkpnt_maxsz = (size_t) kXR_ckpMinMax;
    }
    /* oss.maxsize create-size cap; 0 = no cap (compatibility default). */
    ngx_conf_merge_off_value(conf->oss_maxsize, prev->oss_maxsize, 0);
    /* oss.cgroup space-group name reported by kXR_Qspace; default "default". */
    ngx_conf_merge_str_value(conf->oss_cgroup, prev->oss_cgroup, "default");
    ngx_conf_merge_value(conf->pss_dca, prev->pss_dca, 0);   /* §4.9 */
    ngx_conf_merge_value(conf->dirstats, prev->dirstats, 0);   /* §4.8 */
    /* brix_checksum_default: the algo a Qcksum with no explicit selection uses;
     * empty ⇒ adler32 is applied at the use sites (never breaks on a bad value). */
    ngx_conf_merge_str_value(conf->checksum_default, prev->checksum_default, "");
    ngx_conf_merge_value(conf->cache,           prev->cache,           0);
    ngx_conf_merge_str_value(conf->cache_root,  prev->cache_root,      "");
    ngx_conf_merge_str_value(conf->cache_state_root, prev->cache_state_root, "");
    ngx_conf_merge_str_value(conf->cache_wt_stage_root,
                             prev->cache_wt_stage_root, "");
    ngx_conf_merge_str_value(conf->cache_wt_stage_backend,
                             prev->cache_wt_stage_backend, "");
    ngx_conf_merge_size_value(conf->cache_wt_stage_block_size,
                              prev->cache_wt_stage_block_size, 0);

    /* Staging backpressure: default OFF (high == 0). When only HIGH is set, LOW
     * defaults 50000 ppm (5%) below it for hysteresis. The ordering invariant
     * (0 < low < high < 1e6) is enforced in runtime_server.c. */
    ngx_conf_merge_uint_value(conf->cache_wt_stage_high_watermark,
                              prev->cache_wt_stage_high_watermark, 0);
    ngx_conf_merge_uint_value(conf->cache_wt_stage_low_watermark,
                              prev->cache_wt_stage_low_watermark,
                              conf->cache_wt_stage_high_watermark > 50000
                                  ? conf->cache_wt_stage_high_watermark - 50000
                                  : conf->cache_wt_stage_high_watermark / 2);
    ngx_conf_merge_sec_value(conf->cache_dirty_max_age,
                             prev->cache_dirty_max_age, 604800);   /* 7 days */
    /* Cold read-fill purge defaults OFF: unlike the dirty horizon (which bounds
     * a leak) this one DISCARDS otherwise-serviceable cache, so it is only ever
     * an explicit operator choice. */
    ngx_conf_merge_sec_value(conf->cache_cold_max_age,
                             prev->cache_cold_max_age, 0);
    if (conf->cache_deny_prefixes == NULL) {
        conf->cache_deny_prefixes = prev->cache_deny_prefixes;
    }
    if (conf->cache_allow_prefixes == NULL) {
        conf->cache_allow_prefixes = prev->cache_allow_prefixes;
    }
}

/*
 * WHAT: merge the read-through cache origin + eviction group — origin address/
 *       TLS/family, lock timeout, the on-fill eviction threshold, the watermark
 *       reaper, the file-size/memory budgets, and the readv segment size.
 * WHY:  the reaper HIGH/LOW watermarks derive from the just-merged eviction
 *       threshold; grouping keeps that dependency chain visible.
 * HOW:  inherit the origin scalars, then the reaper watermarks (HIGH ← eviction
 *       threshold, LOW ← HIGH − 5%) and the budget/segment defaults.
 */
static void
brix_merge_srv_cache_origin(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_str_value(conf->cache_origin, prev->cache_origin,   "");
    ngx_conf_merge_value(conf->cache_origin_tls, prev->cache_origin_tls, 0);
    ngx_conf_merge_uint_value(conf->cache_origin_family,
                              prev->cache_origin_family, BRIX_AF_AUTO);
    ngx_conf_merge_value(conf->cache_lock_timeout,
                         prev->cache_lock_timeout, 300);
    ngx_conf_merge_uint_value(conf->cache_eviction_threshold,
                              prev->cache_eviction_threshold, 900000);

    /* Phase-88 loose end: brix_cache_evict_at/_to (tier grammar, PERCENT) are
     * an alternate spelling of the watermark pair — an explicitly-set pair
     * seeds the reaper (percent -> ppm); the ppm-native brix_cache_high/
     * low_watermark directives win when both are given. A lone evict_at takes
     * the documented 80% target, a lone evict_to the 90% trigger. Percent
     * range/order is validated in runtime_server.c BEFORE the ppm check so a
     * unit mistake gets the percent-worded error. */
    if (conf->common.cache_evict_at != NGX_CONF_UNSET_UINT
        || conf->common.cache_evict_to != NGX_CONF_UNSET_UINT)
    {
        ngx_conf_merge_uint_value(conf->reaper.high_watermark,
            prev->reaper.high_watermark,
            (conf->common.cache_evict_at == NGX_CONF_UNSET_UINT
                 ? 90 : conf->common.cache_evict_at) * 10000);
        ngx_conf_merge_uint_value(conf->reaper.low_watermark,
            prev->reaper.low_watermark,
            (conf->common.cache_evict_to == NGX_CONF_UNSET_UINT
                 ? 80 : conf->common.cache_evict_to) * 10000);
    }

    /* Watermark reaper: HIGH defaults to the on-fill eviction threshold so an
     * existing config keeps its bound; LOW defaults 50000 ppm (5%) below HIGH for
     * hysteresis; the timer runs every 60s by default. The ordering invariant
     * (0 < low < high < 1e6) is enforced in runtime_server.c. */
    ngx_conf_merge_uint_value(conf->reaper.high_watermark,
                              prev->reaper.high_watermark,
                              conf->cache_eviction_threshold);
    ngx_conf_merge_uint_value(conf->reaper.low_watermark,
                              prev->reaper.low_watermark,
                              conf->reaper.high_watermark > 50000
                                  ? conf->reaper.high_watermark - 50000
                                  : conf->reaper.high_watermark / 2);
    ngx_conf_merge_sec_value(conf->reaper.reap_interval,
                             prev->reaper.reap_interval, 60);
    ngx_conf_merge_off_value(conf->reaper.max_bytes, prev->reaper.max_bytes, 0);
    ngx_conf_merge_off_value(conf->cache_max_file_size,
                             prev->cache_max_file_size, 0);
    ngx_conf_merge_off_value(conf->memory_budget,
                             prev->memory_budget, 768 * 1024 * 1024);
    /* Default = stock XRootD maxReadv_ior = maxBuffsz(2 MiB) - sizeof(readahead_list). */
    ngx_conf_merge_size_value(conf->readv_segment_size,
                              prev->readv_segment_size,
                              (size_t) (2 * 1024 * 1024) - BRIX_READV_SEGSIZE);
}

/*
 * WHAT: merge the io_uring backend group, the checksum-on-fill verify mode, the
 *       Pelican advertisement group, and inherit the compiled include-regex.
 * WHY:  the advertisement interval is clamped to the federation minimum and the
 *       regex inheritance is a struct-copy neither expressible via
 *       ngx_conf_merge_*; grouping keeps both special cases together.
 * HOW:  inherit the io_uring/verify/advertise scalars, floor the advertise
 *       interval at 60s, and copy the parent's compiled regex when unset.
 */
static void
brix_merge_srv_iouring_advertise(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    /* Phase 44: optional io_uring backend — default OFF (strictly opt-in).
     *
     * WHY not AUTO: the startup probe can only prove the ring accepts opcodes
     * and (SB-W hardening) that the registered eventfd delivers a NOP
     * completion — neither of which proves real buffered file WRITES complete
     * on THIS kernel + filesystem.  On at least one production host (EL9 elrepo
     * 6.15, plain local fs) NOPs drained fine yet io_uring writes never
     * completed: transfers wedged after exactly queue_depth in-flight ops
     * (queue_depth x 32 KiB = 8 MiB) with a worker spinning, and a torn-down
     * connection's still-in-flight ops became a late-CQE use-after-free.  The
     * thread pool is both correct there and FASTER (50 vs stall).  io_uring is
     * a performance option, not a correctness feature, so it must be an
     * explicit, operator-verified `brix_io_uring on` — never silently engaged.
     * `on` still fail-fasts if the backend is unavailable; `auto` remains for
     * anyone who wants best-effort enable. */
    ngx_conf_merge_uint_value(conf->io_uring,
                              prev->io_uring, BRIX_IO_URING_OFF);
    /* D-3: seccomp filter default OFF — strictly opt-in (audit-first rollout).
     * An empirical flip to ENFORCE (2026-07) confirmed it must stay opt-in: the
     * worker deny-set KILLs execve, and a few EXTERNAL-helper features fork+exec:
     * the FRM "exec" MSS adapter ($BRIX_FRM_STAGECMD, a real HSM) / OIDC token
     * fetch / native-TPC token-exchange / the kXR_prepare hook, so a blanket
     * enforce default would break them.  (The DEFAULT tape/nearline backend uses
     * the built-in POSIX stub adapter — recall/migrate/purge are plain file copies,
     * no exec — so it is fine under strict enforce.)  Sites that use those now
     * set
     * `brix_seccomp_allow_exec on` to allowlist execve under enforce (ptrace/
     * process_vm_* stay killed); the xattr allowlist gap is fixed; and HTTP-only
     * (WebDAV/S3) workers are filtered too (the install runs from the WebDAV
     * init_process when there is no stream{} block).  So opt-in `brix_seccomp
     * enforce` (+ allow_exec when needed) is viable for every deployment. */
    ngx_conf_merge_uint_value(conf->seccomp,
                              prev->seccomp, BRIX_SECCOMP_OFF);
    /* E-4: negative-path backoff default OFF (threshold 0) — availability-first,
     * strictly opt-in. window_ms/backoff_s only matter when threshold > 0. */
    ngx_conf_merge_uint_value(conf->negcache.threshold,
                              prev->negcache.threshold, 0);
    ngx_conf_merge_uint_value(conf->negcache.window_ms,
                              prev->negcache.window_ms, 0);
    ngx_conf_merge_uint_value(conf->negcache.backoff_s,
                              prev->negcache.backoff_s, 0);
    ngx_conf_merge_value(conf->io_uring_queue_depth,
                         prev->io_uring_queue_depth,
                         BRIX_IO_URING_QUEUE_DEPTH);
    ngx_conf_merge_str_value(conf->io_uring_panic_file,
                             prev->io_uring_panic_file, "");
    ngx_conf_merge_value(conf->io_uring_admin, prev->io_uring_admin, 0);
    ngx_conf_merge_value(conf->io_uring_restrict, prev->io_uring_restrict, 1);


    /* Checksum-on-fill: default best-effort (verify when a digest is available,
     * fail-closed on mismatch). Operators opt down to off or up to require. */
    ngx_conf_merge_uint_value(conf->cache_verify, prev->cache_verify,
                              BRIX_CACHE_VERIFY_BESTEFFORT);
    ngx_conf_merge_str_value(conf->cache_verify_digest,
                             prev->cache_verify_digest, "");

    /* Pelican cache advertisement (default off; interval clamped to the
     * federation minimum of 60s = MinFedTokenTickerRate). */
    ngx_conf_merge_value(conf->advertise.enable, prev->advertise.enable, 0);
    ngx_conf_merge_msec_value(conf->advertise.interval,
                              prev->advertise.interval, 60000);
    if (conf->advertise.interval < 60000) {
        conf->advertise.interval = 60000;
    }
    ngx_conf_merge_str_value(conf->advertise.key,
                             prev->advertise.key, "");
    ngx_conf_merge_str_value(conf->advertise.data_url, prev->advertise.data_url, "");
    ngx_conf_merge_str_value(conf->advertise.web_url, prev->advertise.web_url, "");
    ngx_conf_merge_str_value(conf->advertise.sitename, prev->advertise.sitename, "");
    ngx_conf_merge_str_value(conf->advertise.issuer_url, prev->advertise.issuer_url, "");
    if (conf->advertise.ns == NULL) {
        conf->advertise.ns = prev->advertise.ns;
    }

    /* Durable async backend-op queue: default off; batch 64 ops; coalesce cap
     * 200ms. When enabled, mutations (unlink/rmdir/rename/mkdir/write-commit) are
     * journalled + parked until the batch flushes (size OR time, whichever first).
     * A batch of 0 or a 0ms wait would defeat coalescing, so clamp both up. */
    ngx_conf_merge_value(conf->backend_async, prev->backend_async, 0);
    ngx_conf_merge_uint_value(conf->backend_async_batch,
                              prev->backend_async_batch, 64);
    if (conf->backend_async_batch < 1) {
        conf->backend_async_batch = 1;
    }
    ngx_conf_merge_msec_value(conf->backend_async_wait,
                              prev->backend_async_wait, 200);

    /* Inherit compiled regex from parent if the child didn't set one */
    if (!conf->include_regex.set && prev->include_regex.set) {
        conf->include_regex.str = prev->include_regex.str;
        conf->include_regex.re     = prev->include_regex.re;
        conf->include_regex.set = 1;
    }
}

/* Storage: read/write compression, ZIP access, the read-through cache (origin,
 * sizing, eviction, slice validation, include-regex inheritance), the memory
 * budget, readv segment sizing, and the io_uring backend. */
char *
brix_merge_srv_storage(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    /* common.* (storage backend, pblock stripe, tier grammar) is merged by
     * ngx_http_brix_shared_merge() in brix_merge_srv_security — only the
     * stream-specific validation below stays here. */

    /* §6.5: the tier slice size must be 0 (off) or a positive multiple of the
     * 1 MiB cinfo block granule (so a partial fill never records a mis-aligned
     * block) — the same rule the legacy brix_cache_slice enforced. */
    if (conf->common.cache_slice_size != 0
        && (conf->common.cache_slice_size < (1024 * 1024)
            || (conf->common.cache_slice_size % (1024 * 1024)) != 0))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_slice_size must be a positive multiple of 1m");
        return NGX_CONF_ERROR;
    }

    /* Background block prefetch: the in-flight cap bounds detached thread-pool
     * jobs per worker — an unbounded value would let one client queue arbitrary
     * speculative origin traffic. */
    if (conf->common.cache_prefetch != NGX_CONF_UNSET
        && (conf->common.cache_prefetch < 0
            || conf->common.cache_prefetch > 64))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_prefetch must be between 0 and 64");
        return NGX_CONF_ERROR;
    }
    if (conf->common.cache_prefetch_window != NGX_CONF_UNSET_SIZE
        && conf->common.cache_prefetch_window != 0
        && conf->common.cache_prefetch_window < 64 * 1024)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_prefetch_window must be 0 or at least 64k");
        return NGX_CONF_ERROR;
    }

    brix_merge_srv_zip_stage(conf, prev);
    brix_merge_srv_cache_origin(conf, prev);
    brix_merge_srv_iouring_advertise(conf, prev);

    return NGX_CONF_OK;
}
