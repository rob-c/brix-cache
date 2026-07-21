/*
 * server_conf_merge_security.c — server-block merge for the identity/crypto and
 * storage-plane configuration areas.
 *
 * WHAT: Owns brix_merge_srv_security() (auth scheme + GSI/pwd, XrdAcc engine,
 *       X.509/CRL, tokens + L1/L2 caches, sss/krb5/unix/host, TLS toggles) and
 *       brix_merge_srv_storage() (compression, ZIP, the read-through cache
 *       origin/sizing/eviction/verify, memory budget, readv sizing, io_uring),
 *       together with the file-local per-concern helpers each delegates to.
 * WHY:  Split (phase-79 file-size cap) out of the former 1249-line
 *       server_conf.c. Grouping the identity/crypto and storage merges keeps
 *       their sentinel-vs-configured contracts reviewable in isolation. The two
 *       entry points are non-static (declared in server_conf_internal.h) because
 *       the top-level orchestrator in server_conf.c calls them in linear order;
 *       every sub-helper stays file-local.
 * HOW:  Standard nginx parent->child inheritance via ngx_conf_merge_* and the
 *       BRIX_MERGE_* macros, one helper per concern group, invoked in the
 *       original order so cross-group derivations (staging LOW watermark from
 *       HIGH, reaper watermarks from the eviction threshold) still observe their
 *       already-merged inputs. No behaviour change from the split.
 */

#include "config.h"
#include "server_conf_internal.h"
#include "auth/crypto/store_policy.h"   /* BRIX_SP_MODE_*, BRIX_CRL_MODE_* defaults */
#include "core/compat/af_policy.h"      /* BRIX_AF_AUTO default for origin family */
#include "fs/cache/verify.h"          /* brix_cache_verify_mode_e default */
#include "net/ratelimit/ratelimit.h"   /* phase-59 W3a: throttle zone lookup */

/*
 * WHAT: merge the GSI/pwd + XrdAcc engine group and validate the native-authdb
 *       auth-scheme requirement.
 * WHY:  the native-authdb rule couples the merged `auth` scheme and `acc.format`
 *       so it must run after both settle; grouping keeps that dependency local.
 * HOW:  inherit the GSI/pwd/acc scalars child<-parent, then reject a native
 *       authdb without an authenticating scheme (xrdacc is exempt: it authorizes
 *       anonymous `u *` rules).
 */
static char *
brix_merge_srv_gsi_acc(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        BRIX_AUTH_NONE);
    ngx_conf_merge_uint_value(conf->gsi_signed_dh, prev->gsi_signed_dh,
                              BRIX_GSI_SDH_OFF);
    ngx_conf_merge_value(conf->gsi_max_inflight, prev->gsi_max_inflight, 256);
    ngx_conf_merge_uint_value(conf->gsi_keypool_size, prev->gsi_keypool_size,
                              BRIX_GSI_KEYPOOL_SIZE_DEFAULT);
    ngx_conf_merge_uint_value(conf->gsi_keypool_seed, prev->gsi_keypool_seed,
                              BRIX_GSI_KEYPOOL_SEED_DEFAULT);
    ngx_conf_merge_str_value(conf->gsi_ciphers, prev->gsi_ciphers, "");
    ngx_conf_merge_str_value(conf->pwd_file, prev->pwd_file, "");

    /* XrdAcc engine: default native, audit off, refresh off, 12h gid cache. */
    ngx_conf_merge_uint_value(conf->acc.format, prev->acc.format,
                              BRIX_AUTHDB_FORMAT_NATIVE);
    ngx_conf_merge_uint_value(conf->acc.audit, prev->acc.audit,
                              BRIX_AUTHDB_AUDIT_NONE);
    ngx_conf_merge_value(conf->acc.refresh, prev->acc.refresh, 0);
    ngx_conf_merge_value(conf->acc.gidlifetime, prev->acc.gidlifetime, 43200);
    ngx_conf_merge_value(conf->acc.pgo, prev->acc.pgo, 0);
    ngx_conf_merge_value(conf->acc.resolve_hosts, prev->acc.resolve_hosts, 0);
    ngx_conf_merge_value(conf->acc.encoding, prev->acc.encoding, 0);
    ngx_conf_merge_str_value(conf->acc.nisdomain, prev->acc.nisdomain, "");
    ngx_conf_merge_str_value(conf->acc.spacechar, prev->acc.spacechar, "");
    ngx_conf_merge_str_value(conf->acc.gidretran, prev->acc.gidretran, "");

    /*
     * The native authdb engine matches by DN/VO and so needs an authenticating
     * scheme; the xrdacc engine also authorizes anonymous `u *` rules, so it is
     * exempt.  Validated here, where both directives have settled.
     */
    if (conf->authdb.len > 0
        && conf->acc.format == BRIX_AUTHDB_FORMAT_NATIVE
        && conf->auth != BRIX_AUTH_GSI && conf->auth != BRIX_AUTH_TOKEN
        && conf->auth != (BRIX_AUTH_GSI | BRIX_AUTH_TOKEN))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_authdb (native format) requires brix_auth gsi, token "
            "or both; use `brix_authdb_format xrdacc` for anonymous rules");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/*
 * WHAT: merge the FRM prepare command + the X.509 material (cert/key/CA, VOMS)
 *       and CRL/signing-policy toggles, plus the access/session logging fields.
 * WHY:  brix_frm_conf_merge() depends on the merged prepare_command; grouping
 *       makes that ordering explicit and keeps the fallible FRM merge local.
 * HOW:  merge prepare_command, delegate to brix_frm_conf_merge(), then inherit
 *       the X.509/CRL/log scalars child<-parent.
 */
static char *
brix_merge_srv_x509(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_str_value(conf->prepare_command, prev->prepare_command, "");
    if (brix_frm_conf_merge(cf, &conf->frm, &prev->frm, &conf->prepare_command)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");
    ngx_conf_merge_str_value(conf->vomsdir,         prev->vomsdir,         "");
    ngx_conf_merge_str_value(conf->voms_cert_dir,   prev->voms_cert_dir,   "");
    ngx_conf_merge_str_value(conf->crl,             prev->crl,             "");
    ngx_conf_merge_value(conf->crl_reload,    prev->crl_reload,      0);
    ngx_conf_merge_uint_value(conf->signing_policy_mode,
                              prev->signing_policy_mode, BRIX_SP_MODE_ON);
    ngx_conf_merge_uint_value(conf->crl_mode, prev->crl_mode, BRIX_CRL_MODE_TRY);
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");
    ngx_conf_merge_value(conf->session_log, prev->session_log, 1);

    return NGX_CONF_OK;
}

/*
 * WHAT: merge the token group (JWKS, issuer/audience, config/registry, macaroon
 *       secrets) and the throttle group (limits + named rate-limit zone), and
 *       validate the clock-skew bound and throttle-zone reference.
 * WHY:  both carry config-time validation (clock-skew range, zone existence);
 *       keeping them together isolates the two failure paths.
 * HOW:  inherit the token/throttle scalars, clamp-check clock skew to [0,300],
 *       then resolve the named rate-limit zone, failing if it was not declared.
 */
static char *
brix_merge_srv_tokens(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    ngx_conf_merge_str_value(conf->token_jwks,      prev->token_jwks,      "");
    ngx_conf_merge_msec_value(conf->token_jwks_refresh_interval,
                              prev->token_jwks_refresh_interval,
                              NGX_CONF_UNSET_MSEC);
    ngx_conf_merge_str_value(conf->token_issuer,    prev->token_issuer,    "");
    ngx_conf_merge_str_value(conf->token_audience,  prev->token_audience,  "");
    ngx_conf_merge_value(conf->token_clock_skew,    prev->token_clock_skew,
                         BRIX_TOKEN_CLOCK_SKEW_SECS);
    if (conf->token_clock_skew < 0 || conf->token_clock_skew > 300) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_token_clock_skew must be >= 0 and <= 300");
        return NGX_CONF_ERROR;
    }
    ngx_conf_merge_str_value(conf->token_config,    prev->token_config,    "");
    ngx_conf_merge_ptr_value(conf->token_registry,  prev->token_registry,  NULL);
    ngx_conf_merge_str_value(conf->throttle.zone_name,
                             prev->throttle.zone_name, "");
    ngx_conf_merge_ptr_value(conf->throttle.zone, prev->throttle.zone, NULL);
    ngx_conf_merge_uint_value(conf->throttle.max_open_files,
                              prev->throttle.max_open_files, 0);
    ngx_conf_merge_uint_value(conf->throttle.max_active_conn,
                              prev->throttle.max_active_conn, 0);

    /* phase-59 W3a: resolve the named rate-limit zone the throttle keys its
     * per-user counters into (declared via brix_rate_limit_zone). */
    if (conf->throttle.zone == NULL && conf->throttle.zone_name.len > 0) {
        conf->throttle.zone = brix_rl_zone_get(&conf->throttle.zone_name);
        if (conf->throttle.zone == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_throttle_zone \"%V\" is not a declared "
                "brix_rate_limit_zone", &conf->throttle.zone_name);
            return NGX_CONF_ERROR;
        }
    }

    ngx_conf_merge_str_value(conf->token_macaroon_secret,
                             prev->token_macaroon_secret,     "");
    ngx_conf_merge_str_value(conf->token_macaroon_secret_old,
                             prev->token_macaroon_secret_old, "");
    return NGX_CONF_OK;
}

/*
 * WHAT: merge the CSI record cache, the Phase-20 L1/L2 caches (token/auth/rate),
 *       the sss/krb5/unix/host schemes, the security level, and the TLS toggles.
 * WHY:  a plain inheritance tail with no validation; a void helper trims the
 *       orchestrator without splitting a decision.
 * HOW:  whole-config inherit for the kv-backed caches (NULL == disabled), then
 *       child<-parent for the remaining scheme/TLS scalars.
 */
static void
brix_merge_srv_authtail(ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    brix_csi_conf_merge(&conf->csi, &prev->csi);

    /* Phase 20 caches/limits: inherit the parent's whole config when this
     * block did not declare its own (kv still NULL). */
    if (conf->token_cache_kv == NULL) {
        conf->token_cache_kv = prev->token_cache_kv;
    }
    if (conf->auth_cache.kv == NULL) {
        conf->auth_cache = prev->auth_cache;
    }
    if (conf->rate_limit.kv == NULL) {
        conf->rate_limit = prev->rate_limit;
    }
    ngx_conf_merge_str_value(conf->sss_keytab,      prev->sss_keytab,      "");
    ngx_conf_merge_value(conf->sss_lifetime,        prev->sss_lifetime,    13);
    ngx_conf_merge_str_value(conf->krb5.principal,  prev->krb5.principal,  "");
    ngx_conf_merge_str_value(conf->krb5.keytab,     prev->krb5.keytab,     "");
    ngx_conf_merge_value(conf->krb5.ip_check,       prev->krb5.ip_check,   0);
    ngx_conf_merge_value(conf->unix_trust_remote,   prev->unix_trust_remote, 0);
    ngx_conf_merge_ptr_value(conf->host_allow,      prev->host_allow,      NULL);
    ngx_conf_merge_uint_value(conf->security_level, prev->security_level, 0);
    ngx_conf_merge_uint_value(conf->min_sec_level, prev->min_sec_level, 0);
    ngx_conf_merge_value(conf->opaque_strict, prev->opaque_strict, 0);
    ngx_conf_merge_value(conf->tls,             prev->tls,             0);
    /* kTLS default ON (unified with the HTTP plane); SSL_OP_ENABLE_KTLS is a
     * transparent no-op when the negotiated cipher/kernel cannot offload. */
    ngx_conf_merge_value(conf->tls_ktls,        prev->tls_ktls,        1);
}

/* Identity & crypto: auth scheme + GSI/pwd, XrdAcc engine (+ native-authdb
 * validation), SciTags/FRM, X.509 material + CRL, access log, tokens + L1/L2
 * caches, sss/krb5/unix/host, security level, and TLS toggles. */
char *
brix_merge_srv_security(ngx_conf_t *cf, ngx_stream_brix_srv_conf_t *conf,
    ngx_stream_brix_srv_conf_t *prev)
{
    /*
     * Standard nginx inheritance rules: values set on the current server
     * override the parent, otherwise we fall back to the parent or the hard
     * coded module default. Each concern group is delegated to a helper below,
     * invoked in the original linear order so cross-group derivations still see
     * their already-merged inputs.
     */
    /* Shared common.* preamble (root defaults to "/": a pure cache node may
     * omit brix_root and serve the whole namespace). Also covers the tier
     * grammar + pmark + hard read-only enforcement — do not re-merge those. */
    if (ngx_http_brix_shared_merge(cf, &prev->common, &conf->common, "/")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }
    if (brix_merge_srv_gsi_acc(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (brix_merge_srv_x509(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    if (brix_merge_srv_tokens(cf, conf, prev) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }
    brix_merge_srv_authtail(conf, prev);

    return NGX_CONF_OK;
}

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

    brix_merge_srv_zip_stage(conf, prev);
    brix_merge_srv_cache_origin(conf, prev);
    brix_merge_srv_iouring_advertise(conf, prev);

    return NGX_CONF_OK;
}
