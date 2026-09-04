/*
 * server_conf_merge_security.c — server-block merge for the identity/crypto
 * configuration area (storage-plane merge split to server_conf_merge_storage.c).
 *
 * WHAT: Owns brix_merge_srv_security() (auth scheme + GSI/pwd, XrdAcc engine,
 *       X.509/CRL, tokens + L1/L2 caches, sss/krb5/unix/host, TLS toggles) and
 *       brix_merge_srv_storage() (compression, ZIP, the read-through cache
 *       origin/sizing/eviction/verify, memory budget, readv sizing, io_uring),
 *       together with the file-local per-concern helpers each delegates to.
 * WHY:  Split (phase-79 file-size cap) out of the former 1249-line
 *       server_conf.c; the two entry points are non-static (declared in
 *       server_conf_internal.h) for server_conf.c's linear orchestrator, every
 *       sub-helper file-local.
 * HOW:  Standard ngx_conf_merge_* / BRIX_MERGE_* inheritance, one helper per
 *       concern group, invoked in the original order so cross-group derivations
 *       (staging LOW from HIGH, reaper watermarks from the eviction threshold)
 *       observe already-merged inputs. No behaviour change from the split.
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
    ngx_conf_merge_value(conf->auth_maxfail, prev->auth_maxfail, 0);   /* §5.7 */

    /* protbind rules are inherited whole: a server block that states none of
     * its own keeps the outer block's host policy, but the moment it states one
     * it owns the ordering, and silently prepending the parent's rules would
     * change which template matches first. */
    if (conf->protbind == NULL) {
        conf->protbind = prev->protbind;
    }
    ngx_conf_merge_uint_value(conf->gsi_signed_dh, prev->gsi_signed_dh,
                              BRIX_GSI_SDH_OFF);
    ngx_conf_merge_value(conf->gsi_max_inflight, prev->gsi_max_inflight, 256);
    /* §5.10: GSI client-cert chain depth cap; 0 = unlimited (default). */
    ngx_conf_merge_value(conf->gsi_verify_depth, prev->gsi_verify_depth, 0);
    ngx_conf_merge_uint_value(conf->gsi_keypool_size, prev->gsi_keypool_size,
                              BRIX_GSI_KEYPOOL_SIZE_DEFAULT);
    ngx_conf_merge_uint_value(conf->gsi_keypool_seed, prev->gsi_keypool_seed,
                              BRIX_GSI_KEYPOOL_SEED_DEFAULT);
    ngx_conf_merge_str_value(conf->gsi_ciphers, prev->gsi_ciphers, "");
    ngx_conf_merge_str_value(conf->pwd_file, prev->pwd_file, "");

    /*
     * The native authdb engine matches by DN/VO, so it needs an authenticating
     * scheme — but ANY of them will do: sss/krb5/pwd/host/unix all stamp
     * ctx->login.dn (and pwd/sss also fill the VO list) exactly as gsi and
     * token do, so u/g rules bind behind them too.  Only anonymous servers are
     * rejected; the xrdacc engine is exempt even there, because it also
     * authorizes anonymous `u *` rules.  Validated here, where both directives
     * have settled.
     */
    if (conf->common.acc.authdb.len > 0
        && conf->common.acc.format == BRIX_AUTHDB_FORMAT_NATIVE
        && conf->auth == BRIX_AUTH_NONE)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_authdb (native format) requires an authenticating brix_auth "
            "scheme; use `brix_authdb_engine xrdacc` for anonymous rules");
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
    /* §5.10: root:// TLS cipher list; empty = OpenSSL defaults (default). */
    ngx_conf_merge_str_value(conf->tls_ciphers,     prev->tls_ciphers,     "");
    /* §5.10: root:// TLSv1.3 cipher-suite list; empty = OpenSSL defaults. */
    ngx_conf_merge_str_value(conf->tls_ciphersuites, prev->tls_ciphersuites, "");
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
    ngx_conf_merge_ptr_value(conf->token_registry,  prev->token_registry,  NULL);
    ngx_conf_merge_str_value(conf->throttle.zone_name,
                             prev->throttle.zone_name, "");
    ngx_conf_merge_ptr_value(conf->throttle.zone, prev->throttle.zone, NULL);
    ngx_conf_merge_uint_value(conf->throttle.max_open_files,
                              prev->throttle.max_open_files, 0);
    ngx_conf_merge_str_value(conf->throttle.bwm_zone_name,
                             prev->throttle.bwm_zone_name, "");
    ngx_conf_merge_size_value(conf->throttle.bwm_budget,
                              prev->throttle.bwm_budget, 0);

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

    /* F3/P90-28.1: the macaroon root-secret hex lives in conf memory for the
     * process lifetime — keep its pages out of core dumps and off swap.
     * Best-effort, never fatal (per-request binary copies are stack + F1-
     * cleansed; this guards the only long-lived form of the key). */
    if (conf->common.token_macaroon_secret.len > 0
        && brix_secret_page_guard(conf->common.token_macaroon_secret.data,
                         conf->common.token_macaroon_secret.len) != 0)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
            "brix: could not fully page-guard the macaroon secret "
            "(madvise/mlock); continuing unguarded");
    }
    if (conf->common.token_macaroon_secret_old.len > 0
        && brix_secret_page_guard(conf->common.token_macaroon_secret_old.data,
                         conf->common.token_macaroon_secret_old.len) != 0)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
            "brix: could not fully page-guard the old macaroon secret "
            "(madvise/mlock); continuing unguarded");
    }
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
    ngx_conf_merge_value(conf->krb5.delegate,       prev->krb5.delegate,   0);
    ngx_conf_merge_value(conf->unix_trust_remote,   prev->unix_trust_remote, 0);
    ngx_conf_merge_ptr_value(conf->host_allow,      prev->host_allow,      NULL);
    ngx_conf_merge_uint_value(conf->security_level, prev->security_level, 0);
    /* Off by default: fail-closed signing refuses every client whose auth
     * protocol cannot sign (all stock non-GSI clients), so it is opt-in. */
    ngx_conf_merge_value(conf->signing_required, prev->signing_required, 0);
    ngx_conf_merge_uint_value(conf->min_sec_level, prev->min_sec_level, 0);
    ngx_conf_merge_value(conf->ztn_cleartext, prev->ztn_cleartext, 0);
    /* ztn -maxsz analog; 0 = no extra cap (compatibility default). */
    ngx_conf_merge_size_value(conf->ztn_maxsz, prev->ztn_maxsz, 0);
    ngx_conf_merge_value(conf->opaque_strict, prev->opaque_strict, 0);
    ngx_conf_merge_value(conf->tls,             prev->tls,             0);
    /* kTLS default OFF (phase-33 P5): software kTLS regresses vs OpenSSL's
     * userspace AES-GCM on AES-NI hosts and is broken on some kernels (WSL2), so
     * it is opt-in and documented HW-offload-only (`brix_ktls on`).
     * SSL_OP_ENABLE_KTLS is a transparent no-op when the cipher/kernel cannot
     * offload, so this default is byte-exact vs userspace TLS. */
    ngx_conf_merge_value(conf->tls_ktls,        prev->tls_ktls,        0);
    /* §5.10: TLS session resumption on by default (unchanged); off full-handshakes. */
    ngx_conf_merge_value(conf->tls_reuse,       prev->tls_reuse,       1);
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
