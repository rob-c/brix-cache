/*
 * directives.c — parse and validate the cache and write-through nginx config
 * directives (called during startup when reading the configuration file).
 */

#include "core/config/config.h"

#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/str_dup.h"
#include "core/compat/checksum.h"  /* brix_checksum_parse */
#include "core/compat/af_policy.h" /* brix_af_policy_parse */
#include "verify.h"           /* brix_cache_verify_mode_e */
#include "core/compat/cstr.h" /* brix_str_cbuf / brix_pstrdup_z */
#include "cache_internal.h"   /* brix_conf_push_prefix (shared with directives_wt.c) */
#include "core/compat/tmp_path.h" /* brix_tmp_reap_set_policy — brix_posc_persist */

/* §14 (phase-64): brix_conf_set_cache_origin is DELETED with the legacy
 * cache_origin config model (a cache's source is brix_storage_backend). */

/* brix_conf_set_cache_origin_family — parse auto|inet|inet6 into the origin
 * connect's address-family policy (brix_af_policy_t stored as ngx_uint_t). */
char *
brix_conf_set_cache_origin_family(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    int                           pol;

    (void) cmd;

    pol = brix_af_policy_parse((const char *) value[1].data, value[1].len);
    if (pol < 0) {
        return "must be one of: auto, inet, inet6";
    }
    xcf->cache_origin_family = (ngx_uint_t) pol;
    return NGX_CONF_OK;
}

/* brix_conf_set_posc_persist — parse `brix_posc_persist <auto|manual|off>
 * [hold <time>]`, the ofs.persist analog (parity audit §1.9). It governs the
 * boot-time reaper (core/compat/tmp_path.c) that removes "<final>.xrd-tmp.*"
 * temps a crash orphaned mid non-staged write: `auto` reaps dead-owner orphans
 * (the historical default), `manual`/`off` keep them for an operator to recover,
 * and `hold <time>` adds a grace period so a temp whose writer is about to
 * reconnect-and-resume is not reaped mid-recovery. The reaper is process-global
 * (runs once at worker-0 startup), so the directive is a NODE-global policy set
 * at config-parse time: the last brix_posc_persist parsed wins, absent = auto,
 * and a server block WITHOUT the directive never clobbers one that has it. The
 * one caveat is conservative-by-design: a reload that REMOVES the directive
 * retains the last explicit value until the next full restart (the failure mode
 * is "orphans kept", never a wrongful delete) — set it explicitly to change a
 * running node's policy. */

char *
brix_conf_set_posc_persist(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    int        mode;
    time_t     hold = 0;

    (void) cmd;
    (void) conf;   /* node-global policy — no per-server field to store */

    if (ngx_strcmp(value[1].data, "auto") == 0) {
        mode = BRIX_POSC_PERSIST_AUTO;
    } else if (ngx_strcmp(value[1].data, "manual") == 0) {
        mode = BRIX_POSC_PERSIST_MANUAL;
    } else if (ngx_strcmp(value[1].data, "off") == 0) {
        mode = BRIX_POSC_PERSIST_OFF;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_posc_persist: invalid mode \"%V\", must be auto, manual or off",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    /* The optional grace period is the two-token tail `hold <time>`. NGX_CONF_TAKE13
     * already fixed the count at 1 or 3 args, so nelts == 4 means the tail is
     * present; anything but the literal `hold` keyword is a usage error. */
    if (cf->args->nelts == 4) {
        ngx_int_t secs;

        if (ngx_strcmp(value[2].data, "hold") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_posc_persist: expected \"hold\" before a grace time, got "
                "\"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        secs = ngx_parse_time(&value[3], 1 /* seconds */);
        if (secs == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_posc_persist: invalid hold time \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }
        hold = (time_t) secs;
    }

    brix_tmp_reap_set_policy(mode, hold);
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: posc persist=%V hold=%T", &value[1], hold);
    return NGX_CONF_OK;
}

/* brix_conf_set_fsoverload_redirect — parse `brix_fsoverload_redirect <host>
 * <port>`, the xrootd.fsoverload redirect action (§1.10). On a memory-budget
 * overload a read/readv is answered with a kXR_redirect to <host>:<port> (offload
 * to a sibling) instead of the kXR_wait stall. `<host> <port>` (two tokens, not
 * host:port) keeps the parse trivial — a documented spelling divergence. */
char *
brix_conf_set_fsoverload_redirect(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    char                          portbuf[16];
    char                         *endp;
    long                          pnum;

    (void) cmd;

    if (xcf->fsoverload_redirect_host.len > 0) {
        return "is duplicate";
    }
    if (value[1].len == 0) {
        return "host must not be empty";
    }
    if (value[2].len == 0 || value[2].len >= sizeof(portbuf)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_fsoverload_redirect: invalid port \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(portbuf, value[2].data, value[2].len);
    portbuf[value[2].len] = '\0';
    pnum = strtol(portbuf, &endp, 10);
    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_fsoverload_redirect: invalid port \"%V\" (1-65535)", &value[2]);
        return NGX_CONF_ERROR;
    }
    if (brix_pstrdupz(cf->pool, &xcf->fsoverload_redirect_host,
                        value[1].data, value[1].len) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    xcf->fsoverload_redirect_port = (in_port_t) pnum;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: fsoverload redirect -> %V:%l", &value[1], pnum);
    return NGX_CONF_OK;
}

/* brix_conf_set_cache_eviction_threshold — parse the eviction threshold as a
 * decimal (0.95) or percentage (95%), stored as parts-per-million. */

char *
brix_conf_set_cache_eviction_threshold(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *copy;
    char                         *endp;
    double                        ratio;
    ngx_uint_t                    ppm;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_eviction_threshold != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    copy = brix_pstrdup_z(cf->pool, &value[1]);
    if (copy == NULL) {
        return NGX_CONF_ERROR;
    }

    errno = 0;
    ratio = strtod(copy, &endp);
    if (endp == copy || errno != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_eviction_threshold: invalid value \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    if (*endp == '%') {
        endp++;
        ratio /= 100.0;
    } else if (ratio > 1.0) {
        ratio /= 100.0;
    }

    if (*endp != '\0' || ratio <= 0.0 || ratio >= 1.0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_eviction_threshold must be greater than 0 "
            "and less than 1.0 (or 1%% and 100%%)");
        return NGX_CONF_ERROR;
    }

    ppm = (ngx_uint_t) (ratio * 1000000.0 + 0.5);
    if (ppm == 0 || ppm >= BRIX_CACHE_PPM_FULL_SCALE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_eviction_threshold is out of range");
        return NGX_CONF_ERROR;
    }

    xcf->cache_eviction_threshold = ppm;

    return NGX_CONF_OK;
}

/* brix_conf_set_cache_watermark — parse a fullness watermark as a decimal
 * (0.9) or percentage (90%), stored as parts-per-million at cmd->offset. Shared
 * by the read-cache reaper watermarks and the write-back staging watermarks; the
 * pair-ordering constraint (low < high) is checked once at runtime_server.c so a
 * single directive never needs to know its sibling. */
char *
brix_conf_set_cache_watermark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char       *base = conf;
    ngx_uint_t *field = (ngx_uint_t *) (base + cmd->offset);
    ngx_str_t  *value;
    char       *copy;
    char       *endp;
    double      ratio;
    ngx_uint_t  ppm;

    value = cf->args->elts;

    if (*field != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    copy = brix_pstrdup_z(cf->pool, &value[1]);
    if (copy == NULL) {
        return NGX_CONF_ERROR;
    }

    errno = 0;
    ratio = strtod(copy, &endp);
    if (endp == copy || errno != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%V: invalid value \"%V\"", &cmd->name, &value[1]);
        return NGX_CONF_ERROR;
    }

    if (*endp == '%') {
        endp++;
        ratio /= 100.0;
    } else if (ratio > 1.0) {
        ratio /= 100.0;
    }

    if (*endp != '\0' || ratio <= 0.0 || ratio >= 1.0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%V must be greater than 0 and less than 1.0 (or 1%% and 100%%)",
            &cmd->name);
        return NGX_CONF_ERROR;
    }

    ppm = (ngx_uint_t) (ratio * 1000000.0 + 0.5);
    if (ppm == 0 || ppm >= BRIX_CACHE_PPM_FULL_SCALE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%V is out of range", &cmd->name);
        return NGX_CONF_ERROR;
    }

    *field = ppm;
    return NGX_CONF_OK;
}

/* brix_conf_set_cache_max_file_size — parse the byte limit (raw bytes or k/m/g
 * suffixes) into an off_t. Admission control: files larger than this are served
 * from origin only, never cached. */

char *
brix_conf_set_cache_max_file_size(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                          copy[64];
    char                         *endp;
    unsigned long long            raw;
    off_t                         bytes;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_max_file_size != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 0
        || brix_str_cbuf(copy, sizeof(copy), &value[1]) == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_max_file_size: invalid value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    errno = 0;
    raw = strtoull(copy, &endp, 10);
    if (endp == copy || errno != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_max_file_size: invalid number \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    switch (*endp) {
    case 'k': case 'K': raw *= 1024ULL;              endp++; break;
    case 'm': case 'M': raw *= 1024ULL * 1024;        endp++; break;
    case 'g': case 'G': raw *= 1024ULL * 1024 * 1024; endp++; break;
    case '\0': break;
    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_max_file_size: unknown suffix in \"%V\" "
            "(use k/m/g)", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (*endp != '\0') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_max_file_size: trailing garbage in \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    bytes = (off_t) raw;
    if (bytes < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_max_file_size: value \"%V\" overflows off_t",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    xcf->cache_max_file_size = bytes;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: cache admission limit: %llu bytes",
        (unsigned long long) bytes);

    return NGX_CONF_OK;
}

/* brix_conf_set_cache_include_regex — compile the POSIX extended pattern
 * (regcomp REG_EXTENDED|REG_NOSUB). Admission filter: only matching paths are
 * cached; all others serve from origin. */

char *
brix_conf_set_cache_include_regex(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *pattern;
    int                           rc;
    char                          errbuf[256];

    value = cf->args->elts;
    (void) cmd;

    if (xcf->include_regex.set) {
        return "is duplicate";
    }

    /* Copy to NUL-terminated buffer for regcomp */
    pattern = brix_pstrdup_z(cf->pool, &value[1]);
    if (pattern == NULL) {
        return NGX_CONF_ERROR;
    }

    rc = regcomp(&xcf->include_regex.re, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        regerror(rc, &xcf->include_regex.re, errbuf, sizeof(errbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_include_regex: invalid pattern \"%V\": %s",
            &value[1], errbuf);
        return NGX_CONF_ERROR;
    }

    xcf->include_regex.str.data = (u_char *) pattern;
    xcf->include_regex.str.len  = value[1].len;
    xcf->include_regex.set      = 1;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: cache include regex: \"%V\"", &value[1]);

    return NGX_CONF_OK;
}

/* brix_conf_set_cache_verify — parse off|best-effort|require into cache_verify,
 * the checksum-on-fill policy: off trusts the transfer; best-effort (default)
 * verifies when a digest is available and fails closed on mismatch; require makes
 * a usable digest mandatory. Exact match; anything else is rejected. */
char *
brix_conf_set_cache_verify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_verify != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        xcf->cache_verify = BRIX_CACHE_VERIFY_OFF;
    } else if (ngx_strcmp(value[1].data, "best-effort") == 0) {
        xcf->cache_verify = BRIX_CACHE_VERIFY_BESTEFFORT;
    } else if (ngx_strcmp(value[1].data, "require") == 0) {
        xcf->cache_verify = BRIX_CACHE_VERIFY_REQUIRE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_verify: invalid value \"%V\", must be "
            "off, best-effort, or require", &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: cache checksum-on-fill: %V", &value[1]);
    return NGX_CONF_OK;
}

/* brix_conf_set_cache_verify_digest — parse the preferred digest name (e.g.
 * crc32c) into cache_verify_digest: the Want-Digest preference for HTTP/Pelican
 * origins, advisory for root:// (the origin reports its own default).
 * brix_checksum_parse() rejects unknown names; the lowercase form is stored. */
char *
brix_conf_set_cache_verify_digest(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    brix_checksum_alg_t         alg;
    char                          norm[32];

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_verify_digest.len > 0) {
        return "is duplicate";
    }

    if (brix_checksum_parse((const char *) value[1].data, value[1].len,
                              &alg, norm, sizeof(norm)) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cache_verify_digest: unknown algorithm \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (brix_pstrdupz(cf->pool, &xcf->cache_verify_digest,
                        (u_char *) norm, ngx_strlen(norm)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: cache verify preferred digest: %s", norm);
    return NGX_CONF_OK;
}

/* brix_conf_set_cache_advertise_ns — brix_cache_advertise_namespace <prefix>
 * (repeatable) adds one namespace path this cache advertises to the Pelican
 * Director; with none configured the advertiser defaults to "/" (everything).
 * Lazily creates the ngx_array_t and pushes a pool-copied ngx_str_t. */
char *
brix_conf_set_cache_advertise_ns(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    ngx_str_t                    *entry;
    u_char                       *copy;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->advertise.ns == NULL) {
        xcf->advertise.ns =
            ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (xcf->advertise.ns == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(xcf->advertise.ns);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    BRIX_PNALLOC_OR_RETURN(copy, cf->pool, value[1].len, NGX_CONF_ERROR);
    ngx_memcpy(copy, value[1].data, value[1].len);
    entry->data = copy;
    entry->len  = value[1].len;

    return NGX_CONF_OK;
}

/* Prefix list helpers for the read-cache allow/deny directives (the
 * write-through prefix directives live in directives_wt.c and reuse the same
 * brix_conf_push_prefix helper via cache_internal.h). */

/* Push one cf->args[1] prefix onto *target (created on first use, cf->pool-lived
 * so it persists across merges). Shared by the write-through AND read-cache
 * allow/deny directives so both lists are parsed identically. */
char *
brix_conf_push_prefix(ngx_conf_t *cf, ngx_array_t **target,
    const char *log_label)
{
    ngx_str_t                *value = cf->args->elts;
    brix_wt_prefix_entry_t *entry;
    char                     *prefix_copy;

    if (*target == NULL) {
        *target = ngx_array_create(cf->pool, 4, sizeof(brix_wt_prefix_entry_t));
        if (*target == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    entry = ngx_array_push(*target);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    prefix_copy = brix_pstrdup_z(cf->pool, &value[1]);
    if (prefix_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    entry->prefix.data = (u_char *) prefix_copy;
    entry->prefix.len  = value[1].len;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s: \"%V\"", log_label, &value[1]);
    return NGX_CONF_OK;
}

/* brix_conf_set_cache_deny_prefix / _allow_prefix — read-cache admission
 * prefixes (parity with the write-through lists). */
char *
brix_conf_set_cache_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_conf_push_prefix(cf, &xcf->cache_deny_prefixes,
                                   "brix_cache_deny_prefix");
}

char *
brix_conf_set_cache_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_conf_push_prefix(cf, &xcf->cache_allow_prefixes,
                                   "brix_cache_allow_prefix");
}
