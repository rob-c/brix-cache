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
#include "core/compat/checksum.h"  /* xrootd_checksum_parse */
#include "core/compat/af_policy.h" /* xrootd_af_policy_parse */
#include "verify.h"           /* xrootd_cache_verify_mode_e */

/* §14 (phase-64): xrootd_conf_set_cache_origin is DELETED with the legacy
 * cache_origin config model (a cache's source is xrootd_storage_backend). */

/* xrootd_conf_set_cache_origin_family — parse auto|inet|inet6 into the origin
 * connect's address-family policy (xrootd_af_policy_t stored as ngx_uint_t). */
char *
xrootd_conf_set_cache_origin_family(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value = cf->args->elts;
    int                           pol;

    (void) cmd;

    pol = xrootd_af_policy_parse((const char *) value[1].data, value[1].len);
    if (pol < 0) {
        return "must be one of: auto, inet, inet6";
    }
    xcf->cache_origin_family = (ngx_uint_t) pol;
    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_eviction_threshold — parse the eviction threshold as a
 * decimal (0.95) or percentage (95%), stored as parts-per-million. */

char *
xrootd_conf_set_cache_eviction_threshold(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
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

    XROOTD_PNALLOC_OR_RETURN(copy, cf->pool, value[1].len + 1, NGX_CONF_ERROR);

    ngx_memcpy(copy, value[1].data, value[1].len);
    copy[value[1].len] = '\0';

    errno = 0;
    ratio = strtod(copy, &endp);
    if (endp == copy || errno != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_eviction_threshold: invalid value \"%V\"",
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
            "xrootd_cache_eviction_threshold must be greater than 0 "
            "and less than 1.0 (or 1%% and 100%%)");
        return NGX_CONF_ERROR;
    }

    ppm = (ngx_uint_t) (ratio * 1000000.0 + 0.5);
    if (ppm == 0 || ppm >= 1000000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_eviction_threshold is out of range");
        return NGX_CONF_ERROR;
    }

    xcf->cache_eviction_threshold = ppm;

    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_watermark — parse a fullness watermark as a decimal
 * (0.9) or percentage (90%), stored as parts-per-million at cmd->offset. Shared
 * by the read-cache reaper watermarks and the write-back staging watermarks; the
 * pair-ordering constraint (low < high) is checked once at runtime_server.c so a
 * single directive never needs to know its sibling. */
char *
xrootd_conf_set_cache_watermark(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
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

    XROOTD_PNALLOC_OR_RETURN(copy, cf->pool, value[1].len + 1, NGX_CONF_ERROR);
    ngx_memcpy(copy, value[1].data, value[1].len);
    copy[value[1].len] = '\0';

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
    if (ppm == 0 || ppm >= 1000000) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "%V is out of range", &cmd->name);
        return NGX_CONF_ERROR;
    }

    *field = ppm;
    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_max_file_size — parse the byte limit (raw bytes or k/m/g
 * suffixes) into an off_t. Admission control: files larger than this are served
 * from origin only, never cached. */

char *
xrootd_conf_set_cache_max_file_size(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
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

    if (value[1].len == 0 || value[1].len >= sizeof(copy)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_max_file_size: invalid value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(copy, value[1].data, value[1].len);
    copy[value[1].len] = '\0';

    errno = 0;
    raw = strtoull(copy, &endp, 10);
    if (endp == copy || errno != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_max_file_size: invalid number \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    switch (*endp) {
    case 'k': case 'K': raw *= 1024ULL;              endp++; break;
    case 'm': case 'M': raw *= 1024ULL * 1024;        endp++; break;
    case 'g': case 'G': raw *= 1024ULL * 1024 * 1024; endp++; break;
    case '\0': break;
    default:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_max_file_size: unknown suffix in \"%V\" "
            "(use k/m/g)", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (*endp != '\0') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_max_file_size: trailing garbage in \"%V\"",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    bytes = (off_t) raw;
    if (bytes < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_max_file_size: value \"%V\" overflows off_t",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    xcf->cache_max_file_size = bytes;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: cache admission limit: %llu bytes",
        (unsigned long long) bytes);

    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_include_regex — compile the POSIX extended pattern
 * (regcomp REG_EXTENDED|REG_NOSUB). Admission filter: only matching paths are
 * cached; all others serve from origin. */

char *
xrootd_conf_set_cache_include_regex(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *pattern;
    int                           rc;
    char                          errbuf[256];

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_include_regex_set) {
        return "is duplicate";
    }

    /* Copy to NUL-terminated buffer for regcomp */
    XROOTD_PNALLOC_OR_RETURN(pattern, cf->pool, value[1].len + 1, NGX_CONF_ERROR);
    ngx_memcpy(pattern, value[1].data, value[1].len);
    pattern[value[1].len] = '\0';

    rc = regcomp(&xcf->cache_include_regex, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        regerror(rc, &xcf->cache_include_regex, errbuf, sizeof(errbuf));
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_include_regex: invalid pattern \"%V\": %s",
            &value[1], errbuf);
        return NGX_CONF_ERROR;
    }

    xcf->cache_include_regex_str.data = (u_char *) pattern;
    xcf->cache_include_regex_str.len  = value[1].len;
    xcf->cache_include_regex_set      = 1;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: cache include regex: \"%V\"", &value[1]);

    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_verify — parse off|best-effort|require into cache_verify,
 * the checksum-on-fill policy: off trusts the transfer; best-effort (default)
 * verifies when a digest is available and fails closed on mismatch; require makes
 * a usable digest mandatory. Exact match; anything else is rejected. */
char *
xrootd_conf_set_cache_verify(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_verify != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        xcf->cache_verify = XROOTD_CACHE_VERIFY_OFF;
    } else if (ngx_strcmp(value[1].data, "best-effort") == 0) {
        xcf->cache_verify = XROOTD_CACHE_VERIFY_BESTEFFORT;
    } else if (ngx_strcmp(value[1].data, "require") == 0) {
        xcf->cache_verify = XROOTD_CACHE_VERIFY_REQUIRE;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_verify: invalid value \"%V\", must be "
            "off, best-effort, or require", &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: cache checksum-on-fill: %V", &value[1]);
    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_verify_digest — parse the preferred digest name (e.g.
 * crc32c) into cache_verify_digest: the Want-Digest preference for HTTP/Pelican
 * origins, advisory for root:// (the origin reports its own default).
 * xrootd_checksum_parse() rejects unknown names; the lowercase form is stored. */
char *
xrootd_conf_set_cache_verify_digest(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_checksum_alg_t         alg;
    char                          norm[32];

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_verify_digest.len > 0) {
        return "is duplicate";
    }

    if (xrootd_checksum_parse((const char *) value[1].data, value[1].len,
                              &alg, norm, sizeof(norm)) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_verify_digest: unknown algorithm \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (xrootd_pstrdupz(cf->pool, &xcf->cache_verify_digest,
                        (u_char *) norm, ngx_strlen(norm)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: cache verify preferred digest: %s", norm);
    return NGX_CONF_OK;
}

/* xrootd_conf_set_cache_advertise_ns — xrootd_cache_advertise_namespace <prefix>
 * (repeatable) adds one namespace path this cache advertises to the Pelican
 * Director; with none configured the advertiser defaults to "/" (everything).
 * Lazily creates the ngx_array_t and pushes a pool-copied ngx_str_t. */
char *
xrootd_conf_set_cache_advertise_ns(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    ngx_str_t                    *entry;
    u_char                       *copy;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_advertise_ns == NULL) {
        xcf->cache_advertise_ns =
            ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
        if (xcf->cache_advertise_ns == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(xcf->cache_advertise_ns);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    XROOTD_PNALLOC_OR_RETURN(copy, cf->pool, value[1].len, NGX_CONF_ERROR);
    ngx_memcpy(copy, value[1].data, value[1].len);
    entry->data = copy;
    entry->len  = value[1].len;

    return NGX_CONF_OK;
}

/* Write-through configuration directives */

/* xrootd_conf_set_wt_enable — parse xrootd_write_through on|off. When on, dirty
 * write handles are mirrored to origin on kXR_sync/kXR_close, making client
 * uploads eligible for write-through. */

char *
xrootd_conf_set_wt_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    int                           flag;

    value = cf->args->elts;
    (void) cmd;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        flag = 1;
    } else if (ngx_strcmp(value[1].data, "off") == 0) {
        flag = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_write_through: invalid value \"%V\", must be on or off",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    xcf->wt_enable = flag;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: write-through %s", (flag ? "on" : "off"));
    return NGX_CONF_OK;
}

/* xrootd_conf_set_wt_mode — parse xrootd_wt_mode sync|async. sync flushes dirty
 * close data before kXR_close returns; async posts close flushes to the thread
 * pool. An explicit kXR_sync always flushes synchronously. */

char *
xrootd_conf_set_wt_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;
    (void) cmd;

    if (ngx_strcmp(value[1].data, "sync") == 0) {
        xcf->wt_mode = XROOTD_WT_MODE_SYNC;
    } else if (ngx_strcmp(value[1].data, "async") == 0) {
        xcf->wt_mode = XROOTD_WT_MODE_ASYNC;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_wt_mode: invalid value \"%V\", must be sync or async",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: write-through mode: %s", (xcf->wt_mode == XROOTD_WT_MODE_SYNC) ? "sync" : "async");
    return NGX_CONF_OK;
}

/* xrootd_conf_set_wt_origin — parse xrootd_wt_origin (same format as cache_origin:
 * plain host:port or root://host:port, IPv6 brackets supported), the destination
 * for write-through propagation when wt_enable=on. */

char *
xrootd_conf_set_wt_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *addr_copy, *colon, *endp;
    const u_char                 *addr_data;
    size_t                        addr_len;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->wt_origin_host.len > 0) {
        return "is duplicate";
    }

    /* Accept plain host:port or root://host:port (same as cache_origin). */
    addr_data = value[1].data;
    addr_len  = value[1].len;

    if (addr_len > sizeof("root://") - 1
        && ngx_strncmp(addr_data, "root://", sizeof("root://") - 1) == 0)
    {
        addr_data += sizeof("root://") - 1;
        addr_len  -= sizeof("root://") - 1;
    }

    XROOTD_PNALLOC_OR_RETURN(addr_copy, cf->pool, addr_len + 1, NGX_CONF_ERROR);
    ngx_memcpy(addr_copy, addr_data, addr_len);
    addr_copy[addr_len] = '\0';

    /* Parse host:port — supports IPv6 bracket notation. */
    if (addr_copy[0] == '[') {
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_origin: invalid address \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        if (xrootd_pstrdupz(cf->pool, &xcf->wt_origin_host,
                            (u_char *) addr_copy + 1, hostlen) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_origin: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        if (xrootd_pstrdupz(cf->pool, &xcf->wt_origin_host,
                            (u_char *) addr_copy, hostlen) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_wt_origin: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    xcf->wt_origin_port = (uint16_t) pnum;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: write-through origin: %s:%d",
        (char *) xcf->wt_origin_host.data, (int) xcf->wt_origin_port);

    return NGX_CONF_OK;
}

/* Prefix list helpers for WT allow/deny directives */

/* xrootd_conf_add_wt_prefix — push a parsed prefix onto the WT allow or deny
 * ngx_array_t (created on first use, capacity 4, cf->pool-lived across merges).
 * Shared by the wt_allow_prefix and wt_deny_prefix directives. */

/* Push one cf->args[1] prefix onto *target (created on first use, cf->pool-lived
 * so it persists across merges). Shared by the write-through AND read-cache
 * allow/deny directives so both lists are parsed identically. */
static char *
xrootd_conf_push_prefix(ngx_conf_t *cf, ngx_array_t **target,
    const char *log_label)
{
    ngx_str_t                *value = cf->args->elts;
    xrootd_wt_prefix_entry_t *entry;
    char                     *prefix_copy;

    if (*target == NULL) {
        *target = ngx_array_create(cf->pool, 4, sizeof(xrootd_wt_prefix_entry_t));
        if (*target == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    entry = ngx_array_push(*target);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    prefix_copy = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (prefix_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(prefix_copy, value[1].data, value[1].len);
    prefix_copy[value[1].len] = '\0';
    entry->prefix.data = (u_char *) prefix_copy;
    entry->prefix.len  = value[1].len;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "%s: \"%V\"", log_label, &value[1]);
    return NGX_CONF_OK;
}

static char *
xrootd_conf_add_wt_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, int is_deny)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    (void) cmd;
    return xrootd_conf_push_prefix(cf,
        is_deny ? &xcf->wt_deny_prefixes : &xcf->wt_allow_prefixes,
        is_deny ? "xrootd_wt_deny_prefix" : "xrootd_wt_allow_prefix");
}

/* xrootd_conf_set_cache_deny_prefix / _allow_prefix — read-cache admission
 * prefixes (parity with the write-through lists). */
char *
xrootd_conf_set_cache_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    (void) cmd;
    return xrootd_conf_push_prefix(cf, &xcf->cache_deny_prefixes,
                                   "xrootd_cache_deny_prefix");
}

char *
xrootd_conf_set_cache_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    (void) cmd;
    return xrootd_conf_push_prefix(cf, &xcf->cache_allow_prefixes,
                                   "xrootd_cache_allow_prefix");
}

/* xrootd_conf_set_wt_deny_prefix — add a path prefix to the WT deny list: matching
 * paths are blocked from write-through propagation. Deny takes precedence over allow. */

char *
xrootd_conf_set_wt_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return xrootd_conf_add_wt_prefix(cf, cmd, conf, 1);
}

/* xrootd_conf_set_wt_allow_prefix — add a path prefix to the WT allow list: matching
 * paths are eligible for write-through propagation unless a deny entry blocks them. */

char *
xrootd_conf_set_wt_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return xrootd_conf_add_wt_prefix(cf, cmd, conf, 0);
}
