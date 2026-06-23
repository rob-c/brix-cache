/* ---- Cache configuration directives — nginx config parsing ----
 *
 * WHAT: Parse and validate all cache-related nginx configuration directives.
 *       Called during nginx startup when reading the configuration file. */

#include "../config/config.h"

#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include "../compat/alloc_guard.h"

/* ---- Cache origin directive — parse host:port address ----
 *
 * WHAT: Parse and validate the xrootd_cache_origin directive (e.g. "root://ceph.example.com:1094").
 *       Accepts plain host:port or root://host:port prefixes. roots:// enables TLS automatically. */

char *
xrootd_conf_set_cache_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *addr_copy, *colon, *endp;
    const u_char                 *addr_data;
    size_t                        addr_len;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cache_origin_host.len > 0) {
        return "is duplicate";
    }

    if (xrootd_copy_conf_string(cf, &value[1], &xcf->cache_origin)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    /*
     * Accept plain host:port as well as root://host:port and
     * roots://host:port. roots:// also enables direct TLS unless the admin
     * later overrides it with xrootd_cache_origin_tls.
     */
    addr_data = value[1].data;
    addr_len = value[1].len;

    if (addr_len > sizeof("root://") - 1
        && ngx_strncmp(addr_data, "root://", sizeof("root://") - 1) == 0)
    {
        addr_data += sizeof("root://") - 1;
        addr_len  -= sizeof("root://") - 1;
    } else if (addr_len > sizeof("roots://") - 1
               && ngx_strncmp(addr_data, "roots://",
                              sizeof("roots://") - 1) == 0)
    {
        addr_data += sizeof("roots://") - 1;
        addr_len  -= sizeof("roots://") - 1;
        if (xcf->cache_origin_tls == NGX_CONF_UNSET) {
            xcf->cache_origin_tls = 1;
        }
    }

    XROOTD_PNALLOC_OR_RETURN(addr_copy, cf->pool, addr_len + 1, NGX_CONF_ERROR);
    ngx_memcpy(addr_copy, addr_data, addr_len);
    addr_copy[addr_len] = '\0';

    if (addr_copy[0] == '[') {
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_origin: invalid address \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        xcf->cache_origin_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->cache_origin_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->cache_origin_host.data, addr_copy + 1, hostlen);
        xcf->cache_origin_host.data[hostlen] = '\0';
        xcf->cache_origin_host.len = hostlen;
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cache_origin: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        xcf->cache_origin_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->cache_origin_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->cache_origin_host.data, addr_copy, hostlen);
        xcf->cache_origin_host.data[hostlen] = '\0';
        xcf->cache_origin_host.len = hostlen;
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cache_origin: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    xcf->cache_origin_port = (uint16_t) pnum;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: cache origin: %s:%d tls=%s",
        (char *) xcf->cache_origin_host.data, (int) xcf->cache_origin_port,
        (xcf->cache_origin_tls == 1) ? "on" : "off");

    return NGX_CONF_OK;
}

/* ---- Cache eviction threshold directive — parse occupancy percentage ----
 *
 * WHAT: Parse and validate the xrootd_cache_eviction_threshold directive.
 *       Accepts decimal (0.95) or percentage format (95%). Stored as parts-per-million internally. */

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

/* ---- Cache max file size directive — parse byte-limit with k/m/g suffixes ----
 *
 * WHAT: Parse and validate the xrootd_cache_max_file_size directive. Accepts raw bytes,
 * or kilobyte (k/K), megabyte (m/M), gigabyte (g/G) suffixes. Stored as off_t internally.
 * This limit controls admission: files exceeding this size are served from origin only. */

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

/* ---- Cache include regex directive — parse POSIX extended pattern ----
 *
 * WHAT: Parse and validate the xrootd_cache_include_regex directive. Accepts a POSIX
 * extended regular expression compiled via regcomp(REG_EXTENDED | REG_NOSUB). Used to
 * filter cache admission: only paths matching this pattern are cached; all others serve from origin. */

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

/* ---- Write-through configuration directives ---- */

/* ---- Write-through enable directive — parse on/off flag ----
 *
 * WHAT: Parse and validate the xrootd_write_through directive. Accepts "on" or "off".
 * When enabled, dirty write handles are mirrored to origin on kXR_sync or
 * kXR_close. Controls whether client uploads are eligible for write-through. */

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

/* ---- Write-through mode directive — parse sync/async selection ----
 *
 * WHAT: Parse and validate the xrootd_wt_mode directive. Accepts "sync" or "async".
 * Sync mode flushes dirty close data before kXR_close returns; async mode posts
 * close flushes to the thread pool. Explicit kXR_sync always flushes
 * synchronously. */

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

/* ---- Write-through origin directive — parse upstream host:port address ----
 *
 * WHAT: Parse and validate the xrootd_wt_origin directive. Same format as cache_origin
 * (plain host:port or root://host:port). Sets the destination for write-through propagation
 * when wt_enable=on. Supports IPv6 bracket notation in address parsing. */

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
        xcf->wt_origin_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->wt_origin_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->wt_origin_host.data, addr_copy + 1, hostlen);
        xcf->wt_origin_host.data[hostlen] = '\0';
        xcf->wt_origin_host.len = hostlen;
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_wt_origin: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        xcf->wt_origin_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->wt_origin_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->wt_origin_host.data, addr_copy, hostlen);
        xcf->wt_origin_host.data[hostlen] = '\0';
        xcf->wt_origin_host.len = hostlen;
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

/* ---- Prefix list helpers for WT allow/deny directives ---- */

/* ---- Write-through prefix helper — add allow/deny path prefix entry ----
 *
 * WHAT: Internal helper that allocates or grows an ngx_array_t for WT prefix entries,
 * then pushes a new xrootd_wt_prefix_entry_t with the parsed prefix string. The array
 * is created on first use (capacity=4) and persists across config merges via cf->pool.
 * Used by both wt_allow_prefix and wt_deny_prefix directives to build path-based access control lists. */

static char *
xrootd_conf_add_wt_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, int is_deny)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;
    (void) cmd;

    /* Allocate the array on first use. */
    ngx_array_t **target = is_deny ? &xcf->wt_deny_prefixes : &xcf->wt_allow_prefixes;
    if (*target == NULL) {
        *target = ngx_array_create(cf->pool, 4, sizeof(xrootd_wt_prefix_entry_t));
        if (*target == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    /* Push a new entry. */
    xrootd_wt_prefix_entry_t *entry = ngx_array_push(*target);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    /* Allocate prefix string from cf->pool so it persists across merges. */
    char *prefix_copy = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (prefix_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(prefix_copy, value[1].data, value[1].len);
    prefix_copy[value[1].len] = '\0';
    entry->prefix.data = (u_char *) prefix_copy;
    entry->prefix.len  = value[1].len;

    const char *label = is_deny ? "deny" : "allow";
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd_wt_%s_prefix: \"%V\"", label, &value[1]);
    return NGX_CONF_OK;
}

/* ---- Write-through deny prefix directive — add path to deny list ----
 *
 * WHAT: Parse and validate the xrootd_wt_deny_prefix directive. Adds a path prefix to
 * the WT deny list: paths matching this prefix are blocked from write-through propagation,
 * even if other prefixes allow access. Deny takes precedence over allow entries. */

char *
xrootd_conf_set_wt_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return xrootd_conf_add_wt_prefix(cf, cmd, conf, 1);
}

/* ---- Write-through allow prefix directive — add path to allow list ----
 *
 * WHAT: Parse and validate the xrootd_wt_allow_prefix directive. Adds a path prefix to
 * the WT allow list: paths matching this prefix are eligible for write-through propagation.
 * Only if not denied by wt_deny_prefix entries does the prefix allow access. */

char *
xrootd_conf_set_wt_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return xrootd_conf_add_wt_prefix(cf, cmd, conf, 0);
}
