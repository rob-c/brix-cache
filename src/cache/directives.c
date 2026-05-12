#include "../config/config.h"

#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

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

    addr_copy = ngx_pnalloc(cf->pool, addr_len + 1);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }
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

    copy = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (copy == NULL) {
        return NGX_CONF_ERROR;
    }

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
    pattern = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (pattern == NULL) {
        return NGX_CONF_ERROR;
    }
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
