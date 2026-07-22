/*
 * directives_wt.c — parse and validate the write-through nginx config
 * directives (called during startup when reading the configuration file).
 * Split verbatim from directives.c; the read-cache directives stay there.
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
#include "cache_internal.h"   /* brix_conf_push_prefix (shared with directives.c) */

/* Write-through configuration directives */

/* brix_conf_set_wt_enable — parse brix_write_through on|off. When on, dirty
 * write handles are mirrored to origin on kXR_sync/kXR_close, making client
 * uploads eligible for write-through. */

char *
brix_conf_set_wt_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
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
            "brix_write_through: invalid value \"%V\", must be on or off",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    xcf->wt.enable = flag;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: write-through %s", (flag ? "on" : "off"));
    return NGX_CONF_OK;
}

/* brix_conf_set_wt_mode — parse brix_wt_mode sync|async. sync flushes dirty
 * close data before kXR_close returns; async posts close flushes to the thread
 * pool. An explicit kXR_sync always flushes synchronously. */

char *
brix_conf_set_wt_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;

    value = cf->args->elts;
    (void) cmd;

    if (ngx_strcmp(value[1].data, "sync") == 0) {
        xcf->wt.mode = BRIX_WT_MODE_SYNC;
    } else if (ngx_strcmp(value[1].data, "async") == 0) {
        xcf->wt.mode = BRIX_WT_MODE_ASYNC;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_mode: invalid value \"%V\", must be sync or async",
            &value[1]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: write-through mode: %s", (xcf->wt.mode == BRIX_WT_MODE_SYNC) ? "sync" : "async");
    return NGX_CONF_OK;
}

/* brix_conf_set_wt_origin — parse brix_wt_origin (same format as cache_origin:
 * plain host:port or root://host:port, IPv6 brackets supported), the destination
 * for write-through propagation when wt_enable=on. */

char *
brix_conf_set_wt_origin(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *addr_copy, *colon, *endp;
    const u_char                 *addr_data;
    size_t                        addr_len;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->wt.origin_host.len > 0) {
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

    BRIX_PNALLOC_OR_RETURN(addr_copy, cf->pool, addr_len + 1, NGX_CONF_ERROR);
    ngx_memcpy(addr_copy, addr_data, addr_len);
    addr_copy[addr_len] = '\0';

    /* Parse host:port — supports IPv6 bracket notation. */
    if (addr_copy[0] == '[') {
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_wt_origin: invalid address \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        if (brix_pstrdupz(cf->pool, &xcf->wt.origin_host,
                            (u_char *) addr_copy + 1, hostlen) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_wt_origin: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        if (brix_pstrdupz(cf->pool, &xcf->wt.origin_host,
                            (u_char *) addr_copy, hostlen) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_wt_origin: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    xcf->wt.origin_port = (uint16_t) pnum;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "brix: write-through origin: %s:%d",
        (char *) xcf->wt.origin_host.data, (int) xcf->wt.origin_port);

    return NGX_CONF_OK;
}

/* Prefix list helpers for WT allow/deny directives */

/* brix_conf_add_wt_prefix — push a parsed prefix onto the WT allow or deny
 * ngx_array_t (created on first use, capacity 4, cf->pool-lived across merges).
 * Shared by the wt_allow_prefix and wt_deny_prefix directives. The underlying
 * brix_conf_push_prefix helper lives in directives.c (declared in
 * cache_internal.h) and is shared with the read-cache prefix directives. */

static char *
brix_conf_add_wt_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf, int is_deny)
{
    ngx_stream_brix_srv_conf_t *xcf = conf;
    (void) cmd;
    return brix_conf_push_prefix(cf,
        is_deny ? &xcf->wt.deny_prefixes : &xcf->wt.allow_prefixes,
        is_deny ? "brix_wt_deny_prefix" : "brix_wt_allow_prefix");
}

/* brix_conf_set_wt_deny_prefix — add a path prefix to the WT deny list: matching
 * paths are blocked from write-through propagation. Deny takes precedence over allow. */

char *
brix_conf_set_wt_deny_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return brix_conf_add_wt_prefix(cf, cmd, conf, 1);
}

/* brix_conf_set_wt_allow_prefix — add a path prefix to the WT allow list: matching
 * paths are eligible for write-through propagation unless a deny entry blocks them. */

char *
brix_conf_set_wt_allow_prefix(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return brix_conf_add_wt_prefix(cf, cmd, conf, 0);
}
