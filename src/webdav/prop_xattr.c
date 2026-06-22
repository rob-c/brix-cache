/*
 * prop_xattr.c — xattr-based lock persistence for WebDAV.
 *
 * A WebDAV lock is encoded as a single xattr on the locked resource:
 *   token=<tok>|owner=<owner>|expires=<msec>|scope=<exclusive|shared>|depth=<infinity|0>
 *
 * XATTR_CREATE semantics make lock creation atomic across workers: if two
 * workers race on the same unlocked path, exactly one setxattr(XATTR_CREATE)
 * succeeds and the other gets EEXIST → NGX_DECLINED → 423 Locked.
 */
#include "webdav.h"
#include "../path/path.h"

#include <sys/xattr.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

/*
 * Phase 40: lock xattrs must be written/read/removed AS THE MAPPED USER under
 * impersonation, else the worker (svc) cannot setxattr on the user-owned lock
 * file (EACCES) and LOCK/UNLOCK break.  These helpers take the request so they
 * can resolve the export root and route through xrootd_*xattr_confined_canon,
 * which delegates to the broker when map mode is active and falls back to the
 * raw path-based syscall otherwise (unchanged when impersonation is off).
 */
static const char *
webdav_lock_root_canon(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    return conf->common.root_canon;
}

#ifndef ENOATTR
#define ENOATTR ENODATA
#endif

ngx_int_t
webdav_lock_xattr_encode(const webdav_lock_xattr_t *e, char *out, size_t outsz)
{
    int n;

    n = snprintf(out, outsz,
                 "token=%s|owner=%s|expires=%llu|scope=%s|depth=%s",
                 e->token, e->owner,
                 (unsigned long long) e->expires,
                 e->exclusive ? "exclusive" : "shared",
                 e->depth_infinity ? "infinity" : "0");
    return (n > 0 && (size_t) n < outsz) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
webdav_lock_xattr_decode(const char *raw, size_t rawlen, webdav_lock_xattr_t *e)
{
    char   buf[WEBDAV_LOCK_XATTR_MAXLEN];
    char  *p, *end, *val, *next;

    if (rawlen == 0 || rawlen >= sizeof(buf)) {
        return NGX_DECLINED;
    }

    ngx_memcpy(buf, raw, rawlen);
    buf[rawlen] = '\0';
    ngx_memzero(e, sizeof(*e));

    p   = buf;
    end = buf + rawlen;

    while (p < end) {
        next = strchr(p, '|');
        if (next != NULL) {
            *next = '\0';
        }

        val = strchr(p, '=');
        if (val != NULL) {
            *val++ = '\0';

            if (strcmp(p, "token") == 0) {
                ngx_cpystrn((u_char *) e->token, (u_char *) val,
                            sizeof(e->token));
            } else if (strcmp(p, "owner") == 0) {
                ngx_cpystrn((u_char *) e->owner, (u_char *) val,
                            sizeof(e->owner));
            } else if (strcmp(p, "expires") == 0) {
                e->expires = (ngx_msec_t) strtoull(val, NULL, 10);
            } else if (strcmp(p, "scope") == 0) {
                e->exclusive = (strcmp(val, "exclusive") == 0) ? 1 : 0;
            } else if (strcmp(p, "depth") == 0) {
                e->depth_infinity = (strcmp(val, "infinity") == 0) ? 1 : 0;
            }
        }

        p = next ? next + 1 : end;
    }

    return (e->token[0] != '\0') ? NGX_OK : NGX_DECLINED;
}

ngx_int_t
webdav_lock_xattr_write(ngx_http_request_t *r, const char *path,
    const webdav_lock_xattr_t *e, int flags)
{
    ngx_log_t  *log = r->connection->log;
    const char *root_canon = webdav_lock_root_canon(r);
    char        buf[WEBDAV_LOCK_XATTR_MAXLEN];

    if (webdav_lock_xattr_encode(e, buf, sizeof(buf)) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_webdav: lock xattr encode failed for \"%s\"", path);
        return NGX_ERROR;
    }

    if (xrootd_setxattr_confined_canon(log, root_canon, path,
            WEBDAV_LOCK_XATTR_KEY, buf, strlen(buf), flags) != 0)
    {
        if (errno == EEXIST) {
            return NGX_DECLINED;   /* XATTR_CREATE race — another worker won */
        }
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd_webdav: setxattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
webdav_lock_xattr_read(ngx_http_request_t *r, const char *path,
    webdav_lock_xattr_t *e)
{
    ngx_log_t  *log = r->connection->log;
    const char *root_canon = webdav_lock_root_canon(r);
    char        buf[WEBDAV_LOCK_XATTR_MAXLEN];
    ssize_t     n;

    n = xrootd_getxattr_confined_canon(log, root_canon, path,
            WEBDAV_LOCK_XATTR_KEY, buf, sizeof(buf) - 1);
    if (n < 0) {
        if (errno == ENODATA || errno == ENOATTR || errno == ENOENT) {
            return NGX_DECLINED;
        }
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd_webdav: getxattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return webdav_lock_xattr_decode(buf, (size_t) n, e);
}

ngx_int_t
webdav_lock_xattr_delete(ngx_http_request_t *r, const char *path)
{
    ngx_log_t  *log = r->connection->log;
    const char *root_canon = webdav_lock_root_canon(r);

    if (xrootd_removexattr_confined_canon(log, root_canon, path,
            WEBDAV_LOCK_XATTR_KEY) != 0)
    {
        if (errno == ENODATA || errno == ENOATTR || errno == ENOENT) {
            return NGX_OK;   /* idempotent */
        }
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd_webdav: removexattr lock on \"%s\" failed", path);
        return NGX_ERROR;
    }

    return NGX_OK;
}
