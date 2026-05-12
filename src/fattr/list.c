#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <arpa/inet.h>

ngx_int_t fattr_list(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    const char *path, int fd, int options) {
    ngx_pool_t *pool = c->pool;
    int aData = (options & kXR_fa_aData);
    ssize_t list_sz = path ? listxattr(path, NULL, 0)
                           : flistxattr(fd,   NULL, 0);
    if (list_sz < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP) {
            XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_FSError, "listxattr failed");
    }
    if (list_sz == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    char *raw = ngx_palloc(pool, list_sz + 4096);
    if (raw == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    ssize_t actual = path ? listxattr(path, raw, list_sz + 4096)
                          : flistxattr(fd,   raw, list_sz + 4096);
    if (actual < 0) {
        return xrootd_send_error(ctx, c, kXR_FSError, "listxattr failed");
    }
    if (actual == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    size_t resp_cap = (size_t) actual + kXR_faMaxVars * (4 + 4096) + 64;
    u_char *resp = ngx_palloc(pool, resp_cap);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    u_char *wp   = resp;
    char   *lp   = raw;
    char   *lend = raw + actual;
    while (lp < lend) {
        size_t full_nlen = strlen(lp);
        if (strncmp(lp, XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN) == 0
            && full_nlen > XROOTD_FATTR_XKEY_PFX_LEN) {
            const char *resp_name = lp + 5;
            size_t      resp_nlen = full_nlen - 5;
            size_t space_needed = resp_nlen + 1
                                  + (aData ? 4 + 4096 : 0);
            if ((size_t)(wp - resp) + space_needed > resp_cap) break;
            ngx_memcpy(wp, resp_name, resp_nlen);
            wp += resp_nlen;
            *wp++ = '\0';
            if (aData) {
                char    val[4096];
                ssize_t vlen = path ? getxattr(path, lp, val, sizeof(val))
                                    : fgetxattr(fd,   lp, val, sizeof(val));
                if (vlen < 0) vlen = 0;
                uint32_t vlen_be = htonl((uint32_t) vlen);
                ngx_memcpy(wp, &vlen_be, 4);
                wp += 4;
                if (vlen > 0) {
                    ngx_memcpy(wp, val, vlen);
                    wp += vlen;
                }
            }
        }
        lp += full_nlen + 1;
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    size_t resp_len = (size_t)(wp - resp);
    if (resp_len == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    return xrootd_send_ok(ctx, c, resp, (uint32_t) resp_len);
}
