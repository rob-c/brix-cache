#include "fattr/ngx_xrootd_fattr.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <arpa/inet.h>
#include <dirent.h>

/* ---- kXR_fa_recurse support ---- */

#define FATTR_RECURSE_XLIST_BUF  8192
#define FATTR_RECURSE_RESP_CAP   (256 * 1024)
#define FATTR_RECURSE_MAX_DEPTH  16

typedef struct {
    u_char *buf;
    size_t  cap;
    size_t  len;
    size_t  root_len;   /* length of root path; relpath = fullpath + root_len */
} fattr_recurse_ctx_t;

static void
fattr_recurse_dir(fattr_recurse_ctx_t *rctx, const char *dir_path, int depth)
{
    DIR           *dir;
    struct dirent *de;
    char           fpath[XROOTD_PATH_MAX];
    char           xlist[FATTR_RECURSE_XLIST_BUF];
    struct stat    sb;
    ssize_t        list_sz;
    char          *lp, *lend;
    size_t         full_nlen;
    const char    *relpath;
    int            plen;

    if (depth > FATTR_RECURSE_MAX_DEPTH) {
        return;
    }

    dir = opendir(dir_path);
    if (dir == NULL) {
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        plen = snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, de->d_name);
        if (plen < 0 || plen >= (int) sizeof(fpath)) {
            continue;
        }

        if (lstat(fpath, &sb) != 0) {
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            fattr_recurse_dir(rctx, fpath, depth + 1);
            continue;
        }

        if (!S_ISREG(sb.st_mode)) {
            continue;
        }

        relpath = fpath + rctx->root_len;
        if (*relpath == '/') {
            relpath++;
        }

        list_sz = listxattr(fpath, xlist, sizeof(xlist));
        if (list_sz <= 0) {
            continue;
        }

        lp   = xlist;
        lend = xlist + list_sz;
        while (lp < lend) {
            full_nlen = strlen(lp);
            if (strncmp(lp, XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN) == 0
                && full_nlen > XROOTD_FATTR_XKEY_PFX_LEN)
            {
                /* Strip "user." (5 bytes) to keep "U.name" */
                const char *resp_name   = lp + 5;
                size_t      resp_nlen   = full_nlen - 5;
                size_t      relpath_len = strlen(relpath);
                /* entry = "relpath:U.name\0" */
                size_t      entry_len   = relpath_len + 1 + resp_nlen + 1;

                if (rctx->len + entry_len <= rctx->cap) {
                    ngx_memcpy(rctx->buf + rctx->len, relpath, relpath_len);
                    rctx->len += relpath_len;
                    rctx->buf[rctx->len++] = ':';
                    ngx_memcpy(rctx->buf + rctx->len, resp_name, resp_nlen);
                    rctx->len += resp_nlen;
                    rctx->buf[rctx->len++] = '\0';
                }
            }
            lp += full_nlen + 1;
        }
    }

    closedir(dir);
}

static ngx_int_t
fattr_list_recurse(xrootd_ctx_t *ctx, ngx_connection_t *c, const char *path)
{
    fattr_recurse_ctx_t rctx;
    u_char             *buf;

    buf = ngx_palloc(c->pool, FATTR_RECURSE_RESP_CAP);
    if (buf == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    rctx.buf      = buf;
    rctx.cap      = FATTR_RECURSE_RESP_CAP;
    rctx.len      = 0;
    rctx.root_len = strlen(path);

    fattr_recurse_dir(&rctx, path, 0);

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    if (rctx.len == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    return xrootd_send_ok(ctx, c, rctx.buf, (uint32_t) rctx.len);
}

/* ---- Function: fattr_list() — handle kXR_fattrList: enumerate extended attributes ----
 *
 * WHAT: Handles kXR_fattrList by calling listxattr(path, NULL, 0) for path-based
 *       operations or flistxattr(fd, NULL, 0) for open-file-handle operations to
 *       query the size of all attribute names stored on the filesystem, then reads
 *       the full NUL-separated name string into a buffer. Filters entries to only
 *       those prefixed with XROOTD_FATTR_XKEY_PFX (the user namespace prefix used by
 *       nginx-xrootd), stripping the 5-byte prefix from returned names so clients see
 *       bare attribute keys. When kXR_fa_aData flag is set, also reads each filtered
 *       attribute's value via getxattr/fgetxattr and appends it to the response.
 *
 * WHY: XRootD fattrList returns all user-space extended attributes on a file;
 *       nginx-xrootd uses only the user namespace prefixed with "user." so filtering
 *       ensures only managed attributes are visible. The two-phase list (query size
 *       then read) prevents over-allocation. ENOTSUP/EOPNOTSUPP handled gracefully —
 *       filesystems without xattr support return empty response rather than error.
 *       Thread safety: operates only on provided ctx, c, pool and local stack variables. */
ngx_int_t fattr_list(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    const char *path, int fd, int options) {
    ngx_pool_t *pool = c->pool;
    int aData = (options & kXR_fa_aData);

    if ((options & kXR_fa_recurse) && path != NULL) {
        struct stat rsb;
        if (stat(path, &rsb) == 0 && S_ISDIR(rsb.st_mode)) {
            return fattr_list_recurse(ctx, c, path);
        }
    }
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
