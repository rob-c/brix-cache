#include "ngx_brix_fattr.h"
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "core/compat/safe_size.h"

/* Outcome of the two-phase name-list read (fattr_list_read_names). When
 * `done` is set the caller must return `rc` verbatim (a terminal send already
 * happened, whether OK-empty or an error); otherwise (raw, actual) hold the
 * NUL-separated name list to build the response from. */
typedef struct {
    int       done;      /* terminal response already sent → return rc */
    ngx_int_t rc;        /* value to return when done                  */
    char     *raw;       /* name-list buffer (valid when !done)        */
    ssize_t   actual;    /* bytes in raw (valid when !done)            */
} fattr_list_read_t;

/*
 *
 * WHAT: Two-phase read of the full NUL-separated xattr name list: probe the size,
 *       allocate, then read the names into a buffer.
 *
 * WHY: Factors the size-probe + allocation + read (and their several terminal
 *       responses: no-xattr-support, empty list, alloc failure, read error) out of
 *       fattr_list, so the handler body is just "read then build".
 *
 * HOW: Returns a fattr_list_read_t. When `done` is set the caller returns `rc`
 *       (a terminal send already happened — OK-empty or error); otherwise (raw,
 *       actual) hold the name list. A +4096 slack absorbs names added between the
 *       two phases (TOCTOU). Behaviour and error codes are identical to the inline
 *       original. */
static fattr_list_read_t
fattr_list_read_names(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_vfs_ctx_t *vctx, const char *path, int fd)
{
    fattr_list_read_t out = { 0 };
    char             *raw;
    size_t            raw_cap;
    ssize_t           list_sz;
    ssize_t           actual;

    /* Phase 1: probe (size, NULL) to learn how big the name list is. */
    list_sz = path ? brix_vfs_listxattr(vctx, NULL, 0)
                   : brix_vfs_flistxattr(vctx, fd, NULL, 0);
    if (list_sz < 0) {
        out.done = 1;
        /* Filesystem/backend with no xattr support → empty list, not an error.
         * Three errnos mean exactly that here, depending on where the "no
         * xattrs" verdict came from: the local POSIX path and the VFS's own
         * NULL-driver checks report ENOTSUP/EOPNOTSUPP (vfs_xattr.c), while the
         * storage seam reports a driver without the slot as ENOSYS
         * (brix_sd_listxattr_maybe_cred, sd_cred_forward.h) — which is what a
         * composed tier over an xattr-less leaf (e.g. brix_stage over an http
         * origin) produces. Treating ENOSYS as a hard error made fattr list
         * answer kXR_FSError for a perfectly healthy backend that simply has no
         * extended attributes. */
        if (errno == ENOTSUP || errno == EOPNOTSUPP || errno == ENOSYS) {
            BRIX_OP_OK(ctx, BRIX_OP_FATTR);
            out.rc = brix_send_ok(ctx, c, NULL, 0);
            return out;
        }
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_error(ctx, c, kXR_FSError, "listxattr failed");
        return out;
    }
    if (list_sz == 0) {
        out.done = 1;
        BRIX_OP_OK(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_ok(ctx, c, NULL, 0);
        return out;
    }

    /* +BRIX_ROOT_FATTR_PATH_SLACK absorbs names added between the two reads. */
    if (brix_size_add((size_t) list_sz, BRIX_ROOT_FATTR_PATH_SLACK,
                      &raw_cap) != NGX_OK)
    {
        out.done = 1;
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_error(ctx, c, kXR_ArgTooLong,
                                 "fattr list too large");
        return out;
    }
    raw = ngx_palloc(c->pool, raw_cap);
    if (raw == NULL) {
        out.done = 1;
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
        return out;
    }

    /* Phase 2: read the actual NUL-separated name list into raw. */
    actual = path ? brix_vfs_listxattr(vctx, raw, raw_cap)
                  : brix_vfs_flistxattr(vctx, fd, raw, raw_cap);
    if (actual < 0) {
        out.done = 1;
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_error(ctx, c, kXR_FSError, "listxattr failed");
        return out;
    }
    if ((size_t) actual > raw_cap) {
        out.done = 1;
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_error(ctx, c, kXR_FSError,
                                 "invalid listxattr length");
        return out;
    }
    if (actual == 0) {
        out.done = 1;
        BRIX_OP_OK(ctx, BRIX_OP_FATTR);
        out.rc = brix_send_ok(ctx, c, NULL, 0);
        return out;
    }

    out.raw    = raw;
    out.actual = actual;
    return out;
}

/*
 *
 * WHAT: Reads one direct attribute value into a caller-bounded response slot.
 *
 * WHY: Factors the kXR_fa_aData value-append out of the build loop. Note getxattr
 *       uses the full internal key while the emitted name is the stripped form.
 *
 * HOW: Probe first, enforce both the protocol maximum and destination capacity,
 *       then perform the bounded read. A disappearing/unreadable value retains
 *       the historical zero-length representation; a growth race fails closed. */
static ngx_int_t
fattr_list_read_value(brix_vfs_ctx_t *vctx, const char *path, int fd,
    const char *full_key, u_char *dst, size_t dst_cap, size_t *value_len)
{
    ssize_t expected;
    ssize_t actual;

    *value_len = 0;
    expected = path ? brix_vfs_getxattr(vctx, full_key, NULL, 0)
                    : brix_vfs_fgetxattr(vctx, fd, full_key, NULL, 0);
    if (expected < 0) return NGX_OK;
    if ((size_t) expected > kXR_faMaxVlen || (size_t) expected > dst_cap) {
        errno = ERANGE;
        return NGX_ERROR;
    }
    if (expected == 0) return NGX_OK;

    actual = path ? brix_vfs_getxattr(vctx, full_key, dst, (size_t) expected)
                  : brix_vfs_fgetxattr(vctx, fd, full_key, dst,
                                       (size_t) expected);
    if (actual < 0) return errno == ERANGE ? NGX_ERROR : NGX_OK;
    if (actual > expected || (size_t) actual > kXR_faMaxVlen) {
        errno = ERANGE;
        return NGX_ERROR;
    }
    *value_len = (size_t) actual;
    return NGX_OK;
}

/*
 *
 * WHAT: Builds the fattrList response body into `resp` (capacity resp_cap) by
 *       striding the raw NUL-separated name list, keeping managed "user.U.*" keys,
 *       and (when aData) appending each attribute's value. Returns the byte length.
 *
 * WHY: Factors the response-assembly loop out of fattr_list so the handler is a
 *       thin read→build→send sequence.
 *
 * HOW: Each kept name has its full 7-byte internal prefix stripped so the client
 *       sees the bare name it set (matching the reference XeqFALsd). Entries that
 *       would exceed resp_cap reject the complete response; a partial successful
 *       list would hide attributes and make retry behavior ambiguous. */
static ssize_t
fattr_list_build(ngx_pool_t *pool, brix_vfs_ctx_t *vctx, const char *path,
    int fd, int aData, const char *raw, ssize_t actual, u_char *resp,
    size_t resp_cap)
{
    /* wp = write cursor into resp; lp/lend stride the raw name list. */
    u_char     *wp   = resp;
    const char *lp   = raw;
    const char *lend = raw + actual;

    while (lp < lend) {
        const char          *nul;
        size_t               full_nlen;
        brix_fattr_stored_t  stored;
        int                  decoded;

        nul = memchr(lp, '\0', (size_t) (lend - lp));
        if (nul == NULL) {
            errno = EIO;
            return -1;
        }
        full_nlen = (size_t) (nul - lp);
        decoded = fattr_storage_decode_list(pool, vctx, path, fd, lp,
                                             &stored);
        if (decoded < 0) return -1;
        if (decoded == 1) {
            /* Strip the full internal "user.U." prefix (7 bytes) so the client
             * sees the bare name it set — matching the reference XeqFALsd, which
             * returns verbatim names (the 'U' namespace is internal only). */
            const char *resp_name = stored.name;
            size_t      resp_nlen = stored.nlen;
            size_t      used = (size_t) (wp - resp);
            size_t      entry_len;
            size_t      value_len = 0;

            if (brix_size_add(resp_nlen, 1U, &entry_len) != NGX_OK
                || (aData && brix_size_add(entry_len, 4U, &entry_len) != NGX_OK)
                || used > resp_cap || entry_len > resp_cap - used)
            {
                errno = ERANGE;
                return -1;
            }
            if (aData && stored.value != NULL) {
                value_len = stored.vlen;
                if (value_len > kXR_faMaxVlen
                    || value_len > resp_cap - used - entry_len)
                {
                    errno = ERANGE;
                    return -1;
                }
            } else if (aData
                       && fattr_list_read_value(vctx, path, fd, lp,
                              resp + used + entry_len,
                              resp_cap - used - entry_len,
                              &value_len) != NGX_OK)
            {
                return -1;
            }
            if (brix_size_add(entry_len, value_len, &entry_len) != NGX_OK
                || entry_len > resp_cap - used)
            {
                errno = ERANGE;
                return -1;
            }
            ngx_memcpy(wp, resp_name, resp_nlen);
            wp += resp_nlen;
            *wp++ = '\0';
            if (aData) {
                uint32_t vlen_be = htonl((uint32_t) value_len);

                ngx_memcpy(wp, &vlen_be, 4);
                wp += 4;
                if (stored.value != NULL && value_len != 0) {
                    ngx_memcpy(wp, stored.value, value_len);
                }
                wp += value_len;
            }
        }
        /* Advance past this name and its NUL terminator. */
        lp += full_nlen + 1;
    }

    return (ssize_t) (wp - resp);
}

/*
 *
 * WHAT: Handles kXR_fattrList by calling listxattr(path, NULL, 0) for path-based
 *       operations or flistxattr(fd, NULL, 0) for open-file-handle operations to
 *       query the size of all attribute names stored on the filesystem, then reads
 *       the full NUL-separated name string into a buffer. Filters entries to only
 *       those prefixed with BRIX_FATTR_XKEY_PFX (the user namespace prefix used by
 *       nginx-xrootd), stripping the 5-byte prefix from returned names so clients see
 *       bare attribute keys. When kXR_fa_aData flag is set, also reads each filtered
 *       attribute's value via getxattr/fgetxattr and appends it to the response.
 *
 * WHY: XRootD fattrList returns all user-space extended attributes on a file;
 *       nginx-xrootd uses only the user namespace prefixed with "user." so filtering
 *       ensures only managed attributes are visible. The two-phase list (query size
 *       then read) prevents over-allocation. ENOTSUP/EOPNOTSUPP handled gracefully —
 *       filesystems without xattr support return empty response rather than error.
 *       Thread safety: operates only on provided ctx, c, pool and local stack variables.
 *
 * HOW: Recurse dispatch → two-phase read (fattr_list_read_names) → build
 *       (fattr_list_build) → send. Each stage is a small helper; this body is the
 *       straight-line composition. */
ngx_int_t fattr_list(brix_ctx_t *ctx, ngx_connection_t *c,
                    brix_vfs_ctx_t *vctx, const char *path, int fd,
                    int options) {
    int                aData = (options & kXR_fa_aData);
    ngx_int_t          recurse_rc = NGX_OK;
    fattr_list_read_t  rd;
    size_t             resp_cap;
    ssize_t            resp_len;
    u_char            *resp;

    /* Directory + recurse flag → take the subtree-walk path instead. */
    if (fattr_list_try_recurse(ctx, c, vctx, path, options, &recurse_rc)) {
        return recurse_rc;
    }

    rd = fattr_list_read_names(ctx, c, vctx, path, fd);
    if (rd.done) {
        return rd.rc;
    }

    /* Keep response memory bounded. The builder accounts exact decoded values
     * and rejects the whole request before an entry would cross this cap. */
    resp_cap = BRIX_ROOT_FATTR_RESP_CAP;
    resp = ngx_palloc(c->pool, resp_cap);
    if (resp == NULL) {
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        return brix_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    resp_len = fattr_list_build(c->pool, vctx, path, fd, aData, rd.raw,
        rd.actual, resp, resp_cap);
    if (resp_len < 0) {
        int build_errno = errno;

        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        if (build_errno == ERANGE || build_errno == E2BIG) {
            return brix_send_error(ctx, c, kXR_ArgTooLong,
                                   "fattr list response too large");
        }
        return brix_send_error(ctx, c, kXR_FSError, "fattr list failed");
    }

    BRIX_OP_OK(ctx, BRIX_OP_FATTR);
    if (resp_len == 0) {
        return brix_send_ok(ctx, c, NULL, 0);
    }
    return brix_send_ok(ctx, c, resp, (uint32_t) resp_len);
}
