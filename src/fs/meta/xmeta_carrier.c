/*
 * fs/meta/xmeta_carrier.c — xattr-preferred / sidecar-fallback persistence
 * for the unified metadata record. See xmeta_carrier.h for the contract.
 */

#include "xmeta_carrier.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compose the sidecar object key "<key>.cinfo" into out[cap]. 0 / -1. */
static int
xmeta_sidecar_key(const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s%s", key, BRIX_XMETA_SIDECAR_SUFFIX);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* "the value cannot ride in an xattr here" — fall back, don't fail */
static int
xmeta_xattr_unfit(int err)
{
    return err == E2BIG || err == ERANGE || err == ENOSPC || err == ENOTSUP
#ifdef EOPNOTSUPP
           /* phase74-fp: ENOTSUP == EOPNOTSUPP on Linux so the operands are
            * equivalent HERE, but POSIX allows them to differ — the second
            * test is deliberate portability, not a typo. */
           || err == EOPNOTSUPP  /* NOLINT(misc-redundant-expression) */
#endif
           ;
}

/* ---- sidecar carrier ------------------------------------------------------ */

static ngx_int_t
xmeta_sidecar_write(brix_sd_instance_t *store, const char *key,
    const uint8_t *buf, size_t len)
{
    char                ck[PATH_MAX];
    brix_sd_staged_t *st;
    int                 err = 0;

    if (store->driver->staged_open == NULL
        || store->driver->staged_write == NULL
        || store->driver->staged_commit == NULL)
    {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (xmeta_sidecar_key(key, ck, sizeof(ck)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    /* SECURITY: the "<key>.cinfo" sidecar leaks cache residency (block-present
     * bitmap), size and mtime. 0600 (not 0644) so a mapped low-priv uid cannot
     * read another user's cache metadata from the svc-owned store. */
    st = store->driver->staged_open(store, ck, 0600, &err);
    if (st == NULL) {
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    if (store->driver->staged_write(st, buf, len, 0) != (ssize_t) len) {
        int e = errno;

        if (store->driver->staged_abort != NULL) {
            store->driver->staged_abort(st);
        }
        errno = e ? e : EIO;
        return NGX_ERROR;
    }
    if (store->driver->staged_commit(st, 0) != NGX_OK) {
        return NGX_ERROR;                          /* errno from the driver */
    }
    return NGX_OK;
}

/* ---- Close an open sidecar object, preserving errno ----
 *
 * WHAT: Releases the driver object and, when the driver returned a heap-shell
 * wrapper, frees that too. errno is saved and restored so a preceding read
 * failure's errno survives this best-effort cleanup.
 *
 * WHY: The read loop sets the caller-visible errno before tearing the object
 * down (see the original inline ordering), and close/free may clobber errno.
 * Centralising the close keeps that ordering guarantee in one place and drops
 * the thrice-repeated close+heap_shell idiom.
 *
 * HOW:
 *   1. Snapshot errno.
 *   2. Call the driver close, then free the heap shell if present.
 *   3. Restore the snapshot.
 */
static void
xmeta_obj_close(brix_sd_instance_t *store, brix_sd_obj_t *obj)
{
    int saved = errno;

    store->driver->close(obj);
    if (obj->heap_shell) { free(obj); }
    errno = saved;
}

/* ---- Ensure the read buffer has room for one more pread chunk ----
 *
 * WHAT: When the buffer is full (got == *capp), doubles the capacity (seeding
 * an empty buffer at 64 KiB) via realloc. Returns 0 on success (buffer may have
 * moved); -1 on allocation failure, in which case the old buffer is freed and
 * *bufp is set to NULL so the caller must not free it again.
 *
 * WHY: Isolates the grow-on-demand branch out of the read loop so the loop body
 * stays flat, and makes the "free + NULL on failure" ownership rule explicit.
 *
 * HOW:
 *   1. If not yet full, return 0 unchanged.
 *   2. Compute the next capacity and realloc.
 *   3. On failure free the old block, NULL the handle, return -1.
 *   4. On success publish the grown block and capacity, return 0.
 */
static int
xmeta_read_buf_ensure(uint8_t **bufp, size_t *capp, size_t got)
{
    uint8_t *grown;
    size_t   cap = *capp;

    if (got != cap) {
        return 0;
    }
    cap = cap ? cap * 2 : 64 * 1024;
    grown = realloc(*bufp, cap);
    if (grown == NULL) {
        free(*bufp);
        *bufp = NULL;
        return -1;
    }
    *bufp = grown;
    *capp = cap;
    return 0;
}

/* ---- Slurp a whole open object into a fresh malloc buffer ----
 *
 * WHAT: Reads the object to EOF into a growing malloc buffer. On a non-empty
 * object sets out and out_len and returns NGX_OK; on a zero-length object returns
 * NGX_DECLINED; on error returns NGX_ERROR with errno set (ENOMEM for growth
 * failure, else the pread errno or EIO). Owns nothing it returns on the error
 * and declined paths (buffer freed).
 *
 * WHY: Pulls the buffer-management loop out of xmeta_sidecar_read so that
 * function reduces to open + slurp + close, each independently reviewable. The
 * object itself is left open for the caller to close.
 *
 * HOW:
 *   1. Loop: grow the buffer when full, then pread at the current offset.
 *   2. On a short/negative read, free and return NGX_ERROR with errno.
 *   3. On EOF (n == 0) break.
 *   4. Empty object -> free and NGX_DECLINED; otherwise publish and NGX_OK.
 */
static ngx_int_t
xmeta_obj_slurp(brix_sd_instance_t *store, brix_sd_obj_t *obj,
    uint8_t **out, size_t *out_len)
{
    uint8_t *buf = NULL;
    size_t   cap = 0, got = 0;

    for ( ;; ) {
        ssize_t n;

        if (xmeta_read_buf_ensure(&buf, &cap, got) != 0) {
            errno = ENOMEM;
            return NGX_ERROR;
        }
        n = store->driver->pread(obj, buf + got, cap - got, (off_t) got);
        if (n < 0) {
            int e = errno;

            free(buf);
            errno = e ? e : EIO;
            return NGX_ERROR;
        }
        if (n == 0) {
            break;
        }
        got += (size_t) n;
    }
    if (got == 0) {
        free(buf);
        return NGX_DECLINED;
    }
    *out = buf;
    *out_len = got;
    return NGX_OK;
}

/* Read the whole sidecar object into a malloc'd buffer. NGX_OK/DECLINED/ERROR. */
static ngx_int_t
xmeta_sidecar_read(brix_sd_instance_t *store, const char *key,
    uint8_t **out, size_t *out_len)
{
    char             ck[PATH_MAX];
    brix_sd_obj_t *obj;
    ngx_int_t        rc;
    int              err = 0;

    if (store->driver->open == NULL || store->driver->pread == NULL) {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (xmeta_sidecar_key(key, ck, sizeof(ck)) != 0) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }
    obj = store->driver->open(store, ck, BRIX_SD_O_READ, 0, &err);
    if (obj == NULL) {
        return (err == ENOENT) ? NGX_DECLINED : NGX_ERROR;
    }

    rc = xmeta_obj_slurp(store, obj, out, out_len);
    xmeta_obj_close(store, obj);
    return rc;
}

/* ---- public API ------------------------------------------------------------ */

ngx_int_t
brix_xmeta_save(brix_sd_instance_t *store, const char *key,
    const brix_xmeta_t *m)
{
    uint8_t  *buf = NULL;
    size_t    len = 0;
    ngx_int_t rc;

    if (store == NULL || store->driver == NULL || key == NULL || m == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (brix_xmeta_encode(m, &buf, &len) != BRIX_XMETA_OK) {
        return NGX_ERROR;
    }

    if (store->driver->setxattr != NULL && len <= BRIX_XMETA_XATTR_MAX) {
        rc = store->driver->setxattr(store, key, BRIX_XMETA_XATTR_NAME,
                                     buf, len, 0);
        if (rc == NGX_OK) {
            free(buf);
            return NGX_OK;
        }
        if (!xmeta_xattr_unfit(errno)) {
            int e = errno;

            free(buf);
            errno = e;
            return NGX_ERROR;
        }
        /* doesn't fit / not supported here: ride the sidecar instead */
    }

    rc = xmeta_sidecar_write(store, key, buf, len);
    free(buf);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }
    /* exactly one carrier: drop any (stale or just-outgrown) xattr copy */
    if (store->driver->removexattr != NULL) {
        (void) store->driver->removexattr(store, key,
                                          BRIX_XMETA_XATTR_NAME);
    }
    return NGX_OK;
}

/* ---- Map a brix_xmeta_decode() result to the load API's ngx_int_t ----
 *
 * WHAT: Translates the decode status: BRIX_XMETA_OK -> NGX_OK, BRIX_XMETA_FOREIGN
 * -> NGX_DECLINED (a valid record owned by someone else), anything else ->
 * NGX_ERROR.
 *
 * WHY: The identical three-way mapping is applied to both the xattr and sidecar
 * decode results; factoring it keeps the two carriers in lock-step and out of the
 * caller's branch count.
 *
 * HOW:
 *   1. OK -> NGX_OK.
 *   2. FOREIGN -> NGX_DECLINED, else NGX_ERROR.
 */
static ngx_int_t
xmeta_decode_rc(int drc)
{
    if (drc == BRIX_XMETA_OK) {
        return NGX_OK;
    }
    return (drc == BRIX_XMETA_FOREIGN) ? NGX_DECLINED : NGX_ERROR;
}

/* ---- Attempt the xattr carrier for a load ----
 *
 * WHAT: When the driver exposes getxattr, reads the metadata xattr into a
 * fixed-size buffer and decodes it. Returns NGX_OK/NGX_DECLINED/NGX_ERROR when
 * the xattr settled the outcome, or NGX_AGAIN when the record is simply absent
 * / the xattr is unsupported here and the caller should fall through to the
 * sidecar. NGX_ERROR carries errno (ENOMEM on alloc failure, else the getxattr
 * errno for a genuine failure).
 *
 * WHY: The xattr-first branch is the bulk of brix_xmeta_load's complexity;
 * isolating it lets the public function read as "try xattr, else sidecar". The
 * NGX_AGAIN sentinel is internal only (the public API never returns it) and
 * distinguishes "not here, keep looking" from a hard decode/IO result.
 *
 * HOW:
 *   1. No getxattr -> NGX_AGAIN (fall through).
 *   2. Alloc the max-size buffer; ENOMEM -> NGX_ERROR.
 *   3. getxattr; on a positive length decode and map the result.
 *   4. On a real error (not absent/unsupported) -> NGX_ERROR.
 *   5. Otherwise (absent / unsupported) -> NGX_AGAIN.
 */
static ngx_int_t
xmeta_load_from_xattr(brix_sd_instance_t *store, const char *key,
    brix_xmeta_t *m)
{
    uint8_t *buf;
    ssize_t  n;
    int      drc;

    if (store->driver->getxattr == NULL) {
        return NGX_AGAIN;
    }
    buf = malloc(BRIX_XMETA_XATTR_MAX);
    if (buf == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    n = store->driver->getxattr(store, key, BRIX_XMETA_XATTR_NAME,
                                buf, BRIX_XMETA_XATTR_MAX);
    if (n > 0) {
        drc = brix_xmeta_decode(buf, (size_t) n, m);
        free(buf);
        return xmeta_decode_rc(drc);
    }
    free(buf);
    if (n < 0 && errno != ENODATA && errno != ENOENT
#ifdef ENOATTR
        && errno != ENOATTR
#endif
        && !xmeta_xattr_unfit(errno))
    {
        return NGX_ERROR;
    }
    return NGX_AGAIN;   /* absent / unsupported: try the sidecar */
}

ngx_int_t
brix_xmeta_load(brix_sd_instance_t *store, const char *key,
    brix_xmeta_t *m)
{
    uint8_t  *buf;
    size_t    len = 0;
    ngx_int_t rc;
    int       drc;

    if (store == NULL || store->driver == NULL || key == NULL || m == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* xattr carrier first */
    rc = xmeta_load_from_xattr(store, key, m);
    if (rc != NGX_AGAIN) {
        return rc;
    }

    rc = xmeta_sidecar_read(store, key, &buf, &len);
    if (rc != NGX_OK) {
        return rc;
    }
    drc = brix_xmeta_decode(buf, len, m);
    free(buf);
    return xmeta_decode_rc(drc);
}

ngx_int_t
brix_xmeta_remove(brix_sd_instance_t *store, const char *key)
{
    char ck[PATH_MAX];

    if (store == NULL || store->driver == NULL || key == NULL) {
        return NGX_OK;
    }
    if (store->driver->removexattr != NULL) {
        (void) store->driver->removexattr(store, key,
                                          BRIX_XMETA_XATTR_NAME);
    }
    if (store->driver->unlink != NULL
        && xmeta_sidecar_key(key, ck, sizeof(ck)) == 0)
    {
        (void) store->driver->unlink(store, ck, 0);   /* best-effort */
    }
    return NGX_OK;
}
