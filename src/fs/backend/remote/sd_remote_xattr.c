/*
 * sd_remote_xattr.c — metadata-mutation slots for the remote-origin (s3://)
 * storage driver: setxattr / removexattr (the user.<name> ↔ x-amz-meta-<name>
 * surface, the write side of the getxattr/listxattr read slots in
 * sd_remote_meta.c) and setattr (the reserved advisory unix-attr blob, so a
 * chmod / kXR_setattr over an s3:// export "sticks" and round-trips — the
 * approved advisory model, meta_advisory.h).
 *
 * S3 has NO in-place metadata edit: any write REPLACES the object's entire
 * user-metadata set via a copy-onto-self (x-amz-metadata-directive: REPLACE).
 * A single-attribute mutation must therefore READ the complete current set,
 * apply the one change, and REWRITE the whole set — otherwise every other
 * attribute (including the advisory blob) is silently dropped. Enumerating the
 * current set needs the transport's raw-header slot; without it every mutation
 * reports ENOTSUP, exactly as listxattr does (sd_remote_meta.c). The read runs
 * as the requesting user for the *_cred variants, so a deny-mode request never
 * touches the origin under the shared service credential.
 */

#include "sd_remote_internal.h"
#include "fs/backend/s3/sd_s3.h"
#include "fs/backend/meta_advisory.h"
#include "fs/backend/meta_advisory_sd.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>      /* UTIME_OMIT / UTIME_NOW */
#include <sys/xattr.h>     /* XATTR_CREATE / XATTR_REPLACE */

/* AWS caps total user metadata at 2 KiB; 32 attrs matches sd_s3_set_meta's hard
 * limit. Names/values are held bare (no "x-amz-meta-" prefix) — sd_s3_set_meta
 * lowercases and prefixes on the wire. */
#define SD_REMOTE_XA_MAX    32
#define SD_REMOTE_XA_NAME   160
#define SD_REMOTE_XA_VALUE  2048

typedef struct {
    size_t n;
    char   name [SD_REMOTE_XA_MAX][SD_REMOTE_XA_NAME];
    char   value[SD_REMOTE_XA_MAX][SD_REMOTE_XA_VALUE];
} sd_remote_meta_set;

/* Lowercase copy of a bare attribute name into dst (AWS lowercases user-meta
 * names). 0 / -1 (name too long). */
static int
sd_remote_xa_lname(const char *name, char *dst, size_t cap)
{
    size_t i, n = strlen(name);

    if (n == 0 || n >= cap) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char c = name[i];
        dst[i] = (c >= 'A' && c <= 'Z') ? (char) (c - 'A' + 'a') : c;
    }
    dst[n] = '\0';
    return 0;
}

/* Index of `lname` in the set, or -1 if absent (names are already lowercased). */
static int
sd_remote_xa_find(const sd_remote_meta_set *ms, const char *lname)
{
    size_t i;

    for (i = 0; i < ms->n; i++) {
        if (strcmp(ms->name[i], lname) == 0) {
            return (int) i;
        }
    }
    return -1;
}

/* Append one bare name=value pair (value may hold `vlen` bytes). NGX_OK, or
 * NGX_ERROR with errno E2BIG (set full) / ERANGE (name or value too long). */
static ngx_int_t
sd_remote_xa_append(sd_remote_meta_set *ms, const char *lname,
    const char *val, size_t vlen)
{
    if (ms->n >= SD_REMOTE_XA_MAX) {
        errno = E2BIG;
        return NGX_ERROR;
    }
    if (strlen(lname) >= SD_REMOTE_XA_NAME || vlen >= SD_REMOTE_XA_VALUE) {
        errno = ERANGE;
        return NGX_ERROR;
    }
    memcpy(ms->name[ms->n], lname, strlen(lname) + 1);
    memcpy(ms->value[ms->n], val, vlen);
    ms->value[ms->n][vlen] = '\0';
    ms->n++;
    return NGX_OK;
}

/* Load the object's COMPLETE current user-metadata set (every user.<name> plus
 * the reserved advisory blob, which listxattr deliberately omits) so a single
 * mutation can be rewritten whole. NGX_OK (ms filled), or NGX_ERROR with errno:
 * ENOENT (object absent / 404), ENOTSUP (transport cannot enumerate headers),
 * E2BIG (> 32 attrs), EIO otherwise. */
static ngx_int_t
sd_remote_meta_load(const brix_sd_remote_cfg_t *cfg, const char *objpath,
    const char *ak, const char *sk, const char *region, const char *session,
    sd_remote_meta_set *ms)
{
    sd_s3_open_params  p;
    char               listbuf[4096];   /* NUL-separated "user.<name>" block */
    char               errbuf[256];
    sd_s3_file        *s3;
    ssize_t            ln;
    const char        *e;

    ms->n = 0;
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);

    s3 = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (s3 == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }

    errno = 0;
    ln = sd_s3_list_meta(s3, listbuf, sizeof(listbuf), errbuf, sizeof(errbuf));
    if (ln < 0) {
        int saved = errno;
        sd_s3_close(s3);
        errno = saved ? saved : EIO;       /* ENOTSUP / ENOENT / EIO */
        return NGX_ERROR;
    }

    for (e = listbuf; (size_t) (e - listbuf) < (size_t) ln && *e != '\0'; ) {
        const char    *nm = e;
        size_t         elen = strlen(e);
        char           vbuf[SD_REMOTE_XA_VALUE];
        sd_s3_meta_buf dst = { vbuf, sizeof(vbuf) };
        ssize_t        vn;

        e += elen + 1;
        if (strncmp(nm, "user.", 5) != 0 || nm[5] == '\0') {
            continue;                       /* only the user. namespace maps */
        }
        nm += 5;
        vn = sd_s3_get_meta(s3, nm, &dst, errbuf, sizeof(errbuf));
        if (vn < 0) {
            sd_s3_close(s3);
            errno = EIO;
            return NGX_ERROR;
        }
        if (sd_remote_xa_append(ms, nm, vbuf, (size_t) vn) != NGX_OK) {
            int saved = errno;
            sd_s3_close(s3);
            errno = saved;
            return NGX_ERROR;
        }
    }

    /* The advisory blob surfaces as POSIX attrs, not a user xattr, so
     * sd_s3_list_meta skips it; fetch it explicitly to preserve it on rewrite. */
    {
        char           vbuf[SD_REMOTE_XA_VALUE];
        sd_s3_meta_buf dst = { vbuf, sizeof(vbuf) };
        ssize_t        vn = sd_s3_get_meta(s3, BRIX_META_ADVISORY_S3META, &dst,
                                           errbuf, sizeof(errbuf));

        if (vn < 0) {
            sd_s3_close(s3);
            errno = EIO;
            return NGX_ERROR;
        }
        if (vn > 0
            && sd_remote_xa_append(ms, BRIX_META_ADVISORY_S3META, vbuf,
                                   (size_t) vn) != NGX_OK)
        {
            int saved = errno;
            sd_s3_close(s3);
            errno = saved;
            return NGX_ERROR;
        }
    }

    sd_s3_close(s3);
    return NGX_OK;
}

/* Rewrite `objpath`'s user metadata to exactly the pairs in `ms` (copy-onto-self
 * REPLACE). NGX_OK / NGX_ERROR (errno set). */
static ngx_int_t
sd_remote_meta_store(const brix_sd_remote_cfg_t *cfg, const char *objpath,
    const char *ak, const char *sk, const char *region, const char *session,
    const sd_remote_meta_set *ms)
{
    sd_s3_open_params p;
    sd_s3_meta_kv     kv[SD_REMOTE_XA_MAX];
    char              errbuf[256];
    size_t            i;

    for (i = 0; i < ms->n; i++) {
        kv[i].name  = ms->name[i];
        kv[i].value = ms->value[i];
    }
    sd_remote_s3_params(cfg, objpath, &p);
    sd_remote_params_cred(&p, ak, sk, region, session);

    errno = 0;
    if (sd_s3_set_meta(&p, kv, ms->n, errbuf, sizeof(errbuf)) != 0) {
        if (errno == 0) { errno = EIO; }
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- setxattr ------------------------------------------------------------- */

/* Shared set/removexattr plumbing, run after the caller's own name/value
 * validation: derive the lowercase header name from `name5` (the xattr name
 * past "user."), compute the object key, load the current metadata set and
 * locate the attribute (*idx < 0 when absent). NGX_OK, or NGX_ERROR with
 * errno (ERANGE, or meta-load's ENOENT / ENOTSUP / EIO). */
static ngx_int_t
sd_remote_xa_open(const brix_sd_remote_cfg_t *cfg, const char *path,
    const char *name5, const char *ak, const char *sk, const char *region,
    const char *session, char *objpath, size_t objcap, char *lname,
    size_t lcap, sd_remote_meta_set *ms, int *idx)
{
    if (sd_remote_xa_lname(name5, lname, lcap) != 0) {
        errno = ERANGE;
        return NGX_ERROR;
    }

    sd_remote_s3_key(cfg, path, objpath, objcap);
    if (sd_remote_meta_load(cfg, objpath, ak, sk, region, session, ms)
        != NGX_OK)
    {
        return NGX_ERROR;                    /* ENOENT / ENOTSUP / EIO */
    }

    *idx = sd_remote_xa_find(ms, lname);
    return NGX_OK;
}

static ngx_int_t
sd_remote_setxattr_impl(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_remote_meta_set          ms;
    char                        objpath[768];
    char                        lname[SD_REMOTE_XA_NAME];
    int                         idx;

    /* Only the user. namespace maps to x-amz-meta-*; a NUL/CR/LF in the value
     * cannot ride in an HTTP header. */
    if (strncmp(name, "user.", 5) != 0 || name[5] == '\0') {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (len >= SD_REMOTE_XA_VALUE
        || memchr(val, '\0', len) != NULL
        || memchr(val, '\r', len) != NULL
        || memchr(val, '\n', len) != NULL)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }
    if (sd_remote_xa_open(cfg, path, name + 5, ak, sk, region, session,
                          objpath, sizeof(objpath), lname, sizeof(lname),
                          &ms, &idx) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (idx >= 0 && (flags & XATTR_CREATE)) {
        errno = EEXIST;
        return NGX_ERROR;
    }
    if (idx < 0 && (flags & XATTR_REPLACE)) {
        errno = ENODATA;
        return NGX_ERROR;
    }
    if (idx >= 0) {
        memcpy(ms.value[idx], val, len);
        ms.value[idx][len] = '\0';
    } else if (sd_remote_xa_append(&ms, lname, val, len) != NGX_OK) {
        return NGX_ERROR;                    /* E2BIG */
    }

    return sd_remote_meta_store(cfg, objpath, ak, sk, region, session, &ms);
}

ngx_int_t
sd_remote_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    return sd_remote_setxattr_impl(inst, path, name, val, len, flags,
                                   NULL, NULL, NULL, NULL);
}

ngx_int_t
sd_remote_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags,
    const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_setxattr_impl(inst, path, name, val, len, flags,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_setxattr_impl(inst, path, name, val, len, flags,
                                   NULL, NULL, NULL, NULL);
}

/* ---- removexattr ---------------------------------------------------------- */

static ngx_int_t
sd_remote_removexattr_impl(brix_sd_instance_t *inst, const char *path,
    const char *name,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_remote_meta_set          ms;
    char                        lname[SD_REMOTE_XA_NAME];
    char                        objpath[768];
    int                         idx;

    if (strncmp(name, "user.", 5) != 0 || name[5] == '\0') {
        errno = ENOTSUP;
        return NGX_ERROR;
    }
    if (sd_remote_xa_open(cfg, path, name + 5, ak, sk, region, session,
                          objpath, sizeof(objpath), lname, sizeof(lname),
                          &ms, &idx) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (idx < 0) {
        errno = ENODATA;                     /* attribute absent */
        return NGX_ERROR;
    }
    /* Drop the entry by moving the last one into its slot (order is immaterial
     * — S3 metadata is an unordered set). */
    ms.n--;
    if ((size_t) idx != ms.n) {
        memcpy(ms.name[idx], ms.name[ms.n], sizeof(ms.name[idx]));
        memcpy(ms.value[idx], ms.value[ms.n], sizeof(ms.value[idx]));
    }

    return sd_remote_meta_store(cfg, objpath, ak, sk, region, session, &ms);
}

ngx_int_t
sd_remote_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    return sd_remote_removexattr_impl(inst, path, name,
                                      NULL, NULL, NULL, NULL);
}

ngx_int_t
sd_remote_removexattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_removexattr_impl(inst, path, name,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_removexattr_impl(inst, path, name,
                                      NULL, NULL, NULL, NULL);
}

/* ---- setattr (advisory unix-attr blob) ------------------------------------
 *
 * WHAT: Apply chmod / kXR_setattr (mode, mtime, owner) to `path` by patching the
 *       reserved advisory blob (x-amz-meta-xrd-unixattr) that overlays stat.
 * WHY:  finding #4 — WebDAV/xrdfs chmod/setattr over an s3:// backend hit the
 *       NULL setattr slot; the VFS treated that as a no-op so the change was
 *       silently lost.
 * HOW:  Resolve the target object (the "path" file key, else the "path/" folder
 *       marker for a directory), read its full metadata set, decode+patch the
 *       advisory blob with the present fields of *attr (atime is not tracked —
 *       S3 has no atime; UTIME_OMIT skips a field, UTIME_NOW stamps wall time),
 *       and rewrite the whole set so co-existing user xattrs survive.
 */

static ngx_int_t
sd_remote_setattr_impl(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr,
    const char *ak, const char *sk, const char *region, const char *session)
{
    const brix_sd_remote_cfg_t *cfg = inst->state;
    sd_remote_meta_set          ms;
    brix_meta_advisory_t        delta;
    char                        objpath[768];
    char                        blob[SD_REMOTE_XA_VALUE];
    int                         idx;

    /* Nothing representable is success (matches the POSIX/no-op setattr
     * contract) — and it is decided BEFORE the object round-trip, so an
     * atime-only request costs no request pair. */
    if (!brix_meta_advisory_from_setattr(attr, &delta)) {
        return NGX_OK;
    }

    /* Target the file key; fall back to the "path/" directory marker. Either
     * absent -> ENOENT (never fabricate an object to hang metadata on). */
    sd_remote_s3_key(cfg, path, objpath, sizeof(objpath));
    if (sd_remote_meta_load(cfg, objpath, ak, sk, region, session, &ms)
        != NGX_OK)
    {
        if (errno != ENOENT) {
            return NGX_ERROR;                /* ENOTSUP / EIO */
        }
        sd_remote_s3_dirkey(cfg, path, objpath, sizeof(objpath));
        if (sd_remote_meta_load(cfg, objpath, ak, sk, region, session, &ms)
            != NGX_OK)
        {
            return NGX_ERROR;                /* ENOENT (neither) / ENOTSUP / EIO */
        }
    }

    idx = sd_remote_xa_find(&ms, BRIX_META_ADVISORY_S3META);
    blob[0] = '\0';
    if (idx >= 0) {
        memcpy(blob, ms.value[idx], strlen(ms.value[idx]) + 1);
    }
    if (brix_meta_advisory_patch(blob, sizeof(blob), &delta) < 0) {
        errno = EIO;
        return NGX_ERROR;
    }
    if (idx >= 0) {
        memcpy(ms.value[idx], blob, strlen(blob) + 1);
    } else if (sd_remote_xa_append(&ms, BRIX_META_ADVISORY_S3META, blob,
                                   strlen(blob)) != NGX_OK)
    {
        return NGX_ERROR;                    /* E2BIG */
    }

    return sd_remote_meta_store(cfg, objpath, ak, sk, region, session, &ms);
}

ngx_int_t
sd_remote_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr)
{
    return sd_remote_setattr_impl(inst, path, attr, NULL, NULL, NULL, NULL);
}

ngx_int_t
sd_remote_setattr_cred(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr, const brix_sd_cred_t *cred)
{
    int gate = sd_remote_cred_gate(cred);

    if (gate > 0) {
        return sd_remote_setattr_impl(inst, path, attr,
            cred->s3_ak, cred->s3_sk, cred->s3_region, cred->s3_session);
    }
    if (gate < 0) {
        errno = EACCES;
        return NGX_ERROR;
    }
    return sd_remote_setattr_impl(inst, path, attr, NULL, NULL, NULL, NULL);
}
