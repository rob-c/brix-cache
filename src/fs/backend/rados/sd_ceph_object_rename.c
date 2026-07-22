/*
 * sd_ceph_object_rename.c — Ceph/RADOS driver: the rename vtable slot.
 *
 * WHAT: The copy+delete rename path (phase-89 §B.2 / ADR-5) split out of
 *       sd_ceph_object.c (file-size guard): the bare-oid existence/layout probe,
 *       the layout-aware object remove, the chunked byte copy, the striped and
 *       flat xattr-copy legs, the absent-source classifier, the destination
 *       prep, the copy+size-verify, and the sd_ceph_rename orchestrator.
 *
 * WHY:  Rename is the single largest self-contained concern in the object TU —
 *       a non-atomic copy+delete with its own probe/remove/copy machinery that
 *       nothing else in the driver shares. Isolating it keeps every file under
 *       the source-size guard while preserving byte-for-byte behaviour.
 *
 * HOW:  The private struct definitions and the cross-TU helper/op declarations
 *       come from sd_ceph_internal.h (the child-prefix probe callback it reuses
 *       is defined in sd_ceph_object.c and declared there). The whole body is
 *       gated on BRIX_HAVE_CEPH, exactly like the driver it was split from.
 */
#include "sd_ceph.h"
#include "sd_ceph_compat.h"   /* pure striper-layout helpers (catalog enumeration) */

#include <errno.h>
#include <string.h>

#include "sd_ceph_internal.h"

#if BRIX_HAVE_CEPH

#include <rados/librados.h>
#include "sd_ceph_striper.h"   /* libradosstriper read path (stock XrdCeph layout) */
#include <time.h>

/* ---- rename (copy + delete; phase-89 §B.2 / ADR-5) ----------------------- */

/* Chunk size for the rename copy loop (matches the striper object-size class). */
#define SD_CEPH_COPY_CHUNK (4u * 1024 * 1024)

/* sd_ceph_path_probe_t / sd_ceph_probe_oid — existence/layout probe for a
 * bare oid (no open request): striper view first (a striped object must be
 * copied through the striper to reassemble), then flat. 0 on success (present
 * or cleanly absent), negative errno on a hard stat error. */
typedef struct {
    int      present;
    int      striped;
    uint64_t size;
} sd_ceph_path_probe_t;

static int
sd_ceph_probe_oid(sd_ceph_state_t *st, const char *oid,
    sd_ceph_path_probe_t *pr)
{
    uint64_t size = 0;
    time_t   mtime = 0;
    int      rc;

    ngx_memzero(pr, sizeof(*pr));

#if defined(BRIX_HAVE_RADOSSTRIPER)
    {
        rados_striper_t s = sd_ceph_striper(st);

        if (s != NULL && sd_ceph_striper_stat(s, oid, &size, &mtime) == 0) {
            pr->present = 1;
            pr->striped = 1;
            pr->size    = size;
            return 0;
        }
    }
#endif
    rc = rados_stat(st->ioctx, oid, &size, &mtime);
    if (rc == 0) {
        pr->present = 1;
        pr->size    = size;
        return 0;
    }
    return (rc == -ENOENT) ? 0 : rc;
}

/* sd_ceph_remove_oid — remove an object through the layout it was found in. */
static int
sd_ceph_remove_oid(sd_ceph_state_t *st, const char *oid, int striped)
{
#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (striped) {
        rados_striper_t s = sd_ceph_striper(st);

        return (s != NULL) ? sd_ceph_striper_remove(s, oid) : -EIO;
    }
#else
    (void) striped;
#endif
    return rados_remove(st->ioctx, oid);
}

/* sd_ceph_copy_bytes — chunked byte copy src → dst. A striped source is read
 * AND written through the striper so the destination keeps the stock-XrdCeph
 * layout; a flat source copies flat. An empty source is created flat (the
 * caller forces striped=0 for size 0 — a zero-length striper write would not
 * materialize the first stripe). 0 or negative errno. */
static int
sd_ceph_copy_bytes(sd_ceph_state_t *st, const char *src, int striped,
    uint64_t size, const char *dst)
{
    char     *buf;
    uint64_t  off = 0;

#if !defined(BRIX_HAVE_RADOSSTRIPER)
    (void) striped;
#endif

    if (size == 0) {
        return rados_write_full(st->ioctx, dst, "", 0);
    }

    buf = malloc(SD_CEPH_COPY_CHUNK);
    if (buf == NULL) {
        return -ENOMEM;
    }

    while (off < size) {
        size_t  want = (size - off < SD_CEPH_COPY_CHUNK)
                       ? (size_t) (size - off) : SD_CEPH_COPY_CHUNK;
        ssize_t n;
        ssize_t wrc;

#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (striped) {
            rados_striper_t s = sd_ceph_striper(st);

            if (s == NULL) {
                free(buf);
                return -EIO;
            }
            n = sd_ceph_striper_read(s, src, buf, want, off);
            if (n > 0) {
                wrc = sd_ceph_striper_write(s, dst, buf, (size_t) n, off);
            } else {
                wrc = 0;
            }
        } else
#endif
        {
            n = rados_read(st->ioctx, src, buf, want, off);
            wrc = (n > 0) ? rados_write(st->ioctx, dst, buf, (size_t) n, off)
                          : 0;
        }

        if (n < 0) {
            free(buf);
            return (int) n;
        }
        if (n == 0) {
            free(buf);
            return -EIO;                       /* source shrank mid-copy */
        }
        if (wrc < 0) {
            free(buf);
            return (int) wrc;
        }
        off += (uint64_t) n;
    }

    free(buf);
    return 0;
}

#if defined(BRIX_HAVE_RADOSSTRIPER)
/* sd_ceph_copy_xattrs_striped — the striped-source leg of the xattr copy:
 * list the striper object's names, then get/set each one. Striper-internal
 * "striper.*" layout attrs are never copied — the destination's own write path
 * stamps its layout. 0 or negative errno. */
static int
sd_ceph_copy_xattrs_striped(sd_ceph_state_t *st, const char *src,
    const char *dst, int dst_striped)
{
    rados_striper_t s = sd_ceph_striper(st);
    char           *names;
    char           *val;
    ssize_t         total;
    ssize_t         used = 0;
    int             rc = 0;

    if (s == NULL) {
        return -EIO;
    }
    names = malloc(SD_CEPH_XATTR_MAX);
    val   = malloc(SD_CEPH_XATTR_MAX);
    if (names == NULL || val == NULL) {
        free(names);
        free(val);
        return -ENOMEM;
    }
    total = sd_ceph_striper_listxattr(s, src, names, SD_CEPH_XATTR_MAX);
    if (total < 0) {
        free(names);
        free(val);
        return (int) total;
    }
    while (rc == 0 && used < total) {
        const char *nm = names + used;
        ssize_t     vlen;

        used += (ssize_t) strlen(nm) + 1;
        if (strncmp(nm, "striper.", 8) == 0) {
            continue;                      /* layout attrs: never copied */
        }
        vlen = sd_ceph_striper_getxattr(s, src, nm, val,
                                        SD_CEPH_XATTR_MAX);
        if (vlen < 0) {
            rc = (int) vlen;
            break;
        }
        rc = dst_striped
             ? sd_ceph_striper_setxattr(s, dst, nm, val, (size_t) vlen)
             : rados_setxattr(st->ioctx, dst, nm, val, (size_t) vlen);
    }
    free(names);
    free(val);
    return rc;
}
#endif

/* sd_ceph_copy_xattrs_plain — the flat-object leg of the xattr copy: walk the
 * source's xattr iterator and stamp each pair onto the destination (striper
 * or flat, per dst_striped). 0 or negative errno. */
static int
sd_ceph_copy_xattrs_plain(sd_ceph_state_t *st, const char *src,
    const char *dst, int dst_striped)
{
    rados_xattrs_iter_t it;
    int                 rc;

    rc = rados_getxattrs(st->ioctx, src, &it);
    if (rc < 0) {
        return rc;
    }
    for (;;) {
        const char *nm = NULL;
        const char *vv = NULL;
        size_t      vlen = 0;

        rc = rados_getxattrs_next(it, &nm, &vv, &vlen);
        if (rc < 0 || nm == NULL) {
            break;
        }
#if defined(BRIX_HAVE_RADOSSTRIPER)
        if (dst_striped) {
            rados_striper_t s = sd_ceph_striper(st);

            rc = (s != NULL)
                 ? sd_ceph_striper_setxattr(s, dst, nm, vv, vlen) : -EIO;
        } else
#endif
        {
            rc = rados_setxattr(st->ioctx, dst, nm, vv, vlen);
        }
        if (rc < 0) {
            break;
        }
    }
    rados_getxattrs_end(it);
#if !defined(BRIX_HAVE_RADOSSTRIPER)
    (void) dst_striped;
#endif
    return (rc < 0) ? rc : 0;
}

/* sd_ceph_copy_xattrs — carry the object xattrs across the copy (the cache
 * cinfo/meta/checksum-at-rest records must survive a rename). Dispatches on
 * the source's layout to the striped or plain leg above. Values are bounded
 * by SD_CEPH_XATTR_MAX (the driver's existing xattr value bound). 0 or
 * negative errno. */
static int
sd_ceph_copy_xattrs(sd_ceph_state_t *st, const char *src, int src_striped,
    const char *dst, int dst_striped)
{
#if defined(BRIX_HAVE_RADOSSTRIPER)
    if (src_striped) {
        return sd_ceph_copy_xattrs_striped(st, src, dst, dst_striped);
    }
#else
    (void) src_striped;
#endif
    return sd_ceph_copy_xattrs_plain(st, src, dst, dst_striped);
}

/* sd_ceph_rename_missing_src — classify a rename whose source object is
 * absent. A populated synthetic-directory source is EISDIR (no collection
 * rename on a flat namespace), a bare miss is ENOENT. Always NGX_ERROR with
 * errno set. */
static ngx_int_t
sd_ceph_rename_missing_src(brix_sd_instance_t *inst, const char *src)
{
    char                  norm[1024];
    sd_ceph_child_probe_t c;

    errno = ENOENT;
    if (sd_ceph_normalize(src, norm, sizeof(norm)) == 0) {
        c.dir   = norm;
        c.found = 0;
        if (sd_ceph_enumerate(inst, 0, sd_ceph_child_probe_cb, &c)
                == NGX_OK && c.found)
        {
            errno = EISDIR;
        }
    }
    return NGX_ERROR;
}

/* sd_ceph_rename_prep_dst — probe the destination oid and clear the way:
 * honour noreplace (EEXIST) and remove a pre-existing destination object.
 * NGX_OK or NGX_ERROR with errno set. */
static ngx_int_t
sd_ceph_rename_prep_dst(sd_ceph_state_t *st, const char *dm, int noreplace)
{
    sd_ceph_path_probe_t dp;
    int                  rc;

    rc = sd_ceph_probe_oid(st, dm, &dp);
    if (rc < 0) {
        errno = -rc;
        return NGX_ERROR;
    }
    if (dp.present && noreplace) {
        errno = EEXIST;
        return NGX_ERROR;
    }
    if (dp.present) {
        rc = sd_ceph_remove_oid(st, dm, dp.striped);
        if (rc < 0) {
            errno = -rc;
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* sd_ceph_rename_copy_verify — land the destination's bytes AND xattrs, then
 * size-verify it against the source probe. 0 or negative errno (the caller
 * cleans up the partial destination on failure). */
static int
sd_ceph_rename_copy_verify(sd_ceph_state_t *st, const char *so,
    const char *dm, const sd_ceph_path_probe_t *sp, int dst_striped)
{
    int rc;

    rc = sd_ceph_copy_bytes(st, so, dst_striped, sp->size, dm);
    if (rc == 0) {
        rc = sd_ceph_copy_xattrs(st, so, sp->striped, dm, dst_striped);
    }
    if (rc == 0) {
        sd_ceph_path_probe_t vp;

        rc = sd_ceph_probe_oid(st, dm, &vp);
        if (rc == 0 && (!vp.present || vp.size != sp->size)) {
            rc = -EIO;                         /* verify: dst must hold src's bytes */
        }
    }
    return rc;
}

/* sd_ceph_rename — copy + delete on the flat namespace (phase-89 §B.2).
 * NON-ATOMIC by design (the driver honestly does not advertise
 * CAP_HARD_RENAME — same posture as the other object backends): the source is
 * removed only after the destination's bytes AND xattrs landed and a size
 * verify passed, so a mid-copy failure leaves the source intact (the partial
 * destination is cleaned up best-effort). `noreplace` is honoured by a probe
 * (racy by nature on an object store — documented). Directory rename is
 * refused (EISDIR): a flat namespace has no atomic prefix move, and a
 * recursive key rewrite is out of scope (ADR-5). */
ngx_int_t
sd_ceph_rename(brix_sd_instance_t *inst, const char *src, const char *dst,
    int noreplace)
{
    sd_ceph_state_t     *st = inst->state;
    char                 so[1024];
    char                 dm[1024];
    sd_ceph_path_probe_t sp;
    int                  dst_striped;
    int                  rc;

    if (sd_ceph_key(st->key_prefix, src, so, sizeof(so)) != 0
        || sd_ceph_key(st->key_prefix, dst, dm, sizeof(dm)) != 0)
    {
        return NGX_ERROR;
    }
    if (strcmp(so, dm) == 0) {
        return NGX_OK;                         /* same object — nothing to do */
    }

    rc = sd_ceph_probe_oid(st, so, &sp);
    if (rc < 0) {
        errno = -rc;
        return NGX_ERROR;
    }
    if (!sp.present) {
        return sd_ceph_rename_missing_src(inst, src);
    }

    if (sd_ceph_rename_prep_dst(st, dm, noreplace) != NGX_OK) {
        return NGX_ERROR;
    }

    dst_striped = (sp.striped && sp.size > 0);
    rc = sd_ceph_rename_copy_verify(st, so, dm, &sp, dst_striped);
    if (rc < 0) {
        (void) sd_ceph_remove_oid(st, dm, dst_striped);  /* best-effort cleanup */
        errno = -rc;
        return NGX_ERROR;
    }

    rc = sd_ceph_remove_oid(st, so, sp.striped);
    if (rc < 0) {
        errno = -rc;                           /* dst intact; src survived too */
        return NGX_ERROR;
    }
    return NGX_OK;
}

#endif /* BRIX_HAVE_CEPH */
