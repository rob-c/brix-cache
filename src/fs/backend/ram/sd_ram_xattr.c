/*
 * sd_ram_xattr.c — the RAM store's in-memory user.* xattrs.
 *
 * WHAT: getxattr / listxattr / setxattr / removexattr over the per-entry xattr
 *       list, and the two allocators behind them.
 * WHY:  Split out of sd_ram_staged.c, which had grown past the size cap
 *       carrying three planes. These four verbs share no state with the staged
 *       fill or the directory walk beyond the entry they look up, so the cut
 *       costs nothing: sd_ram_internal.h already declared every one of them.
 *       In XATTR meta mode this list IS the cache's cinfo record, which is why
 *       the plane is worth reading on its own.
 * HOW:  Every verb takes st->mtx for the whole lookup-and-mutate, and a node is
 *       built DETACHED (name copied, or nothing allocated at all) before it is
 *       linked, so a failed allocation never leaves a half-built xattr on an
 *       entry a reader can already see.
 */

#include "sd_ram_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Find `name` on `ent`, or NULL. Caller holds st->mtx. */
static sd_ram_xattr_t *
sd_ram_xattr_find(sd_ram_ent_t *ent, const char *name)
{
    sd_ram_xattr_t *x;

    for (x = ent->xattrs; x != NULL; x = x->next) {
        if (strcmp(x->name, name) == 0) {
            return x;
        }
    }
    return NULL;
}

ssize_t
brix_sd_ram_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap)
{
    sd_ram_state_t *st = inst->state;
    sd_ram_ent_t   *e;
    sd_ram_xattr_t *x;
    ssize_t         rc;

    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return -1;
    }
    (void) pthread_mutex_lock(&st->mtx);
    e = brix_sd_ram_find(st, path);
    x = (e != NULL) ? sd_ram_xattr_find(e, name) : NULL;
    if (x == NULL) {
        errno = (e == NULL) ? ENOENT : ENODATA;
        rc = -1;
    } else if (buf == NULL || cap == 0) {
        rc = (ssize_t) x->len;           /* size probe */
    } else if (cap < x->len) {
        errno = ERANGE;
        rc = -1;
    } else {
        memcpy(buf, x->val, x->len);
        rc = (ssize_t) x->len;
    }
    (void) pthread_mutex_unlock(&st->mtx);
    return rc;
}

ssize_t
brix_sd_ram_listxattr(brix_sd_instance_t *inst, const char *path, void *buf,
    size_t cap)
{
    sd_ram_state_t *st = inst->state;
    sd_ram_ent_t   *e;
    sd_ram_xattr_t *x;
    size_t          need = 0;
    ssize_t         rc;

    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return -1;
    }
    (void) pthread_mutex_lock(&st->mtx);
    e = brix_sd_ram_find(st, path);
    if (e == NULL) {
        errno = ENOENT;
        rc = -1;
    } else {
        for (x = e->xattrs; x != NULL; x = x->next) {
            need += strlen(x->name) + 1;
        }
        if (buf == NULL || cap == 0) {
            rc = (ssize_t) need;         /* size probe */
        } else if (cap < need) {
            errno = ERANGE;
            rc = -1;
        } else {
            char *p = buf;

            for (x = e->xattrs; x != NULL; x = x->next) {
                size_t n = strlen(x->name) + 1;

                memcpy(p, x->name, n);
                p += n;
            }
            rc = (ssize_t) need;
        }
    }
    (void) pthread_mutex_unlock(&st->mtx);
    return rc;
}

/* A DETACHED xattr node owning a copy of `name`, or NULL. All-or-nothing: a
 * half-built node is never returned, so the caller's only job is to link it. */
static sd_ram_xattr_t *
sd_ram_xattr_new(const char *name)
{
    sd_ram_xattr_t *x = calloc(1, sizeof(*x));

    if (x == NULL) {
        return NULL;
    }
    x->name = strdup(name);
    if (x->name == NULL) {
        free(x);
        return NULL;
    }
    return x;
}

/* Replace (or create) `name` on `ent` with `len` bytes of `val`. Caller holds
 * st->mtx. Returns 0, or the errno to report. */
static int
sd_ram_xattr_put(sd_ram_ent_t *ent, const char *name, const void *val,
    size_t len)
{
    sd_ram_xattr_t *x = sd_ram_xattr_find(ent, name);
    u_char         *nv = malloc(len > 0 ? len : 1);

    if (nv == NULL) {
        return ENOMEM;
    }
    memcpy(nv, val, len);

    /* Ownership of the node and of nv transfers INTO ent->xattrs;
     * brix_sd_ram_ent_free releases the whole chain.
     *
     * gcc 11's -fanalyzer cannot see a store through a parameter into a linked
     * list as an escape, so it reports both leaking at the return below.
     * Suppress exactly that diagnostic, at exactly its emission point. */
#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif
    if (x == NULL) {
        x = sd_ram_xattr_new(name);
        if (x == NULL) {
            free(nv);
            return ENOMEM;
        }
        x->next     = ent->xattrs;
        ent->xattrs = x;
    } else {
        free(x->val);
    }
    x->val = nv;
    x->len = len;
    return 0;
#pragma GCC diagnostic pop
}

ngx_int_t
brix_sd_ram_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags)
{
    sd_ram_state_t *st = inst->state;
    sd_ram_ent_t   *e;
    int             err = 0;

    (void) flags;
    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    (void) pthread_mutex_lock(&st->mtx);
    e = brix_sd_ram_find(st, path);
    err = (e == NULL) ? ENOENT : sd_ram_xattr_put(e, name, val, len);
    (void) pthread_mutex_unlock(&st->mtx);

    if (err != 0) {
        errno = err;
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_sd_ram_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name)
{
    sd_ram_state_t  *st = inst->state;
    sd_ram_ent_t    *e;
    sd_ram_xattr_t **pp;
    int              err = ENODATA;

    if (!brix_sd_ram_path_ok(path)) {
        errno = EINVAL;
        return NGX_ERROR;
    }
    (void) pthread_mutex_lock(&st->mtx);
    e = brix_sd_ram_find(st, path);
    if (e == NULL) {
        err = ENOENT;
    } else {
        for (pp = &e->xattrs; *pp != NULL; pp = &(*pp)->next) {
            sd_ram_xattr_t *x = *pp;

            if (strcmp(x->name, name) != 0) {
                continue;
            }
            *pp = x->next;
            free(x->name);
            free(x->val);
            free(x);
            err = 0;
            break;
        }
    }
    (void) pthread_mutex_unlock(&st->mtx);

    if (err != 0) {
        errno = err;
        return NGX_ERROR;
    }
    return NGX_OK;
}
