/*
 * sd_ram_staged.c — the RAM store's write, listing and xattr surface.
 *
 * WHAT: the staged fill spine (the store's only writer), prefix directory
 *       iteration, and the in-memory user.* xattrs that carry the cache's
 *       cinfo record in XATTR meta mode.
 * WHY:  sd_ram.c owns the read path and the vtable; keeping the mutating half
 *       beside it — not inside it — holds both files inside the size cap and
 *       puts the whole "how does a byte get in" story in one place.
 * HOW:  a fill builds a DETACHED entry and publishes it under one mutex hold,
 *       so a reader never observes a half-filled object under its final name.
 *       The declared size is RESERVED at open, which is what makes the cap a
 *       guarantee rather than a race: two concurrent fills cannot both be told
 *       there is room for the same bytes.
 */

#include "sd_ram_internal.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---- staged fill ---------------------------------------------------------- */

brix_sd_staged_t *
brix_sd_ram_staged_open(brix_sd_instance_t *inst, const char *final_path,
    mode_t mode, off_t declared_size, int *err_out)
{
    sd_ram_state_t        *st = inst->state;
    brix_sd_staged_t      *sh;
    sd_ram_staged_state_t *ss;
    int                    err = 0;

    (void) mode;
    if (!brix_sd_ram_path_ok(final_path) || declared_size < 0) {
        err = EINVAL;
    } else if (st->capacity < (uint64_t) declared_size) {
        /* The object can never fit, whatever is evicted first — say so now
         * rather than after pulling it across the network. */
        err = ENOSPC;
    }
    if (err != 0) {
        if (err_out != NULL) { *err_out = err; }
        errno = err;
        return NULL;
    }

    sh = calloc(1, sizeof(*sh) + sizeof(*ss));
    if (sh == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        errno = ENOMEM;
        return NULL;
    }
    ss = (sd_ram_staged_state_t *) (sh + 1);

    (void) pthread_mutex_lock(&st->mtx);
    if (brix_sd_ram_make_room(st, (uint64_t) declared_size) != NGX_OK) {
        err = ENOSPC;                    /* full of live objects: degrade, §16 */
    } else {
        ss->ent = brix_sd_ram_ent_new(st, final_path, 0);
        if (ss->ent == NULL) {
            err = errno;
        } else {
            ss->reserved  = (uint64_t) declared_size;
            st->reserved += ss->reserved;
        }
    }
    (void) pthread_mutex_unlock(&st->mtx);

    if (err != 0) {
        free(sh);
        if (err_out != NULL) { *err_out = err; }
        errno = err;
        return NULL;
    }
    sh->inst  = inst;
    sh->state = ss;
    return sh;
}

ssize_t
brix_sd_ram_staged_write(brix_sd_staged_t *sh, const void *buf, size_t len,
    off_t off)
{
    sd_ram_state_t        *st = sh->inst->state;
    sd_ram_staged_state_t *ss = sh->state;
    uint64_t               end;
    ngx_int_t              rc;

    if (off < 0) {
        errno = EINVAL;
        return -1;
    }
    end = (uint64_t) off + (uint64_t) len;
    if (end > (uint64_t) SSIZE_MAX) {
        errno = EFBIG;
        return -1;
    }

    (void) pthread_mutex_lock(&st->mtx);
    rc = brix_sd_ram_ent_grow(st, ss->ent, (size_t) end, &ss->reserved);
    if (rc == NGX_OK) {
        memcpy(ss->ent->data + off, buf, len);
        if (end > (uint64_t) ss->ent->size) {
            ss->ent->size = (size_t) end;
        }
    }
    (void) pthread_mutex_unlock(&st->mtx);

    return (rc == NGX_OK) ? (ssize_t) len : -1;   /* errno set by grow */
}

/* Release this fill's reservation. Caller holds st->mtx. */
static void
sd_ram_staged_unreserve(sd_ram_state_t *st, sd_ram_staged_state_t *ss)
{
    st->reserved -= (st->reserved >= ss->reserved) ? ss->reserved : st->reserved;
    ss->reserved = 0;
}

/* Evaluate `pre` against whatever currently holds the fill's final name.
 * Caller holds st->mtx. Returns 0 when the publish may proceed, else the errno
 * to refuse with. Every refusal is storage-decided (the compare and the publish
 * happen under one hold), so pre->atomic is set on refusals too. */
static int
sd_ram_staged_precond(sd_ram_state_t *st, const char *path,
    brix_sd_precond_t *pre)
{
    sd_ram_ent_t *cur;

    if (pre == NULL || pre->kind == BRIX_SD_PRECOND_NONE) {
        return 0;
    }
    pre->atomic = 1;
    cur = brix_sd_ram_find(st, path);

    if (pre->kind == BRIX_SD_PRECOND_ABSENT) {
        return (cur != NULL) ? EEXIST : 0;
    }
    if (cur == NULL) {
        return ENOENT;
    }
    if (brix_sd_precond_eval_stat(pre, (off_t) cur->size, cur->mtime) != 0) {
        return errno;                    /* ECANCELED, or ENOTSUP for a kind
                                          * this evaluator does not know */
    }
    return 0;
}

ngx_int_t
brix_sd_ram_staged_commit(brix_sd_staged_t *sh, brix_sd_precond_t *pre)
{
    sd_ram_state_t        *st = sh->inst->state;
    sd_ram_staged_state_t *ss = sh->state;
    int                    err;

    (void) pthread_mutex_lock(&st->mtx);
    err = sd_ram_staged_precond(st, ss->ent->path, pre);
    if (err == 0) {
        ss->ent->mtime = time(NULL);
        brix_sd_ram_insert(st, ss->ent);     /* charges ent->cap to st->used */
        ss->ent = NULL;
    }
    sd_ram_staged_unreserve(st, ss);
    if (err != 0) {
        brix_sd_ram_unref(st, ss->ent);      /* never charged: drop the bytes */
        ss->ent = NULL;
    }
    (void) pthread_mutex_unlock(&st->mtx);

    free(sh);
    if (err != 0) {
        errno = err;
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
brix_sd_ram_staged_abort(brix_sd_staged_t *sh)
{
    sd_ram_state_t        *st;
    sd_ram_staged_state_t *ss;

    if (sh == NULL) {
        return;
    }
    st = sh->inst->state;
    ss = sh->state;

    (void) pthread_mutex_lock(&st->mtx);
    sd_ram_staged_unreserve(st, ss);
    brix_sd_ram_unref(st, ss->ent);          /* never charged to st->used */
    ss->ent = NULL;
    (void) pthread_mutex_unlock(&st->mtx);

    free(sh);
}

/* ---- directory iteration (a key-prefix namespace) ------------------------- */

/*
 * A listing is a SNAPSHOT taken under the lock: the names are copied out at
 * opendir and readdir walks the copy. The alternative — holding a cursor into
 * live hash chains across readdir calls — would either hold the mutex for the
 * whole walk (blocking every fill) or follow a chain a concurrent evict had
 * already freed. The cache's reaper scans and evicts in the same pass, so that
 * is not a hypothetical race.
 */
typedef struct {
    char   **names;      /* owned, each strdup'd  */
    u_char  *types;      /* DT_REG / DT_DIR       */
    size_t   n;
    size_t   i;
} sd_ram_dir_t;

/* Does `path` name a direct child of directory `dir` (which has no trailing
 * '/')? Writes the child component into *out when so. */
static int
sd_ram_child_of(const char *path, const char *dir, size_t dirlen,
    const char **out)
{
    const char *rest;

    if (strncmp(path, dir, dirlen) != 0 || path[dirlen] != '/') {
        return 0;
    }
    rest = path + dirlen + 1;
    return (*rest != '\0') ? ((*out = rest), 1) : 0;
}

/* Append one child name (up to its next '/') to the snapshot. Returns NGX_OK,
 * or NGX_ERROR with errno ENOMEM. */
static ngx_int_t
sd_ram_dir_add(sd_ram_dir_t *d, const char *child, size_t cap)
{
    const char *slash = strchr(child, '/');
    size_t      len   = (slash != NULL) ? (size_t) (slash - child)
                                        : strlen(child);
    size_t      i;
    char       *name;

    if (len == 0 || len >= 256 || d->n >= cap) {
        return NGX_OK;                   /* unnameable or snapshot full */
    }
    for (i = 0; i < d->n; i++) {         /* one entry per intermediate dir */
        if (strncmp(d->names[i], child, len) == 0
            && d->names[i][len] == '\0')
        {
            return NGX_OK;
        }
    }
    name = strndup(child, len);
    if (name == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    d->names[d->n] = name;
    d->types[d->n] = (slash != NULL) ? DT_DIR : DT_REG;
    d->n++;
    return NGX_OK;
}

/* Fill the snapshot with every direct child of `path`. Caller holds st->mtx. */
static ngx_int_t
sd_ram_dir_snapshot(sd_ram_state_t *st, const char *path, sd_ram_dir_t *d,
    size_t cap)
{
    size_t dirlen = strlen(path);
    size_t b;

    while (dirlen > 1 && path[dirlen - 1] == '/') {
        dirlen--;                        /* "/a/" and "/a" list the same */
    }
    if (dirlen == 1) {
        dirlen = 0;                      /* the root: every path is a child */
    }
    for (b = 0; b < st->nbuckets; b++) {
        sd_ram_ent_t *e;

        for (e = st->buckets[b]; e != NULL; e = e->hnext) {
            const char *child = NULL;

            if (!sd_ram_child_of(e->path, path, dirlen, &child)) {
                continue;
            }
            if (sd_ram_dir_add(d, child, cap) != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }
    return NGX_OK;
}

static void
sd_ram_dir_free(sd_ram_dir_t *d)
{
    size_t i;

    for (i = 0; i < d->n; i++) {
        free(d->names[i]);
    }
    free(d->names);
    free(d->types);
    free(d);
}

brix_sd_dir_t *
brix_sd_ram_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_ram_state_t *st = inst->state;
    brix_sd_dir_t  *dir;
    sd_ram_dir_t   *d;
    size_t          cap;
    int             err = 0;

    if (!brix_sd_ram_path_ok(path)) {
        if (err_out != NULL) { *err_out = EINVAL; }
        errno = EINVAL;
        return NULL;
    }
    dir = ngx_calloc(sizeof(*dir), inst->log);
    d   = calloc(1, sizeof(*d));
    if (dir == NULL || d == NULL) {
        if (dir != NULL) { ngx_free(dir); }
        free(d);
        if (err_out != NULL) { *err_out = ENOMEM; }
        errno = ENOMEM;
        return NULL;
    }

    (void) pthread_mutex_lock(&st->mtx);
    cap = st->count;
    d->names = calloc(cap + 1, sizeof(*d->names));
    d->types = calloc(cap + 1, sizeof(*d->types));
    if (d->names == NULL || d->types == NULL) {
        err = ENOMEM;
    } else if (sd_ram_dir_snapshot(st, path, d, cap) != NGX_OK) {
        err = ENOMEM;
    }
    (void) pthread_mutex_unlock(&st->mtx);

    if (err != 0) {
        sd_ram_dir_free(d);
        ngx_free(dir);
        if (err_out != NULL) { *err_out = err; }
        errno = err;
        return NULL;
    }
    dir->inst  = inst;
    dir->state = d;
    return dir;
}

ngx_int_t
brix_sd_ram_readdir(brix_sd_dir_t *dir, brix_sd_dirent_t *out)
{
    sd_ram_dir_t *d = dir->state;

    if (d->i >= d->n) {
        return NGX_DONE;
    }
    ngx_cpystrn((u_char *) out->name, (u_char *) d->names[d->i],
                sizeof(out->name));
    out->d_type = d->types[d->i];
    d->i++;
    return NGX_OK;
}

ngx_int_t
brix_sd_ram_closedir(brix_sd_dir_t *dir)
{
    sd_ram_dir_free(dir->state);
    ngx_free(dir);
    return NGX_OK;
}

/* ---- xattrs (the cinfo carrier in XATTR meta mode) ------------------------ */

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

    if (x == NULL) {
        x = calloc(1, sizeof(*x));
        if (x == NULL) {
            free(nv);
            return ENOMEM;
        }
        x->name = strdup(name);
        if (x->name == NULL) {
            free(x);
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
