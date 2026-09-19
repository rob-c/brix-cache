/*
 * sd_ram_staged.c — the RAM store's write and listing surface.
 *
 * WHAT: the staged fill spine (the store's only writer) and prefix directory
 *       iteration.  The in-memory user.* xattrs that carried the cache's cinfo
 *       record alongside them are now in sd_ram_xattr.c; the cut was the size
 *       cap, and it was free — that plane touches nothing here but the entry it
 *       looks up.
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
    /* Ownership transfers INTO the snapshot; sd_ram_dir_free releases every
     * entry.
     *
     * gcc 11's -fanalyzer cannot see a symbolic-index store through a
     * parameter as an escape, so it reports `name` leaking at the return
     * below. Suppress exactly that diagnostic, at exactly its emission point. */
#pragma GCC diagnostic push
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif
    d->names[d->n] = name;
    d->types[d->n] = (slash != NULL) ? DT_DIR : DT_REG;
    d->n++;
    return NGX_OK;
#pragma GCC diagnostic pop
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

/* The finished listing snapshot for `path`, or NULL when out of memory.
 * Caller holds st->mtx. All-or-nothing: every partial allocation is released
 * here, so the caller owns either a whole snapshot or nothing — which is also
 * the shape gcc 11's -fanalyzer can follow, the arrays being allocated and
 * released inside one function rather than across the opendir/error-arm pair. */
static sd_ram_dir_t *
sd_ram_dir_build(sd_ram_state_t *st, const char *path, size_t cap)
{
    sd_ram_dir_t *d = calloc(1, sizeof(*d));

    if (d == NULL) {
        return NULL;
    }
    /* Guards kept as separate ifs: the analyzer loses track of the first
     * allocation across a compound `a == NULL || b == NULL` test. */
    d->names = calloc(cap + 1, sizeof(*d->names));
    if (d->names == NULL) {
        sd_ram_dir_free(d);
        return NULL;
    }
    d->types = calloc(cap + 1, sizeof(*d->types));
    if (d->types == NULL) {
        sd_ram_dir_free(d);
        return NULL;
    }
    if (sd_ram_dir_snapshot(st, path, d, cap) != NGX_OK) {
        sd_ram_dir_free(d);
        return NULL;
    }
    return d;
}

brix_sd_dir_t *
brix_sd_ram_opendir(brix_sd_instance_t *inst, const char *path, int *err_out)
{
    sd_ram_state_t *st = inst->state;
    brix_sd_dir_t  *dir;
    sd_ram_dir_t   *d;

    if (!brix_sd_ram_path_ok(path)) {
        if (err_out != NULL) { *err_out = EINVAL; }
        errno = EINVAL;
        return NULL;
    }
    dir = ngx_calloc(sizeof(*dir), inst->log);
    if (dir == NULL) {
        if (err_out != NULL) { *err_out = ENOMEM; }
        errno = ENOMEM;
        return NULL;
    }

    (void) pthread_mutex_lock(&st->mtx);
    d = sd_ram_dir_build(st, path, st->count);
    (void) pthread_mutex_unlock(&st->mtx);

    if (d == NULL) {
        ngx_free(dir);
        if (err_out != NULL) { *err_out = ENOMEM; }
        errno = ENOMEM;
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
