/*
 * sd_frm_arc_extract.c — restore one confined dataset member from its archive.
 * Owns archive indexing, lost-sidecar rebuilding and failed-copy cleanup;
 * composition and sidecar publication remain in sd_frm_arc_store.c.
 */
#include "sd_frm_arc_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- extract ------------------------------------------------------------- */

typedef struct {
    const char       *want;
    brix_zip_entry_t  e;
    int               found;
    int               rebuild;      /* no sidecar: collect every entry */
    brix_zip_entry_t *all;
    unsigned          n, cap;
} arc_find_t;

static int
arc_find_cb(void *ud, const brix_zip_entry_t *e)
{
    arc_find_t *f = ud;

    if (!f->found && strcmp(e->name, f->want) == 0) {
        f->e = *e;
        f->found = 1;
    }
    if (!f->rebuild) {
        return f->found;                /* stop as soon as the member is known */
    }
    if (f->n == f->cap) {
        unsigned          ncap = f->cap ? f->cap * 2 : 64;
        brix_zip_entry_t *grown = realloc(f->all, ncap * sizeof(*grown));

        if (grown == NULL) {
            f->rebuild = 0;             /* keep serving; just do not rebuild */
            return f->found;
        }
        f->all = grown;
        f->cap = ncap;
    }
    f->all[f->n++] = *e;
    return 0;
}

static int
arc_copy_member(arc_ctx_t *c, const arc_key_t *k, int afd, const brix_zip_entry_t *e)
{
    int dst = c->inner->create_online(c->ictx, k->key, 0644);
    int rc;

    if (dst < 0) {
        return -1;
    }
    rc = brix_zip_extract(afd, e, dst);
    if (close(dst) != 0) {
        rc = -1;
    }
    if (rc != 0) {
        int err = errno;

        (void) c->inner->purge(c->ictx, k->key);
        ARC_LOG(c, NGX_LOG_ERR, err, "brix: tape archive \"%s\": extracting member \"%s\" failed",
                k->ds, k->member);
        errno = err ? err : EIO;
    }
    return rc;
}

int
arc_extract(arc_ctx_t *c, const arc_key_t *k)
{
    char       akey[PATH_MAX], archive[PATH_MAX];
    arc_find_t f;
    unsigned   skipped = 0;
    int        afd, rc;

    if (arc_archive_key(k, akey, sizeof(akey)) != 0
        || frm_online_path(c->base, akey, archive, sizeof(archive)) != 0)
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    afd = open(archive, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (afd < 0) {
        /* The inner adapter said the archive is online, yet its buffer copy is
         * not openable: name it — a silent -1 surfaces as a bare "recall failed". */
        ARC_LOG(c, NGX_LOG_ERR, errno, "brix: tape archive \"%s\": online copy unreadable", k->ds);
        return -1;
    }
    memset(&f, 0, sizeof(f));
    f.want = k->member;
    f.rebuild = !arc_sealed(c, k->ds);
    rc = brix_zip_index(afd, arc_find_cb, &f, &skipped);
    if (rc != 0) {
        ARC_LOG(c, NGX_LOG_ERR, errno, "brix: tape archive \"%s\": not a readable zip container", k->ds);
    }
    if (skipped != 0) {
        ARC_LOG(c, NGX_LOG_WARN, 0, "brix: tape archive \"%s\": skipped %ud unsafe member name(s)",
                k->ds, skipped);
    }
    if (rc == 0 && f.rebuild && f.n > 0 && arc_sidecar_write(c, k->ds, f.all, f.n) != 0) {
        ARC_LOG(c, NGX_LOG_WARN, errno, "brix: tape archive \"%s\": index sidecar rebuild failed", k->ds);
    }
    free(f.all);
    if (rc == 0 && !f.found) {
        errno = ENOENT;
        rc = -1;
    }
    if (rc == 0) {
        rc = arc_copy_member(c, k, afd, &f.e);
    }
    close(afd);
    return rc;
}

