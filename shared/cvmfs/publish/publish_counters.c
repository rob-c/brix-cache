/* publish_counters.c — subtree_* statistics aggregation (phase-96 S8).
 *
 * A catalog's subtree_<x> counter is the sum of (self_<x> + subtree_<x>) over
 * its DIRECT nested children; fsck and the official client read them as the
 * whole-subtree totals. Finalize order is deepest-first, so children touched
 * by this publish carry fresh totals on their pub_cat_t; untouched children
 * are fetched from CAS and read once (publish cost stays proportional to the
 * touched subtree plus its direct nested children). */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* unlink & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"
#include "cvmfs/object/object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *const pub_counter_names[PUB_NCOUNTERS] = {
    "regular", "chunked", "chunks", "dir", "symlink",
    "nested", "file_size", "chunked_size", "xattr",
};

typedef struct {
    char         mount[PUB_PATH_MAX];
    cvmfs_hash_t hash;
} pc_child_t;

typedef struct {
    pc_child_t *v;
    size_t      n, cap;
    int         bad;
} pc_list_t;

static void pc_collect_cb(const char *path, const char *sha1_hex, uint64_t size,
                          void *ud) {
    pc_list_t *l = ud;
    (void) size;
    if (l->bad) return;
    if (l->n == l->cap) {
        size_t ncap = l->cap ? l->cap * 2 : 8;
        pc_child_t *nv = realloc(l->v, ncap * sizeof(*nv));
        if (nv == NULL) {
            l->bad = 1;
            return;
        }
        l->v = nv;
        l->cap = ncap;
    }
    pc_child_t *c = &l->v[l->n];
    snprintf(c->mount, sizeof(c->mount), "%s", path);
    if (cvmfs_hash_parse(sha1_hex, strlen(sha1_hex), &c->hash) != 0) {
        l->bad = 1;
        return;
    }
    l->n++;
}

/* Totals of a child finalized in THIS publish, if any. */
static const int64_t *pc_open_totals(pub_ctx_t *px, const char *mount) {
    for (pub_cat_t *c = px->cats; c != NULL; c = c->next)
        if (c->has_tot && strcmp(c->mount, mount) == 0) return c->tot;
    return NULL;
}

/* Totals (self+subtree) of an untouched child, read from its CAS catalog. */
static int pc_cas_totals(pub_ctx_t *px, const pc_child_t *ch, int64_t out[]) {
    size_t plen = 0;
    unsigned char *plain = pub_fetch_catalog(px, &ch->hash, &plen);
    if (plain == NULL) return -1;
    char tmp[PUB_PATH_MAX + 32];
    snprintf(tmp, sizeof(tmp), "%s/cnt.%d.db", px->workdir, px->seq++);
    int rc = pub_spit(tmp, plain, plen, 0);
    free(plain);
    cvmfs_catalog_t *rd = rc == 0 ? cvmfs_catalog_open(tmp) : NULL;
    if (rd == NULL) {
        unlink(tmp);
        return pub_fail(px, "cannot open nested catalog %s", ch->mount);
    }
    for (int i = 0; i < PUB_NCOUNTERS; i++) {
        char name[48];
        int64_t v = 0;
        out[i] = 0;
        snprintf(name, sizeof(name), "self_%s", pub_counter_names[i]);
        if (cvmfs_catalog_counter(rd, name, &v) == 1) out[i] += v;
        snprintf(name, sizeof(name), "subtree_%s", pub_counter_names[i]);
        v = 0;
        if (cvmfs_catalog_counter(rd, name, &v) == 1) out[i] += v;
    }
    cvmfs_catalog_close(rd);
    unlink(tmp);
    return 0;
}

int pub_subtree_counters(pub_ctx_t *px, pub_cat_t *c) {
    pc_list_t l = { NULL, 0, 0, 0 };
    if (cvmfs_catwriter_list_nested(c->w, pc_collect_cb, &l) < 0 || l.bad) {
        free(l.v);
        return pub_fail(px, "cannot list nested children of %s",
                        c->mount[0] ? c->mount : "(root)");
    }
    int64_t sub[PUB_NCOUNTERS] = { 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < l.n; i++) {
        const int64_t *open_tot = pc_open_totals(px, l.v[i].mount);
        int64_t cas_tot[PUB_NCOUNTERS];
        if (open_tot == NULL) {
            rc = pc_cas_totals(px, &l.v[i], cas_tot);
            open_tot = cas_tot;
        }
        for (int k = 0; rc == 0 && k < PUB_NCOUNTERS; k++) sub[k] += open_tot[k];
    }
    free(l.v);
    for (int k = 0; rc == 0 && k < PUB_NCOUNTERS; k++) {
        char name[48];
        int64_t self = 0;
        snprintf(name, sizeof(name), "subtree_%s", pub_counter_names[k]);
        if (cvmfs_catwriter_set_counter(c->w, name, sub[k]) != 0)
            rc = pub_fail(px, "cannot set %s", name);
        snprintf(name, sizeof(name), "self_%s", pub_counter_names[k]);
        if (rc == 0 && cvmfs_catwriter_get_counter(c->w, name, &self) < 0)
            rc = pub_fail(px, "cannot read %s", name);
        c->tot[k] = self + sub[k];
    }
    if (rc == 0) c->has_tot = 1;
    return rc;
}
