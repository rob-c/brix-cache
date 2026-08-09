/* _admin_part2.c — fragment 2 of admin.c (auto-split).
 * Do not compile directly; it is #included by admin.c. */
#ifndef _ADMIN_PART2_C_INC
#define _ADMIN_PART2_C_INC
#ifndef __ADMIN_C_COMPILED__
/* admin.c — Stratum-0 GC + tags over the publish engine's trust chain.
 * See admin.h; shares pub_* plumbing via publish_internal.h.
 *
 * GC is reflog-anchored mark & sweep: the keep set is decided ONLY from a
 * checksum-verified reflog, the mark set is built by walking every kept root
 * catalog through CAS-identity-verified fetches, and references are dropped
 * (reflog prune + manifest re-sign) BEFORE any file is unlinked, so a crash
 * mid-sweep leaves garbage, never dangling references. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* mkdir/unlink & friends under -std=c11 */
#endif
#include "cvmfs/publish/publish_internal.h"
#include "cvmfs/publish/admin.h"
#include "cvmfs/reflog/reflog.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---- shared context setup ------------------------------------------------ */

#endif /* __ADMIN_C_COMPILED__ */

int cvmfs_tag_add(const char *repo_dir, const char *keys_dir, const char *name,
                  const char *description, char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, repo_dir, keys_dir, err, errlen);
    if (name == NULL || name[0] == '\0' || strlen(name) >= 128)
        return pub_fail(&px, "invalid tag name%s", "");
    int rc = adm_workdir(&px, ".brix.tag.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    char hist[PUB_PATH_MAX + 16] = "";
    int have = rc == 0 ? tag_fetch_history(&px, hist, sizeof(hist)) : -1;
    if (rc == 0 && have < 0) rc = -1;
    if (rc == 0) rc = tag_row_insert(&px, hist, have == 1, name, description);
    if (rc == 0) rc = tag_store_history(&px, hist);
    if (hist[0]) unlink(hist);
    adm_close(&px);
    return rc;
}

int cvmfs_tag_list(const char *repo_dir, cvmfs_history_cb cb, void *ud,
                   char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, repo_dir, NULL, err, errlen);
    int rc = adm_workdir(&px, ".brix.tag.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    char hist[PUB_PATH_MAX + 16] = "";
    int n = -1;
    int have = rc == 0 ? tag_fetch_history(&px, hist, sizeof(hist)) : -1;
    if (have == 1) {
        n = 0;                           /* no history object yet: zero tags */
    } else if (have == 0) {
        cvmfs_history_t *h = cvmfs_history_open(hist, NULL);
        n = h != NULL ? cvmfs_history_list(h, cb, ud) : -1;
        if (h != NULL) cvmfs_history_close(h);
        if (n < 0) pub_fail(&px, "cannot enumerate history DB%s", "");
        unlink(hist);
    }
    adm_close(&px);
    return n;
}

static int tag_lookup(pub_ctx_t *px, const char *name, cvmfs_history_tag_t *out) {
    char hist[PUB_PATH_MAX + 16];
    int have = tag_fetch_history(px, hist, sizeof(hist));
    if (have < 0) return -1;
    if (have == 1) return pub_fail(px, "repository has no tags%s", "");
    cvmfs_history_t *h = cvmfs_history_open(hist, NULL);
    int got = h != NULL ? cvmfs_history_tag_get(h, name, out) : -1;
    if (h != NULL) cvmfs_history_close(h);
    unlink(hist);
    if (got == 1) return 0;
    if (got == 0) return pub_fail(px, "unknown tag %s", name);
    return pub_fail(px, "cannot read history DB%s", "");
}

/* The tagged tree comes back as a NEW catalog object: same rows, but with
 * revision/previous_revision/last_modified rewritten so the republished root
 * is self-consistent with the manifest that will carry it. */
static int tag_republish_catalog(pub_ctx_t *px, const cvmfs_hash_t *tagged,
                                 long newrev, cvmfs_hash_t *out, size_t *out_size) {
    size_t plen = 0;
    unsigned char *plain = pub_fetch_catalog(px, tagged, &plen);
    if (plain == NULL) return -1;
    char db[PUB_PATH_MAX + 32];
    snprintf(db, sizeof(db), "%s/roll.%d.db", px->workdir, px->seq++);
    int rc = pub_spit(db, plain, plen, 0);
    free(plain);
    cvmfs_catwriter_t *w = rc == 0 ? cvmfs_catwriter_open(db) : NULL;
    if (w == NULL) {
        unlink(db);
        return pub_fail(px, "cannot open tagged catalog%s", "");
    }
    char rev[32], oldhex[64];
    snprintf(rev, sizeof(rev), "%ld", newrev);
    cvmfs_hash_to_hex(&px->man.root_catalog, 0, oldhex, sizeof(oldhex));
    char now[32];
    snprintf(now, sizeof(now), "%lld", (long long) time(NULL));
    int ok = cvmfs_catwriter_set_property(w, "revision", rev) == 0
          && cvmfs_catwriter_set_property(w, "previous_revision", oldhex) == 0
          && cvmfs_catwriter_set_property(w, "last_modified", now) == 0
          && cvmfs_catwriter_commit(w) == 0;
    if (!ok) {
        unlink(db);
        return pub_fail(px, "cannot rewrite tagged catalog%s", "");
    }
    size_t len = 0;
    unsigned char *buf = pub_slurp(db, &len);
    unlink(db);
    if (buf == NULL) return pub_fail(px, "cannot read rewritten catalog%s", "");
    cvmfs_objstore_t store;
    rc = -1;
    if (cvmfs_objstore_open(&store, px->o->repo_dir) == 0) {
        rc = cvmfs_object_store(&store, buf, len, 'C', 1, out, out_size);
        cvmfs_objstore_close(&store);
    }
    free(buf);
    return rc == 0 ? 0 : pub_fail(px, "cannot store rewritten catalog%s", "");
}

int cvmfs_tag_rollback(const char *repo_dir, const char *keys_dir,
                       const char *name, long *new_revision,
                       char *err, size_t errlen) {
    cvmfs_publish_opts_t po;
    pub_ctx_t px;
    adm_init(&px, &po, repo_dir, keys_dir, err, errlen);
    int rc = adm_workdir(&px, ".brix.tag.tmp");
    if (rc == 0) rc = pub_load_and_verify(&px);
    cvmfs_history_tag_t t;
    if (rc == 0) rc = tag_lookup(&px, name, &t);
    long newrev = rc == 0 ? px.man.revision + 1 : 0;   /* NEVER rewinds */
    cvmfs_hash_t newroot;
    size_t newsize = 0;
    if (rc == 0)
        rc = tag_republish_catalog(&px, &t.root_hash, newrev, &newroot, &newsize);
    if (rc == 0) rc = pub_swap_manifest(&px, &newroot, newsize, newrev);
    if (rc == 0 && new_revision != NULL) *new_revision = newrev;
    adm_close(&px);
    return rc;
}
#endif /* _ADMIN_PART2_C_INC */
