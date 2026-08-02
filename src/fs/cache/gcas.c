/*
 * gcas.c — phase-87 G13: cross-repo hardlink dedup of verified CAS objects.
 *
 * WHAT: after a cvmfs-cas-verified fill commits, bind the per-repo cache
 *       object and a canonical repo-agnostic name ("/.gcas/<2hex>/<hex><sfx>")
 *       to one inode; after an eviction, unlink the canonical once it is the
 *       last remaining name.
 * WHY:  a stratum serving N repos stores byte-identical CAS objects once per
 *       repo. The verify step proves key-hash == content-hash, so identity at
 *       the byte layer is safe to collapse — while keys, cinfo, authz and
 *       origin fetches stay strictly per-repo (no cross-repo leak surface).
 * HOW:  first appearance registers the canonical via link(2); later fills of
 *       the same hash adopt it via link-to-temp + rename(2) (atomic, open
 *       readers keep their inode). The filesystem's st_nlink is the combined
 *       refcount, so there is no bookkeeping to corrupt: losing the canonical
 *       early (e.g. LRU-reaped) only forfeits future dedup. Every path is
 *       best-effort — any failure leaves plain, correct per-repo copies.
 */

#include "gcas.h"

#include "cache_internal.h"            /* append_suffix / ensure_parent */
#include "protocols/cvmfs/classify.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int
brix_gcas_canonical_rel(const char *key, char *dst, size_t cap)
{
    int              n;
    char             sfx[2];
    cvmfs_url_info_t info;

    if (key == NULL || dst == NULL
        || cvmfs_classify_url(key, strlen(key), &info) != 0
        || info.cls != CVMFS_URL_CAS)
    {
        return -1;
    }

    sfx[0] = info.cas_suffix;   /* 0 or C/H/X/M/L/P — part of the identity */
    sfx[1] = '\0';

    n = snprintf(dst, cap, "/.gcas/%.2s/%s%s",
                 info.cas_hex, info.cas_hex + 2, sfx);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }

    return 0;
}

/* Absolute store path for a store-relative name (mirrors cstore_local_path:
 * the root may carry a trailing '/', rel always starts with one). */
static int
gcas_abs(const brix_cstore_t *cs, const char *rel, char *out, size_t cap)
{
    int         n;
    size_t      rlen;
    const char *root;

    root = brix_cstore_local_root(cs);
    if (root == NULL) {
        return -1;
    }

    rlen = strlen(root);
    while (rlen > 0 && root[rlen - 1] == '/') {
        rlen--;
    }

    n = snprintf(out, cap, "%.*s%s", (int) rlen, root, rel);
    if (n < 0 || (size_t) n >= cap) {
        return -1;
    }

    return 0;
}

/* Adopt an EXISTING canonical: swap the per-repo name onto its inode via a
 * temp link + rename (atomic, open readers keep their inode). Returns 0 when
 * publish is finished (bound, skipped or failed terminally), -1 when the
 * canonical was evicted underneath us and the caller should retry. */
static int
gcas_adopt(brix_cstore_t *cs, const char *key, const char *canon,
    const char *obj, const struct stat *cst, const struct stat *ost)
{
    char tmp[PATH_MAX];

    if (cst->st_ino == ost->st_ino) {
        return 0;                           /* already bound */
    }

    if (cst->st_size != ost->st_size) {
        /* Hash collision or a damaged canonical: never collapse
         * mismatched bytes — keep the verified per-repo copy. */
        ngx_log_error(NGX_LOG_WARN, cs->log, 0,
            "gcas: canonical size mismatch for \"%s\" "
            "(%O vs %O) — dedup skipped", key,
            (off_t) cst->st_size, (off_t) ost->st_size);
        return 0;
    }

    if (brix_cache_append_suffix(tmp, sizeof(tmp), obj, ".gclnk") != 0) {
        return 0;
    }
    unlink(tmp); /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
    if (link(canon, tmp) != 0) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
        return -1;                          /* canonical evicted underneath us */
    }
    if (rename(tmp, obj) != 0) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
        unlink(tmp); /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
        return 0;
    }

    ngx_log_error(NGX_LOG_INFO, cs->log, 0,
        "gcas: dedup \"%s\" onto canonical inode", key);
    return 0;
}

void
brix_gcas_publish(brix_cstore_t *cs, const char *key)
{
    int         attempt;
    char        rel[PATH_MAX], canon[PATH_MAX], obj[PATH_MAX];
    struct stat ost, cst;

    if (cs == NULL || !cs->gcas
        || brix_gcas_canonical_rel(key, rel, sizeof(rel)) != 0
        || gcas_abs(cs, rel, canon, sizeof(canon)) != 0
        || gcas_abs(cs, key, obj, sizeof(obj)) != 0)
    {
        return;
    }

    if (stat(obj, &ost) != 0) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
        return;                 /* committed object already gone — nothing to bind */
    }

    /* Two attempts cover the register/adopt race: attempt 1 may lose a
     * concurrent link(2) of the canonical (EEXIST) and then adopts it. */
    for (attempt = 0; attempt < 2; attempt++) {

        if (stat(canon, &cst) == 0) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
            if (gcas_adopt(cs, key, canon, obj, &cst, &ost) == 0) {
                return;
            }
            continue;           /* canonical evicted underneath us — retry */
        }

        /* Canonical absent — register this verified copy as the canonical. */
        if (brix_cache_ensure_parent(canon) != 0) {
            return;
        }
        if (link(obj, canon) == 0) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
            ngx_log_error(NGX_LOG_INFO, cs->log, 0,
                "gcas: registered canonical for \"%s\"", key);
            return;
        }
        /* EEXIST: lost the race — loop once and adopt the winner. */
    }
}

void
brix_gcas_evict_gc(brix_cstore_t *cs, const char *key)
{
    char        rel[PATH_MAX], canon[PATH_MAX];
    struct stat cst;

    if (cs == NULL || !cs->gcas
        || brix_gcas_canonical_rel(key, rel, sizeof(rel)) != 0
        || gcas_abs(cs, rel, canon, sizeof(canon)) != 0)
    {
        return;   /* a /.gcas/... key itself classifies REJECT — no-op */
    }

    if (stat(canon, &cst) != 0 || cst.st_nlink > 1) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
        return;   /* other per-repo links still hold the inode */
    }

    if (unlink(canon) == 0) { /* vfs-seam-allow: cache-store gcas hardlink farm, svc-owned domain */
        ngx_log_error(NGX_LOG_INFO, cs->log, 0,
            "gcas: reaped canonical for \"%s\" (last link)", key);
    }
}
