/*
 * gcas.c — phase-87 G13: cross-repo dedup of verified CAS objects.
 *
 * WHAT: after a cvmfs-cas-verified fill commits, hand the committed key and
 *       its canonical repo-agnostic alias ("/.gcas/<2hex>/<hex><sfx>") to the
 *       cache store driver's dedup_publish slot; after an eviction, hand the
 *       alias to dedup_gc so a last-link canonical is reaped.
 *
 * WHY:  a stratum serving N repos stores byte-identical CAS objects once per
 *       repo. The verify step proves key-hash == content-hash, so identity at
 *       the byte layer is safe to collapse — while keys, cinfo, authz and
 *       origin fetches stay strictly per-repo (no cross-repo leak surface).
 *
 * HOW:  phase-88 W1 moved the dedup MECHANICS below the SD seam: posix stores
 *       run the hardlink farm (sd_posix_dedup.c, st_nlink is the refcount),
 *       pblock stores fold byte-identical blobs via F10 refs (dedup_gc NULL —
 *       eviction is refcount-driven). This file keeps what is protocol
 *       knowledge, not storage knowledge: the CVMFS classify gate and the
 *       canonical-name grammar. Every step stays best-effort — any failure
 *       leaves plain, correct per-repo copies.
 */

#include "gcas.h"

#include "protocols/cvmfs/classify.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

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

void
brix_gcas_publish(brix_cstore_t *cs, const char *key)
{
    char rel[PATH_MAX];

    if (cs == NULL || !cs->gcas || cs->store == NULL
        || cs->store->driver->dedup_publish == NULL
        || brix_gcas_canonical_rel(key, rel, sizeof(rel)) != 0)
    {
        return;
    }

    if (cs->store->driver->dedup_publish(cs->store, key, rel) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, cs->log, errno,
            "gcas: dedup publish failed for \"%s\"%s", key,
            errno == ENOTSUP
                ? " — the store is not armed for dedup (pblock: opts dedup=1)"
                : "");
    }
}

void
brix_gcas_evict_gc(brix_cstore_t *cs, const char *key)
{
    char rel[PATH_MAX];

    if (cs == NULL || !cs->gcas || cs->store == NULL
        || cs->store->driver->dedup_gc == NULL
        || brix_gcas_canonical_rel(key, rel, sizeof(rel)) != 0)
    {
        return;   /* a /.gcas/... key itself classifies REJECT — no-op; a
                   * refcounting store (dedup_gc NULL) needs no alias GC */
    }

    (void) cs->store->driver->dedup_gc(cs->store, rel);
}
