/*
 * scan_drift.h — namespace↔catalog reconciliation set (D2 "object-store fsck").
 *
 * WHAT: a pure, ngx-free key→size set seeded from the backend's physical object
 *       catalog; the namespace walk is then streamed against it to classify each
 *       logical path (in-both / size-mismatch / namespace-only) and, afterward,
 *       to surface catalog keys never matched (orphan objects with no namespace
 *       entry).
 * WHY:  this is the algorithmic heart of `drift` — isolating it from the VFS /
 *       driver makes it unit-testable (scan_unittest.c) and keeps peak memory at
 *       O(catalog): the catalog side is held; the namespace side streams.
 * HOW:  open-addressing hash map (linear probe, power-of-two capacity); add()
 *       seeds the catalog, match() marks + classifies a namespace key, orphans()
 *       iterates the unmarked remainder.
 */
#ifndef XROOTD_SCAN_DRIFT_H
#define XROOTD_SCAN_DRIFT_H

#include <stddef.h>
#include <stdint.h>

typedef struct xrootd_scan_driftset_s xrootd_scan_driftset_t;

typedef enum {
    XROOTD_DRIFT_NAMESPACE_ONLY = 0, /* logical path with no backing object     */
    XROOTD_DRIFT_IN_BOTH,            /* present both sides, sizes equal          */
    XROOTD_DRIFT_SIZE_MISMATCH       /* present both sides, sizes differ         */
} xrootd_scan_drift_class_t;

/* Create a set sized for ~`expected` catalog keys (rounded up to a power of two
 * with headroom). NULL on OOM. */
xrootd_scan_driftset_t *xrootd_scan_driftset_create(size_t expected);
void xrootd_scan_driftset_free(xrootd_scan_driftset_t *s);

/* Seed one catalog object (key + size). A repeated key updates its size.
 * 0 ok, -1 on OOM (grow failure) or an over-long key. */
int xrootd_scan_driftset_add(xrootd_scan_driftset_t *s, const char *key,
                             int64_t size);

/* Classify a namespace key against the catalog and mark it seen. When the key is
 * in the catalog, *cat_size (may be NULL) is set to the catalog's recorded size. */
xrootd_scan_drift_class_t xrootd_scan_driftset_match(xrootd_scan_driftset_t *s,
                                                     const char *key,
                                                     int64_t ns_size,
                                                     int64_t *cat_size);

/* Invoke cb for every catalog key that match() never marked (orphan objects). */
typedef void (*xrootd_scan_orphan_cb)(void *ctx, const char *key, int64_t size);
void xrootd_scan_driftset_orphans(xrootd_scan_driftset_t *s,
                                  xrootd_scan_orphan_cb cb, void *ctx);

#endif /* XROOTD_SCAN_DRIFT_H */
