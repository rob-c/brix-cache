/* gc.h — mark-and-sweep over an on-disk OCI registry store (phase-104
 * D15.3 offline pass, D15.5 background pass).
 *
 * WHAT: one complete pass over a `brix_oci_registry_root`: every digest any
 *       manifest in any repository names is LIVE, and everything else the
 *       request handlers deliberately left behind — unreferenced CAS blobs,
 *       layer marks a manifest DELETE orphaned, referrer descriptors whose
 *       referrer is gone — is removed.
 * WHY:  a manifest DELETE cannot see the other repositories holding the same
 *       layer, and content addressing means "the same" is byte-identical, so
 *       a handler is the wrong place to prove a blob is dead. That is a
 *       whole-store question, and this is where it is answered. It is asked
 *       from two places — `brixoci gc` offline and the registry's own
 *       maintenance timer — which is why the kernel lives in shared/ and
 *       neither caller owns it.
 * HOW:  mark first, sweep second, so a blob is always judged against the
 *       COMPLETE live set. Liveness comes from manifest BODIES, never from
 *       the layer marks: a mark is per-repository bookkeeping written at
 *       upload seal, so it can outlive the manifest that justified it (that
 *       is one of the things swept here) and can never be the authority.
 *       Every name unlinked has first parsed as a digest under the shared
 *       grammar, so the pass cannot be talked into removing a path the
 *       registry did not build. libc + shared/oci/digest.h only: no ngx, no
 *       CLI, no allocation beyond the live set.
 */
#ifndef BRIX_OCI_GC_H
#define BRIX_OCI_GC_H

#include <stddef.h>
#include <time.h>

/* The live set: NUL-terminated digest hexes, open-addressed. Content
 * addressing means the key IS uniformly distributed already, so the table
 * needs no hashing subtleties — only a bound on its load factor. Slots are
 * sized for the widest registered algorithm rather than for whichever one
 * the store happens to hold, because a table that fits sha256 exactly would
 * silently keep sha512 keys by their first 64 characters. */
typedef struct {
    char   *slots;              /* cap × (hex + NUL), "" = free */
    size_t  cap;
    size_t  n;
} brix_oci_gc_set_t;

typedef struct {
    unsigned long long bytes;   /* reclaimed (or reclaimable, dry_run) */
    unsigned long      repos;
    unsigned long      manifests;
    unsigned long      blobs_live;
    unsigned long      blobs_swept;
    unsigned long      blobs_young;   /* unreferenced but inside the grace */
    unsigned long      marks;         /* stale repos/<n>/layers/<hex>      */
    unsigned long      refs;          /* dangling referrer descriptors     */
} brix_oci_gc_stats_t;

/* One pass over one store. The caller fills `root`, `grace` and `dry_run`
 * and zeroes the rest; everything below the line is the pass's own state,
 * and `st` is what it has to say when it returns. */
typedef struct {
    const char          *root;      /* the registry store root             */
    long                 grace;     /* seconds an unreferenced blob is kept */
    int                  dry_run;   /* count what would go; remove nothing */

    time_t               now;
    brix_oci_gc_set_t    live;
    brix_oci_gc_stats_t  st;
    char                 err[512];
} brix_oci_gc_t;

#define BRIX_OCI_GC_OK      0
/* The walk could not see the whole store; nothing was swept, because a
 * sweep run on an incomplete live set deletes blobs that are in use. */
#define BRIX_OCI_GC_EIO   (-1)
/* `root` does not look like a registry store. `brixoci gc /` is a plausible
 * typo, and this is what stops it. */
#define BRIX_OCI_GC_EROOT (-2)

/* Run the pass: root check, mark walk, blob sweep, live set released. `err`
 * (may be NULL) receives the reason on a non-OK return. The grace window
 * protects the gap between a blob upload sealing and the manifest that names
 * it arriving; a pass is otherwise safe to run against a live registry. */
int brix_oci_gc_run(brix_oci_gc_t *c, char *err, size_t errlen);

#endif /* BRIX_OCI_GC_H */
