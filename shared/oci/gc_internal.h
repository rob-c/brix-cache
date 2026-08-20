/*
 * gc_internal.h — split contract for the registry GC pass (phase-104 D15.5):
 * gc.c drives (live set, path helpers, root check, repository walk),
 * gc_mark.c marks from manifest bodies and sweeps a repository's own
 * bookkeeping, gc_sweep.c sweeps the CAS. Not a public API.
 */
#ifndef BRIX_OCI_GC_INTERNAL_H
#define BRIX_OCI_GC_INTERNAL_H

#include "oci/gc.h"

#include <sys/types.h>

/* A manifest body is JSON describing an image; the registry refuses larger
 * ones on the wire (BRIX_OCI_MANIFEST_MAX), so a body above this cap did not
 * come from the push surface and is not read. */
#define BRIX_OCI_GC_MANIFEST_MAX  (4 * 1024 * 1024)

/* Repository names carry '/', so `repos/` is a tree rather than a flat list.
 * The cap bounds the walk regardless of what the directory actually holds. */
#define BRIX_OCI_GC_DEPTH_MAX     12

/* Insert / test a digest hex. add: 1 inserted, 0 already present, -1 OOM. */
int  brix_oci_gc_set_add(brix_oci_gc_set_t *s, const char *hex);
int  brix_oci_gc_set_has(const brix_oci_gc_set_t *s, const char *hex);
void brix_oci_gc_set_free(brix_oci_gc_set_t *s);

/* snprintf into a PATH_MAX-class buffer with the overflow check applied
 * once, here, instead of at every call site. 0 ok / -1 truncated. */
int brix_oci_gc_fmt(char *out, size_t outsz, const char *fmt, ...);

/* Is `path` a directory in its own right — never a symlink to one? */
int brix_oci_gc_isdir(const char *path);

/* The registered algorithm whose hex `name` is, by the shared digest
 * grammar — or NULL when the name is not a digest at all. WIDTH is what
 * decides: 64 hex chars is sha256 and 128 is sha512, so a bare store
 * filename is never ambiguous, which is why the layer marks and the live
 * set stay flat while the CAS itself is keyed by algorithm.
 *
 * This is also what separates a manifest body from its `.meta`/`.subject`
 * sidecars, and what makes every name this pass unlinks one it has already
 * validated. */
const char *brix_oci_gc_hex_alg(const char *name);

/* brix_oci_gc_hex_alg() as a predicate, for the walkers that only need to
 * know whether the name is a digest. */
int brix_oci_gc_is_hex(const char *name);

/* Is this an ordinary file, and old enough that no push in flight can still
 * be about to name it? `size` receives its size when it is. */
int brix_oci_gc_reapable(brix_oci_gc_t *c, const char *path, off_t *size);

/* Remove one validated path, or account for what a dry run would remove. */
void brix_oci_gc_reap(brix_oci_gc_t *c, const char *path, off_t size,
                      unsigned long *counter);

/* Mark, then sweep, one repository named `rel` (relative to `<root>/repos`):
 * every digest its manifests name enters c->live, its stale layer marks and
 * dangling referrer descriptors are removed. 0 ok / -1 with c->err set. */
int brix_oci_gc_repo(brix_oci_gc_t *c, const char *rel);

/* Unlink every blob the walk did not mark and that has aged past the grace
 * window. 0 ok / -1 with c->err set. */
int brix_oci_gc_sweep_blobs(brix_oci_gc_t *c);

#endif /* BRIX_OCI_GC_INTERNAL_H */
