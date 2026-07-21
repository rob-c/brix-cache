#ifndef BRIX_SD_CEPH_COMPAT_H
#define BRIX_SD_CEPH_COMPAT_H

/*
 * sd_ceph_compat.h — pure libradosstriper on-RADOS layout helpers, matching stock
 * XrdCeph byte-for-byte (see docs spec §1.0). A striper file <name> is striped
 * across RADOS objects "<name>.%016x"; the FIRST stripe ".0000000000000000"
 * carries the layout/size/user xattrs. Stock `readdir` enumerates the pool, keeps
 * oids ending in that 17-char suffix, and strips it to recover the (physical)
 * file name. These helpers are libc-only so they unit-test without a cluster.
 */

#include <stddef.h>

/* The first-stripe suffix (17 chars incl. the dot), as stock writes/filters it. */
#define BRIX_CEPH_FIRST_STRIPE_SUFFIX ".0000000000000000"

/* oid of the first stripe for a striper object name: name + the suffix. 0 / -1. */
int sd_ceph_first_stripe(const char *name, char *oid, size_t cap);

/* 1 iff oid ends in the first-stripe suffix (the one-per-file marker), else 0. */
int sd_ceph_oid_is_first_stripe(const char *oid);

/* Strip the first-stripe suffix from a first-stripe oid → the physical name (pfn).
 * 0, or -1 if oid is not a first stripe (or overflow). */
int sd_ceph_oid_to_pfn(const char *oid, char *pfn, size_t cap);

/* 1 iff oid is a NON-first striper data stripe — it carries a ".%016x" suffix
 * (dot + 16 lowercase-hex digits) whose stripe index is not zero. These are the
 * objects a catalog enumeration must SKIP: the first stripe (".0000000000000000")
 * already represents the whole file. A flat object with no 16-hex stripe suffix
 * returns 0 (it IS its own catalog entry). */
int sd_ceph_oid_is_stripe_data(const char *oid);

/* Classify a normalized logical `path` as a one-level child of the normalized
 * directory `dir` (both "/"-rooted, as sd_ceph_normalize emits). On a match the
 * child's name (the first component after `dir`) is copied NUL-terminated into
 * `name`. Returns 0 = not a child (also: path == dir, or the name would not fit
 * `cap` — an unrepresentable entry is skipped, matching the enumerator's
 * unrepresentable-pfn policy), 1 = file child (no further components),
 * 2 = directory child (more components follow — a synthetic subdirectory). */
int sd_ceph_path_child(const char *dir, const char *path,
                       char *name, size_t cap);

#endif /* BRIX_SD_CEPH_COMPAT_H */
