/*
 * sd_ceph.h — Ceph/RADOS storage driver (phase-60, basic librados backend).
 *
 * WHAT: Declares (a) the always-available, dependency-free LFN->object-key
 *       helpers (lexical path normalization + key composition + a stable inode
 *       hash) that map a confined logical path to a flat RADOS object id, and
 *       (b) — only when the build found librados (XROOTD_HAVE_CEPH) — the
 *       per-export config struct the config layer fills and the driver vtable
 *       symbol the registry registers.
 *
 * WHY:  RADOS is a flat object store: there is no kernel fd, no directory tree,
 *       no atomic rename. The driver therefore needs a deterministic, injective,
 *       escape-proof LFN->oid map (two logical paths must never alias one object,
 *       and no `..` may address an object outside the export's key prefix). That
 *       map is pure string logic with no librados/nginx dependency, so it is
 *       split out here and unit-tested standalone (sd_ceph_unittest.c) without a
 *       live cluster.
 *
 * HOW:  The helpers are plain C (libc only). The driver body (sd_ceph.c, under
 *       #if XROOTD_HAVE_CEPH) implements the worker-safe raw byte ops and the
 *       minimal namespace ops against raw librados (rados_read/write/trunc/stat/
 *       remove). libradosstriper interop with stock XrdCeph (ADR-3) is a follow-on.
 */
#ifndef XROOTD_SD_CEPH_H
#define XROOTD_SD_CEPH_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * sd_ceph_normalize — lexically canonicalize a logical path into `out` (cap
 * bytes): collapse repeated/leading/trailing '/', drop "." components, and apply
 * ".." by popping the previous component. A ".." that would climb above the root
 * is rejected (escape attempt). The result always begins with '/', has no "."/
 * ".." and no "//", and never ends in '/' (except the bare root "/"). Returns 0,
 * or -1 with errno set (EINVAL on bad args / escape, ENAMETOOLONG if it won't
 * fit). This is the single point that guarantees the LFN->oid map is injective
 * and prefix-confined.
 */
int sd_ceph_normalize(const char *lfn, char *out, size_t cap);

/*
 * sd_ceph_key — compose the RADOS object id for a logical path:
 * `key_prefix` followed by sd_ceph_normalize(lfn). Returns 0, or -1 (errno) when
 * normalization fails or the result won't fit in `out` (cap bytes).
 */
int sd_ceph_key(const char *key_prefix, const char *lfn, char *out, size_t cap);

/*
 * sd_ceph_ino — a stable 64-bit inode number synthesized from an object id
 * (FNV-1a). RADOS objects have no inode; protocol stat needs a stable, distinct
 * value per object, and a content-independent hash of the (already-confined) oid
 * provides one.
 */
uint64_t sd_ceph_ino(const char *oid);

#if XROOTD_HAVE_CEPH
#include "../sd.h"

/*
 * Per-export Ceph configuration, populated by the config/merge layer and passed
 * to the driver's init() as driver_conf. Strings are borrowed for the duration
 * of init() (the driver copies what it keeps). `pool` is required; the rest take
 * the documented defaults when NULL.
 */
typedef struct {
    const char *conf_file;    /* ceph.conf (default /etc/ceph/ceph.conf) */
    const char *pool;         /* RADOS pool (REQUIRED)                    */
    const char *user;         /* ceph user (default client.admin)        */
    const char *keyring;      /* optional keyring path override           */
    const char *key_prefix;   /* object-key prefix (default "")           */
} xrootd_sd_ceph_conf_t;

/* The Ceph driver descriptor (defined in sd_ceph.c, registered by sd_registry.c). */
extern const xrootd_sd_driver_t xrootd_sd_ceph_driver;

#endif /* XROOTD_HAVE_CEPH */

#endif /* XROOTD_SD_CEPH_H */
