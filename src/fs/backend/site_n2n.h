#ifndef XROOTD_SITE_N2N_H
#define XROOTD_SITE_N2N_H

/*
 * site_n2n.h — pluggable, tunable site name-translation (LFN ↔ physical name).
 *
 * WHAT: A pure (libc-only) translation from a logical path (the wire LFN, export-
 *       relative, leading slash) to the PHYSICAL name a backend addresses, plus
 *       the reverse for directory listing. It models the real GridPP Ceph site
 *       conventions so one driver serves many sites by config alone.
 *
 * WHY:  "ceph.namelib" means different things per architecture (see the design
 *       spec §1.0a). RAL/Glasgow (XrdCeph/RADOS) name objects "<pool>:<prefix><lfn>"
 *       — the pool is a ':'-prefix that stock XrdCephOss::extractPool splits off.
 *       CephFS sites (Lancaster/Manchester/Brunel) are POSIX, so the physical name
 *       is a path "<localroot><lfn>". This module is the single, tunable home for
 *       both, so the rados driver and a posix-on-CephFS export both reach storage
 *       the way the site already wrote its Pb+ of data.
 *
 * HOW:  Scheme + a few string knobs (pool, prefix/localroot). Every translation
 *       rejects path traversal ("..") in the LFN. Dependency-free (unit-tested
 *       standalone; links into the module and libxrdproto).
 */

#include <stddef.h>

typedef enum {
    XROOTD_N2N_IDENTITY = 0,   /* pfn = lfn (no translation) */
    XROOTD_N2N_RAL,            /* RAL/Glasgow RADOS: "<pool>:<prefix><lfn>" */
    XROOTD_N2N_CEPHFS_PATH     /* CephFS POSIX path: "<localroot><lfn>" */
} xrootd_n2n_scheme_t;

typedef struct {
    xrootd_n2n_scheme_t scheme;
    char pool[128];     /* RAL: the pool name emitted as the "<pool>:" prefix */
    char prefix[256];   /* RAL: spacetoken/base inserted before the LFN;
                         * CephFS: the localroot (mount + base) prepended to the LFN */
} xrootd_n2n_cfg_t;

/* LFN → physical name. Rejects ".." traversal. 0, or -1 (bad args/escape/overflow). */
int xrootd_n2n_lfn2pfn(const xrootd_n2n_cfg_t *cfg, const char *lfn,
                       char *pfn, size_t cap);

/* Physical name → LFN (reverse; used to render the root listing in logical terms).
 * Rejects a pfn that is not under the configured pool/prefix. 0 / -1. */
int xrootd_n2n_pfn2lfn(const xrootd_n2n_cfg_t *cfg, const char *pfn,
                       char *lfn, size_t cap);

/* Split "<pool>:<rest>" — faithful to stock XrdCephOss::extractPool: with a colon,
 * pool = text before the first ':' and *rest = text after; with NO colon, the
 * whole string is the pool and *rest points at "". 0 / -1 (overflow). */
int xrootd_n2n_extract_pool(const char *objname, char *pool, size_t cap,
                            const char **rest);

#endif /* XROOTD_SITE_N2N_H */
