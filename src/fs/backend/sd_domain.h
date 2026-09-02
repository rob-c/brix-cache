#ifndef BRIX_SD_DOMAIN_H
#define BRIX_SD_DOMAIN_H

/*
 * sd_domain.h — the typed storage domain (phase-107 C9).
 *
 * WHAT: brix_vfs_domain_t — what a bound driver instance's storage IS. Typed
 *       onto brix_sd_instance_s.domain (sd.h); asserted at runtime by
 *       src/fs/vfs/vfs_policy_domain.c and, on the seam-waiver side, by
 *       tools/ci/check_vfs_seam.py's domain entitlement table (W9).
 *
 * WHY:  Phase 105 drew the export/service line in prose and free-text
 *       vfs-seam-allow comments; nothing runtime-checked it. EXPORT is zero
 *       on purpose: an instance built by code that has not been taught about
 *       domains is treated as client-named export storage — the strictest
 *       domain, protected by the phase-105 mutation gate — exactly as
 *       BRIX_VFS_MUTATION_READ_ONLY = 0 fails closed on the policy axis.
 *       A domain is a statement about what the storage is, never a grant:
 *       no code path becomes reachable by naming one.
 *
 * HOW:  A plain C enum with no ngx or libc dependency, split from sd.h for
 *       the 600-line budget and included by it, so every sd.h consumer —
 *       ngx-free (XRDPROTO_NO_NGX) ones included — sees the type.
 */

typedef enum {
    BRIX_VFS_DOMAIN_EXPORT = 0,   /* client-named storage — the phase-105 gate */
    BRIX_VFS_DOMAIN_CACHE,        /* cache store: cstore, meta sidecars, verify */
    BRIX_VFS_DOMAIN_STAGE,        /* upload stage dir, TPC transfer temps       */
    BRIX_VFS_DOMAIN_REGISTRY,     /* OCI store tree, tag pointers, indexes      */
    BRIX_VFS_DOMAIN_CREDENTIAL,   /* delegated proxies, minted creds, keytabs   */
    BRIX_VFS_DOMAIN_CONFIG,       /* trust anchors, CA bundles, operator files  */
    BRIX_VFS_DOMAIN_JOURNAL,      /* FRM/stage journals and registries          */
    BRIX_VFS_DOMAIN_COUNT
} brix_vfs_domain_t;

#endif /* BRIX_SD_DOMAIN_H */
