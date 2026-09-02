#ifndef BRIX_VFS_POLICY_DOMAIN_H
#define BRIX_VFS_POLICY_DOMAIN_H

/*
 * vfs_policy_domain.h — the typed storage-domain assert (phase-107 C8/C9).
 *
 * WHAT: Declares the runtime half of the storage-domain claim: a caller states
 *       what it believes an instance's storage IS (brix_vfs_domain_t, defined
 *       next to the field it types in fs/backend/sd.h), and the assert checks
 *       the instance agrees before a service-storage mutation proceeds.
 *
 * WHY:  Phase 105 drew the export/service line in prose and 108 free-text
 *       vfs-seam-allow comments; nothing enforced it at runtime. These two
 *       functions turn the paragraph into a refusal: service code pointed at
 *       export storage is a programming error and fails with EINVAL — loudly —
 *       where the export kernel's client-facing policy refusal is EROFS and
 *       discloses nothing. Conflating the two is how a service path acquires
 *       an export-shaped refusal nobody notices.
 *
 * HOW:  brix_vfs_domain_mutation() checks the caller's claimed domain against
 *       inst->domain; EXPORT routes to the phase-105 kernel with the
 *       fail-closed policy. brix_vfs_service_mutation() is the narrow form —
 *       "this must be service storage at all" — for callers whose only claim
 *       is not-export (gcas dedup). A domain is a statement, never a grant.
 *
 * Requires nothing beyond its own includes; usable from fs/cache and every
 * service-storage mutator.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"        /* brix_vfs_domain_t, brix_sd_instance_t */
#include "fs/vfs/vfs_policy.h"    /* brix_vfs_mutation_op_t */

/* Assert `inst` belongs to `domain` before a mutation attributed to `op`.
 * EXPORT delegates to the phase-105 kernel: an instance carries no request
 * policy, so the only policy available is the fail-closed default and the
 * result is EROFS — an export mutation must arrive through a policy-bearing
 * form, never through a domain claim. Any other domain returns NGX_OK on a
 * match, else NGX_ERROR with errno = EINVAL and one crit log line: a service
 * path cannot launder an export mutation through a domain claim, and a
 * zero-initialised instance is EXPORT, so the untaught site gets the strict
 * domain. */
ngx_int_t brix_vfs_domain_mutation(const brix_sd_instance_t *inst,
    brix_vfs_domain_t domain, brix_vfs_mutation_op_t op);

/* The narrow form: `inst` must be service storage of ANY domain (its own says
 * which). NGX_OK, or NGX_ERROR with errno = EINVAL when the instance is
 * EXPORT-domain — the caller is service code and pointing it at export
 * storage is the exact defect this assert exists to catch. First callers:
 * the gcas dedup slots (C8). */
ngx_int_t brix_vfs_service_mutation(const brix_sd_instance_t *inst,
    brix_vfs_mutation_op_t op);

#endif /* BRIX_VFS_POLICY_DOMAIN_H */
