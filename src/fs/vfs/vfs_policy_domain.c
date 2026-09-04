/*
 * vfs_policy_domain.c — the typed storage-domain assert (phase-107 C8/C9).
 *
 * WHAT: Implements brix_vfs_domain_mutation() and brix_vfs_service_mutation():
 *       the runtime check that the instance a service-storage mutator is about
 *       to drive really IS the kind of storage the caller claims
 *       (inst->domain, fs/backend/sd.h).
 *
 * WHY:  The export/service split was reasoning in a document; what enforced it
 *       was nothing. A dedup publish, a cache invalidation, a journal write
 *       pointed at an export root would have mutated client-named storage with
 *       no gate in the way. The assert refuses with EINVAL and logs at crit —
 *       deliberately NOT the export kernel's EROFS, because this is a
 *       programming error a client cannot provoke, and an EROFS here would be
 *       a lie caught by the wrong test.
 *
 * HOW:  Validate, then compare the claim against the field. EXPORT is the one
 *       special case: it routes to the phase-105 kernel with the fail-closed
 *       READ_ONLY policy, because an instance carries no request policy —
 *       export mutations must arrive through the policy-bearing forms
 *       (vfs_policy.c / vfs_policy_export.c), never through a domain claim.
 *       No allocation, no I/O, no backend call; one crit log line on a
 *       mismatch is the only side effect.
 */
#include "vfs_internal.h"
#include "vfs_policy_domain.h"

/* The metrics layer mirrors the domain vocabulary as a plain count so it
 * keeps no dependency on the fs layer (phase-107 §7.5); if a domain is
 * appended in sd_domain.h the mirror must grow with it. */
_Static_assert((int) BRIX_VFS_DOMAIN_COUNT == BRIX_VFS_DOMAIN_METRIC_COUNT,
    "brix_vfs_domain_t and BRIX_VFS_DOMAIN_METRIC_COUNT disagree");

/* ---- Assert an instance belongs to a claimed storage domain ----
 *
 * WHAT: NGX_OK when inst->domain == domain (service domains) — EROFS via the
 *       phase-105 kernel for an EXPORT claim; NGX_ERROR/EINVAL otherwise.
 *
 * WHY:  The caller states its claim instead of the assert inferring "service
 *       or not" from the instance, so a mis-composed tier (a CACHE mutator
 *       handed a STAGE store) is caught, not just an export-pointed one.
 *
 * HOW:  1. Range-check inst, op, domain; 2. route an EXPORT claim to the
 *       kernel under the fail-closed policy; 3. compare the claim; 4. log the
 *       mismatch at crit and refuse with EINVAL.
 */
ngx_int_t
brix_vfs_domain_mutation(const brix_sd_instance_t *inst,
    brix_vfs_domain_t domain, brix_vfs_mutation_op_t op)
{
    if (inst == NULL
        || (ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT
        || (ngx_uint_t) domain >= BRIX_VFS_DOMAIN_COUNT)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (domain == BRIX_VFS_DOMAIN_EXPORT) {
        /* An instance carries no request policy, so the only policy available
         * to an export claim is the fail-closed default: always EROFS. Export
         * mutations arrive through the policy-bearing kernel forms. */
        return brix_vfs_require_mutation_policy(BRIX_VFS_MUTATION_READ_ONLY,
                                                op);
    }

    if (inst->domain != domain) {
        if (inst->log != NULL) {
            ngx_log_error(NGX_LOG_CRIT, inst->log, 0,
                "brix vfs: service mutation \"%s\" claimed domain %d but the "
                "instance is domain %d — refused (wrong_domain)",
                brix_vfs_mutation_op_name(op), (int) domain,
                (int) inst->domain);
        }
        errno = EINVAL;
        return NGX_ERROR;
    }

    brix_metric_vfs_domain_mutation((ngx_uint_t) domain, (ngx_uint_t) op);
    return NGX_OK;
}

/* ---- Assert a claimed storage domain with no instance in hand ----
 *
 * WHAT: The instance-free form of the assert above, for mutators whose
 *       service storage is not a bound driver instance at all — the
 *       credential staging dir (phase-108 C11), the OCI store tree (C10).
 *       NGX_OK for a valid service-domain claim (one metric sample booked);
 *       EROFS via the phase-105 kernel for an EXPORT claim; EINVAL out of
 *       range.
 *
 * WHY:  brix_vfs_domain_mutation() deliberately refuses a NULL instance —
 *       for instance-bearing paths that is a wiring bug. But a credential
 *       write has no brix_sd_instance_t and never will; without this form
 *       those verbs would either skip the domain gate (untyped, unaccounted)
 *       or fake an instance (worse). With nothing to cross-check, the claim's
 *       enforcement is the seam guard's source-level entitlement table plus
 *       the EXPORT routing here: no caller can launder an export mutation
 *       through a bare claim, because EXPORT routes to the fail-closed
 *       kernel and answers EROFS.
 *
 * HOW:  1. Range-check op and domain; 2. route an EXPORT claim to the kernel
 *       under the fail-closed policy (with one crit line — a service caller
 *       claiming EXPORT is a programming error, same as a domain mismatch);
 *       3. book the accounting sample and allow.
 */
ngx_int_t
brix_vfs_domain_claim(ngx_log_t *log, brix_vfs_domain_t domain,
    brix_vfs_mutation_op_t op)
{
    if ((ngx_uint_t) op >= BRIX_VFS_MUTATE_OP_COUNT
        || (ngx_uint_t) domain >= BRIX_VFS_DOMAIN_COUNT)
    {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (domain == BRIX_VFS_DOMAIN_EXPORT) {
        if (log != NULL) {
            ngx_log_error(NGX_LOG_CRIT, log, 0,
                "brix vfs: service mutation \"%s\" claimed the EXPORT domain "
                "with no instance — refused (wrong_domain)",
                brix_vfs_mutation_op_name(op));
        }
        /* Only the fail-closed policy is available to a bare claim: export
         * mutations arrive through the policy-bearing kernel forms. */
        return brix_vfs_require_mutation_policy(BRIX_VFS_MUTATION_READ_ONLY,
                                                op);
    }

    brix_metric_vfs_domain_mutation((ngx_uint_t) domain, (ngx_uint_t) op);
    return NGX_OK;
}

/* ---- Assert an instance is service storage at all ----
 *
 * WHAT: NGX_OK when inst->domain is any service domain; NGX_ERROR/EINVAL when
 *       it is EXPORT (or the arguments are invalid).
 *
 * WHY:  gcas' dedup slots know only "this must not be the export"; making
 *       them claim CACHE would couple the CAS layer to the tier shape for no
 *       safety gain. The instance's own domain is the claim.
 *
 * HOW:  Refuse EXPORT with the crit log, then delegate to the general form
 *       with the instance's own domain (which then validates op and matches
 *       trivially).
 */
ngx_int_t
brix_vfs_service_mutation(const brix_sd_instance_t *inst,
    brix_vfs_mutation_op_t op)
{
    if (inst == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    if (inst->domain == BRIX_VFS_DOMAIN_EXPORT) {
        if (inst->log != NULL) {
            ngx_log_error(NGX_LOG_CRIT, inst->log, 0,
                "brix vfs: service mutation \"%s\" against EXPORT-domain "
                "storage — refused (wrong_domain)",
                brix_vfs_mutation_op_name(op));
        }
        errno = EINVAL;
        return NGX_ERROR;
    }

    return brix_vfs_domain_mutation(inst, inst->domain, op);
}
