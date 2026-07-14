#ifndef BRIX_TYPES_IDENTITY_INTERNAL_H
#define BRIX_TYPES_IDENTITY_INTERNAL_H

/*
 * identity_internal.h — declarations shared between the two halves of the
 * identity builder after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the single function that calls across the identity.c /
 *       identity_attrs.c file boundary.
 * WHY:  identity.c (lifecycle, setters, accessors, scope check, audit summary)
 *       and identity_attrs.c (the VOMS-FQAN → xrdacc vorg/role/group CSV
 *       derivation) were one 602-line file; splitting keeps each focused and
 *       under the 500-line cap. brix_identity_set_vos_csv (in identity.c) calls
 *       brix_identity_derive_attrs (now in identity_attrs.c), so exactly that
 *       one function becomes non-static.
 * HOW:  Both translation units include this header; the symbol is not exported
 *       beyond the identity module.
 *
 * Requires: identity.h before inclusion.
 */

#include "identity.h"   /* brix_identity_t, ngx_pool_t */

/*
 * Defined in identity_attrs.c; called by brix_identity_set_vos_csv (identity.c).
 * Split each comma-separated VOMS FQAN / token group in `vo_csv` into (vorg,
 * role, group) and store them as three index-aligned CSVs on `id` for the
 * xrdacc engine (acc_vorg_csv / acc_role_csv / acc_group_csv).  A NULL/empty
 * input clears the three views and still returns NGX_OK; NGX_ERROR on OOM.
 */
ngx_int_t brix_identity_derive_attrs(brix_identity_t *id, ngx_pool_t *pool,
    const char *vo_csv);

#endif /* BRIX_TYPES_IDENTITY_INTERNAL_H */
