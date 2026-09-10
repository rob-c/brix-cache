/*
 * tier_internal.h — the two operator-error helpers the store-line parser shares
 * across its own files.
 *
 * WHAT: tier_fail (format an [emerg] operator error) and tier_role_directive
 *       (the directive name a role was parsed from), both defined in
 *       tier_config.c.
 * WHY:  the store-line PARAM parser (tier_config_args.c) split out of
 *       tier_config.c when the two halves outgrew the 600-line file cap, and
 *       every refusal it can raise is phrased by these two.  Duplicating them
 *       would let the two halves drift into two different error vocabularies.
 * HOW:  driver-private — nothing outside src/fs/tier/ includes this header;
 *       the public surface stays tier.h.
 */
#ifndef BRIX_TIER_INTERNAL_H
#define BRIX_TIER_INTERNAL_H

#include "tier.h"

/* Format an operator-error message into err[errcap] and, when log_emerg, also
 * emit it as an [emerg] so nginx -t fails (Appendix F). Always NGX_ERROR. */
ngx_int_t tier_fail(ngx_conf_t *cf, int log_emerg, char *err, size_t errcap,
    const char *fmt, ...) __attribute__((format(printf, 5, 6)));

/* The consuming directive name for a role (used in operator-error text). */
const char *tier_role_directive(brix_tier_role_t role);

/* Parse the trailing store-line params (credential=/block_size=/verify_pages/
 * nearline) into *out.  Defined in tier_config_args.c. */
ngx_int_t tier_parse_args(ngx_conf_t *cf, ngx_array_t *args,
    brix_tier_cfg_t *out, char *err, size_t errcap);

#endif /* BRIX_TIER_INTERNAL_H */
