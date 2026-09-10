/*
 * write_space_group.h — per-space-group accounting + write admission
 * (phase-115 W3.3; the enforced half of `brix_oss_space ... quota=`).
 *
 * WHAT: resolves the group a handle's FINAL path belongs to, measures the
 *       bytes charged to a group, and refuses a data write that would push
 *       the group past its quota with the same kXR_overQuota the export-wide
 *       brix_oss_quota gate uses. kXR_Qspace reuses the measurement so the
 *       report and the gate never disagree.
 *
 * WHY:  a per-VO cap is the whole point of space groups; an advertised quota
 *       nobody enforces is just a label.
 *
 * HOW:  usage = a confined brix_vfs_walk of the prefix summing regular-file
 *       sizes (no allocation, RESOLVE_BENEATH), cached per worker for
 *       BRIX_SPACE_GROUP_TTL_MS and bumped by every admitted write so a burst
 *       inside the TTL cannot overrun the cap. A measurement failure admits
 *       the write (fail-open, like the export-wide gate: a quota is a policy
 *       cap, not an integrity gate) and is logged.
 */
#ifndef BRIX_WRITE_SPACE_GROUP_H
#define BRIX_WRITE_SPACE_GROUP_H

#include "core/ngx_brix_module.h"
#include "core/config/space_group_conf.h"

#define BRIX_SPACE_GROUP_TTL_MS  5000   /* same TTL as write_over_quota */

/* The group owning the handle's final path (POSC/staged handles: the
 * destination, not the temp), or NULL when no group covers it. */
brix_oss_space_t *brix_space_group_of_handle(ngx_stream_brix_srv_conf_t *conf,
    const brix_file_t *f);

/* Bytes charged to `g` (cached; see the header comment). NGX_ERROR when the
 * prefix could not be walked, errno set. */
ngx_int_t brix_space_group_usage(ngx_log_t *log,
    ngx_stream_brix_srv_conf_t *conf, brix_oss_space_t *g,
    unsigned long long *used);

/* Write admission for handle `idx`: 1 = refused (kXR_overQuota sent, *rc set);
 * 0 = admitted (len bytes charged); -1 = the path is in no group (the caller
 * applies the export-wide rules). */
int brix_write_space_group_admit(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int idx, size_t len,
    ngx_uint_t op_id, const char *op, ngx_int_t *rc);

#endif /* BRIX_WRITE_SPACE_GROUP_H */
