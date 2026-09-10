/*
 * write_space_group.c — per-space-group accounting + write admission
 * (phase-115 W3.3). Contract and rationale: write_space_group.h.
 */
#include "write_space_group.h"
#include "protocols/ssi/ssi.h"
#include "fs/vfs/vfs.h"
#include "fs/vfs/vfs_ops.h"        /* brix_vfs_walk: confined, non-allocating */
#include "fs/vfs/vfs_internal.h"   /* brix_vfs_export_relative_root */

#include <errno.h>
#include <string.h>

#define SPACE_GROUP_WALK_DEPTH  128   /* deeper than any confined path can be */

brix_oss_space_t *
brix_space_group_of_handle(ngx_stream_brix_srv_conf_t *conf,
    const brix_file_t *f)
{
    const char *abs, *logical;

    if (conf->oss_spaces == NULL) {
        return NULL;
    }
    abs = (f->posc_final_path != NULL) ? f->posc_final_path : f->path;
    if (abs == NULL) {
        return NULL;
    }
    logical = brix_vfs_export_relative_root(abs,
                                            conf->common.root_canon);
    return brix_oss_space_for_path(conf->oss_spaces, logical, strlen(logical));
}

static ngx_int_t
space_walk_add_file(void *cookie, const char *logical,
    const brix_vfs_stat_t *st, int fd)
{
    unsigned long long *sum = cookie;

    (void) logical;
    (void) fd;
    if (st->size > 0) {
        *sum += (unsigned long long) st->size;
    }
    return NGX_OK;
}

ngx_int_t
brix_space_group_usage(ngx_log_t *log, ngx_stream_brix_srv_conf_t *conf,
    brix_oss_space_t *g, unsigned long long *used)
{
    brix_vfs_walk_opts_t opts;
    unsigned long long   sum = 0;
    char                 err[128];
    ngx_int_t            rc;

    if (g->used_valid
        && ngx_current_msec - g->used_at < BRIX_SPACE_GROUP_TTL_MS)
    {
        *used = g->used_bytes;
        return NGX_OK;
    }

    ngx_memzero(&opts, sizeof(opts));
    opts.max_depth = SPACE_GROUP_WALK_DEPTH;
    rc = brix_vfs_walk(log, conf->rootfd, (const char *) g->prefix.data,
                       &opts, space_walk_add_file, &sum, NULL, err, sizeof(err));
    if (rc == NGX_ERROR) {
        g->used_valid = 0;
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "brix: space group \"%V\" (%V): usage walk failed: %s",
                      &g->name, &g->prefix, err);
        return NGX_ERROR;
    }
    /* NGX_DECLINED = the prefix does not exist yet: an empty group. */
    g->used_bytes = sum;
    g->used_at    = ngx_current_msec;
    g->used_valid = 1;
    *used = sum;
    return NGX_OK;
}

int
brix_write_space_group_admit(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, int idx, size_t len,
    ngx_uint_t op_id, const char *op, ngx_int_t *rc)
{
    brix_oss_space_t   *g;
    unsigned long long  used;
    char                msg[160];

    g = brix_space_group_of_handle(conf, &ctx->files[idx]);
    if (g == NULL) {
        return -1;                          /* export-wide rules apply */
    }
    if (g->quota < 0 || conf->oss_quota_enforce != 1) {
        return 0;                           /* accounting only */
    }
    if (brix_space_group_usage(c->log, conf, g, &used) != NGX_OK) {
        return 0;                           /* fail-open, logged by the walk */
    }
    if (used + (unsigned long long) len > (unsigned long long) g->quota) {
        snprintf(msg, sizeof(msg),
                 "write exceeds the quota of space group %.*s (brix_oss_space)",
                 (int) g->name.len, (const char *) g->name.data);
        brix_log_access(ctx, c, op, ctx->files[idx].path, "-", 0,
                        kXR_overQuota, msg, 0);
        BRIX_OP_ERR(ctx, op_id);
        *rc = brix_send_error(ctx, c, kXR_overQuota, msg);
        return 1;
    }
    g->used_bytes = used + (unsigned long long) len;   /* charge before pwrite */
    return 0;
}
