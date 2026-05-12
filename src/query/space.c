#include "query_internal.h"

#include <errno.h>

/*
 * kXR_Qspace and kXR_QFSinfo: filesystem capacity reports.
 */

static void
xrootd_query_statvfs_values(struct statvfs *vfs, unsigned long long *total,
    unsigned long long *free_bytes, unsigned long long *used_bytes)
{
    *total = (unsigned long long) vfs->f_blocks * vfs->f_frsize;
    *free_bytes = (unsigned long long) vfs->f_bavail * vfs->f_frsize;
    *used_bytes = *total - (unsigned long long) vfs->f_bfree * vfs->f_frsize;
}


ngx_int_t
xrootd_query_space(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    struct statvfs     vfs;
    char               resp[256];
    unsigned long long total, free_bytes, used_bytes;

    if (statvfs((const char *) conf->root.data, &vfs) != 0) {
        xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                          "space", 0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_SPACE);
        return xrootd_send_error(ctx, c, kXR_IOError, "statvfs failed");
    }

    xrootd_query_statvfs_values(&vfs, &total, &free_bytes, &used_bytes);

    snprintf(resp, sizeof(resp),
             "oss.cgroup=default"
             "&oss.space=%llu"
             "&oss.free=%llu"
             "&oss.maxf=%llu"
             "&oss.used=%llu"
             "&oss.quota=-1",
             total, free_bytes, free_bytes, used_bytes);

    xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                      "space", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_SPACE);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}


ngx_int_t
xrootd_query_fsinfo(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    struct statvfs     vfs;
    char               resp[256];
    unsigned long long total, free_bytes, used_bytes;

    if (statvfs((const char *) conf->root.data, &vfs) != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_FSINFO);
        return xrootd_send_error(ctx, c, kXR_IOError, "statvfs failed");
    }

    xrootd_query_statvfs_values(&vfs, &total, &free_bytes, &used_bytes);

    snprintf(resp, sizeof(resp),
             "oss.paths=1"
             "&oss.free=%llu"
             "&oss.maxf=%llu"
             "&oss.total=%llu"
             "&oss.used=%llu"
             "&oss.quota=-1",
             free_bytes, free_bytes, total, used_bytes);

    xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                      "fsinfo", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_FSINFO);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}
