/*
 * cns_emit.c — data-server CNS event emission (§6 wire wrappers). See cns_emit.h.
 *
 * Shared emit seam. Extracted from the original inline ADD-on-close path so that
 * every namespace mutation (ADD/DEL/MKDIR/RMDIR) reports through one function.
 */

#include "cns_emit.h"
#include "cns.h"            /* BRIX_CNS_*, brix_cns_event_encode, CMS_RR_CNS   */
#include "cms_internal.h"   /* ngx_brix_cms_ctx_t, CMS_MOD_RAW                 */
#include "frame_io.h"       /* brix_cms_send_frame                             */

/*
 * brix_cns_emit — report one namespace mutation to the manager.
 *
 * Best-effort, fire-and-forget: only in EMIT mode, only when the worker's manager
 * link is connected + logged in. The logical (client-facing) path is derived by
 * stripping the export root_canon prefix from `resolved`, keeping the leading '/'.
 */
void
brix_cns_emit(ngx_stream_brix_srv_conf_t *conf, uint8_t op,
    const char *resolved, uint64_t size, uint64_t mtime)
{
    const char  *root, *logical;
    size_t       rlen;
    uint8_t      buf[BRIX_CNS_HDR_LEN + BRIX_CNS_PATH_MAX];
    size_t       n;

    if (conf == NULL || conf->cns_mode != BRIX_CNS_EMIT || resolved == NULL) {
        return;
    }
    if (conf->cms.ctx == NULL || conf->cms.ctx->connection == NULL
        || !conf->cms.ctx->logged_in)
    {
        return;
    }

    root    = conf->common.root_canon;
    rlen    = (root != NULL) ? ngx_strlen(root) : 0;
    logical = resolved;
    if (rlen > 0 && ngx_strncmp(resolved, root, rlen) == 0
        && resolved[rlen] == '/')
    {
        logical = resolved + rlen;   /* keep the leading '/' → client-facing path */
    }

    n = brix_cns_event_encode(op, logical, size, mtime, buf, sizeof(buf));
    if (n == 0) {
        return;   /* empty or over-long logical path → skip (torn/oversized) */
    }

    (void) brix_cms_send_frame(conf->cms.ctx->connection, 0, CMS_RR_CNS,
                                 CMS_MOD_RAW, buf, n);
}
