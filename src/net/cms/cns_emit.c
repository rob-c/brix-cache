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
 * cns_emit_ready — is this worker in a position to report a mutation at all?
 *
 * EMIT mode plus at least one manager link that is connected and logged in.
 * Shared by both emit entry points so the gate is stated once.
 */
static ngx_flag_t
cns_emit_ready(ngx_stream_brix_srv_conf_t *conf)
{
    ngx_uint_t  i;

    if (conf == NULL || conf->cns_mode != BRIX_CNS_EMIT) {
        return 0;
    }

    for (i = 0; i < conf->cms.nctxs; i++) {
        if (conf->cms.ctxs[i]->connection != NULL
            && conf->cms.ctxs[i]->logged_in)
        {
            return 1;
        }
    }

    return 0;
}

/*
 * cns_emit_send — fan one encoded CNS event out to EVERY ready manager link.
 *
 * Redundant managers each keep their own inventory, so an event that reached
 * only one of them would leave the others' catalogues stale — exactly the
 * split-brain redundancy is meant to prevent.  Best-effort per link.
 */
static void
cns_emit_send(ngx_stream_brix_srv_conf_t *conf, const uint8_t *buf, size_t n)
{
    ngx_uint_t  i;

    for (i = 0; i < conf->cms.nctxs; i++) {
        if (conf->cms.ctxs[i]->connection != NULL
            && conf->cms.ctxs[i]->logged_in)
        {
            (void) brix_cms_send_frame(conf->cms.ctxs[i]->connection, 0,
                                         CMS_RR_CNS, CMS_MOD_RAW, buf, n);
        }
    }
}

/*
 * cns_logical — the client-facing path for an on-disk resolved path.
 *
 * Strips the export root_canon prefix, keeping the leading '/'. A path that is
 * not under the export root is returned unchanged (the encode step then rejects
 * anything oversized).
 *
 * Takes the root as a plain string rather than the conf it came from: an HTTP
 * plane resolves against its OWN export root, which is the prefix that has to
 * come off, even though the frame leaves over the stream plane's manager link.
 */
static const char *
cns_logical(const char *root, const char *resolved)
{
    size_t rlen = (root != NULL) ? ngx_strlen(root) : 0;

    if (rlen > 0 && ngx_strncmp(resolved, root, rlen) == 0
        && resolved[rlen] == '/')
    {
        return resolved + rlen;
    }
    return resolved;
}

/*
 * cns_emit_conf — the server block whose manager link this worker reports over.
 *
 * WHY: the CMS link hangs off a stream{} server conf, but WebDAV/S3/gridftp are
 *      http{} planes with no path to it. Rather than a new directive and a
 *      per-worker cached pointer (a global, which CLAUDE.md forbids), this
 *      derives the emitter from the cycle on demand — the same walk
 *      config/process.c already does at worker init, so it introduces no state
 *      at all and cannot go stale across a reload.
 * HOW: first server block that is in EMIT mode with a live, logged-in link.
 *      A node's manager links all hang off one server block (worker-0-gated,
 *      see cms_start.c), so "first ready" is "the" emitter, not an arbitrary
 *      pick among equals — and the send fans out to every ready link.
 *
 * The walk is over server blocks (a handful), and every caller is already
 * committing a namespace mutation — a syscall plus a frame — so it is noise
 * against the work it accompanies.
 */
static ngx_stream_brix_srv_conf_t *
cns_emit_conf(void)
{
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_core_srv_conf_t  **cscfp;
    ngx_stream_brix_srv_conf_t   *xcf;
    ngx_uint_t                    i;

    if (ngx_cycle == NULL) {
        return NULL;
    }

    cmcf = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
                                                  ngx_stream_core_module);
    if (cmcf == NULL) {
        return NULL;            /* no stream{} block → no CMS link → no CNS */
    }

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_brix_module);
        if (cns_emit_ready(xcf)) {
            return xcf;
        }
    }

    return NULL;
}

/*
 * brix_cns_emit — report one namespace mutation to the manager.
 *
 * Best-effort, fire-and-forget: only in EMIT mode, only when the worker's manager
 * link is connected + logged in.
 */
void
brix_cns_emit(ngx_stream_brix_srv_conf_t *conf, uint8_t op,
    const char *resolved, uint64_t size, uint64_t mtime)
{
    uint8_t      buf[BRIX_CNS_HDR_LEN + BRIX_CNS_PATH_MAX];
    size_t       n;

    if (resolved == NULL || !cns_emit_ready(conf)) {
        return;
    }

    n = brix_cns_event_encode(op, cns_logical(conf->common.root_canon, resolved),
                                size, mtime, buf, sizeof(buf));
    if (n == 0) {
        return;   /* empty or over-long logical path → skip (torn/oversized) */
    }

    cns_emit_send(conf, buf, n);
}

/*
 * brix_cns_emit_rename — report a rename as ONE event, not a DEL plus an ADD.
 *
 * A DEL/ADD pair would be wrong for a directory: the manager would drop the
 * directory entry and add the new one while every recorded child stayed at a
 * path the cluster no longer serves. The single BRIX_CNS_MV event lets the
 * manager carry the subtree atomically under its inventory lock, and it also
 * survives the pair arriving out of order, which two independent frames cannot.
 */
void
brix_cns_emit_rename(ngx_stream_brix_srv_conf_t *conf, const char *src_resolved,
    const char *dst_resolved, uint64_t size, uint64_t mtime, int is_dir)
{
    uint8_t  buf[BRIX_CNS_HDR_LEN + 2 * BRIX_CNS_PATH_MAX + 2];
    size_t   n;

    if (src_resolved == NULL || dst_resolved == NULL || !cns_emit_ready(conf)) {
        return;
    }

    n = brix_cns_event_encode_mv(cns_logical(conf->common.root_canon,
                                                 src_resolved),
                                   cns_logical(conf->common.root_canon,
                                                 dst_resolved),
                                   size, mtime, is_dir, buf, sizeof(buf));
    if (n == 0) {
        return;
    }

    cns_emit_send(conf, buf, n);
}

/*
 * ---------------------------------------------------------------------------
 * HTTP-plane seam (WebDAV / S3 / gridftp)
 *
 * Same events, same wire, same manager link — but resolved against the CALLER's
 * export root, because an http{} location has its own root_canon and its own
 * identity binding. The caller observes the object through its own VFS context
 * (which is where its identity, backend credential and delegation live) and
 * passes the result in; this seam only decides whether to report and how to
 * phrase the path.
 * ---------------------------------------------------------------------------
 */

ngx_flag_t
brix_cns_emit_active(void)
{
    return cns_emit_conf() != NULL;
}

void
brix_cns_emit_at(const char *root_canon, uint8_t op, const char *resolved,
    uint64_t size, uint64_t mtime)
{
    uint8_t                      buf[BRIX_CNS_HDR_LEN + BRIX_CNS_PATH_MAX];
    ngx_stream_brix_srv_conf_t  *conf;
    size_t                       n;

    if (resolved == NULL) {
        return;
    }

    conf = cns_emit_conf();
    if (conf == NULL) {
        return;
    }

    n = brix_cns_event_encode(op, cns_logical(root_canon, resolved), size,
                                mtime, buf, sizeof(buf));
    if (n == 0) {
        return;
    }

    cns_emit_send(conf, buf, n);
}

void
brix_cns_emit_rename_at(const char *root_canon, const char *src_resolved,
    const char *dst_resolved, uint64_t size, uint64_t mtime, int is_dir)
{
    uint8_t                      buf[BRIX_CNS_HDR_LEN + 2 * BRIX_CNS_PATH_MAX + 2];
    ngx_stream_brix_srv_conf_t  *conf;
    size_t                       n;

    if (src_resolved == NULL || dst_resolved == NULL) {
        return;
    }

    conf = cns_emit_conf();
    if (conf == NULL) {
        return;
    }

    n = brix_cns_event_encode_mv(cns_logical(root_canon, src_resolved),
                                   cns_logical(root_canon, dst_resolved),
                                   size, mtime, is_dir, buf, sizeof(buf));
    if (n == 0) {
        return;
    }

    cns_emit_send(conf, buf, n);
}
