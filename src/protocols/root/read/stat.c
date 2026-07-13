#include "core/ngx_brix_module.h"
#include "stat.h"
#include "net/cms/cns.h"            /* §6 CNS inventory stat answer */
#include "fs/vfs/vfs.h"            /* path stat via the VFS seam */
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "net/manager/pending.h"
#include "net/cms/cms_internal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/statvfs.h>

/*
 * brix_make_vfs_body — kXR_stat(kXR_vfs) / `xrdfs statvfs` response body.
 *
 * The reference format (XrdCl StatInfoVFS::ParseServerResponse) is SIX
 * space-separated integers, each a bare number:
 *   "<nodesRW> <freeRW_MB> <utilRW%> <nodesStaging> <freeStaging_MB> <utilStaging%>"
 * (We previously emitted the 4-field "id size flags mtime" stat line here, which
 * the stock client rejects as "Invalid response".) Free space comes from
 * statvfs(2) on the export root; staging is reported as 0 (no tape staging tier).
 */
static void
brix_make_vfs_body(ngx_stream_brix_srv_conf_t *conf, char *out, size_t outsz)
{
    struct statvfs vfs;
    const char    *root = conf->common.root_canon[0]
                          ? conf->common.root_canon : "/";
    long long      free_mb = 0, total_mb = 0;
    int            util = 0;
    int            nrw = conf->common.allow_write ? 1 : 0;

    if (statvfs(root, &vfs) == 0) {
        unsigned long bs = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
        free_mb  = (long long) ((double) vfs.f_bavail * (double) bs / 1048576.0);
        total_mb = (long long) ((double) vfs.f_blocks * (double) bs / 1048576.0);
        if (total_mb > 0) {
            util = (int) (100.0 * (double) (total_mb - free_mb)
                          / (double) total_mb);
        }
    }

    snprintf(out, outsz, "%d %lld %d 0 0 0", nrw, free_mb, util);
}

extern char **environ;

/* §14 (phase-64): the fork/exec `xrdfs <origin> stat` forward for a legacy
 * cache_origin GSI cache is RETIRED with the cache_origin config model — a tier
 * cache's stat resolves through the composed sd_cache (cinfo hit) or the
 * backend driver's in-process stat. */

/*
 * brix_vfs_to_struct_stat — project a VFS stat result back into the struct
 * stat fields the kXR_stat response builder reads: the unique id (st_ino<<32 |
 * st_dev), st_size, the permission triplet (st_mode/st_uid/st_gid →
 * readable/writable flags), st_mtime, and st_blocks (statvfs-style body). The
 * VFS is the only thing that touched the namespace; this is a pure field copy.
 */
void
brix_vfs_to_struct_stat(const brix_vfs_stat_t *v, struct stat *st)
{
    ngx_memzero(st, sizeof(*st));
    st->st_mode   = (mode_t) v->mode;
    st->st_size   = v->size;
    st->st_mtime  = v->mtime;
    st->st_ctime  = v->ctime;
    st->st_ino    = v->ino;
    st->st_dev    = v->dev;
    st->st_uid    = v->uid;
    st->st_gid    = v->gid;
    st->st_blocks = v->blocks;
    st->st_nlink  = 1;
}

/* Return kXR_cachersp if reqpath (client's clean path) exists in cache_root. */
int
brix_cache_path_flag(const ngx_stream_brix_srv_conf_t *conf, const char *reqpath)
{
    char        cache_path[PATH_MAX];
    struct stat cst;
    int         n;

    if (!conf->cache || conf->cache_root.len == 0 || reqpath == NULL) {
        return 0;
    }

    n = snprintf(cache_path, sizeof(cache_path), "%s%s",
                 (char *) conf->cache_root.data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(cache_path)) {
        return 0;
    }

    /* vfs-seam-allow: separate storage domain. cache_path is under the
     * server-managed cache root (svc-owned, distinct from the export root); the
     * cachersp existence probe runs as the worker, not via the export VFS. */
    return (stat(cache_path, &cst) == 0 && S_ISREG(cst.st_mode))  /* vfs-seam-allow: separate cache-root domain */
           ? kXR_cachersp : 0;
}

/*
 * stat_target_t — one kXR_stat resolution in flight.
 *
 * kXR_stat is dual-mode (path payload vs open handle) but both modes must
 * produce the same result set: the on-disk struct stat, the logging paths,
 * and the extra kXR flag bits.  Bundling the request pointer, the caller's
 * path buffers, and the result slots into one carrier keeps every helper at
 * a small explicit signature instead of threading six parameters around.
 */
typedef struct {
    const xrdw_stat_req_t *req;             /* decoded kXR_stat request */
    char                  *reqpath_buf;     /* client-path scratch buffer */
    size_t                 reqpath_size;    /* sizeof(reqpath_buf) */
    const char            *reqpath;         /* client's clean path (path mode) */
    char                  *full_path;       /* resolved on-disk path buffer */
    size_t                 full_path_size;  /* sizeof(full_path) */
    struct stat           *st;              /* metadata result */
    int                    extra_flags;     /* kXR_cachersp / offline flag bits */
} stat_target_t;

/*
 * stat_vfs_ctx_prepare — bind a confined VFS context for one stat probe.
 *
 * Every namespace touch in this handler goes through the VFS seam
 * (impersonation-aware, RESOLVE_IN_ROOT-confined), and the init +
 * backend-credential + delegation binding triple is identical at each probe
 * site — so it lives here once.  Pure setup: fills *vctx from conf/ctx for
 * the given absolute path; no I/O happens until the caller queries.
 */
static void
stat_vfs_ctx_prepare(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *path, brix_vfs_ctx_t *vctx)
{
    brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, ctx->identity, path);
    brix_vfs_ctx_bind_backend_cred(vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_root_vfs_bind_deleg(ctx, conf, vctx);
}

/*
 * stat_manager_route — redirector-side answers for a path-mode stat.
 *
 * A redirector must answer stat without local storage — stock and go-hep
 * clients stat a path before they open it.  In precedence order: a static
 * manager_map prefix redirects outright (mirrors the open/locate paths); in
 * manager mode the §6 CNS inventory can answer size/mtime directly (a true
 * global-namespace stat), tried/triedrc exhaustion answers not-found to stop
 * redirect loops, the registry redirects to a live data server (tolerating a
 * just-dropped heartbeat, like open), and a registry miss is forwarded to
 * the CMS parent, parking the session (NGX_AGAIN).  Returns 0 when the
 * request was answered (*rc holds the value to return, possibly NGX_AGAIN)
 * and 1 when the caller should continue with a local stat.
 */
static int
stat_manager_route(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *reqpath, ngx_int_t *rc)
{
    /* Static manager_map: an explicit prefix→backend redirect (mirrors the
     * open/locate paths) so a static-map redirector also serves stat — stock
     * and go-hep clients stat a path before they open it, and without this a
     * map-only redirector answered stat locally (IOError, no root). */
    if (conf->manager_map != NULL) {
        const brix_manager_map_t *m =
            brix_find_manager_map(reqpath, conf->manager_map);
        if (m != NULL) {
            brix_log_access(ctx, c, "STAT", reqpath, "manager_map",
                              1, kXR_ok, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_STAT);
            *rc = brix_send_redirect(ctx, c, (const char *) m->host.data,
                                       m->port);
            return 0;
        }
    }

    /* Manager mode: redirect to a registered data server. */
    if (!conf->manager_mode) {
        return 1;
    }

    /* §6 CNS: if the cluster name space inventory has this path, answer
     * stat directly (size/mtime) instead of redirecting — a true global
     * namespace stat at the redirector. */
    if (conf->cns_mode == BRIX_CNS_COLLECT) {
        struct stat cst;
        if (brix_cns_stat(reqpath, &cst) == NGX_OK) {
            char cbody[256];
            brix_make_stat_body(&cst, 0, 0, cbody, sizeof(cbody));
            brix_log_access(ctx, c, "STAT", reqpath, "cns",
                              1, 0, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_STAT);
            *rc = brix_send_ok(ctx, c, cbody,
                                 (uint32_t) (strlen(cbody) + 1));
            return 0;
        }
    }

    /* tried/triedrc: if the client has already visited every server
     * that holds this path and they returned enoent, stop redirecting
     * and answer not-found — otherwise the client redirect-loops. */
    if (brix_manager_tried_exhausted(ctx->recv.payload, ctx->recv.cur_dlen,
                                       reqpath)) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", reqpath, "-",
                        kXR_NotFound, "file not found on any data server", rc);
    }

    /* Like open: tolerate a server whose CMS heartbeat just dropped (it
     * is almost certainly still serving) rather than a false NotFound. */
    {
        char     redir_host[256];
        uint16_t redir_port;

        if (brix_srv_select_or_blacklisted(reqpath, 0, redir_host,
                              sizeof(redir_host), &redir_port)) {
            brix_log_access(ctx, c, "STAT", reqpath, "registry",
                              1, kXR_ok, NULL, 0);
            BRIX_OP_OK(ctx, BRIX_OP_STAT);
            *rc = brix_send_redirect(ctx, c, redir_host, redir_port);
            return 0;
        }
    }

    /* Registry miss — ask CMS parent if configured. */
    if (conf->cms.ctx != NULL) {
        uint32_t streamid;

        streamid = ngx_brix_cms_next_streamid(conf->cms.ctx);
        if (brix_pending_insert(streamid, ngx_pid, c->fd,
                                  c->number,
                                  ctx->recv.cur_streamid,
                                  conf->cms.locate_timeout) == NGX_OK)
        {
            ctx->cms_wait_streamid = streamid;
            ctx->state = XRD_ST_WAITING_CMS;
            ngx_add_timer(c->read, conf->cms.locate_timeout);
            if (ngx_brix_cms_send_locate(conf->cms.ctx, streamid,
                                           reqpath) == NGX_OK)
            {
                *rc = NGX_AGAIN;
                return 0;
            }
            ngx_del_timer(c->read);
            ctx->state = XRD_ST_REQ_HEADER;
            brix_pending_remove(streamid, ngx_pid);
        }
    }

    return 1;
}

/*
 * stat_symlink_follow_fallback — confined follow of a host-absolute symlink.
 *
 * Follow fallback for an in-export symlink with a host-ABSOLUTE target:
 * RESOLVE_IN_ROOT chroots the absolute target and lands on ENOENT, where
 * stock follows it on the real fs.  Match stock, but CONFINE via realpath —
 * accept only when the canonical target is within the export root (an
 * escaping link is rejected).  Read-only, so the realpath/stat TOCTOU window
 * is benign.  Returns 0 with *tgt->st filled from the confirmed in-root
 * target, or -1 (errno describes the last failing probe) to keep the
 * original miss.
 */
static int
stat_symlink_follow_fallback(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, stat_target_t *tgt)
{
    char            real[PATH_MAX];
    size_t          rl = ngx_strlen(conf->common.root_canon);
    brix_vfs_ctx_t  rvctx;
    brix_vfs_stat_t rvst;

    if (realpath(tgt->full_path, real) == NULL
        || ngx_strncmp(real, conf->common.root_canon, rl) != 0
        || (real[rl] != '/' && real[rl] != '\0'))
    {
        return -1;
    }

    /* The canonical target is confirmed within the export root;
     * read its metadata through the VFS (the symlink chain is
     * already resolved, so a non-follow probe is exact). */
    stat_vfs_ctx_prepare(ctx, c, conf, real, &rvctx);
    if (brix_vfs_probe(&rvctx, 0 /* follow */, &rvst) != NGX_OK) {
        return -1;
    }

    brix_vfs_to_struct_stat(&rvst, tgt->st);
    return 0;
}

/*
 * stat_vfs_query — path-mode metadata through the VFS seam.
 *
 * kXR_statNoFollow (vendor): lstat the final component so a symlink reports
 * as itself (kXR_other + target-length size) for FUSE getattr; default
 * follows symlinks exactly as before.  Both go through the VFS seam
 * (impersonation-aware, RESOLVE_IN_ROOT-confined); the result is projected
 * back into struct stat for the response code.  An ENOENT on a followable
 * path gets one confined symlink-follow fallback so a host-absolute in-root
 * link still stats like stock.  Returns 0 with *tgt->st filled, or -1 with
 * errno describing the failure for the caller's error mapping.
 */
static int
stat_vfs_query(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, stat_target_t *tgt)
{
    brix_vfs_ctx_t  vctx;
    brix_vfs_stat_t vst;
    int             src;

    stat_vfs_ctx_prepare(ctx, c, conf, tgt->full_path, &vctx);
    src = (((tgt->req->options & kXR_statNoFollow)
            ? brix_vfs_stat(&vctx, &vst)
            : brix_vfs_statf(&vctx, &vst)) == NGX_OK) ? 0 : -1;
    if (src == 0) {
        brix_vfs_to_struct_stat(&vst, tgt->st);
    }

    if (src != 0 && errno == ENOENT
        && !(tgt->req->options & kXR_statNoFollow)
        && conf->common.root_canon[0] != '\0')
    {
        src = stat_symlink_follow_fallback(ctx, c, conf, tgt);
    }

    return src;
}

/*
 * stat_residency_flags — offline/nearline classification for the flag bits.
 *
 * Phase 64: a nearline file (on a tape/MSS backend, not resident in the
 * cache) is reported offline so the client prepares/stages before reading.
 * Residency comes from the backend's model via the VFS seam — so a tape://
 * export advertises offline with NO FRM config; a non-nearline export always
 * classifies ONLINE and sets no flag.  Pure query: returns the extra kXR
 * flag bits to OR in (0 when online or unknown).
 */
static int
stat_residency_flags(ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf,
    const char *full_path)
{
    brix_vfs_ctx_t      rvc;
    brix_sd_residency_t res;

    brix_vfs_ctx_init(&rvc, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, NULL, full_path);
    if (brix_vfs_residency(&rvc, &res, NULL) == NGX_OK
        && (res == BRIX_SD_RES_NEARLINE
            || res == BRIX_SD_RES_OFFLINE))
    {
        return kXR_offline | kXR_bkpexist;
    }

    return 0;
}

/*
 * stat_query_path — path-mode stat: resolve, authorize, query metadata.
 *
 * dlen > 0 means the payload names a path to resolve and stat(2).  Extract
 * and sanity-check the client path (".." rejected outright, internal
 * sidecars reported absent), give redirector routing first refusal, then
 * confine the path beneath the export root, run the auth gate, and read the
 * metadata through the VFS seam.  On success the cache-residency and
 * nearline flag bits land in tgt->extra_flags.  Returns 1 to continue with
 * the common response tail; 0 when a response was already arranged (*rc
 * carries the handler's return value).
 */
static int
stat_query_path(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, stat_target_t *tgt, ngx_int_t *rc)
{
    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             tgt->reqpath_buf, tgt->reqpath_size, 1)) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", "-", "-",
                        kXR_ArgInvalid, "invalid path payload", rc);
    }
    tgt->reqpath = tgt->reqpath_buf;

    /* Reject any ".." component outright (the reference does not normalize
     * "..").  This op resolves through the kernel RESOLVE_BENEATH, which
     * would silently collapse an in-tree "..", so the guard is explicit. */
    if (brix_reject_dotdot_path(ctx, c, BRIX_OP_STAT, "STAT", tgt->reqpath)) {
        *rc = ctx->write_rc;
        return 0;
    }

    /* Internal artifacts (sidecars, upload temps) are invisible → report as
     * absent, never leaking their size/mtime/existence. */
    if (brix_is_internal_name(tgt->reqpath)) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", tgt->reqpath, "-",
                        kXR_NotFound, "file not found", rc);
    }

    if (!stat_manager_route(ctx, c, conf, tgt->reqpath, rc)) {
        return 0;
    }

    brix_beneath_full_path(conf->common.root_canon, tgt->reqpath,
                              tgt->full_path, tgt->full_path_size);

    if (brix_auth_gate(ctx, c, BRIX_OP_STAT, "STAT",
                          tgt->reqpath, tgt->full_path, conf,
                          BRIX_AUTH_LOOKUP, 0) != NGX_OK) {
        *rc = ctx->write_rc;
        return 0;
    }

    if (stat_vfs_query(ctx, c, conf, tgt) != 0) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", tgt->reqpath,
                        "-", brix_kxr_from_errno(errno),
                        strerror(errno), rc);
    }

    tgt->extra_flags = brix_cache_path_flag(conf, tgt->reqpath);
    tgt->extra_flags |= stat_residency_flags(c, conf, tgt->full_path);

    return 1;
}

/*
 * stat_query_handle — handle-based stat: fhandle[0] is our slot index.
 *
 * The cached path is only for logging; the real metadata comes from fstat().
 * Two handle shapes need a size correction: a ZIP member's fd is the ARCHIVE
 * (take the archive metadata, override size with the member's UNCOMPRESSED
 * length) and a driver-backed handle's bare fd is only block 0 (ask the
 * storage driver's worker-safe fstat slot for the catalog-backed metadata).
 * Returns 1 to continue with the common response tail; 0 when an error
 * response was sent (*rc carries the handler's return value).
 */
static int
stat_query_handle(brix_ctx_t *ctx, ngx_connection_t *c,
    stat_target_t *tgt, ngx_int_t *rc)
{
    int          idx = (int)(unsigned char) tgt->req->fhandle[0];
    struct stat *st = tgt->st;

    if (!brix_validate_file_handle(ctx, c, idx, "STAT",
                                     BRIX_OP_STAT, rc)) {
        return 0;
    }

    tgt->full_path[0] = '\0';
    ngx_cpystrn((u_char *) tgt->full_path,
                (u_char *) (ctx->files[idx].path != NULL
                            ? ctx->files[idx].path : "-"),
                tgt->full_path_size);

    if (ctx->files[idx].zip_mode) {
        /*
         * ZIP member (phase-57 W2): the handle's fd is the ARCHIVE, so a
         * plain fstat would report the archive's size.  Take the archive's
         * metadata (mode/mtime/ino) but override the size with the member's
         * UNCOMPRESSED length (cached_size) so the client sees the logical
         * file size.
         */
        if (fstat(ctx->files[idx].fd, st) != 0) {
            BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", tgt->full_path, "-",
                            kXR_IOError, strerror(errno), rc);
        }
        st->st_size = (off_t) ctx->files[idx].cached_size;
    } else if (ctx->files[idx].sd_obj.driver != NULL
               && ctx->files[idx].sd_obj.driver
                      != brix_sd_default_driver()) {
        /*
         * Driver-backed handle (e.g. pblock): the bare fd is only block 0,
         * so a plain fstat would report the block size, not the logical
         * object size.  Ask the storage driver for the object's
         * (catalog-backed) metadata via its worker-safe fstat slot.
         */
        brix_sd_stat_t sdst;

        if (ctx->files[idx].sd_obj.driver->fstat == NULL
            || ctx->files[idx].sd_obj.driver->fstat(
                   &ctx->files[idx].sd_obj, &sdst) != NGX_OK)
        {
            BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", tgt->full_path,
                            "-", kXR_IOError, strerror(errno), rc);
        }
        ngx_memzero(st, sizeof(*st));
        st->st_size  = sdst.size;
        st->st_mtime = sdst.mtime;
        st->st_ctime = sdst.ctime;
        st->st_ino   = sdst.ino;
        st->st_nlink = 1;
        st->st_mode  = sdst.mode ? (mode_t) sdst.mode
                     : (sdst.is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644));
    } else if (fstat(ctx->files[idx].fd, st) != 0) {
        BRIX_BAIL_ERR(ctx, c, BRIX_OP_STAT, "STAT", tgt->full_path, "-",
                        kXR_IOError, strerror(errno), rc);
    }

    tgt->extra_flags = ctx->files[idx].from_cache ? kXR_cachersp : 0;

    return 1;
}

/*
 * brix_handle_stat — kXR_stat entry: dual-mode like upstream XRootD.
 *
 *   - dlen > 0 means the payload names a path to resolve and stat(2)
 *   - dlen == 0 means the opaque handle identifies an already-open fd
 *
 * The logging path and the syscall target are deliberately separated in the
 * handle case: logs use the cached canonical path, while fstat() uses the fd.
 * Both query helpers fill one stat_target_t; the shared tail encodes it and
 * sends the reply.
 */
ngx_int_t brix_handle_stat(brix_ctx_t *ctx, ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_stat_req_t    req;
    struct stat        st;
    char               full_path[PATH_MAX];
    char               reqpath_buf[BRIX_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    ngx_int_t          rc;
    stat_target_t      tgt;

    xrdw_stat_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    is_vfs = (req.options & kXR_vfs) ? 1 : 0;

    ngx_memzero(&tgt, sizeof(tgt));
    tgt.req            = &req;
    tgt.reqpath_buf    = reqpath_buf;
    tgt.reqpath_size   = sizeof(reqpath_buf);
    tgt.full_path      = full_path;
    tgt.full_path_size = sizeof(full_path);
    tgt.st             = &st;

    if (ctx->recv.cur_dlen > 0 && ctx->recv.payload != NULL) {
        if (!stat_query_path(ctx, c, conf, &tgt, &rc)) {
            return rc;
        }
    } else {
        if (!stat_query_handle(ctx, c, &tgt, &rc)) {
            return rc;
        }
    }

    /* Convert into the exact ASCII body the client expects. statvfs has its own
     * 6-field RW/staging-space format (xrdfs statvfs); a plain stat is the
     * 4-field "id size flags mtime" line. */
    if (is_vfs) {
        brix_make_vfs_body(conf, body, sizeof(body));
    } else {
        brix_make_stat_body(&st, 0, tgt.extra_flags, body, sizeof(body));
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_stat ok: %s", body);

    brix_log_access(ctx, c, "STAT",
                      (tgt.reqpath && tgt.reqpath[0]) ? tgt.reqpath : full_path,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_STAT);

    return brix_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}
