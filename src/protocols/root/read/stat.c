#include "core/ngx_brix_module.h"
#include "stat.h"
#include "net/cms/cns.h"            /* §6 CNS inventory stat answer */
#include "fs/vfs/vfs.h"            /* path stat via the VFS seam */
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

ngx_int_t brix_handle_stat(brix_ctx_t *ctx, ngx_connection_t *c, ngx_stream_brix_srv_conf_t *conf)
{
    xrdw_stat_req_t    req;
    struct stat        st;
    char               full_path[PATH_MAX];
    char               reqpath_buf[BRIX_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;
    ngx_int_t          validate_rc;
    int                extra_flags = 0;

    xrdw_stat_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    is_vfs = (req.options & kXR_vfs) ? 1 : 0;

    /*
     * kXR_stat is dual-mode like upstream XRootD:
     *   - dlen > 0 means the payload names a path to resolve and stat(2)
     *   - dlen == 0 means the opaque handle identifies an already-open fd
     *
     * The logging path and the syscall target are deliberately separated in the
     * handle case: logs use the cached canonical path, while fstat() uses the fd.
     */

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        if (!brix_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath_buf, sizeof(reqpath_buf), 1)) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_STAT, "STAT", "-", "-",
                              kXR_ArgInvalid, "invalid path payload");
        }
        reqpath = reqpath_buf;
        /* Reject any ".." component outright (the reference does not normalize
         * "..").  This op resolves through the kernel RESOLVE_BENEATH, which
         * would silently collapse an in-tree "..", so the guard is explicit. */
        if (brix_reject_dotdot_path(ctx, c, BRIX_OP_STAT, "STAT", reqpath)) {
            return ctx->write_rc;
        }
        /* Static manager_map: an explicit prefix→backend redirect (mirrors the
         * open/locate paths) so a static-map redirector also serves stat — stock
         * and go-hep clients stat a path before they open it, and without this a
         * map-only redirector answered stat locally (IOError, no root). */
        if (conf->manager_map != NULL) {
            const brix_manager_map_t *m =
                brix_find_manager_map(reqpath, conf->manager_map);
            if (m != NULL) {
                BRIX_RETURN_REDIR(ctx, c, BRIX_OP_STAT, "STAT", reqpath,
                                    "manager_map",
                                    (const char *) m->host.data, m->port);
            }
        }
        /* Manager mode: redirect to a registered data server. */
        if (conf->manager_mode) {
            char     redir_host[256];
            uint16_t redir_port;

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
                    return brix_send_ok(ctx, c, cbody,
                                          (uint32_t) (strlen(cbody) + 1));
                }
            }

            /* tried/triedrc: if the client has already visited every server
             * that holds this path and they returned enoent, stop redirecting
             * and answer not-found — otherwise the client redirect-loops. */
            if (brix_manager_tried_exhausted(ctx->payload, ctx->cur_dlen,
                                               reqpath)) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_STAT, "STAT", reqpath, "-",
                                  kXR_NotFound,
                                  "file not found on any data server");
            }

            /* Like open: tolerate a server whose CMS heartbeat just dropped (it
             * is almost certainly still serving) rather than a false NotFound. */
            if (brix_srv_select_or_blacklisted(reqpath, 0, redir_host,
                                  sizeof(redir_host), &redir_port)) {
                BRIX_RETURN_REDIR(ctx, c, BRIX_OP_STAT, "STAT",
                                    reqpath, "registry",
                                    redir_host, redir_port);
            }

            /* Registry miss — ask CMS parent if configured. */
            if (conf->cms_ctx != NULL) {
                uint32_t streamid;

                streamid = ngx_brix_cms_next_streamid(conf->cms_ctx);
                if (brix_pending_insert(streamid, ngx_pid, c->fd,
                                          c->number,
                                          ctx->cur_streamid,
                                          conf->cms_locate_timeout) == NGX_OK)
                {
                    ctx->cms_wait_streamid = streamid;
                    ctx->state = XRD_ST_WAITING_CMS;
                    ngx_add_timer(c->read, conf->cms_locate_timeout);
                    if (ngx_brix_cms_send_locate(conf->cms_ctx, streamid,
                                                   reqpath) == NGX_OK)
                    {
                        return NGX_AGAIN;
                    }
                    ngx_del_timer(c->read);
                    ctx->state = XRD_ST_REQ_HEADER;
                    brix_pending_remove(streamid, ngx_pid);
                }
            }
        }

        brix_beneath_full_path(conf->common.root_canon, reqpath,
                                  full_path, sizeof(full_path));

        if (brix_auth_gate(ctx, c, BRIX_OP_STAT, "STAT",
                              reqpath, full_path, conf,
                              BRIX_AUTH_LOOKUP, 0) != NGX_OK) {
            return ctx->write_rc;
        }

        {
            /* kXR_statNoFollow (vendor): lstat the final component so a symlink
             * reports as itself (kXR_other + target-length size) for FUSE getattr;
             * default follows symlinks exactly as before. Both go through the VFS
             * seam (impersonation-aware, RESOLVE_IN_ROOT-confined); the result is
             * projected back into struct st for the response/fallback/frm code. */
            brix_vfs_ctx_t  vctx;
            brix_vfs_stat_t vst;
            int               src;

            brix_vfs_ctx_init(&vctx, c->pool, c->log, BRIX_PROTO_ROOT,
                conf->common.root_canon, NULL, conf->common.allow_write,
                0 /* is_tls */, NULL, full_path);
            src = (((req.options & kXR_statNoFollow)
                    ? brix_vfs_stat(&vctx, &vst)
                    : brix_vfs_statf(&vctx, &vst)) == NGX_OK) ? 0 : -1;
            if (src == 0) {
                brix_vfs_to_struct_stat(&vst, &st);
            }

            /* Follow fallback for an in-export symlink with a host-ABSOLUTE
             * target: RESOLVE_IN_ROOT chroots the absolute target and lands on
             * ENOENT, where stock follows it on the real fs.  Match stock, but
             * CONFINE via realpath — accept only when the canonical target is
             * within the export root (an escaping link is rejected).  Read-only,
             * so the realpath/stat TOCTOU window is benign. */
            if (src != 0 && errno == ENOENT
                && !(req.options & kXR_statNoFollow)
                && conf->common.root_canon[0] != '\0')
            {
                char        real[PATH_MAX];
                size_t      rl = ngx_strlen(conf->common.root_canon);
                if (realpath(full_path, real) != NULL
                    && ngx_strncmp(real, conf->common.root_canon, rl) == 0
                    && (real[rl] == '/' || real[rl] == '\0'))
                {
                    /* The canonical target is confirmed within the export root;
                     * read its metadata through the VFS (the symlink chain is
                     * already resolved, so a non-follow probe is exact). */
                    brix_vfs_ctx_t  rvctx;
                    brix_vfs_stat_t rvst;

                    brix_vfs_ctx_init(&rvctx, c->pool, c->log,
                        BRIX_PROTO_ROOT, conf->common.root_canon, NULL,
                        conf->common.allow_write, 0 /* is_tls */, NULL, real);
                    if (brix_vfs_probe(&rvctx, 0 /* follow */, &rvst)
                        == NGX_OK)
                    {
                        brix_vfs_to_struct_stat(&rvst, &st);
                        src = 0;
                    }
                }
            }
            if (src != 0) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_STAT, "STAT", reqpath,
                                  "-", brix_kxr_from_errno(errno),
                                  strerror(errno));
            }
        }

        extra_flags = brix_cache_path_flag(conf, reqpath);

        /* Phase 64: a nearline file (on a tape/MSS backend, not resident in the
         * cache) is reported offline so the client prepares/stages before reading.
         * Residency comes from the backend's model via the VFS seam — so a tape://
         * export advertises offline with NO FRM config; a non-nearline export always
         * classifies ONLINE and sets no flag. */
        {
            brix_vfs_ctx_t      _rvc;
            brix_sd_residency_t _res;

            brix_vfs_ctx_init(&_rvc, c->pool, c->log, BRIX_PROTO_ROOT,
                conf->common.root_canon, NULL, conf->common.allow_write,
                0 /* is_tls */, NULL, full_path);
            if (brix_vfs_residency(&_rvc, &_res, NULL) == NGX_OK
                && (_res == BRIX_SD_RES_NEARLINE
                    || _res == BRIX_SD_RES_OFFLINE))
            {
                extra_flags |= kXR_offline | kXR_bkpexist;
            }
        }

    } else {
        /* Handle-based stat: fhandle[0] is our slot index. */
        /* The cached path is only for logging; the real metadata comes from fstat(). */
        int idx = (int)(unsigned char) req.fhandle[0];

        if (!brix_validate_file_handle(ctx, c, idx, "STAT",
                                         BRIX_OP_STAT, &validate_rc)) {
            return validate_rc;
        }

        full_path[0] = '\0';
        ngx_cpystrn((u_char *) full_path,
                    (u_char *) (ctx->files[idx].path != NULL
                                ? ctx->files[idx].path : "-"),
                    sizeof(full_path));

        if (ctx->files[idx].zip_mode) {
            /*
             * ZIP member (phase-57 W2): the handle's fd is the ARCHIVE, so a
             * plain fstat would report the archive's size.  Take the archive's
             * metadata (mode/mtime/ino) but override the size with the member's
             * UNCOMPRESSED length (cached_size) so the client sees the logical
             * file size.
             */
            if (fstat(ctx->files[idx].fd, &st) != 0) {
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_STAT, "STAT", full_path, "-",
                                  kXR_IOError, strerror(errno));
            }
            st.st_size = (off_t) ctx->files[idx].cached_size;
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
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_STAT, "STAT", full_path,
                                  "-", kXR_IOError, strerror(errno));
            }
            ngx_memzero(&st, sizeof(st));
            st.st_size  = sdst.size;
            st.st_mtime = sdst.mtime;
            st.st_ctime = sdst.ctime;
            st.st_ino   = sdst.ino;
            st.st_nlink = 1;
            st.st_mode  = sdst.mode ? (mode_t) sdst.mode
                        : (sdst.is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644));
        } else if (fstat(ctx->files[idx].fd, &st) != 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_STAT, "STAT", full_path, "-",
                              kXR_IOError, strerror(errno));
        }

        extra_flags = ctx->files[idx].from_cache ? kXR_cachersp : 0;
    }

    /* Convert into the exact ASCII body the client expects. statvfs has its own
     * 6-field RW/staging-space format (xrdfs statvfs); a plain stat is the
     * 4-field "id size flags mtime" line. */
    if (is_vfs) {
        brix_make_vfs_body(conf, body, sizeof(body));
    } else {
        brix_make_stat_body(&st, 0, extra_flags, body, sizeof(body));
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_stat ok: %s", body);

    brix_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : full_path,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_STAT);

    return brix_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}
