#include "core/ngx_brix_module.h"
#include "stat.h"
#include "stat_internal.h"
#include "net/cms/cns.h"            /* §6 CNS inventory stat answer */
#include "fs/vfs/vfs.h"            /* path stat via the VFS seam */
#include "fs/vfs/vfs_backend_registry.h"   /* F5: driver space slot for statvfs */
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */
#include "protocols/root/path/op_path.h"
#include "core/negcache/negcache.h"    /* E-4: stat-harvest backoff */
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
int
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
