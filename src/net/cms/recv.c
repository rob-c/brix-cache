#include "cms_internal.h"
#include "fs/vfs/vfs.h"   /* confined open/unlink via the VFS seam */
#include "fs/vfs/vfs_backend_registry.h"   /* non-POSIX backend driver routing */
#include "node_ops.h"               /* Plane B forwarded-op planner */
#include "rrdata.h"                 /* Pup decode of forwarded payloads */
#include "router.h"                 /* node-role opcode routing */
#include "net/manager/pending.h"
#include "net/manager/registry.h"
#include "fs/path/beneath.h"
#include "fs/path/path.h"           /* brix_sanitize_log_string (WS6) */
#include "core/compat/net_target.h"   /* brix_net_host_chars_valid (WS6) */
#include "observability/metrics/metrics_macros.h"   /* Phase 51 (A1): resilience counters */

#include <errno.h>
#include <unistd.h>

static ngx_connection_t *cms_find_client_connection(int fd);

/*
 * cms_drv_unlink — remove a file (isdir=0) or directory (isdir=1) through a
 * backend driver's unlink slot. Shared by the RM and RMDIR forwarded-op cases so
 * the ENOSYS-on-missing-slot check lives once. Returns 0 / -1+errno.
 */
static int
cms_drv_unlink(brix_sd_instance_t *sd, const char *path, int isdir)
{
    if (sd->driver->unlink == NULL) { errno = ENOSYS; return -1; }
    return sd->driver->unlink(sd, path, isdir) == NGX_OK ? 0 : -1;
}

/*
 * cms_drv_chmod — apply a forwarded chmod through the driver's setattr slot.
 * A driver with no mutable metadata (setattr slot absent) treats chmod as a
 * successful no-op, matching how object catalogs ignore POSIX modes. Returns
 * 0 / -1+errno.
 */
static int
cms_drv_chmod(brix_sd_instance_t *sd, const brix_cms_node_plan_t *plan)
{
    brix_sd_setattr_t attr;

    if (sd->driver->setattr == NULL) { return 0; }   /* no mutable metadata — no-op */
    ngx_memzero(&attr, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = plan->mode;
    return sd->driver->setattr(sd, plan->path, &attr) == NGX_OK ? 0 : -1;
}

/*
 * cms_drv_trunc — truncate an object through the driver's open/ftruncate/close
 * slots. Owns the driver object handle linearly (open → truncate → close) and
 * preserves the truncate errno across the close so the caller reports the real
 * failure cause. Returns 0 / -1+errno.
 */
static int
cms_drv_trunc(brix_sd_instance_t *sd, const brix_cms_node_plan_t *plan)
{
    const brix_sd_driver_t *drv = sd->driver;
    int              err = 0;
    int              rc;
    int              saved;
    brix_sd_obj_t *o;

    if (drv->open == NULL || drv->ftruncate == NULL) { errno = ENOSYS; return -1; }
    o = drv->open(sd, plan->path, BRIX_SD_O_WRITE, 0, &err);
    if (o == NULL) { errno = err ? err : EIO; return -1; }
    rc = drv->ftruncate(o, (off_t) plan->size) == NGX_OK ? 0 : -1;
    saved = errno;
    if (drv->close != NULL) { drv->close(o); }
    errno = saved;
    return rc;
}

/*
 * cms_node_exec_driver — apply a manager-forwarded namespace op through a
 * NON-default backend driver's slots, so a pblock/object data node mutates its
 * catalog instead of the real filesystem (the confined *_beneath helpers the
 * POSIX path uses only touch the real FS). plan->path/path2 are export-relative
 * (leading slash), the format the driver slots expect. Returns 0 / -1+errno; sets
 * *handled=0 only for an action the driver cannot express. The driver namespace
 * is inherently export-confined, so a hostile manager still cannot escape it.
 */
static int
cms_node_exec_driver(brix_sd_instance_t *sd, const char *root_canon,
    const brix_cms_node_plan_t *plan, ngx_log_t *log, int *handled)
{
    const brix_sd_driver_t *drv = sd->driver;

    *handled = 1;

    switch (plan->action) {
    case XRDCMS_NACT_MKDIR:
        if (drv->mkdir == NULL) { errno = ENOSYS; return -1; }
        return drv->mkdir(sd, plan->path, plan->mode) == NGX_OK ? 0 : -1;

    case XRDCMS_NACT_MKPATH:
        /* create the whole path + missing parents in the driver namespace. */
        return brix_vfs_backend_mkpath(root_canon, plan->path, plan->mode, log);

    case XRDCMS_NACT_RMDIR:
        return cms_drv_unlink(sd, plan->path, 1);

    case XRDCMS_NACT_RM:
        return cms_drv_unlink(sd, plan->path, 0);

    case XRDCMS_NACT_MV:
        if (drv->rename == NULL) { errno = ENOSYS; return -1; }
        return drv->rename(sd, plan->path, plan->path2, 0) == NGX_OK ? 0 : -1;

    case XRDCMS_NACT_CHMOD:
        return cms_drv_chmod(sd, plan);

    case XRDCMS_NACT_TRUNC:
        return cms_drv_trunc(sd, plan);

    default:
        *handled = 0;
        return -1;
    }
}

/* cms_forward_via_driver — driver-backend leg of a forwarded namespace op: run
 * the planned mutation through the non-default backend's namespace slots and
 * reply like stock cmsd (silent on success, kYR_error + strerror on failure,
 * "unsupported operation" for an action the driver cannot express). Split from
 * cms_node_exec_forward so each storage leg owns its own logging/reply tail. */
static ngx_int_t
cms_forward_via_driver(ngx_brix_cms_ctx_t *ctx, brix_sd_instance_t *sd,
    u_char code, uint32_t streamid, const brix_cms_node_plan_t *plan)
{
    const char *root_canon = ctx->conf->common.root_canon;
    int         handled;
    int         rc;

    rc = cms_node_exec_driver(sd, root_canon, plan, ctx->cycle->log,
                              &handled);
    if (!handled) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "unsupported operation");
    }
    if (rc != 0) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
            "brix: CMS node: forwarded op code=%ui path=%s failed: %s",
            (ngx_uint_t) code, plan->path, strerror(errno));
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         strerror(errno));
    }
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
        "brix: CMS node: forwarded op code=%ui path=%s OK (driver)",
        (ngx_uint_t) code, plan->path);
    return NGX_OK;
}

/* cms_posix_apply — POSIX-export leg of a forwarded namespace op: apply the
 * planned mutation to the local filesystem UNDER KERNEL CONFINEMENT
 * (src/fs/path/beneath.h confined helpers / VFS *_at helpers, openat2
 * RESOLVE_BENEATH under the persistent export rootfd). Pure execution — the
 * caller owns logging and the wire reply. Returns 0 / -1+errno; sets
 * *handled=0 only for an action the plan cannot express. */
static int
cms_posix_apply(ngx_brix_cms_ctx_t *ctx, const brix_cms_node_plan_t *plan,
    int *handled)
{
    int         rootfd = ctx->conf->rootfd;
    const char *root_canon = ctx->conf->common.root_canon;

    *handled = 1;

    switch (plan->action) {
    case XRDCMS_NACT_MKDIR:
        return brix_mkdir_beneath(rootfd, plan->path, plan->mode);

    case XRDCMS_NACT_MKPATH: {
        char full[PATH_MAX];
        brix_beneath_full_path(root_canon, plan->path, full, sizeof(full));
        return brix_mkdir_recursive_beneath(ctx->cycle->log, rootfd, root_canon,
                                              full, plan->mode, NULL);
    }
    case XRDCMS_NACT_RMDIR:
        return brix_vfs_unlink_at(rootfd, plan->path, 1);

    case XRDCMS_NACT_RM:
        return brix_vfs_unlink_at(rootfd, plan->path, 0);

    case XRDCMS_NACT_MV:
        return brix_rename_beneath(rootfd, plan->path, plan->path2);

    case XRDCMS_NACT_CHMOD: {
        int rc;
        int fd = brix_vfs_open_fd_at(rootfd, plan->path, O_RDONLY, 0);
        if (fd < 0) { return -1; }
        rc = fchmod(fd, plan->mode);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        close(fd);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        return rc;
    }
    case XRDCMS_NACT_TRUNC: {
        int rc;
        int fd = brix_vfs_open_fd_at(rootfd, plan->path, O_WRONLY, 0);
        if (fd < 0) { return -1; }
        rc = ftruncate(fd, (off_t) plan->size);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        close(fd);  /* vfs-seam-allow: metadata on a VFS-opened confined fd */
        return rc;
    }
    default:
        *handled = 0;
        return -1;
    }
}

/* cms_forward_via_posix — POSIX-export reply wrapper for a forwarded namespace
 * op: run cms_posix_apply and reply like stock cmsd — silent on success (as
 * cmsd Execute() does on a NULL return from a non-forwarding leaf node),
 * kYR_error (kYR_EINVAL + strerror) on failure, "unsupported operation" for an
 * inexpressible action. A hostile manager cannot make the node mutate outside
 * its export root — an escape fails EXDEV and becomes kYR_error. */
static ngx_int_t
cms_forward_via_posix(ngx_brix_cms_ctx_t *ctx, u_char code, uint32_t streamid,
    const brix_cms_node_plan_t *plan)
{
    int  handled;
    int  rc;

    rc = cms_posix_apply(ctx, plan, &handled);
    if (!handled) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "unsupported operation");
    }

    if (rc != 0) {
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                      "brix: CMS node: forwarded op code=%ui path=%s failed: %s",
                      (ngx_uint_t) code, plan->path, strerror(errno));
        /* byte-exact: ecode is always kYR_EINVAL; text carries strerror. */
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         strerror(errno));
    }

    /* Success: stay silent — exactly as cmsd Execute() does on a NULL return
     * from a non-forwarding leaf node. */
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS node: forwarded op code=%ui path=%s ok",
                   (ngx_uint_t) code, plan->path);
    return NGX_OK;
}

/* cms_node_exec_forward — execute a manager-forwarded namespace op (Plane B): decode
 * a kYR_chmod/mkdir/mkpath/mv/rm/rmdir/trunc (the shared request-marshal
 * prologue: rrdata_parse → pure node_plan), then route to the storage leg —
 * a non-POSIX export (pblock/object) mutates through its driver's namespace
 * slots (cms_forward_via_driver); the default POSIX export takes the kernel-
 * confined *_beneath path (cms_forward_via_posix). */
static ngx_int_t
cms_node_exec_forward(ngx_brix_cms_ctx_t *ctx, u_char code, uint32_t streamid,
    const u_char *payload, size_t plen)
{
    brix_cms_rrdata_t      d;
    brix_cms_node_plan_t   plan;
    brix_sd_instance_t    *sd;

    if (brix_cms_rrdata_parse(code, payload, plen, &d) != 0
        || brix_cms_node_plan(code, &d, &plan) != 0)
    {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "badly formed request");
    }

    /* A manager-only node (no local export) cannot satisfy a mutation. */
    if (ctx->conf->rootfd < 0) {
        return ngx_brix_cms_send_error(ctx, streamid, CMS_ERR_EINVAL,
                                         "no local storage");
    }

    /* A non-POSIX export (pblock/object) routes the mutation through its driver's
     * namespace slots; the default POSIX export keeps the confined *_beneath path
     * unchanged. */
    sd = brix_vfs_backend_resolve(ctx->conf->common.root_canon,
                                  ctx->cycle->log);
    if (sd != NULL && sd->driver != brix_sd_default_driver()) {
        return cms_forward_via_driver(ctx, sd, code, streamid, &plan);
    }

    return cms_forward_via_posix(ctx, code, streamid, &plan);
}

/* cms_wake_pending_session — parse the first host:port from a kYR_select/kYR_try
 * payload and wake the suspended XRootD client waiting on its locate: look up the
 * pending entry by streamid+pid, resolve its saved fd to the live connection (same
 * worker, per-worker design), set XRD_ST_REQ_HEADER, brix_send_redirect to the
 * resolved server, and resume reading. */

static ngx_int_t
cms_wake_pending_session(ngx_brix_cms_ctx_t *cms_ctx, uint32_t streamid,
    const char *host, uint16_t port)
{
    brix_pending_locate_t  *pending;
    ngx_connection_t         *client_conn;
    ngx_stream_session_t     *session;
    brix_ctx_t             *xrd_ctx;
    int                       conn_fd;
    ngx_atomic_uint_t         conn_number;
    u_char                    client_streamid[2];

    pending = brix_pending_lookup(streamid, ngx_pid);
    if (pending == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cms_ctx->cycle->log, 0,
                       "brix: CMS wake: streamid=%uD not found in pending table",
                       streamid);
        return NGX_OK;  /* session timed out and was already removed */
    }

    conn_fd = pending->conn_fd;
    conn_number = pending->conn_number;
    client_streamid[0] = pending->client_streamid[0];
    client_streamid[1] = pending->client_streamid[1];
    brix_pending_unlock();

    brix_pending_remove(streamid, ngx_pid);

    client_conn = cms_find_client_connection(conn_fd);
    if (client_conn == NULL || client_conn->number != conn_number) {
        return NGX_OK;  /* fd was recycled after the client disconnected */
    }

    session = client_conn->data;
    if (session == NULL) {
        return NGX_OK;
    }

    xrd_ctx = ngx_stream_get_module_ctx(session, ngx_stream_brix_module);
    if (xrd_ctx == NULL || xrd_ctx->state != XRD_ST_WAITING_CMS) {
        return NGX_OK;
    }

    /*
     * WS6: the redirect host comes straight from the manager's kYR_select /
     * kYR_try payload and is copied verbatim into the "Shost:port" redirect the
     * client parses.  A compromised/hostile manager could inject control bytes or
     * an alternate scheme here, so validate it with the same character allowlist
     * the registry uses as its store choke point (brix_net_host_chars_valid).
     * On reject, drop the redirect and leave the client in XRD_ST_WAITING_CMS to
     * hit its own cms_locate_timeout — we never emit a poisoned host.
     */
    if (host == NULL
        || !brix_net_host_chars_valid(host, ngx_strlen(host)))
    {
        char  safe[256];
        brix_sanitize_log_string(host, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_WARN, cms_ctx->cycle->log, 0,
                      "brix: CMS select: rejected redirect to invalid host "
                      "\"%s\" for fd=%d", safe, conn_fd);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, cms_ctx->cycle->log, 0,
                  "brix: CMS select: redirecting client fd=%d to %s:%u",
                  conn_fd, host, (unsigned) port);

    ngx_del_timer(client_conn->read);
    xrd_ctx->state = XRD_ST_REQ_HEADER;
    xrd_ctx->recv.cur_streamid[0] = client_streamid[0];
    xrd_ctx->recv.cur_streamid[1] = client_streamid[1];
    if (brix_send_redirect(xrd_ctx, client_conn, host, port) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, cms_ctx->cycle->log, 0,
                      "brix: CMS select: failed to queue redirect for fd=%d",
                      conn_fd);
        return NGX_ERROR;
    }
    brix_schedule_read_resume(client_conn);
    return NGX_OK;
}

static ngx_connection_t *
cms_find_client_connection(int fd)
{
    ngx_uint_t        i;
    ngx_connection_t *c;

    if (fd < 0) {
        return NULL;
    }

    if (ngx_cycle->files != NULL && (ngx_uint_t) fd < ngx_cycle->files_n) {
        c = ngx_cycle->files[fd];
        if (c != NULL && c->fd == fd) {
            return c;
        }
        return NULL;
    }

    for (i = 0; i < ngx_cycle->connection_n; i++) {
        c = &ngx_cycle->connections[i];
        if (c->fd == fd) {
            return c;
        }
    }

    return NULL;
}

/* cms_frame_ping — kYR_ping: answer the manager's liveness probe with a PONG
 * echoing the streamid. Table adapter around ngx_brix_cms_send_pong. */
static ngx_int_t
cms_frame_ping(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    return ngx_brix_cms_send_pong(ctx, streamid);
}

/* cms_frame_space — kYR_space: report export free space with an AVAIL reply.
 * Table adapter around ngx_brix_cms_send_avail. */
static ngx_int_t
cms_frame_space(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    return ngx_brix_cms_send_avail(ctx, streamid);
}

/* cms_frame_status — kYR_status: the manager flips our login gate. The modifier
 * byte (offset 5) selects suspend (pause new logins) or resume; any other
 * modifier is a no-op, matching stock cmsd. */
static ngx_int_t
cms_frame_status(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    u_char mod = ctx->inbuf[5];
    if (mod & CMS_ST_SUSPEND) {
        ctx->conf->cms.suspended = 1;
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                      "brix: CMS suspend received — new logins paused");
    } else if (mod & CMS_ST_RESUME) {
        ctx->conf->cms.suspended = 0;
        ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                      "brix: CMS resume received — accepting logins");
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "brix: CMS status modifier=0x%02xi (no action)",
                       (ngx_uint_t) mod);
    }
    return NGX_OK;
}

/* cms_frame_redirect — kYR_select / kYR_try: the manager resolved a pending
 * kYR_locate and names a server.  Both payloads carry a NUL-terminated hostname
 * + 2-byte big-endian port (kYR_try is an ordered list of such entries — use
 * only the first; the client retries remaining entries itself), so one handler
 * serves both opcodes.  Truncated payloads are silently ignored. */
static ngx_int_t
cms_frame_redirect(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    const u_char  *payload = ctx->inbuf + NGX_BRIX_CMS_HDR_LEN;
    size_t         payload_len = ctx->in_need - NGX_BRIX_CMS_HDR_LEN;
    char           host[256];
    size_t         host_len;
    uint16_t       port;

    if (payload_len < 3) {
        /* need at least one host byte, a NUL, and two port bytes */
        return NGX_OK;
    }

    ngx_cpystrn((u_char *) host, (u_char *) payload, sizeof(host));
    host_len = ngx_strlen(host);

    if (host_len + 3 > payload_len) {
        /* port bytes would fall outside the received payload */
        return NGX_OK;
    }

    port = ngx_brix_cms_get16(payload + host_len + 1);
    return cms_wake_pending_session(ctx, streamid, host, port);
}

/* cms_state_extract_path — pure validation of a kYR_state payload: bound the
 * NUL-terminated namespace path, require an absolute path that fits the buffer,
 * and reject any ".." traversal before the registry/filesystem is touched
 * (cheap defence-in-depth ahead of the kernel-confined probe). Copies the
 * NUL-terminated path into pathz and returns its length via *pl_out; returns
 * NGX_OK or NGX_ERROR (caller stays silent, matching real cmsd). */
static ngx_int_t
cms_state_extract_path(const u_char *payload, size_t plen, char *pathz,
    size_t pathz_size, size_t *pl_out)
{
    size_t  pl;
    size_t  k;

    /* bounded length of the NUL-terminated path */
    for (pl = 0; pl < plen && payload[pl] != '\0'; pl++) { /* void */ }
    if (pl == 0 || payload[0] != '/' || pl >= pathz_size) {
        return NGX_ERROR;
    }

    /* reject path traversal before touching the registry/filesystem */
    for (k = 0; k + 1 < pl; k++) {
        if (payload[k] == '.' && payload[k + 1] == '.') {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(pathz, payload, pl);
    pathz[pl] = '\0';
    *pl_out = pl;
    return NGX_OK;
}

/* cms_frame_state — kYR_state (raw): the manager asks "do you hold <path>?" as
 * part of on-demand selection.  The payload is the raw NUL-terminated namespace
 * path (no Pup framing).  We answer kYR_have (echoing streamid = path hash) if
 * we can serve the path, else stay silent so the manager won't select us —
 * matching real cmsd.
 *
 * Two ways to "have" a path:
 *   - manager_mode (a sub-manager registered UP to a meta-manager): forward the
 *     query to our own server registry — if any registered leaf data node
 *     exports a prefix covering the path, we have it (the client will be
 *     redirected to us and we then redirect down to the leaf).  This is what
 *     makes a multi-tier meta->nginx->leaf mesh resolve.
 *   - data node: the file exists on our local export filesystem. */
static ngx_int_t
cms_frame_state(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    const u_char  *payload = ctx->inbuf + NGX_BRIX_CMS_HDR_LEN;
    size_t         plen = ctx->in_need - NGX_BRIX_CMS_HDR_LEN;
    char           pathz[1024];
    size_t         pl;
    struct stat    st;

    if (cms_state_extract_path(payload, plen, pathz, sizeof(pathz), &pl)
        != NGX_OK)
    {
        return NGX_OK;
    }

    if (ctx->conf->manager_mode) {
        char      host[256];
        uint16_t  dport;
        if (brix_srv_select(pathz, 0, host, sizeof(host), &dport)) {
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "brix: CMS state(mgr): registry serves "
                           "\"%*s\", replying kYR_have", pl, payload);
            return ngx_brix_cms_send_have(ctx, streamid, pathz, pl);
        }
        return NGX_OK;
    }

    /*
     * Kernel-confined existence probe.  A malicious manager can ask
     * "do you hold <path>?" for ANY path; the raw stat() this replaced
     * followed symlinks, so a symlink planted under the export root
     * (e.g. /link -> /etc) would make us answer kYR_have for a file
     * OUTSIDE the root — a cross-root information leak and a
     * cluster-poisoning vector.  brix_stat_beneath() resolves the
     * path under the persistent export rootfd with openat2
     * RESOLVE_BENEATH, so any symlink or ".." that escapes the root is
     * rejected by the kernel and we correctly stay silent.  (The ".."
     * pre-check in cms_state_extract_path remains as cheap
     * defence-in-depth.)  A node with no local export root (rootfd < 0)
     * never holds files locally.
     */
    if (ctx->conf->rootfd >= 0
        && brix_stat_beneath(ctx->conf->rootfd, pathz, &st) == 0)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "brix: CMS state: have \"%*s\", "
                       "replying kYR_have", pl, payload);
        return ngx_brix_cms_send_have(ctx, streamid, pathz, pl);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS state: do not have \"%*s\"",
                   pl, payload);
    return NGX_OK;
}

/* cms_frame_forward — kYR_chmod/mkdir/mkpath/mv/rm/rmdir/trunc (Plane B): a
 * manager-forwarded namespace mutation.  Execute it under kernel confinement
 * and reply silent-on-success / kYR_error-on-failure. */
static ngx_int_t
cms_frame_forward(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    const u_char  *payload = ctx->inbuf + NGX_BRIX_CMS_HDR_LEN;
    size_t         plen    = ctx->in_need - NGX_BRIX_CMS_HDR_LEN;
    return cms_node_exec_forward(ctx, code, streamid, payload, plen);
}

/* cms_frame_update — kYR_update: manager asks us to resend state
 * (do_Update -> sendState). */
static ngx_int_t
cms_frame_update(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS node: update -> status");
    return ngx_brix_cms_send_status(ctx);
}

/* cms_frame_disc — kYR_disc: manager requested disconnect (do_Disc on a node
 * simply closes); tear down and schedule the reconnect backoff. */
static ngx_int_t
cms_frame_disc(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                  "brix: CMS node: manager requested disconnect");
    ngx_brix_cms_set_end_hint(ctx, BRIX_SESS_END_SERVER);
    ngx_brix_cms_disconnect(ctx);
    ngx_brix_cms_schedule_retry(ctx);
    return NGX_OK;
}

/* cms_frame_handler_pt — per-opcode frame handler: the complete frame sits in
 * ctx->inbuf (ctx->in_need bytes); streamid/code are pre-decoded from the
 * header.  Handlers derive their payload view from ctx themselves. */
typedef ngx_int_t (*cms_frame_handler_pt)(ngx_brix_cms_ctx_t *ctx,
    uint32_t streamid, u_char code);

/* cms_frame_table — node-role opcode dispatch descriptors (order-independent:
 * codes are distinct; the scan is a handful of entries on a cluster-control
 * path, so linear lookup is fine).  Unknown opcodes fall through to the
 * silent-ignore default in ngx_brix_cms_process_frame. */
static const struct {
    u_char                code;
    cms_frame_handler_pt  handler;
} cms_frame_table[] = {
    { CMS_RR_PING,   cms_frame_ping     },
    { CMS_RR_SPACE,  cms_frame_space    },
    { CMS_RR_STATUS, cms_frame_status   },
    { CMS_RR_SELECT, cms_frame_redirect },
    { CMS_RR_TRY,    cms_frame_redirect },
    { CMS_RR_STATE,  cms_frame_state    },
    { CMS_RR_CHMOD,  cms_frame_forward  },
    { CMS_RR_MKDIR,  cms_frame_forward  },
    { CMS_RR_MKPATH, cms_frame_forward  },
    { CMS_RR_MV,     cms_frame_forward  },
    { CMS_RR_RM,     cms_frame_forward  },
    { CMS_RR_RMDIR,  cms_frame_forward  },
    { CMS_RR_TRUNC,  cms_frame_forward  },
    { CMS_RR_UPDATE, cms_frame_update   },
    { CMS_RR_DISC,   cms_frame_disc     },
};

/* ngx_brix_cms_process_frame — decode a complete CMS frame's streamid + rrCode
 * (first 4 bytes + offset 4) and dispatch by opcode through cms_frame_table:
 * PING→PONG, SPACE→AVAIL, STATUS→suspend/resume conf flags, SELECT/TRY→client
 * redirect, STATE→kYR_have probe, forwarded namespace ops, UPDATE, DISC.
 * Unknown opcodes are silently ignored (debug log). */

static ngx_int_t
ngx_brix_cms_process_frame(ngx_brix_cms_ctx_t *ctx)
{
    uint32_t                  streamid;
    u_char                    code;
    ngx_uint_t                i;
    const brix_cms_route_t *r;

    streamid = ngx_brix_cms_get32(ctx->inbuf);
    code = ctx->inbuf[4];

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS process frame code=%ui streamid=%uD",
                   (ngx_uint_t) code, streamid);

    for (i = 0; i < sizeof(cms_frame_table) / sizeof(cms_frame_table[0]); i++) {
        if (cms_frame_table[i].code == code) {
            return cms_frame_table[i].handler(ctx, streamid, code);
        }
    }

    r = brix_cms_route_lookup(XRDCMS_ROLE_NODE, code);
    if (r != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "brix: CMS node: unhandled opcode '%s'", r->name);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "brix: ignoring CMS rrCode=%ui", (ngx_uint_t) code);
    }
    return NGX_OK;
}

/* cms_conn_fail — shared manager-connection teardown: record why the session
 * ended, drop the connection, and schedule the reconnect backoff.  The three
 * always travel together on every read-side failure path; callers do their own
 * logging/metrics first (the hint is the only per-site variation). */
static void
cms_conn_fail(ngx_brix_cms_ctx_t *ctx, brix_sess_end_t end_hint)
{
    ngx_brix_cms_set_end_hint(ctx, end_hint);
    ngx_brix_cms_disconnect(ctx);
    ngx_brix_cms_schedule_retry(ctx);
}

/* cms_recv_accumulate — buffer/framing half of the read handler: recv into
 * ctx->inbuf until one complete frame (header + dlen payload) is buffered,
 * growing ctx->in_need from header-size to full-frame-size once the header's
 * dlen is known and rejecting oversized frames.  Returns NGX_OK with a complete
 * frame in ctx->inbuf[0..in_need), NGX_AGAIN when the socket drains first, or
 * NGX_ERROR after tearing the connection down itself (EOF/error/too-large).
 * Splitting accumulation from dispatch keeps each half independently
 * reviewable. */
static ngx_int_t
cms_recv_accumulate(ngx_brix_cms_ctx_t *ctx, ngx_connection_t *c,
    ngx_event_t *ev)
{
    ssize_t   n;
    uint16_t  dlen;

    for ( ;; ) {
        n = c->recv(c, ctx->inbuf + ctx->in_pos,
                    ctx->in_need - ctx->in_pos);

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                           "brix: CMS recv EOF/error, disconnecting");
            cms_conn_fail(ctx, n == 0 ? BRIX_SESS_END_SERVER
                                      : BRIX_SESS_END_ERROR);
            return NGX_ERROR;
        }

        ctx->in_pos += (size_t) n;

        if (ctx->in_pos < ctx->in_need) {
            continue;
        }

        if (ctx->in_need == NGX_BRIX_CMS_HDR_LEN) {
            dlen = ngx_brix_cms_get16(ctx->inbuf + 6);

            if ((size_t) dlen + NGX_BRIX_CMS_HDR_LEN
                > NGX_BRIX_CMS_MAX_FRAME)
            {
                ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                              "brix: CMS frame too large: %ui",
                              (ngx_uint_t) dlen);
                cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
                return NGX_ERROR;
            }

            ctx->in_need = NGX_BRIX_CMS_HDR_LEN + dlen;
            if (ctx->in_pos < ctx->in_need) {
                continue;
            }
        }

        return NGX_OK;
    }
}

/* ngx_brix_cms_read_handler — read event handler for the manager connection:
 * accumulate bytes to a complete frame via cms_recv_accumulate() and dispatch
 * each frame via ngx_brix_cms_process_frame(); disconnect and retry on
 * timeout/error. */

void
ngx_brix_cms_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_brix_cms_ctx_t  *ctx;
    ngx_int_t              rc;
    ngx_uint_t             processed = 0;

    c = ev->data;
    ctx = c->data;

    if (ctx == NULL || ctx->connection != c) {
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "brix: CMS read handler timedout=%d in_pos=%uz in_need=%uz",
                   (int) ev->timedout, ctx->in_pos, ctx->in_need);

    if (ev->timedout) {
        /*
         * WS1: the manager went silent past cms_read_timeout (black-holed /
         * half-open).  Tear down and reconnect with backoff so we fail over
         * instead of heartbeating into a dead socket forever.
         */
        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "brix: CMS manager silent past read timeout — "
                      "reconnecting");
        BRIX_RESIL_METRIC_INC(cms_read_timeouts_total);
        cms_conn_fail(ctx, BRIX_SESS_END_TIMEOUT);
        return;
    }

    for ( ;; ) {
        rc = cms_recv_accumulate(ctx, c, ev);
        if (rc == NGX_AGAIN) {
            break;
        }
        if (rc != NGX_OK) {
            return;   /* accumulate already tore the connection down */
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "brix: CMS process_frame code=%ui",
                       (ngx_uint_t) ctx->inbuf[4]);

        if (ngx_brix_cms_process_frame(ctx) != NGX_OK) {
            cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
            return;
        }

        ctx->in_pos = 0;
        ctx->in_need = NGX_BRIX_CMS_HDR_LEN;

        /* WS1: a frame from the manager proves it is alive — reset the silence
         * deadline so a responsive manager is never reconnected. */
        ngx_brix_cms_arm_read_deadline(ctx);

        /* A2: fairness — after a bounded number of frames, yield the worker to
         * other connections and resume via a posted read event, so a flooding
         * manager cannot monopolise the event loop. */
        if (++processed >= NGX_BRIX_CMS_MAX_FRAMES_PER_WAKEUP) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
                return;
            }
            BRIX_RESIL_METRIC_INC(cms_frame_yields_total);
            ngx_post_event(c->read, &ngx_posted_events);
            return;
        }
    }

    if (ctx->connection != NULL
        && ngx_handle_read_event(c->read, 0) != NGX_OK)
    {
        cms_conn_fail(ctx, BRIX_SESS_END_ERROR);
    }
}
