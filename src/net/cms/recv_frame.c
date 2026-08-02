/*
 * cms/recv_frame.c — opcode frame handlers + dispatch for the CMS client-side
 * (manager-connection) receive path.
 *
 * WHAT: The per-opcode handlers a connected CMS node runs on frames from its
 * manager — PING→PONG, SPACE→AVAIL, STATUS→suspend/resume, SELECT/TRY→redirect
 * a waiting client, STATE→kYR_have existence probe, forwarded namespace ops,
 * UPDATE, DISC — plus the pending-client redirect/wake plumbing
 * (brix_cms_wake_pending_session / brix_cms_client_conn_by_fd), the frame dispatch
 * table, and the router ngx_brix_cms_process_frame().
 *
 * WHY: Split (Phase-79 file-size split) from recv.c so the opcode-handler set
 * and its dispatch table live in one focused, independently reviewable file
 * under the size guideline, separate from the read/framing event loop (recv.c)
 * and the Plane-B storage-mutation executor (recv_forward.c).  The one entry
 * point the read loop calls (ngx_brix_cms_process_frame) is declared in
 * recv_internal.h; the forwarded-op executor it invokes (cms_node_exec_forward)
 * is declared there too.
 *
 * HOW: cms_frame_* handlers share the cms_frame_handler_pt signature and derive
 * their payload view from ctx; cms_frame_table maps opcode → handler;
 * ngx_brix_cms_process_frame decodes the header's streamid/rrCode and dispatches
 * through the table, silently ignoring unknown opcodes.
 */

#include "cms_internal.h"
#include "recv_internal.h"
#include "node_ops.h"               /* Plane B forwarded-op planner */
#include "router.h"                 /* node-role opcode routing */
#include "rrdata.h"                 /* Pup decode for supervisor fan-down */
#include "forward.h"                /* per-node forwarded-op re-emit */
#include "server.h"                 /* child node list (supervisor role) */
#include "state_relay.h"            /* multi-tier kYR_state recursion */
#include "net/manager/pending.h"
#include "net/manager/registry.h"
#include "fs/path/beneath.h"
#include "fs/path/path.h"           /* brix_sanitize_log_string (WS6) */
#include "core/compat/net_target.h"   /* brix_net_host_chars_valid (WS6) */

#include <errno.h>
#include <unistd.h>

/* Resolve a saved client fd to its live connection (recycle-guarded by the
 * caller via c->number).  Exported (recv_internal.h) since Phase-89 W8: the
 * rm/rmdir fan-out finalizer (fanout.c) resolves its parked client the same
 * way the locate wake below does. */
ngx_connection_t *
brix_cms_client_conn_by_fd(int fd)
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

/* brix_cms_wake_pending_session — wake the suspended XRootD client waiting on
 * a pending locate: look up the pending entry by streamid+pid, resolve its
 * saved fd to the live connection (same worker, per-worker design), set
 * XRD_ST_REQ_HEADER, brix_send_redirect to the resolved server, and resume
 * reading.  Exported (recv_internal.h) because two ingest paths converge on it:
 * kYR_select/kYR_try from a parent manager (this file) and — Phase-89 W3 —
 * kYR_have from a child node (server_recv_frame.c, state fan-out wake). */

ngx_int_t
brix_cms_wake_pending_session(ngx_log_t *log, uint32_t streamid,
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
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, log, 0,
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

    client_conn = brix_cms_client_conn_by_fd(conn_fd);
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
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: CMS select: rejected redirect to invalid host "
                      "\"%s\" for fd=%d", safe, conn_fd);
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix: CMS select: redirecting client fd=%d to %s:%u",
                  conn_fd, host, (unsigned) port);

    ngx_del_timer(client_conn->read);
    xrd_ctx->state = XRD_ST_REQ_HEADER;
    xrd_ctx->recv.cur_streamid[0] = client_streamid[0];
    xrd_ctx->recv.cur_streamid[1] = client_streamid[1];
    if (brix_send_redirect(xrd_ctx, client_conn, host, port) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix: CMS select: failed to queue redirect for fd=%d",
                      conn_fd);
        return NGX_ERROR;
    }
    brix_schedule_read_resume(client_conn);
    return NGX_OK;
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

/* cms_frame_stats — kYR_stats: answer the manager's statistics query with the
 * Cluster.Stats document (size form only when the kYR_size modifier at offset
 * 5 is set). Table adapter around ngx_brix_cms_send_stats. */
static ngx_int_t
cms_frame_stats(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    return ngx_brix_cms_send_stats(ctx, streamid, ctx->inbuf[5]);
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
    return brix_cms_wake_pending_session(ctx->cycle->log, streamid, host, port);
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

        /*
         * Phase-61 W7: registry miss.  With brix_cms_state_relay on, recurse
         * — park the parent's leg and re-ask our own nodes; the first child
         * kYR_have (server-leg ingest) is echoed back up under the parent's
         * streamid.  Off, or table full, or no child took the probe: stay
         * silent, which the parent reads as "not here" (stock semantics).
         */
        if (ctx->conf->cms.state_relay) {
            uint32_t              down_sid;
            ngx_uint_t            i, sent = 0;
            brix_cms_srv_ctx_t   *node;

            down_sid = brix_cms_state_relay_add(ctx, streamid, pathz);
            if (down_sid == 0) {
                return NGX_OK;
            }
            for (i = 0; i < brix_cms_srv_node_count(); i++) {
                node = brix_cms_srv_node_at(i);
                if (node == NULL || !node->logged_in || node->c == NULL) {
                    continue;
                }
                if (brix_cms_srv_send_state(node, down_sid, pathz) == NGX_OK) {
                    sent++;
                }
            }
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                           "brix: CMS state(mgr): relayed \"%s\" down to "
                           "%ui node(s)", pathz, sent);
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

/* cms_super_fan_down — Phase-61 W7: an explicit supervisor pushes a manager-
 * forwarded namespace op DOWN to its own logged-in data nodes instead of
 * executing it locally (supVOps marks these Forward in stock cmsd's
 * initSUProuting).  The Pup payload is decoded once and re-encoded per child
 * hop; rrdata spans are NUL-terminated in place on the wire, so they pass
 * straight through as C strings.  Silent toward the manager either way —
 * per-child failures are the child's to report on its own leg. */
static ngx_int_t
cms_super_fan_down(ngx_brix_cms_ctx_t *ctx, u_char code,
    const u_char *payload, size_t plen)
{
    brix_cms_rrdata_t     rr;
    brix_cms_srv_ctx_t   *node;
    ngx_uint_t            i, sent;
    uint32_t              sid;

    if (brix_cms_rrdata_parse(code, payload, plen, &rr) != 0) {
        ngx_log_error(NGX_LOG_WARN, ctx->cycle->log, 0,
                      "brix: CMS super: malformed forwarded op=%ui — dropped",
                      (ngx_uint_t) code);
        return NGX_OK;
    }

    sid = brix_cms_srv_next_streamid();
    sent = 0;

    for (i = 0; i < brix_cms_srv_node_count(); i++) {
        node = brix_cms_srv_node_at(i);
        if (node == NULL || !node->logged_in || node->c == NULL) {
            continue;
        }
        if (brix_cms_forward_to_node(node->c, code, sid,
                                     (const char *) rr.ident,
                                     (const char *) rr.path,
                                     (const char *) rr.path2,
                                     (const char *) rr.mode,
                                     (const char *) rr.opaque) == NGX_OK)
        {
            sent++;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                   "brix: CMS super: forwarded op=%ui down to %ui node(s)",
                   (ngx_uint_t) code, sent);
    return NGX_OK;
}

/* cms_frame_forward — kYR_chmod/mkdir/mkpath/mv/rm/rmdir/trunc (Plane B): a
 * manager-forwarded namespace mutation.  An explicit supervisor relays it down
 * to its own data nodes (cms_super_fan_down); every other role executes it
 * locally under kernel confinement and replies silent-on-success /
 * kYR_error-on-failure. */
static ngx_int_t
cms_frame_forward(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    const u_char  *payload = ctx->inbuf + NGX_BRIX_CMS_HDR_LEN;
    size_t         plen    = ctx->in_need - NGX_BRIX_CMS_HDR_LEN;

    if (ctx->conf->cms.role == BRIX_CMS_ROLE_SUPERVISOR) {
        return cms_super_fan_down(ctx, code, payload, plen);
    }

    return cms_node_exec_forward(ctx, code, streamid, payload, plen);
}

/* cms_frame_prepare — kYR_prepadd/kYR_prepdel (Plane B staging): a manager-
 * forwarded stage-in admission or cancellation.  Routed to the registry-backed
 * executor in recv_prepare.c. */
static ngx_int_t
cms_frame_prepare(ngx_brix_cms_ctx_t *ctx, uint32_t streamid, u_char code)
{
    const u_char  *payload = ctx->inbuf + NGX_BRIX_CMS_HDR_LEN;
    size_t         plen    = ctx->in_need - NGX_BRIX_CMS_HDR_LEN;
    return cms_node_exec_prepare(ctx, code, streamid, payload, plen);
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
    { CMS_RR_STATS,  cms_frame_stats    },
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
    { CMS_RR_PREPADD, cms_frame_prepare },
    { CMS_RR_PREPDEL, cms_frame_prepare },
    { CMS_RR_UPDATE, cms_frame_update   },
    { CMS_RR_DISC,   cms_frame_disc     },
};

/* cms_frame_role_ok — Phase-61 W7 valid-ops gate: under an explicit
 * brix_cms_role, only the ops in that role's upward-leg table (manVOps for a
 * sub-manager, supVOps for a supervisor) may arrive from the parent manager —
 * stock cmsd "prohibit[s] a meta-manager from requesting potentially
 * destructive actions".  kYR_select / kYR_try are exempt: they are the
 * streamid-correlated replies to our own kYR_locate, not parent requests.
 * Role auto keeps the legacy accept-everything behaviour. */
static ngx_uint_t
cms_frame_role_ok(ngx_brix_cms_ctx_t *ctx, u_char code)
{
    brix_cms_role_t  role;

    switch (ctx->conf->cms.role) {
    case BRIX_CMS_ROLE_MANAGER:
        role = XRDCMS_ROLE_SUBMAN;
        break;
    case BRIX_CMS_ROLE_SUPERVISOR:
        role = XRDCMS_ROLE_SUPER;
        break;
    default:
        return 1;
    }

    if (code == CMS_RR_SELECT || code == CMS_RR_TRY) {
        return 1;
    }

    if (brix_cms_route_lookup(role, code) != NULL) {
        return 1;
    }

    ngx_log_error(NGX_LOG_NOTICE, ctx->cycle->log, 0,
                  "brix: CMS %s: manager sent an invalid request "
                  "(op=%ui) — dropped",
                  role == XRDCMS_ROLE_SUBMAN ? "subman" : "super",
                  (ngx_uint_t) code);
    return 0;
}

/* ngx_brix_cms_process_frame — decode a complete CMS frame's streamid + rrCode
 * (first 4 bytes + offset 4), apply the per-role valid-ops gate
 * (cms_frame_role_ok), and dispatch by opcode through cms_frame_table:
 * PING→PONG, SPACE→AVAIL, STATS→Cluster.Stats, STATUS→suspend/resume conf
 * flags, SELECT/TRY→client redirect, STATE→kYR_have probe, forwarded
 * namespace ops, UPDATE, DISC. Unknown opcodes are silently ignored (debug
 * log). */

ngx_int_t
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

    if (!cms_frame_role_ok(ctx, code)) {
        return NGX_OK;                    /* logged + dropped, conn kept */
    }

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
