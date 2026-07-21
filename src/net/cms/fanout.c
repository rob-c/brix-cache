/*
 * cms/fanout.c — Phase-89 W8: manager-side rm/rmdir fan-out to all holders.
 *
 * WHAT: Forwards a manager-mode client kXR_rm/kXR_rmdir to every registered
 * node whose exports cover the path (brix_cms_forward_to_node over this
 * worker's accepted CMS connections), parks the client, aggregates the nodes'
 * replies over a deadline window, and answers the client once — kXR_ok when no
 * node errored, else kXR_error carrying the first node error's text.
 *
 * WHY: with replicated exports the shipped single-node redirect deletes one
 * replica and strands the rest — stock cmsd fans namespace deletes out to all
 * holders.  See fanout.h for the WHY of the window design (the node executor
 * is silent on success, so "no error before the deadline" IS the success
 * signal, matching stock ofs.forward semantics).
 *
 * HOW: a small per-worker slot table keyed by the CMS streamid carries the
 * aggregation state (expected/got_err/worst error + a deadline ngx_event_t);
 * the client's identity rides the shared pending-locate table exactly like a
 * parked locate, so the finalizer reuses the same recycle-guarded wake shape
 * as brix_cms_wake_pending_session (fd + c->number + XRD_ST_WAITING_CMS).
 * kYR_error replies arrive in server_recv_frame.c (CMS_RSP_ERROR route) and
 * fold in through brix_cms_fanout_note_error.  Per-worker by design: fan-out
 * only engages when THIS worker owns a CMS connection to EVERY registry
 * holder of the path, so replies and the parked client share one worker.
 */

#include "fanout.h"
#include "cms_internal.h"
#include "server.h"                       /* per-worker node list */
#include "forward.h"                      /* brix_cms_forward_to_node */
#include "recv_internal.h"                /* brix_cms_client_conn_by_fd */
#include "net/manager/pending.h"
#include "net/manager/registry.h"          /* paths_cover / blacklist / count */
#include "protocols/root/protocol/opcodes.h"
#include "protocols/root/response/response.h"
#include "protocols/root/connection/event_sched.h"

#define BRIX_CMS_FANOUT_SLOTS  16   /* concurrent in-flight fan-outs / worker */
#define BRIX_CMS_FANOUT_NODES  32   /* holder connections per fan-out */

typedef struct {
    uint32_t     sid;            /* CMS streamid correlating node replies    */
    ngx_uint_t   expected;       /* nodes the op was actually sent to        */
    ngx_uint_t   got_err;        /* kYR_error replies folded so far          */
    uint32_t     worst_err;      /* first error's code (0 = none yet)        */
    char         errtext[128];   /* first error's sanitized text             */
    ngx_event_t  deadline;       /* window timer; firing finalizes           */
    ngx_uint_t   in_use;
} brix_cms_fanout_slot_t;

static brix_cms_fanout_slot_t  brix_fanout_slots[BRIX_CMS_FANOUT_SLOTS];

static void brix_cms_fanout_finalize(brix_cms_fanout_slot_t *slot,
    ngx_log_t *log);

/* Deadline-timer adapter: the window elapsed with fewer errors than forwards
 * outstanding — whatever folded in by now is the verdict. */
static void
brix_cms_fanout_deadline(ngx_event_t *ev)
{
    brix_cms_fanout_finalize(ev->data, ev->log);
}

static brix_cms_fanout_slot_t *
brix_cms_fanout_slot_get(uint32_t sid)
{
    ngx_uint_t  i;

    for (i = 0; i < BRIX_CMS_FANOUT_SLOTS; i++) {
        if (brix_fanout_slots[i].in_use && brix_fanout_slots[i].sid == sid) {
            return &brix_fanout_slots[i];
        }
    }
    return NULL;
}

static void
brix_cms_fanout_slot_free(brix_cms_fanout_slot_t *slot)
{
    if (slot->deadline.timer_set) {
        ngx_del_timer(&slot->deadline);
    }
    slot->in_use = 0;
}

/*
 * Answer the parked client from the folded slot state and release the slot.
 * Mirrors brix_cms_wake_pending_session's recycle-guarded resolution: the fd
 * and connection generation ride the pending table; a client that timed out
 * or disconnected meanwhile makes every guard a clean no-op (the deletes on
 * the nodes have already happened either way — this only settles the reply).
 */
static void
brix_cms_fanout_finalize(brix_cms_fanout_slot_t *slot, ngx_log_t *log)
{
    brix_pending_locate_t  *pending;
    ngx_connection_t         *client_conn;
    ngx_stream_session_t     *session;
    brix_ctx_t             *xrd_ctx;
    int                       conn_fd;
    ngx_atomic_uint_t         conn_number;
    u_char                    client_streamid[2];

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix: CMS fan-out: finalize sid=%uD errors %ui/%ui",
                  slot->sid, slot->got_err, slot->expected);

    pending = brix_pending_lookup(slot->sid, ngx_pid);
    if (pending == NULL) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "brix: CMS fan-out: sid=%uD client already gone "
                      "(errors %ui/%ui)", slot->sid, slot->got_err,
                      slot->expected);
        brix_cms_fanout_slot_free(slot);
        return;
    }

    conn_fd = pending->conn_fd;
    conn_number = pending->conn_number;
    client_streamid[0] = pending->client_streamid[0];
    client_streamid[1] = pending->client_streamid[1];
    brix_pending_unlock();
    brix_pending_remove(slot->sid, ngx_pid);

    client_conn = brix_cms_client_conn_by_fd(conn_fd);
    if (client_conn == NULL || client_conn->number != conn_number) {
        brix_cms_fanout_slot_free(slot);
        return;
    }

    session = client_conn->data;
    if (session == NULL) {
        brix_cms_fanout_slot_free(slot);
        return;
    }

    xrd_ctx = ngx_stream_get_module_ctx(session, ngx_stream_brix_module);
    if (xrd_ctx == NULL || xrd_ctx->state != XRD_ST_WAITING_CMS
        || xrd_ctx->cms_wait_streamid != slot->sid)
    {
        brix_cms_fanout_slot_free(slot);
        return;
    }

    if (client_conn->read->timer_set) {
        ngx_del_timer(client_conn->read);
    }
    xrd_ctx->state = XRD_ST_REQ_HEADER;
    xrd_ctx->recv.cur_streamid[0] = client_streamid[0];
    xrd_ctx->recv.cur_streamid[1] = client_streamid[1];

    if (slot->worst_err == 0) {
        (void) brix_send_ok(xrd_ctx, client_conn, NULL, 0);
    } else {
        (void) brix_send_error(xrd_ctx, client_conn, kXR_FSError,
                                 slot->errtext[0] != '\0'
                                     ? slot->errtext
                                     : "forwarded operation failed");
    }

    (void) brix_schedule_read_resume(client_conn);
    brix_cms_fanout_slot_free(slot);
}

/* Map the client's request opcode to the CMS request code.  Returns 0 with
 * *code set, -1 for anything outside the v1 fan-out scope. */
static int
brix_cms_fanout_op_code(uint16_t reqid, u_char *code)
{
    switch (reqid) {
    case kXR_rm:
        *code = CMS_RR_RM;
        return 0;
    case kXR_rmdir:
        *code = CMS_RR_RMDIR;
        return 0;
    default:
        return -1;    /* v1 scope: single-path deletes only */
    }
}

/* Collect this worker's logged-in, non-blacklisted node connections whose
 * exports cover path (at most BRIX_CMS_FANOUT_NODES).  Returns the count. */
static ngx_uint_t
brix_cms_fanout_collect_eligible(const char *path, brix_cms_srv_ctx_t **elig)
{
    brix_cms_srv_ctx_t  *node;
    ngx_uint_t           i, n_elig;

    n_elig = 0;
    for (i = 0; i < brix_cms_srv_node_count()
                && n_elig < BRIX_CMS_FANOUT_NODES; i++)
    {
        node = brix_cms_srv_node_at(i);
        if (node == NULL || !node->logged_in || node->c == NULL
            || !brix_srv_paths_cover(node->paths, path)
            || brix_srv_is_blacklisted(node->host, node->port))
        {
            continue;
        }
        elig[n_elig++] = node;
    }
    return n_elig;
}

/* Grab a free aggregation slot, or NULL when the table is full. */
static brix_cms_fanout_slot_t *
brix_cms_fanout_slot_alloc(void)
{
    ngx_uint_t  i;

    for (i = 0; i < BRIX_CMS_FANOUT_SLOTS; i++) {
        if (!brix_fanout_slots[i].in_use) {
            return &brix_fanout_slots[i];
        }
    }
    return NULL;
}

/* Forward the op to every eligible node, warning per failed forward.
 * Returns how many forwards actually went out. */
static ngx_uint_t
brix_cms_fanout_send_all(brix_cms_srv_ctx_t **elig, ngx_uint_t n_elig,
    u_char code, uint32_t sid, const char *ident, const char *path,
    ngx_log_t *log)
{
    ngx_uint_t  i, sent;

    sent = 0;
    for (i = 0; i < n_elig; i++) {
        if (brix_cms_forward_to_node(elig[i]->c, code, sid, ident, path,
                                       NULL, NULL, NULL) == NGX_OK)
        {
            sent++;
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: CMS fan-out: forward of \"%s\" to %s:%d "
                          "failed", path, elig[i]->host, (int) elig[i]->port);
        }
    }
    return sent;
}

ngx_int_t
brix_cms_fanout_mutation(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *path)
{
    brix_cms_srv_ctx_t      *elig[BRIX_CMS_FANOUT_NODES];
    brix_cms_fanout_slot_t  *slot;
    ngx_uint_t               n_elig, sent;
    uint32_t                 sid;
    u_char                   code;
    char                     ident[64];

    if (!conf->cms.fanout) {
        return NGX_DECLINED;
    }

    if (brix_cms_fanout_op_code(ctx->recv.cur_reqid, &code) != 0) {
        return NGX_DECLINED;
    }

    n_elig = brix_cms_fanout_collect_eligible(path, elig);

    /* Engage only for a genuinely replicated path this worker can settle
     * alone: >=2 eligible local connections covering EVERY registry holder.
     * Any shortfall (single holder, a holder connected to another worker, a
     * drained holder) falls back to the shipped single-node redirect. */
    if (n_elig < 2 || (int) n_elig != brix_srv_count_matching(path)) {
        return NGX_DECLINED;
    }

    slot = brix_cms_fanout_slot_alloc();
    if (slot == NULL) {
        return NGX_DECLINED;    /* table full — redirect still deletes one */
    }

    sid = brix_cms_srv_next_streamid();
    if (brix_pending_insert(sid, ngx_pid, c->fd, c->number,
                              ctx->recv.cur_streamid,
                              conf->cms.fanout_window * 2) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    ngx_snprintf((u_char *) ident, sizeof(ident) - 1, "brix.%d:%d@mgr%Z",
                 (int) ngx_pid, c->fd);

    sent = brix_cms_fanout_send_all(elig, n_elig, code, sid, ident, path,
                                    c->log);

    if (sent == 0) {
        brix_pending_remove(sid, ngx_pid);
        return NGX_DECLINED;
    }

    ngx_memzero(slot, sizeof(*slot));
    slot->sid = sid;
    slot->expected = sent;
    slot->in_use = 1;
    slot->deadline.handler = brix_cms_fanout_deadline;
    slot->deadline.data = slot;
    slot->deadline.log = ngx_cycle->log;
    ngx_add_timer(&slot->deadline, conf->cms.fanout_window);

    /* Park the client exactly like a pending locate; the read timer is only
     * the backstop should the deadline event be lost (its timeout path sends
     * kXR_wait and drops the pending entry, making finalize a no-op). */
    ctx->cms_wait_streamid = sid;
    ctx->state = XRD_ST_WAITING_CMS;
    ngx_add_timer(c->read, conf->cms.fanout_window * 2);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: CMS fan-out: op=%ui \"%s\" -> %ui nodes "
                  "(sid=%uD window=%M)",
                  (ngx_uint_t) ctx->recv.cur_reqid, path, sent, sid,
                  conf->cms.fanout_window);

    return NGX_AGAIN;
}

void
brix_cms_fanout_note_error(uint32_t streamid, uint32_t ecode,
    const char *text, ngx_log_t *log)
{
    brix_cms_fanout_slot_t  *slot;
    size_t                   i;

    slot = brix_cms_fanout_slot_get(streamid);
    if (slot == NULL) {
        return;    /* late reply — the window already settled this fan-out */
    }

    slot->got_err++;
    if (slot->worst_err == 0) {
        slot->worst_err = (ecode != 0) ? ecode : 1;
        /* The text is peer-controlled and is relayed to the client verbatim:
         * keep printable ASCII (spaces included), squash everything else so
         * a hostile node cannot smuggle control bytes into the reply. */
        for (i = 0; text != NULL && text[i] != '\0'
                    && i < sizeof(slot->errtext) - 1; i++)
        {
            slot->errtext[i] = (text[i] >= 0x20 && text[i] < 0x7f)
                                   ? text[i] : '?';
        }
        slot->errtext[i] = '\0';
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: CMS fan-out: node error %ui/%ui for sid=%uD: %s",
                  slot->got_err, slot->expected, streamid,
                  slot->errtext);

    if (slot->got_err >= slot->expected) {
        brix_cms_fanout_finalize(slot, log);    /* every node answered */
    }
}
