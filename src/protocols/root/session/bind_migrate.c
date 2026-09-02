/*
 * bind_migrate.c — §1.4 cross-worker kXR_bind secondary migration.
 *
 * See bind_migrate.h for the WHAT/WHY and the safety argument.  Mechanism:
 *
 *   master (init_module, pre-fork)
 *     one AF_UNIX SOCK_SEQPACKET socketpair per worker — every forked worker
 *     inherits the full array, so any worker can sendmsg to any other.
 *
 *   worker B (kXR_bind arrives, session owned by worker A)
 *     brix_bind_migrate_try(): eligibility gates, then sendmsg the socket fd
 *     (SCM_RIGHTS) + a fixed-size message {magic, listening index, sessid,
 *     streamid} to A's channel.  B then abandons its connection without
 *     writing a byte — closing B's fd reference is safe, the in-flight
 *     SCM_RIGHTS copy keeps the socket open.
 *
 *   worker A (channel read event)
 *     brix_bind_migrate_read(): recvmsg, validate, then adopt — fabricate the
 *     ngx_connection_t / ngx_stream_session_t / brix ctx exactly as the
 *     accept path would have (the listening index resolves the same
 *     addr_conf in A's inherited cycle), stamp the bind streamid, and run
 *     brix_bind_attach() to assign the pathid, register the offload slot and
 *     send the kXR_ok reply from the owning worker.
 */

#include "core/ngx_brix_module.h"
#include "bind_migrate.h"
#include "registry.h"
#include "protocols/root/connection/handler.h"      /* recv/send handlers + adopt attach */
#include "protocols/root/connection/disconnect.h"   /* brix_on_disconnect */
#include "protocols/root/connection/fd_table.h"     /* brix_close_all_files */

#include <sys/socket.h>

#define BRIX_BIND_MIGRATE_MAX_WORKERS  64
#define BRIX_BIND_MIGRATE_MAGIC        0x424d4731u   /* "BMG1" */

typedef struct {
    uint32_t  magic;                          /* BRIX_BIND_MIGRATE_MAGIC      */
    uint32_t  ls_index;                       /* cycle->listening index at B  */
    u_char    sessid[BRIX_SESSION_ID_LEN];    /* the bind request's sessid    */
    u_char    streamid[2];                    /* the bind request's streamid  */
    u_char    pad[6];                         /* explicit padding, zeroed     */
} brix_bind_migrate_msg_t;

/* [i][0] = worker i's receive end, [i][1] = the end everyone sends to it on.
 * Created in the master before fork; each worker keeps its own receive end
 * plus every send end.  s_chan_n == 0 means migration is disabled. */
static int         s_chan[BRIX_BIND_MIGRATE_MAX_WORKERS][2];
static ngx_uint_t  s_chan_n;

/* ---- master: create the per-worker channel pairs (pre-fork) --------------
 *
 * WHAT: One SOCK_SEQPACKET socketpair per configured worker.
 * WHY : SCM_RIGHTS fd passing needs a unix socket that exists in both the
 *       sending and receiving worker — only a pre-fork fd is in both.
 * HOW : Read worker_processes from the core conf; skip (disabled) for a
 *       single worker or an over-cap count.  On reload the master runs this
 *       again: close the previous generation's fds first (old workers hold
 *       their own copies; a new generation never mixes channels with an old
 *       one).  Any failure disables migration — never fatal, the fallback is
 *       the pre-§1.4 inline-response behavior.
 */
void
brix_bind_migrate_create_channels(ngx_cycle_t *cycle)
{
    ngx_core_conf_t  *ccf;
    ngx_uint_t        i, n;

    for (i = 0; i < s_chan_n; i++) {
        (void) close(s_chan[i][0]);
        (void) close(s_chan[i][1]);
    }
    s_chan_n = 0;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (ccf == NULL || ccf->worker_processes <= 1) {
        return;                    /* single worker: nothing to migrate to */
    }
    n = (ngx_uint_t) ccf->worker_processes;
    if (n > BRIX_BIND_MIGRATE_MAX_WORKERS) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "brix: %ui workers exceed the bind-migration channel "
                      "cap (%d) — cross-worker kXR_bind secondaries will use "
                      "inline responses", n, BRIX_BIND_MIGRATE_MAX_WORKERS);
        return;
    }

    for (i = 0; i < n; i++) {
        if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, s_chan[i]) != 0
            || ngx_nonblocking(s_chan[i][0]) == -1
            || ngx_nonblocking(s_chan[i][1]) == -1)
        {
            ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                          "brix: bind-migration socketpair failed — "
                          "cross-worker secondaries will use inline responses");
            while (i-- > 0) {
                (void) close(s_chan[i][0]);
                (void) close(s_chan[i][1]);
            }
            return;
        }
    }
    s_chan_n = n;
}

static void brix_bind_migrate_read(ngx_event_t *rev);

/* ---- worker: arm this worker's channel read end --------------------------
 *
 * WHAT: Register the receive end with the event loop; drop the other
 *       workers' receive ends.
 * WHY : Only the owning worker may drain its channel; the send ends stay
 *       open everywhere so any worker can forward a bind.
 * HOW : Same ngx_get_connection + read-handler pattern as the admin socket.
 *       The ngx_worker guard also skips the cache-manager/loader processes
 *       (their ngx_worker is out of range).
 */
void
brix_bind_migrate_init_worker(ngx_cycle_t *cycle)
{
    ngx_connection_t *ch;
    ngx_uint_t        i;

    if (s_chan_n == 0 || ngx_worker >= s_chan_n) {
        return;
    }

    for (i = 0; i < s_chan_n; i++) {
        if (i != ngx_worker) {
            (void) close(s_chan[i][0]);
            s_chan[i][0] = -1;
        }
    }

    ch = ngx_get_connection(s_chan[ngx_worker][0], cycle->log);
    if (ch == NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "brix: no connection slot for the bind-migration "
                      "channel — this worker will not adopt secondaries");
        return;
    }
    ch->read->handler = brix_bind_migrate_read;
    if (ngx_handle_read_event(ch->read, 0) != NGX_OK) {
        ngx_close_connection(ch);
        return;
    }
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0,
                  "brix: bind-migration channel armed (worker %ui of %ui)",
                  ngx_worker, s_chan_n);
}

/* ---- sender side (worker B) ---------------------------------------------
 *
 * WHAT: Decide eligibility and pass the connection fd to the owning worker.
 * WHY : Each gate protects an invariant: TLS state cannot cross processes;
 *       queued responses must not reorder behind frames the owner will send;
 *       an unknown/local owner means there is nothing to migrate to.
 * HOW : Fixed-size SEQPACKET message + SCM_RIGHTS.  A full channel buffer
 *       (EAGAIN) or any error declines — the caller binds locally, which is
 *       always correct.
 */
ngx_int_t
brix_bind_migrate_try(brix_ctx_t *ctx, ngx_connection_t *c,
    const u_char sessid[BRIX_SESSION_ID_LEN])
{
    brix_bind_migrate_msg_t  m;
    struct msghdr            mh;
    struct iovec             iov;
    union {
        struct cmsghdr  align;
        u_char          buf[CMSG_SPACE(sizeof(int))];
    } cmsgu;
    struct cmsghdr          *cm;
    ngx_listening_t         *ls_base;
    ngx_int_t                owner;
    ptrdiff_t                idx;

    if (s_chan_n == 0 || c->listening == NULL) {
        return NGX_DECLINED;
    }
#if (NGX_STREAM_SSL)
    if (c->ssl != NULL) {
        return NGX_DECLINED;       /* TLS state cannot cross processes */
    }
#endif
    if (ctx->out.count != 0) {
        return NGX_DECLINED;       /* never reorder queued replies */
    }
    if (ctx->recv.stash_len != ctx->recv.stash_head) {
        /* Read-ahead stash holds pipelined bytes past the bind frame; they
         * would not travel with the fd.  (Unreachable today — the stash only
         * engages post-auth and a pre-bind secondary never authenticates —
         * but the migration safety argument must not depend on that.) */
        return NGX_DECLINED;
    }

    owner = brix_session_owner_worker(sessid);
    if (owner < 0 || (ngx_uint_t) owner == ngx_worker
        || (ngx_uint_t) owner >= s_chan_n)
    {
        return NGX_DECLINED;
    }

    ls_base = ngx_cycle->listening.elts;
    idx = c->listening - ls_base;
    if (idx < 0 || (ngx_uint_t) idx >= ngx_cycle->listening.nelts) {
        return NGX_DECLINED;
    }

    ngx_memzero(&m, sizeof(m));
    m.magic    = BRIX_BIND_MIGRATE_MAGIC;
    m.ls_index = (uint32_t) idx;
    ngx_memcpy(m.sessid, sessid, BRIX_SESSION_ID_LEN);
    m.streamid[0] = ctx->recv.cur_streamid[0];
    m.streamid[1] = ctx->recv.cur_streamid[1];

    ngx_memzero(&mh, sizeof(mh));
    iov.iov_base = &m;
    iov.iov_len  = sizeof(m);
    mh.msg_iov    = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control    = cmsgu.buf;
    mh.msg_controllen = sizeof(cmsgu.buf);

    cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type  = SCM_RIGHTS;
    cm->cmsg_len   = CMSG_LEN(sizeof(int));
    ngx_memcpy(CMSG_DATA(cm), &c->fd, sizeof(int));

    if (sendmsg(s_chan[owner][1], &mh, 0) != (ssize_t) sizeof(m)) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, ngx_errno,
                       "brix: bind migration to worker %i declined at "
                       "sendmsg — binding locally", owner);
        return NGX_DECLINED;
    }

    brix_log_access(ctx, c, "BIND", "-", "-", 1, 0, "migrated to owner worker", 0);
    return NGX_OK;
}

/* ---- receiver side (worker A): fabricate the adopted connection ---------
 *
 * WHAT: Wrap the received fd in a fully-initialized ngx_connection_t, the
 *       way ngx_event_accept would have.
 * WHY : ngx_get_connection hands out a BARE connection — I/O vtable, pool,
 *       log, peer/local sockaddrs and the connection number are the accept
 *       path's job and every later brix path relies on them.
 * HOW : Mirror ngx_event_accept + ngx_stream_init_connection field-for-field
 *       for the naddrs==1 case; on any failure close everything and return
 *       NULL (the client sees EOF on the secondary and keeps using the
 *       control stream — the documented degraded mode).
 */
static ngx_connection_t *
brix_bind_migrate_wrap_fd(int fd, ngx_listening_t *ls)
{
    ngx_connection_t *c;
    ngx_log_t        *log;
    u_char            text[NGX_SOCKADDR_STRLEN];
    struct sockaddr   sa;
    socklen_t         salen;

    c = ngx_get_connection(fd, ngx_cycle->log);
    if (c == NULL) {
        (void) close(fd);
        return NULL;
    }

    c->pool = ngx_create_pool(ls->pool_size, ngx_cycle->log);
    if (c->pool == NULL) {
        ngx_close_connection(c);
        return NULL;
    }

    log = ngx_palloc(c->pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
        return NULL;
    }
    *log = ls->log;
    c->pool->log  = log;
    c->log        = log;
    c->read->log  = log;
    c->write->log = log;

    c->recv = ngx_recv;
    c->send = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;
    c->type       = SOCK_STREAM;
    c->listening  = ls;
    c->number     = ngx_atomic_fetch_add(ngx_connection_counter, 1);
    c->log->connection = c->number;

    salen = sizeof(sa);
    if (getpeername(fd, &sa, &salen) == 0) {
        c->sockaddr = ngx_palloc(c->pool, salen);
        if (c->sockaddr != NULL) {
            ngx_memcpy(c->sockaddr, &sa, salen);
            c->socklen = salen;
            c->addr_text.data = ngx_pnalloc(c->pool, NGX_SOCKADDR_STRLEN);
            if (c->addr_text.data != NULL) {
                c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                                 text, NGX_SOCKADDR_STRLEN, 0);
                ngx_memcpy(c->addr_text.data, text, c->addr_text.len);
            }
        }
    }
    salen = sizeof(sa);
    if (getsockname(fd, &sa, &salen) == 0) {
        c->local_sockaddr = ngx_palloc(c->pool, salen);
        if (c->local_sockaddr != NULL) {
            ngx_memcpy(c->local_sockaddr, &sa, salen);
            c->local_socklen = salen;
        }
    }

    return c;
}

/* ---- receiver side: fabricate the stream session -------------------------
 *
 * WHAT: The minimal faithful subset of ngx_stream_init_connection — conf
 *       context from the listening address, module ctx array, variables,
 *       start time, per-session error log.
 * WHY : Every brix path reads conf through s; finalize and the stream log
 *       phase read s->variables; skipping any of these breaks teardown.
 * HOW : naddrs==1 only (checked by the caller) — the addr_conf is the
 *       first (only) address entry on the listening port.
 */
static ngx_stream_session_t *
brix_bind_migrate_make_session(ngx_connection_t *c, ngx_listening_t *ls)
{
    ngx_stream_port_t            *port = ls->servers;
    ngx_stream_addr_conf_t       *addr_conf;
    ngx_stream_session_t         *s;
    ngx_stream_core_srv_conf_t   *cscf;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_time_t                   *tp;

    if (ls->sockaddr->sa_family == AF_INET6) {
#if (NGX_HAVE_INET6)
        addr_conf = &((ngx_stream_in6_addr_t *) port->addrs)[0].conf;
#else
        return NULL;
#endif
    } else {
        addr_conf = &((ngx_stream_in_addr_t *) port->addrs)[0].conf;
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_stream_session_t));
    if (s == NULL) {
        return NULL;
    }

    s->signature = NGX_STREAM_MODULE;
    s->main_conf = addr_conf->default_server->ctx->main_conf;
    s->srv_conf  = addr_conf->default_server->ctx->srv_conf;
    s->connection = c;
    c->data = s;

    cscf = ngx_stream_get_module_srv_conf(s, ngx_stream_core_module);
    ngx_set_connection_log(c, cscf->error_log);

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_stream_max_module);
    if (s->ctx == NULL) {
        return NULL;
    }

    cmcf = ngx_stream_get_module_main_conf(s, ngx_stream_core_module);
    s->variables = ngx_pcalloc(c->pool, cmcf->variables.nelts
                                        * sizeof(ngx_stream_variable_value_t));
    if (s->variables == NULL) {
        return NULL;
    }

    tp = ngx_timeofday();
    s->start_sec  = tp->sec;
    s->start_msec = tp->msec;

    return s;
}

/* ---- receiver side: adopt one migrated secondary -------------------------
 *
 * WHAT: Validate the message, build connection + session + brix ctx, stamp
 *       the bind streamid and run the shared attach core.
 * WHY : After this returns the secondary is indistinguishable from one whose
 *       TCP connection was accepted here — same ctx shape, same handlers,
 *       same teardown paths — so every existing bound-stream invariant
 *       (capability restriction, offload registration, disconnect cleanup)
 *       applies unchanged.
 * HOW : Any validation or allocation failure closes the socket: the client
 *       sees EOF on the secondary and degrades to control-stream I/O.
 */
static void
brix_bind_migrate_adopt(brix_bind_migrate_msg_t *m, int fd)
{
    ngx_listening_t      *ls;
    ngx_connection_t     *c;
    ngx_stream_session_t *s;
    brix_ctx_t           *ctx;

    if (m->magic != BRIX_BIND_MIGRATE_MAGIC
        || m->ls_index >= ngx_cycle->listening.nelts)
    {
        (void) close(fd);
        return;
    }
    ls = &((ngx_listening_t *) ngx_cycle->listening.elts)[m->ls_index];
    if (ls->servers == NULL
        || ((ngx_stream_port_t *) ls->servers)->naddrs != 1)
    {
        (void) close(fd);
        return;
    }

    c = brix_bind_migrate_wrap_fd(fd, ls);
    if (c == NULL) {
        return;
    }

    s = brix_bind_migrate_make_session(c, ls);
    if (s == NULL) {
        ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
        return;
    }

    ctx = brix_conn_adopt_attach(s, c);
    if (ctx == NULL) {
        return;             /* attach refused/failed — session already finalized */
    }

    /* The handshake happened on the source worker; this connection re-enters
     * the protocol at the request loop, mid-bind. */
    ctx->state = XRD_ST_REQ_HEADER;
    ctx->recv.cur_streamid[0] = m->streamid[0];
    ctx->recv.cur_streamid[1] = m->streamid[1];
    c->read->handler  = ngx_stream_brix_recv;
    c->write->handler = ngx_stream_brix_send;

    if (brix_bind_attach(ctx, c, m->sessid) == NGX_ERROR) {
        brix_on_disconnect(ctx, c);
        brix_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    /* Park in the request loop: reads the client's next frame or EAGAINs and
     * arms the read event — exactly the post-accept pump. */
    ngx_stream_brix_recv(c->read);
}

/* ---- receiver side: channel read event -----------------------------------
 *
 * WHAT: Drain every queued migration message, adopting each in turn.
 * WHY : SEQPACKET preserves message boundaries — one recvmsg per bind; a
 *       short/garbled datagram or one without an fd is dropped whole.
 * HOW : Loop until EAGAIN, then re-arm.  The channel peer set is exactly the
 *       sibling workers (pre-fork socketpair, never exposed on a filesystem),
 *       but every field is validated anyway before use.
 */
static void
brix_bind_migrate_read(ngx_event_t *rev)
{
    ngx_connection_t         *ch = rev->data;
    brix_bind_migrate_msg_t   m;
    struct msghdr             mh;
    struct iovec              iov;
    union {
        struct cmsghdr  align;
        u_char          buf[CMSG_SPACE(sizeof(int))];
    } cmsgu;
    struct cmsghdr           *cm;
    ssize_t                   n;
    int                       fd;

    for ( ;; ) {
        ngx_memzero(&mh, sizeof(mh));
        iov.iov_base = &m;
        iov.iov_len  = sizeof(m);
        mh.msg_iov    = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control    = cmsgu.buf;
        mh.msg_controllen = sizeof(cmsgu.buf);

        n = recvmsg(ch->fd, &mh, 0);
        if (n < 0) {
            break;                       /* EAGAIN drained; anything else waits */
        }

        fd = -1;
        for (cm = CMSG_FIRSTHDR(&mh); cm != NULL; cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS
                && cm->cmsg_len == CMSG_LEN(sizeof(int)))
            {
                ngx_memcpy(&fd, CMSG_DATA(cm), sizeof(int));
            }
        }
        if (fd < 0) {
            continue;                    /* no fd attached — nothing to adopt */
        }
        if (n != (ssize_t) sizeof(m) || (mh.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
            (void) close(fd);
            continue;
        }

        brix_bind_migrate_adopt(&m, fd);
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ch->log, 0,
                      "brix: bind-migration channel read re-arm failed");
    }
}
