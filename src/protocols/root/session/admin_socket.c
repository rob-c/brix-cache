/*
 * admin_socket.c — §1.16 runtime admin unix socket: the ROOT VERB TABLE only.
 * See admin_socket.h for the protocol, scope and security model.
 *
 * The transport half — accept, framing, reply flush, per-worker path — moved
 * to src/net/admin/admin_unix.c when §2.x's CMS admin socket needed the same
 * socket with different verbs. This TU is now the verbs and nothing else.
 */

#include "admin_socket.h"
#include "offload_registry.h"
#include "registry.h"
#include "net/admin/admin_unix.h"
#include "protocols/root/response/async.h"   /* brix_send_attn_asyncms */

#include <sys/un.h>

/* Directive state (parse-time, node-global — same file-static pattern as
 * brix_posc_persist): the LAST brix_admin_socket wins across server blocks. */
static char  s_admin_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];

/* `list` enumeration state threaded through the offload-registry callback. */
typedef struct {
    u_char *buf;
    size_t  len;
    size_t  cap;
    size_t  n;
} admin_list_state_t;

char *
brix_conf_set_admin_socket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;

    (void) cmd;
    (void) conf;

    if (value[1].len == 0 || value[1].len >= sizeof(s_admin_path)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_admin_socket: path empty or longer than a unix socket "
            "path (%uz max)", sizeof(s_admin_path) - 1);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(s_admin_path, value[1].data, value[1].len);
    s_admin_path[value[1].len] = '\0';
    return NGX_CONF_OK;
}

/* ---- command helpers ---------------------------------------------------- */

/* Parse 32 lowercase/uppercase hex chars into a 16-byte sessid; 0 on error. */
static int
admin_parse_sessid(const u_char *hex, size_t len,
    u_char out[BRIX_SESSION_ID_LEN])
{
    size_t i;

    if (len != BRIX_SESSION_ID_LEN * 2) {
        return 0;
    }
    for (i = 0; i < BRIX_SESSION_ID_LEN; i++) {
        int hi = ngx_hextoi((u_char *) &hex[i * 2], 1);
        int lo = ngx_hextoi((u_char *) &hex[i * 2 + 1], 1);
        if (hi == NGX_ERROR || lo == NGX_ERROR) {
            return 0;
        }
        out[i] = (u_char) ((hi << 4) | lo);
    }
    return 1;
}

static int
admin_list_cb(void *ud, const unsigned char *sessid, unsigned pathid,
    void *conn)
{
    admin_list_state_t *st = ud;
    ngx_connection_t   *tc = conn;
    char                dn[512];
    char                vo[512];
    ngx_uint_t          token_auth;
    size_t              i;
    u_char             *p;

    if (pathid != BRIX_ADMIN_PATHID) {
        return 0;   /* a bound data channel, not a session's primary */
    }
    /* Room for: 32 hex + peer(<=64) + dn(<=128 shown) + separators + '\n'. */
    if (st->cap - st->len < 32 + 1 + 64 + 1 + 128 + 2) {
        return 1;   /* reply buffer full — stop enumerating */
    }

    p = st->buf + st->len;
    for (i = 0; i < BRIX_SESSION_ID_LEN; i++) {
        p = ngx_sprintf(p, "%02xd", sessid[i]);
    }
    /* Peer address: the operator's handle for choosing a session to act on. */
    if (tc->addr_text.len > 0) {
        size_t alen = ngx_min(tc->addr_text.len, 64);
        *p++ = ' ';
        p = ngx_cpymem(p, tc->addr_text.data, alen);
    } else {
        p = ngx_sprintf(p, " -");
    }
    dn[0] = '\0';
    if (brix_session_lookup(sessid, dn, sizeof(dn), vo, sizeof(vo),
                              &token_auth)
        && dn[0] != '\0')
    {
        p = ngx_snprintf(p, 1 + 128, " %s", dn);
    } else {
        p = ngx_sprintf(p, " -");
    }
    *p++ = '\n';
    st->len = (size_t) (p - st->buf);
    st->n++;
    return 0;
}

/* One-shot timed-pause resume: clears the pause flag and posts the read event
 * so the recv loop drains whatever backed up. The connection is guaranteed
 * alive while the timer is armed — disconnect deletes it (disconnect.c). */
static void
admin_pause_timeout(ngx_event_t *ev)
{
    ngx_connection_t *tc = ev->data;
    brix_ctx_t       *tctx;

    tctx = ngx_stream_get_module_ctx((ngx_stream_session_t *) tc->data,
                                       ngx_stream_brix_module);
    if (tctx == NULL || tctx->destroyed) {
        return;
    }
    tctx->admin_paused = 0;
    ngx_post_event(tc->read, &ngx_posted_events);
}

/* Resolve a session id to its local ctx (NULL when unknown/not-local/destroyed);
 * *target_out receives the connection when found. */
static brix_ctx_t *
admin_resolve_ctx(const u_char *sessid, ngx_connection_t **target_out)
{
    ngx_connection_t *target = brix_offload_lookup(sessid, BRIX_ADMIN_PATHID);
    brix_ctx_t       *tctx;

    *target_out = target;
    if (target == NULL) {
        return NULL;
    }
    tctx = ngx_stream_get_module_ctx((ngx_stream_session_t *) target->data,
                                     ngx_stream_brix_module);
    return (tctx == NULL || tctx->destroyed) ? NULL : tctx;
}

/* "list" — enumerate the local offloaded sessions. */
static void
admin_cmd_list(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    admin_list_state_t ls;
    u_char head[32];
    u_char *he;
    size_t  hlen;

    (void) ud; (void) args; (void) alen;

    ls.buf = rep->buf + 32;             /* body after the "ok <n>\n" header */
    ls.len = 0;
    ls.cap = rep->cap - 64;
    ls.n = 0;
    (void) brix_offload_foreach(admin_list_cb, &ls);

    he = ngx_snprintf(head, sizeof(head), "ok %uz\n", ls.n);
    hlen = (size_t) (he - head);
    /* The body was built past the largest possible header; slide the header in
     * front of it so the reply is one contiguous run. */
    ngx_memcpy(rep->buf + 32 - hlen, head, hlen);
    rep->out = rep->buf + 32 - hlen;
    rep->len = hlen + ls.len;
}

/* "disc <sid>" — graceful shutdown(2); the loop's EOF path does the teardown. */
static void
admin_cmd_disc(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;

    (void) ud;

    if (!admin_parse_sessid(args, alen, sessid)) {
        brix_admin_reply_set(rep, "err unknown-command\n");
        return;
    }
    target = brix_offload_lookup(sessid, BRIX_ADMIN_PATHID);
    if (target == NULL) {
        brix_admin_reply_set(rep, "err unknown-or-not-local\n");
        return;
    }
    (void) shutdown(target->fd, SHUT_RDWR);
    brix_admin_reply_set(rep, "ok\n");
}

/* "msg <sid> <text>" — deliver an async attn message to the target session. */
static void
admin_cmd_msg(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    u_char           *sp = ngx_strlchr(args, args + alen, ' ');
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    brix_ctx_t       *tctx;
    const char       *text;
    size_t            tlen;

    (void) ud;

    if (sp == NULL
        || !admin_parse_sessid(args, (size_t) (sp - args), sessid)) {
        brix_admin_reply_set(rep, "err unknown-command\n");
        return;
    }
    text = (const char *) sp + 1;
    tlen = (size_t) (args + alen - (sp + 1));
    tctx = admin_resolve_ctx(sessid, &target);
    if (target == NULL) {
        brix_admin_reply_set(rep, "err unknown-or-not-local\n");
    } else if (tctx == NULL || tlen == 0) {
        brix_admin_reply_set(rep, "err target-unusable\n");
    } else if (brix_send_attn_asyncms(tctx, target, text, tlen) != NGX_OK) {
        brix_admin_reply_set(rep, "err send-failed\n");
    } else {
        brix_admin_reply_set(rep, "ok\n");
    }
}

/* "pause <sid> [secs]" — stop parsing the target; optional auto-resume timer. */
static void
admin_cmd_pause(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    u_char           *sp = ngx_strlchr(args, args + alen, ' ');
    size_t            hexlen = sp ? (size_t) (sp - args) : alen;
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    brix_ctx_t       *tctx;
    ngx_int_t         secs = 0;

    (void) ud;

    if (sp != NULL) {
        secs = ngx_atoi(sp + 1, (size_t) (args + alen - (sp + 1)));
        if (secs == NGX_ERROR || secs < 0) {
            brix_admin_reply_set(rep, "err bad-seconds\n");
            return;
        }
    }
    if (!admin_parse_sessid(args, hexlen, sessid)) {
        brix_admin_reply_set(rep, "err unknown-command\n");
        return;
    }
    tctx = admin_resolve_ctx(sessid, &target);
    if (tctx == NULL) {
        brix_admin_reply_set(rep, "err unknown-or-not-local\n");
        return;
    }
    tctx->admin_paused = 1;
    if (secs > 0) {
        tctx->admin_pause_ev.handler = admin_pause_timeout;
        tctx->admin_pause_ev.data = target;
        tctx->admin_pause_ev.log = target->log;
        ngx_add_timer(&tctx->admin_pause_ev, (ngx_msec_t) secs * BRIX_ROOT_MS_PER_SEC);
    }
    brix_admin_reply_set(rep, "ok\n");
}

/* "cont <sid>" — clear a pause and repost the read event. */
static void
admin_cmd_cont(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    brix_ctx_t       *tctx;

    (void) ud;

    if (!admin_parse_sessid(args, alen, sessid)) {
        brix_admin_reply_set(rep, "err unknown-command\n");
        return;
    }
    tctx = admin_resolve_ctx(sessid, &target);
    if (tctx == NULL) {
        brix_admin_reply_set(rep, "err unknown-or-not-local\n");
        return;
    }
    if (tctx->admin_pause_ev.timer_set) {
        ngx_del_timer(&tctx->admin_pause_ev);
    }
    tctx->admin_paused = 0;
    /* Resume parsing whatever backed up while paused: the recv loop yielded
     * without re-arming, so the read event must be posted. */
    ngx_post_event(target->read, &ngx_posted_events);
    brix_admin_reply_set(rep, "ok\n");
}

/* "abort <sid>" — RST-on-close (SO_LINGER{1,0}) then shutdown(2). */
static void
admin_cmd_abort(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    u_char            sessid[BRIX_SESSION_ID_LEN];
    ngx_connection_t *target;
    struct linger     lg;

    (void) ud;

    if (!admin_parse_sessid(args, alen, sessid)) {
        brix_admin_reply_set(rep, "err unknown-command\n");
        return;
    }
    target = brix_offload_lookup(sessid, BRIX_ADMIN_PATHID);
    if (target == NULL) {
        brix_admin_reply_set(rep, "err unknown-or-not-local\n");
        return;
    }
    /* Abort = disconnect WITHOUT ceremony: SO_LINGER{1,0} makes the teardown's
     * eventual close(2) send an RST instead of a FIN, so the client sees
     * ECONNRESET — stock abort semantics. The teardown still runs through the
     * normal event-loop EOF path (no re-entrancy), exactly like disc. */
    lg.l_onoff = 1;
    lg.l_linger = 0;
    (void) setsockopt(target->fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    (void) shutdown(target->fd, SHUT_RDWR);
    brix_admin_reply_set(rep, "ok\n");
}

/* ---- the table ---------------------------------------------------------- */

/*
 * The ROOT verb table. Order is irrelevant — the transport matches a bare verb
 * against the whole line and an operand verb against "<name> " — so no verb
 * can shadow another by being listed first, and "cont" cannot be reached by a
 * prefix of "continue".
 */
static const brix_admin_verb_t  s_root_verbs[] = {
    BRIX_ADMIN_VERB("list",  admin_cmd_list,  0),
    BRIX_ADMIN_VERB("disc",  admin_cmd_disc,  1),
    BRIX_ADMIN_VERB("msg",   admin_cmd_msg,   1),
    BRIX_ADMIN_VERB("pause", admin_cmd_pause, 1),
    BRIX_ADMIN_VERB("cont",  admin_cmd_cont,  1),
    BRIX_ADMIN_VERB("abort", admin_cmd_abort, 1),
};

static const brix_admin_unix_t  s_root_admin = {
    "admin", s_root_verbs,
    sizeof(s_root_verbs) / sizeof(s_root_verbs[0]), NULL
};

void
brix_admin_socket_init(ngx_cycle_t *cycle)
{
    brix_admin_unix_listen(cycle, s_admin_path, &s_root_admin);
}
