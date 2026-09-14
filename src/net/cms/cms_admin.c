/*
 * cms_admin.c — the CMS admin socket's VERB TABLE. See cms_admin.h for the
 * protocol, the reuse argument and the audit divergence; see
 * net/admin/admin_unix.h for the transport and the security boundary.
 */

#include "cms_admin.h"
#include "net/admin/admin_unix.h"
#include "net/manager/registry.h"

#include <sys/un.h>

/* Directive state (parse-time, node-global — same file-static pattern as
 * brix_admin_socket): the LAST brix_cms_admin_socket wins. */
static char  s_cms_admin_path[sizeof(((struct sockaddr_un *) 0)->sun_path)];

/* The HTTP admin API's drain default (api_admin_cluster.c:220); shared so the
 * two surfaces cannot disagree about how long an unqualified drain lasts. */
#define CMS_ADMIN_DRAIN_DEFAULT_S  300

/* A parsed "<host> <port> [tail]" operand run. */
typedef struct {
    char      host[BRIX_CMS_ADMIN_HOST_BUF];
    uint16_t  port;
    u_char   *tail;       /* text after the port, NULL when absent */
    size_t    tail_len;
} cms_admin_target_t;

char *
brix_conf_set_cms_admin_socket(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;

    (void) cmd;
    (void) conf;

    if (value[1].len == 0 || value[1].len >= sizeof(s_cms_admin_path)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_admin_socket: path empty or longer than a unix socket "
            "path (%uz max)", sizeof(s_cms_admin_path) - 1);
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(s_cms_admin_path, value[1].data, value[1].len);
    s_cms_admin_path[value[1].len] = '\0';
    return NGX_CONF_OK;
}

/* ---- helpers ------------------------------------------------------------ */

/*
 * Structured audit line for a mutating verb — same fields as
 * api_admin_cluster.c's admin_audit(), deliberately unchained (cms_admin.h).
 * Emitted for EVERY outcome including refusals, because "who tried to drain
 * what, and was told no" is exactly what an incident review needs.
 */
static void
cms_admin_audit(const char *action, const char *host, uint16_t port,
    const char *result)
{
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "brix: cms admin: %s target=%s:%d result=%s",
                  action, host, (int) port, result);
}

/*
 * Parse "<host> <port>" and, if present, the remaining text. Returns 0 when
 * the host is missing/oversized or the port is absent, non-numeric, or outside
 * 1-BRIX_CMS_MAX_PORT — a rejected target is never passed to a registry helper,
 * so a typo cannot drain a node the operator did not name.
 */
static int
cms_admin_parse_target(u_char *args, size_t alen, cms_admin_target_t *t)
{
    u_char    *sp = ngx_strlchr(args, args + alen, ' ');
    u_char    *pend;
    size_t     hlen;
    ngx_int_t  port;

    if (sp == NULL) {
        return 0;
    }
    hlen = (size_t) (sp - args);
    if (hlen == 0 || hlen >= sizeof(t->host)) {
        return 0;
    }
    ngx_memcpy(t->host, args, hlen);
    t->host[hlen] = '\0';

    pend = ngx_strlchr(sp + 1, args + alen, ' ');
    if (pend == NULL) {
        pend = args + alen;
        t->tail = NULL;
        t->tail_len = 0;
    } else {
        t->tail = pend + 1;
        t->tail_len = (size_t) (args + alen - (pend + 1));
    }
    port = ngx_atoi(sp + 1, (size_t) (pend - (sp + 1)));
    if (port == NGX_ERROR || port <= 0 || port > BRIX_CMS_MAX_PORT) {
        return 0;
    }
    t->port = (uint16_t) port;
    return 1;
}

/* The operational state one snapshot entry is in, for the `nodes` listing. */
static const char *
cms_admin_state(const brix_srv_snapshot_entry_t *e, ngx_msec_t now)
{
    if (e->blacklisted_until > now) {
        return "drained";
    }
    if (e->space_blocked) {
        return "space-blocked";
    }
    return "up";
}

/* ---- verbs -------------------------------------------------------------- */

/* "nodes" — list the SHM registry. Node-wide: any worker's socket sees all. */
static void
cms_admin_nodes(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    brix_srv_snapshot_entry_t *snap;
    ngx_msec_t  now = ngx_current_msec;
    u_char     *body = rep->buf + 32;   /* header slid in front afterwards */
    u_char     *last = rep->buf + rep->cap;
    u_char     *pos, head[32], *he;
    ngx_uint_t  n, i, listed = 0;
    size_t      hlen;

    (void) ud; (void) args; (void) alen;

    snap = ngx_alloc(sizeof(*snap) * BRIX_SRV_REGISTRY_SLOTS, ngx_cycle->log);
    if (snap == NULL) {
        brix_admin_reply_set(rep, "err out-of-memory\n");
        return;
    }
    n = brix_srv_snapshot(snap, BRIX_SRV_REGISTRY_SLOTS, now);

    pos = body;
    for (i = 0; i < n; i++) {
        /* Stop cleanly rather than truncating a line: a half-written entry
         * would parse as a DIFFERENT node to whatever reads this. */
        if ((size_t) (last - pos) < BRIX_CMS_STATE_SAFE_BUF) {
            break;
        }
        pos = ngx_snprintf(pos, (size_t) (last - pos),
                           "%s:%d role=%s free_mb=%uD util_pct=%uD state=%s\n",
                           snap[i].host, (int) snap[i].port,
                           snap[i].role[0] ? snap[i].role : "-",
                           snap[i].free_mb, snap[i].util_pct,
                           cms_admin_state(&snap[i], now));
        listed++;
    }
    ngx_free(snap);

    he = ngx_snprintf(head, sizeof(head), "ok %ui\n", listed);
    hlen = (size_t) (he - head);
    ngx_memcpy(rep->buf + 32 - hlen, head, hlen);
    rep->out = rep->buf + 32 - hlen;
    rep->len = hlen + (size_t) (pos - body);
}

/* "drain <host> <port> [secs]" — blacklist so the router stops selecting it. */
static void
cms_admin_drain(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    cms_admin_target_t t;
    ngx_int_t          secs = CMS_ADMIN_DRAIN_DEFAULT_S;

    (void) ud;

    if (!cms_admin_parse_target(args, alen, &t)) {
        brix_admin_reply_set(rep, "err bad-target\n");
        return;
    }
    if (t.tail != NULL) {
        secs = ngx_atoi(t.tail, t.tail_len);
        if (secs == NGX_ERROR || secs <= 0) {
            cms_admin_audit("cluster/drain", t.host, t.port, "bad_request");
            brix_admin_reply_set(rep, "err bad-seconds\n");
            return;
        }
    }
    brix_srv_blacklist(t.host, t.port, (ngx_msec_t) secs * BRIX_CMS_SEC_TO_MS_MULTIPLIER);
    cms_admin_audit("cluster/drain", t.host, t.port, "drained");
    brix_admin_reply_set(rep, "ok\n");
}

/*
 * The three plain target verbs — undrain, forget, reset — are one shape:
 * parse "<host> <port>", call one registry helper, audit the outcome, answer.
 * Written once so a change to the refusal wording or the audit fields cannot
 * land on two of the three.
 */
typedef int (*cms_admin_act_pt)(const char *host, uint16_t port);

typedef struct {
    const char       *action;      /* audit action field                    */
    cms_admin_act_pt  act;         /* 0 = no such node                      */
    const char       *ok_result;   /* audit result field on success         */
} cms_admin_op_t;

static void
cms_admin_target_verb(u_char *args, size_t alen, brix_admin_reply_t *rep,
    const cms_admin_op_t *op)
{
    cms_admin_target_t t;

    if (!cms_admin_parse_target(args, alen, &t)) {
        brix_admin_reply_set(rep, "err bad-target\n");
        return;
    }
    if (!op->act(t.host, t.port)) {
        cms_admin_audit(op->action, t.host, t.port, "not_found");
        brix_admin_reply_set(rep, "err not-found\n");
        return;
    }
    cms_admin_audit(op->action, t.host, t.port, op->ok_result);
    brix_admin_reply_set(rep, "ok\n");
}

/* brix_srv_unregister() cannot fail: a node that was never registered is
 * already in the state forget asks for, so absent is success, not not-found. */
static int
cms_admin_do_forget(const char *host, uint16_t port)
{
    brix_srv_unregister(host, port);
    return 1;
}

/* "undrain <host> <port>" — lift a drain; not-found when it was not drained. */
static void
cms_admin_undrain(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    static const cms_admin_op_t op = {
        "cluster/undrain", brix_srv_undrain, "undrained"
    };

    (void) ud;
    cms_admin_target_verb(args, alen, rep, &op);
}

/* "forget <host> <port>" — drop the registration entirely. */
static void
cms_admin_forget(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    static const cms_admin_op_t op = {
        "cluster/forget", cms_admin_do_forget, "removed"
    };

    (void) ud;
    cms_admin_target_verb(args, alen, rep, &op);
}

/* "reset <host> <port>" — forget cached metrics/fault state, keep the node. */
static void
cms_admin_reset(void *ud, u_char *args, size_t alen, brix_admin_reply_t *rep)
{
    static const cms_admin_op_t op = {
        "cluster/reset", brix_srv_reset, "reset"
    };

    (void) ud;
    cms_admin_target_verb(args, alen, rep, &op);
}

/* ---- the table ---------------------------------------------------------- */

static const brix_admin_verb_t  s_cms_verbs[] = {
    BRIX_ADMIN_VERB("nodes",   cms_admin_nodes,   0),
    BRIX_ADMIN_VERB("drain",   cms_admin_drain,   1),
    BRIX_ADMIN_VERB("undrain", cms_admin_undrain, 1),
    BRIX_ADMIN_VERB("forget",  cms_admin_forget,  1),
    BRIX_ADMIN_VERB("reset",   cms_admin_reset,   1),
};

static const brix_admin_unix_t  s_cms_admin = {
    "cms admin", s_cms_verbs,
    sizeof(s_cms_verbs) / sizeof(s_cms_verbs[0]), NULL
};

void
brix_cms_admin_socket_init(ngx_cycle_t *cycle)
{
    brix_admin_unix_listen(cycle, s_cms_admin_path, &s_cms_admin);
}
