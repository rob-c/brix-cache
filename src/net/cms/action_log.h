#pragma once
/*
 * cms/action_log.h — one uniform, greppable NOTICE line per CMS control-plane
 * action, on BOTH sides of a cmsd link (this node as manager/sub-manager taking
 * actions from downstream nodes, and this node as leaf/sub-manager taking
 * actions from its upstream manager).
 *
 * WHAT: brix_cms_log_action(): op + peer + direction + path + result + detail.
 *       brix_cms_log_action_hp(): same, formatting "host:port" for the server
 *       side where the peer identity is a (char host[], int port) pair.
 * WHY:  operators asked for proof of "what was run, against which node, who
 *       requested it, and whether it succeeded" without turning on debug.  A
 *       single stable tag ("cmsd-action") makes the whole control plane one
 *       `grep` away.  Header-only so both the client (recv_frame.c/connect.c/
 *       send.c) and server (server_recv_frame.c) sides share one exact format.
 * HOW:  "dir=out" means THIS node initiated the action (a login/heartbeat we
 *       sent up, a probe we answered); "dir=in" means the PEER requested it (a
 *       manager told us to redirect/suspend, a downstream node registered).  So
 *       (op, peer, dir) answers "what ran and who asked for it" and result/detail
 *       answers "did it work".
 *
 * Requires: ngx_core.h (ngx_log_error, ngx_snprintf, ngx_inline) before inclusion.
 */

/* brix_cms_log_action — emit one cmsd-action line for a peer already rendered as
 * a display string (e.g. an ngx_str_t manager "host:port" from the config). */
static ngx_inline void
brix_cms_log_action(ngx_log_t *log, const char *op, const char *peer,
    const char *dir, const char *path, ngx_int_t ok, const char *detail)
{
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: cmsd-action op=%s peer=%s dir=%s path=%s "
                  "result=%s detail=%s",
                  op, (peer && *peer) ? peer : "-", dir,
                  (path && *path) ? path : "-",
                  ok ? "ok" : "FAIL",
                  (detail && *detail) ? detail : "-");
}

/* brix_cms_log_action_hp — same, for the server side where the peer node is a
 * (host, port) pair; renders "host:port" into a bounded local buffer first. */
static ngx_inline void
brix_cms_log_action_hp(ngx_log_t *log, const char *op, const char *host,
    int port, const char *dir, const char *path, ngx_int_t ok,
    const char *detail)
{
    u_char   peer[288];
    u_char  *p;

    p = ngx_snprintf(peer, sizeof(peer) - 1, "%s:%d",
                     (host && *host) ? host : "-", port);
    *p = '\0';
    brix_cms_log_action(log, op, (const char *) peer, dir, path, ok, detail);
}
