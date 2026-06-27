#ifndef XROOTD_CMS_SERVER_H
#define XROOTD_CMS_SERVER_H

/*
 * cms/server.h — CMS server-side handler types and API.
 *
 * This module listens on the CMS management port (default 1213) and accepts
 * incoming connections from XRootD data servers.  On login it registers the
 * data server in the shared server registry (src/manager/registry.h); on each
 * heartbeat it refreshes load metrics; on disconnect it unregisters.
 *
 * Directive: xrootd_cms_server on;   (inside a stream server {} block)
 * Optional:  xrootd_cms_server_interval 60;   (ping interval in seconds)
 */

#include "cms_internal.h"
#include "../manager/registry.h"

/* Forward decl — the per-block config (defined below) is referenced by ctx. */
typedef struct ngx_stream_xrootd_cms_srv_conf_s ngx_stream_xrootd_cms_srv_conf_t;

/*
 * SSS cluster-authentication handshake state (W1a).  Mirrors the real cmsd
 * kYR_xauth exchange: after the data node's LOGIN frame arrives we send our
 * security parms (REQUESTED) and defer registration until the node returns a
 * valid SSS credential (DONE).  NONE means SSS auth is not required.
 */
typedef enum {
    CMS_AUTH_NONE = 0,    /* no sss keytab configured — auth not required    */
    CMS_AUTH_REQUESTED,   /* sss required; awaiting the node's LOGIN frame    */
    CMS_AUTH_CHALLENGED,  /* parms sent, awaiting the node's kYR_xauth cred   */
    CMS_AUTH_DONE         /* credential verified — registration permitted     */
} xrootd_cms_auth_state_t;

/* Per-connection state for an accepted CMS data-server connection. */
typedef struct {
    ngx_connection_t  *c;
    ngx_stream_xrootd_cms_srv_conf_t *conf;          /* owning srv block       */
    char               host[256];                    /* remote IP (NUL-terminated) */
    uint16_t           port;                         /* XRootD data port from LOGIN */
    char               paths[XROOTD_SRV_MAX_PATHS];  /* colon-delimited export list */
    uint32_t           free_mb;
    uint32_t           util_pct;
    ngx_uint_t         logged_in;
    xrootd_cms_auth_state_t auth_state;              /* sss handshake state    */
    ngx_event_t        ping_timer;
    ngx_msec_t         interval_ms;                  /* ping interval in ms */
    ngx_msec_t         login_timeout_ms;             /* WS3: LOGIN handshake deadline */
    ngx_msec_t         idle_timeout_ms;              /* WS3: post-login inbound silence */
    unsigned           counted:1;                    /* WS4: this conn is in the cap count */
    u_char             inbuf[NGX_XROOTD_CMS_MAX_FRAME];
    size_t             in_pos;
    size_t             in_need;
} xrootd_cms_srv_ctx_t;

/* Per-server-block config for the CMS server module. */
struct ngx_stream_xrootd_cms_srv_conf_s {
    ngx_flag_t   enable;
    time_t       interval;     /* ping interval in seconds; default 60 */
    ngx_array_t *allow;        /* ngx_cidr_t[]: permitted data-node IPs (W1b) */
    ngx_str_t    sss_keytab;   /* path to the cluster sss keytab (W1a)        */
    ngx_array_t *sss_keys;     /* parsed xrootd_sss_key_t[] from the keytab    */

    /* ---- Phase 50: accept-side network-fault resilience (the untrusted face) ----
     * The manager arms no timer until AFTER a node logs in, so a peer that never
     * completes LOGIN (or trickles a partial header) squats a ctx + fd forever,
     * and a silently-dead post-login node is only reaped when a ping *send* fails
     * (which a black-holed peer never does).  These close both holes.  Unset
     * auto-derives a generous ON default; an explicit 0 disables. */
    ngx_msec_t   login_timeout;   /* [xrootd_cms_server_login_timeout] deadline to
                                     complete LOGIN (+sss xauth); unset => 10s. */
    ngx_msec_t   idle_timeout;    /* [xrootd_cms_server_idle_timeout] post-login
                                     inbound-silence deadline; unset =>
                                     max(3*interval, 90s). 0 = off. */
    ngx_int_t    max_connections; /* [xrootd_cms_server_max_connections] per-worker
                                     cap on accepted CMS connections; unset => 4096.
                                     0 = unlimited. */
    ngx_int_t    max_connections_per_ip; /* [xrootd_cms_server_max_connections_per_ip]
                                     A3: per-source-IP cap; unset => 256. 0 = off. */
    ngx_flag_t   tcp_keepalive;   /* [xrootd_cms_server_tcp_keepalive on] */
    ngx_msec_t   tcp_user_timeout;/* [xrootd_cms_server_tcp_user_timeout] ms; unset
                                     => idle-timeout backstop. 0 = off. */
};

/* Module descriptor declared in server_module.c. */
extern ngx_module_t  ngx_stream_xrootd_cms_srv_module;

/* server_handler.c — per-worker accepted-CMS-connection counter (WS4).
 * A live gauge of accepted CMS data-server connections in this worker, used to
 * enforce xrootd_cms_server_max_connections.  Encapsulated behind accessors so
 * the single process-global counter has exactly one definition. */
ngx_uint_t xrootd_cms_srv_conn_count(void);
void       xrootd_cms_srv_conn_inc(void);
void       xrootd_cms_srv_conn_dec(void);

/* A3: per-source-IP connection accounting (per-worker). */
ngx_uint_t xrootd_cms_srv_ip_count(const char *ip);
void       xrootd_cms_srv_ip_inc(const char *ip);
void       xrootd_cms_srv_ip_dec(const char *ip);

/* server_handler.c */

/* Stream connection handler for an accepted CMS data-server connection.
 * Allocates the per-conn ctx on c->pool, runs the W1b CIDR allowlist gate and
 * arms the W1a sss handshake, installs the read/write handlers, then drives the
 * first read inline.  Finalizes the session (no ctx leak — pool-cleaned) on
 * alloc failure or a denied peer; otherwise returns with the conn live. */
void xrootd_cms_srv_handler(ngx_stream_session_t *s);

/* server_recv.c */

/* Read-event handler: accumulates the fixed header then the dlen-sized payload
 * into ctx->inbuf, dispatching each complete frame (LOGIN/LOAD/AVAIL/PONG/...).
 * Closes the connection on peer EOF/error, read timeout, or an oversized frame
 * (> NGX_XROOTD_CMS_MAX_FRAME).  ctx may be freed on return — do not reuse. */
void xrootd_cms_srv_read(ngx_event_t *ev);

/* Write-event handler.  All sends are synchronous (see send_ping), so this only
 * acts as a write-timeout guard: closes the connection if ev->timedout. */
void xrootd_cms_srv_write(ngx_event_t *ev);

/* Tear down one CMS server connection: cancels the ping timer, and if the node
 * was logged_in, blacklists host:port for 30 s (so in-flight locates skip a node
 * that just left) before closing.  Idempotent when ctx->c is already NULL; sets
 * ctx->c = NULL.  Does not free ctx (it lives on the connection pool). */
void xrootd_cms_srv_close(xrootd_cms_srv_ctx_t *ctx);

/* server_send.c */

/* Send an empty CMS_RR_PING heartbeat frame to the data node (synchronous).
 * Returns NGX_OK on success, NGX_ERROR if the connection is closed or the
 * write fails. */
ngx_int_t xrootd_cms_srv_send_ping(xrootd_cms_srv_ctx_t *ctx);

/* Send the manager's kYR_xauth security challenge (the parms string, e.g.
 * "&P=sss", of length len) inviting the node to present its sss credential.
 * parms is borrowed (copied into the wire frame, not retained).  Returns NGX_OK
 * on a successful synchronous write, NGX_ERROR otherwise. */
ngx_int_t xrootd_cms_srv_send_xauth(xrootd_cms_srv_ctx_t *ctx,
    const u_char *parms, size_t len);

/* Plane A liveness/query replies (byte-exact with cmsd do_Ping/do_Disc/do_Update).
 * Each is a header-only frame written synchronously; NGX_OK / NGX_ERROR. */
ngx_int_t xrootd_cms_srv_send_pong(xrootd_cms_srv_ctx_t *ctx);
ngx_int_t xrootd_cms_srv_send_disc(xrootd_cms_srv_ctx_t *ctx);
ngx_int_t xrootd_cms_srv_send_status(xrootd_cms_srv_ctx_t *ctx, u_char modifier);
ngx_int_t xrootd_cms_srv_send_data(xrootd_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t len);

/* server_auth.c — W1 registration authentication (CIDR + sss + host validation) */

/* Accept-time peer check: NGX_OK if the peer is permitted to register.
 * When no allowlist is configured this returns NGX_OK (back-compat) after a
 * one-time warning; when an allowlist is set, only matching IPs pass. */
ngx_int_t xrootd_cms_srv_check_peer(ngx_connection_t *c,
    ngx_stream_xrootd_cms_srv_conf_t *conf);

/* Verify an SSS credential blob from a kYR_xauth response against the cluster
 * keytab.  NGX_OK = authenticated; anything else = reject. */
ngx_int_t xrootd_cms_srv_verify_xauth(xrootd_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len);

#endif /* XROOTD_CMS_SERVER_H */
