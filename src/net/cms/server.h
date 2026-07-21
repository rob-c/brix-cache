#ifndef BRIX_CMS_SERVER_H
#define BRIX_CMS_SERVER_H

/*
 * cms/server.h — CMS server-side handler types and API.
 *
 * This module listens on the CMS management port (default 1213) and accepts
 * incoming connections from XRootD data servers.  On login it registers the
 * data server in the shared server registry (src/manager/registry.h); on each
 * heartbeat it refreshes load metrics; on disconnect it unregisters.
 *
 * Directive: brix_cms_server on;   (inside a stream server {} block)
 * Optional:  brix_cms_server_interval 60;   (ping interval in seconds)
 */

#include "cms_internal.h"
#include "blacklist_file.h"
#include "net/manager/registry.h"

/* Forward decl — the per-block config (defined below) is referenced by ctx. */
typedef struct ngx_stream_brix_cms_srv_conf_s ngx_stream_brix_cms_srv_conf_t;

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
} brix_cms_auth_state_t;

/* Per-connection state for an accepted CMS data-server connection. */
typedef struct {
    ngx_connection_t  *c;
    ngx_stream_brix_cms_srv_conf_t *conf;          /* owning srv block       */
    brix_sess_t       *sess;                       /* lifecycle audit session */
    brix_sess_end_t    sess_end_hint;
    ngx_uint_t         sess_end_hint_set;
    ngx_uint_t         sess_attempt_logged;
    char               host[256];                    /* remote IP (NUL-terminated) */
    uint16_t           port;                         /* XRootD data port from LOGIN */
    char               paths[BRIX_SRV_MAX_PATHS];  /* colon-delimited export list */
    char               vnid[64];                     /* login envCGI vnid= (may be "") */
    uint32_t           free_mb;
    uint32_t           util_pct;
    ngx_uint_t         logged_in;
    brix_cms_auth_state_t auth_state;              /* sss handshake state    */
    ngx_event_t        ping_timer;
    ngx_msec_t         interval_ms;                  /* ping interval in ms */
    ngx_msec_t         login_timeout_ms;             /* WS3: LOGIN handshake deadline */
    ngx_msec_t         idle_timeout_ms;              /* WS3: post-login inbound silence */
    unsigned           counted:1;                    /* WS4: this conn is in the cap count */
    unsigned           in_node_list:1;               /* W3: in the per-worker node list */
    u_char             inbuf[NGX_BRIX_CMS_MAX_FRAME];
    size_t             in_pos;
    size_t             in_need;
} brix_cms_srv_ctx_t;

/* Per-server-block config for the CMS server module. */
struct ngx_stream_brix_cms_srv_conf_s {
    ngx_flag_t   enable;
    time_t       interval;     /* ping interval in seconds; default 60 */
    ngx_array_t *allow;        /* ngx_cidr_t[]: permitted data-node IPs (W1b) */
    ngx_str_t    sss_keytab;   /* path to the cluster sss keytab (W1a)        */
    ngx_array_t *sss_keys;     /* parsed brix_sss_key_t[] from the keytab    */

    /* ---- Phase 50: accept-side network-fault resilience (the untrusted face) ----
     * The manager arms no timer until AFTER a node logs in, so a peer that never
     * completes LOGIN (or trickles a partial header) squats a ctx + fd forever,
     * and a silently-dead post-login node is only reaped when a ping *send* fails
     * (which a black-holed peer never does).  These close both holes.  Unset
     * auto-derives a generous ON default; an explicit 0 disables. */
    ngx_msec_t   login_timeout;   /* [brix_cms_server_login_timeout] deadline to
                                     complete LOGIN (+sss xauth); unset => 10s. */
    ngx_msec_t   idle_timeout;    /* [brix_cms_server_idle_timeout] post-login
                                     inbound-silence deadline; unset =>
                                     max(3*interval, 90s). 0 = off. */
    ngx_int_t    max_connections; /* [brix_cms_server_max_connections] per-worker
                                     cap on accepted CMS connections; unset => 4096.
                                     0 = unlimited. */
    ngx_int_t    max_connections_per_ip; /* [brix_cms_server_max_connections_per_ip]
                                     A3: per-source-IP cap; unset => 256. 0 = off. */
    ngx_flag_t   tcp_keepalive;   /* [brix_cms_server_tcp_keepalive on] */
    ngx_msec_t   tcp_user_timeout;/* [brix_cms_server_tcp_user_timeout] ms; unset
                                     => idle-timeout backstop. 0 = off. */

    brix_cms_meter_t meter;       /* Phase-89 W4: usage-reply load meter (one
                                     per srv block; all-zeroes valid state) */

    /* ---- Phase-89 W6′: file-driven blacklist ----
     * [brix_cms_blacklist_file] path to an operator blacklist (one host,
     * host:port, or IPv4 CIDR per line).  Polled from the ping tick + after
     * each registration; file entries win over admin undrain and over the
     * blacklist-clear inside brix_srv_register (re-asserted every poll). */
    ngx_str_t          blacklist_file;
    brix_cms_blfile_t  blfile;    /* poll state (all-zeroes valid) */
};

/* Module descriptor declared in server_module.c. */
extern ngx_module_t  ngx_stream_brix_cms_srv_module;

/* server_handler.c — per-worker accepted-CMS-connection counter (WS4).
 * A live gauge of accepted CMS data-server connections in this worker, used to
 * enforce brix_cms_server_max_connections.  Encapsulated behind accessors so
 * the single process-global counter has exactly one definition. */
ngx_uint_t brix_cms_srv_conn_count(void);
void       brix_cms_srv_conn_inc(void);
void       brix_cms_srv_conn_dec(void);

/* A3: per-source-IP connection accounting (per-worker). */
ngx_uint_t brix_cms_srv_ip_count(const char *ip);
void       brix_cms_srv_ip_inc(const char *ip);
void       brix_cms_srv_ip_dec(const char *ip);

/* Phase-89 W3: per-worker list of LOGGED-IN node connections, so the locate
 * state fan-out can reach the nodes this worker owns (same per-worker design
 * as the pending table; cross-worker fan-out is the PR-8 aggregation plane).
 * Encapsulated behind accessors like the WS4 counter — add/del are idempotent
 * via ctx->in_node_list; iteration is count + positional fetch (stable only
 * within one event-handler invocation). */
void                brix_cms_srv_node_add(brix_cms_srv_ctx_t *ctx);
void                brix_cms_srv_node_del(brix_cms_srv_ctx_t *ctx);
ngx_uint_t          brix_cms_srv_node_count(void);
brix_cms_srv_ctx_t *brix_cms_srv_node_at(ngx_uint_t i);

/* Phase-89 W3: per-worker streamid generator for manager-initiated kYR_state
 * probes.  High bit set so the ids can never collide with the parent-leg
 * generator (ngx_brix_cms_next_streamid) in the shared pid-keyed pending
 * table when a node is both a CMS server and a CMS client. */
uint32_t brix_cms_srv_next_streamid(void);

/* server_handler.c */

/* Stream connection handler for an accepted CMS data-server connection.
 * Allocates the per-conn ctx on c->pool, runs the W1b CIDR allowlist gate and
 * arms the W1a sss handshake, installs the read/write handlers, then drives the
 * first read inline.  Finalizes the session (no ctx leak — pool-cleaned) on
 * alloc failure or a denied peer; otherwise returns with the conn live. */
void brix_cms_srv_handler(ngx_stream_session_t *s);

/* server_recv.c */

/* Read-event handler: accumulates the fixed header then the dlen-sized payload
 * into ctx->inbuf, dispatching each complete frame (LOGIN/LOAD/AVAIL/PONG/...).
 * Closes the connection on peer EOF/error, read timeout, or an oversized frame
 * (> NGX_BRIX_CMS_MAX_FRAME).  ctx may be freed on return — do not reuse. */
void brix_cms_srv_read(ngx_event_t *ev);

/* Write-event handler.  All sends are synchronous (see send_ping), so this only
 * acts as a write-timeout guard: closes the connection if ev->timedout. */
void brix_cms_srv_write(ngx_event_t *ev);

/* Tear down one CMS server connection: cancels the ping timer, and if the node
 * was logged_in, blacklists host:port for 30 s (so in-flight locates skip a node
 * that just left) before closing.  Idempotent when ctx->c is already NULL; sets
 * ctx->c = NULL.  Does not free ctx (it lives on the connection pool). */
void brix_cms_srv_close(brix_cms_srv_ctx_t *ctx);

/* server_send.c */

/* Send an empty CMS_RR_PING heartbeat frame to the data node (synchronous).
 * Returns NGX_OK on success, NGX_ERROR if the connection is closed or the
 * write fails. */
ngx_int_t brix_cms_srv_send_ping(brix_cms_srv_ctx_t *ctx);

/* Send the manager's kYR_xauth security challenge (the parms string, e.g.
 * "&P=sss", of length len) inviting the node to present its sss credential.
 * parms is borrowed (copied into the wire frame, not retained).  Returns NGX_OK
 * on a successful synchronous write, NGX_ERROR otherwise. */
ngx_int_t brix_cms_srv_send_xauth(brix_cms_srv_ctx_t *ctx,
    const u_char *parms, size_t len);

/* Plane A liveness/query replies (byte-exact with cmsd do_Ping/do_Disc/do_Update).
 * Each is a header-only frame written synchronously; NGX_OK / NGX_ERROR. */
ngx_int_t brix_cms_srv_send_pong(brix_cms_srv_ctx_t *ctx);
ngx_int_t brix_cms_srv_send_disc(brix_cms_srv_ctx_t *ctx);
ngx_int_t brix_cms_srv_send_status(brix_cms_srv_ctx_t *ctx, u_char modifier);
ngx_int_t brix_cms_srv_send_load(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char load6[6], uint32_t free_mb);
ngx_int_t brix_cms_srv_send_data(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const u_char *payload, size_t len);

/* Phase-89 W3: ask the node "do you hold <path>?" — kYR_state with the raw
 * NUL-terminated path (the node answers kYR_have echoing streamid, or stays
 * silent).  Synchronous write; NGX_OK / NGX_ERROR. */
ngx_int_t brix_cms_srv_send_state(brix_cms_srv_ctx_t *ctx, uint32_t streamid,
    const char *path);

/* server_auth.c — W1 registration authentication (CIDR + sss + host validation) */

/* Accept-time peer check: NGX_OK if the peer is permitted to register.
 * When no allowlist is configured this returns NGX_OK (back-compat) after a
 * one-time warning; when an allowlist is set, only matching IPs pass. */
ngx_int_t brix_cms_srv_check_peer(ngx_connection_t *c,
    ngx_stream_brix_cms_srv_conf_t *conf);

/* Verify an SSS credential blob from a kYR_xauth response against the cluster
 * keytab.  NGX_OK = authenticated; anything else = reject. */
ngx_int_t brix_cms_srv_verify_xauth(brix_cms_srv_ctx_t *ctx,
    const u_char *payload, size_t payload_len);

#endif /* BRIX_CMS_SERVER_H */
