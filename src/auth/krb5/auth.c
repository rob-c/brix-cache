#include "core/ngx_brix_module.h"
#include "observability/metrics/unified.h"
#include "protocols/root/session/registry.h"

#include <string.h>

/*
 * auth.c — Kerberos 5 (krb5) authentication for the XRootD stream protocol
 *
 * WHAT: Implements brix_handle_krb5_auth(), the per-connection handler that
 *       verifies an AP_REQ ticket presented by a client during the kXR_login /
 *       kXR_auth exchange. On success it records the mapped client name in
 *       ctx->login.dn, marks the session authenticated, registers it in the session
 *       registry and tracks the identity in shared metrics.
 *
 * WHY: One of the stream protocol's supported auth mechanisms is "krb5". When a
 *      server is configured with brix_auth krb5 (see config.c), inbound
 *      credentials must be validated against the server's keytab/principal so
 *      that only holders of a valid Kerberos ticket gain access. Failures must
 *      emit a kXR_NotAuthorized wire error and a "0" auth metric, never grant.
 *
 * HOW: The payload carries the literal prefix "krb5" followed by the raw AP_REQ
 *      bytes. We init a krb5_auth_context, optionally bind the peer address for
 *      replay/IP checking (conf->krb5.ip_check), then call krb5_rd_req() against
 *      conf->krb5.principal_obj / conf->krb5.keytab_obj prepared at config time.
 *      The verified ticket's client principal is mapped to a local name
 *      (krb5_aname_to_localname, falling back to the full unparsed principal).
 *      All krb5 code is gated on BRIX_HAVE_KRB5; when absent the handler
 *      always denies. Errors are surfaced via brix_krb5_error() which wraps
 *      krb5_get_error_message() and must be paired with brix_krb5_free_error().
 */

#if (BRIX_HAVE_KRB5)
/*
 * Request-scoped bundle for the krb5 auth flow. The connection context, nginx
 * connection and server config travel together through every stage, so grouping
 * them keeps each stage helper at or below the five-parameter limit without
 * introducing any shared/global state (one instance lives on the handler stack).
 */
typedef struct {
    brix_ctx_t                   *ctx;
    ngx_connection_t             *c;
    ngx_stream_brix_srv_conf_t   *conf;
} brix_krb5_req_t;

static const char *
brix_krb5_error(ngx_stream_brix_srv_conf_t *conf, krb5_error_code rc)
{
    return conf->krb5.context != NULL
           ? krb5_get_error_message(conf->krb5.context, rc)
           : NULL;
}

static void
brix_krb5_free_error(ngx_stream_brix_srv_conf_t *conf, const char *msg)
{
    if (conf->krb5.context != NULL && msg != NULL) {
        krb5_free_error_message(conf->krb5.context, msg);
    }
}

/*
 * Fill a krb5_address from the connection's peer sockaddr so the AP_REQ can be
 * checked against the client's source IP (replay/host binding). Supports IPv4
 * (ADDRTYPE_INET) and IPv6 (ADDRTYPE_INET6); returns NGX_DECLINED for any other
 * family or missing sockaddr. The contents pointer aliases c->sockaddr, so the
 * krb5_address is only valid for the lifetime of the call that consumes it.
 */
static ngx_int_t
brix_krb5_peer_addr(ngx_connection_t *c, krb5_address *addr)
{
    if (c == NULL || c->sockaddr == NULL || addr == NULL) {
        return NGX_DECLINED;
    }

    if (c->sockaddr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) c->sockaddr;
        addr->addrtype = ADDRTYPE_INET;
        addr->length = sizeof(sin->sin_addr);
        addr->contents = (krb5_octet *) &sin->sin_addr;
        return NGX_OK;
    }

    if (c->sockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) c->sockaddr;
        addr->addrtype = ADDRTYPE_INET6;
        addr->length = sizeof(sin6->sin6_addr);
        addr->contents = (krb5_octet *) &sin6->sin6_addr;
        return NGX_OK;
    }

    return NGX_DECLINED;
}

/*
 * Resolve the verified ticket's client into a name string in dst. Prefers a
 * Kerberos->local mapping (krb5_aname_to_localname, honouring krb5.conf
 * auth_to_local rules); if no local mapping exists, falls back to the full
 * unparsed principal (user@REALM). Output is always NUL-terminated. Returns
 * NGX_ERROR if the ticket lacks an enc_part2/client or both lookups fail.
 */
static ngx_int_t
brix_krb5_client_name(ngx_stream_brix_srv_conf_t *conf,
    krb5_ticket *ticket, char *dst, size_t dst_len)
{
    krb5_error_code rc;
    char           *principal;

    if (ticket == NULL || ticket->enc_part2 == NULL
        || ticket->enc_part2->client == NULL || dst == NULL || dst_len == 0)
    {
        return NGX_ERROR;
    }

    rc = krb5_aname_to_localname(conf->krb5.context,
                                 ticket->enc_part2->client,
                                 (int) dst_len - 1, dst);
    if (rc == 0) {
        dst[dst_len - 1] = '\0';
        return NGX_OK;
    }

    principal = NULL;
    rc = krb5_unparse_name(conf->krb5.context, ticket->enc_part2->client,
                           &principal);
    if (rc != 0 || principal == NULL) {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) dst, (u_char *) principal, dst_len);
    krb5_free_unparsed_name(conf->krb5.context, principal);
    return NGX_OK;
}

/*
 * Record the authenticated client's name (ctx->login.dn) in the shared-memory
 * metrics so it counts toward the unique-user gauge. No-op if metrics shm is
 * unavailable or the identity is empty.
 */
static void
brix_krb5_track_identity(brix_ctx_t *ctx)
{
    ngx_brix_metrics_t *shm;

    shm = brix_metrics_shared();
    if (shm == NULL || ctx->login.dn[0] == '\0') {
        return;
    }

    brix_track_unique_user(shm, ctx->login.dn, strlen(ctx->login.dn));
}

/*
 * WHAT: Validate that krb5 is configured and the payload is a "krb5"-prefixed
 *       credential blob, before any krb5 library state is created.
 *
 * WHY: These are the two cheap, allocation-free rejections that must deny with
 *      kXR_NotAuthorized and a "0" auth metric. Splitting them out keeps the
 *      main handler focused on the GSSAPI exchange itself.
 *
 * HOW: Returns NGX_OK to proceed. On rejection, emits the metric + wire error
 *      (whose send result is NGX_OK) into *out and returns NGX_DONE so the
 *      caller propagates *out unchanged.
 */
static ngx_int_t
brix_krb5_prechecks(brix_krb5_req_t *rq, ngx_int_t *out)
{
    brix_ctx_t                 *ctx = rq->ctx;
    ngx_connection_t           *c = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;

    if (conf->krb5.context == NULL || conf->krb5.principal_obj == NULL
        || conf->krb5.keytab_obj == NULL)
    {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        brix_log_access(ctx, c, "AUTH", "-", "krb5", 0, kXR_NotAuthorized,
                          "krb5 not configured", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 not configured");
        return NGX_DONE;
    }

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen <= 4
        || ngx_strncmp(ctx->recv.payload, "krb5", 4) != 0)
    {
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        brix_log_access(ctx, c, "AUTH", "-", "krb5", 0, kXR_NotAuthorized,
                          "malformed krb5 credential", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "malformed krb5 credential");
        return NGX_DONE;
    }

    return NGX_OK;
}

/*
 * WHAT: Optionally bind the client's peer address into auth_ctx so krb5_rd_req()
 *       enforces the AP_REQ source-IP check (conf->krb5.ip_check).
 *
 * WHY: When ip_check is enabled the AP_REQ must have been generated for this
 *      client's address; a mismatch or an unbindable address must deny. Keeping
 *      this as its own stage preserves the exact auth_ctx free ordering on the
 *      failure paths.
 *
 * HOW: No-op returning NGX_OK when ip_check is off. On failure it frees auth_ctx,
 *      emits metric + wire error into *out and returns NGX_DONE. On success
 *      returns NGX_OK with auth_ctx bound.
 */
static ngx_int_t
brix_krb5_bind_peer(brix_krb5_req_t *rq, krb5_auth_context auth_ctx,
    ngx_int_t *out)
{
    brix_ctx_t                 *ctx = rq->ctx;
    ngx_connection_t           *c = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    krb5_address                peer_addr;
    krb5_error_code             rc;
    const char                 *kmsg;

    if (!conf->krb5.ip_check) {
        return NGX_OK;
    }

    if (brix_krb5_peer_addr(c, &peer_addr) != NGX_OK) {
        krb5_auth_con_free(conf->krb5.context, auth_ctx);
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        brix_log_access(ctx, c, "AUTH", "-", "krb5", 0, kXR_NotAuthorized,
                          "cannot bind krb5 peer address", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "cannot bind krb5 peer address");
        return NGX_DONE;
    }

    rc = krb5_auth_con_setaddrs(conf->krb5.context, auth_ctx, NULL, &peer_addr);
    if (rc != 0) {
        kmsg = brix_krb5_error(conf, rc);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: krb5 peer address check setup failed: %s",
                      kmsg ? kmsg : "unknown");
        brix_krb5_free_error(conf, kmsg);
        krb5_auth_con_free(conf->krb5.context, auth_ctx);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 authentication failed");
        return NGX_DONE;
    }

    return NGX_OK;
}

/*
 * WHAT: Strip the "krb5" credential prefix and verify the AP_REQ against the
 *       server principal + keytab, yielding the client ticket.
 *
 * WHY: This is the cryptographic core of the exchange. The official XrdSeckrb5
 *      client NUL-terminates the prefix ("krb5\0" + AP-REQ) while the native
 *      client emits a bare "krb5" + AP-REQ, so the optional trailing NUL is
 *      skipped before the raw AP-REQ is handed to krb5_rd_req(). A real AP-REQ
 *      begins with its ASN.1 APPLICATION tag (0x6e/0x7e), never 0x00, so this
 *      is unambiguous and cannot truncate a genuine token.
 *
 * HOW: auth_ctx is passed by pointer because krb5_rd_req() may update the
 *      auth-context handle; the caller's variable must reflect that so its free
 *      operates on the current handle. On failure it frees *auth_ctx, logs
 *      access, emits metric + wire error into *out and returns NGX_DONE. On
 *      success *ticket holds the verified ticket (caller owns the free) and
 *      returns NGX_OK.
 */
static ngx_int_t
brix_krb5_verify_req(brix_krb5_req_t *rq, krb5_auth_context *auth_ctx,
    krb5_ticket **ticket, ngx_int_t *out)
{
    brix_ctx_t                 *ctx = rq->ctx;
    ngx_connection_t           *c = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    krb5_data                   inbuf;
    krb5_error_code             rc;
    const char                 *kmsg;
    size_t                      krb5_off;

    krb5_off = 4;
    if (ctx->recv.cur_dlen > 5 && ctx->recv.payload[4] == '\0') {
        krb5_off = 5;
    }
    inbuf.length = (unsigned int) (ctx->recv.cur_dlen - krb5_off);
    inbuf.data = (char *) (ctx->recv.payload + krb5_off);

    rc = krb5_rd_req(conf->krb5.context, auth_ctx, &inbuf,
                     conf->krb5.principal_obj, conf->krb5.keytab_obj,
                     NULL, ticket);
    if (rc != 0) {
        kmsg = brix_krb5_error(conf, rc);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: krb5 credential verification failed: %s",
                      kmsg ? kmsg : "unknown");
        brix_krb5_free_error(conf, kmsg);
        krb5_auth_con_free(conf->krb5.context, *auth_ctx);
        brix_log_access(ctx, c, "AUTH", "-", "krb5",
                          0, kXR_NotAuthorized,
                          "krb5 credential verification failed", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 authentication failed");
        return NGX_DONE;
    }

    return NGX_OK;
}

/*
 * WHAT: On a verified ticket, map the client principal into ctx->login.dn, mark
 *       the session authenticated, populate the identity, register the session
 *       and track metrics. Consumes (frees) both the ticket and auth_ctx.
 *
 * WHY: Isolates the success-side bookkeeping from the verification stages while
 *      preserving the exact free ordering (ticket then auth_ctx) that the
 *      original single function used on both its success and mapping-failure
 *      paths.
 *
 * HOW: On a principal-mapping failure it frees ticket + auth_ctx, emits metric +
 *      wire error into *out and returns NGX_DONE. On success it frees ticket +
 *      auth_ctx, finalizes the session, sets *out to the OK send result and
 *      returns NGX_DONE (the handler has nothing left to do either way).
 */
static ngx_int_t
brix_krb5_finalize(brix_krb5_req_t *rq, krb5_auth_context auth_ctx,
    krb5_ticket *ticket, ngx_int_t *out)
{
    brix_ctx_t                 *ctx = rq->ctx;
    ngx_connection_t           *c = rq->c;
    ngx_stream_brix_srv_conf_t *conf = rq->conf;
    char                        cname[512];
    char                        safe_cname[1024];

    if (brix_krb5_client_name(conf, ticket, cname, sizeof(cname)) != NGX_OK) {
        krb5_free_ticket(conf->krb5.context, ticket);
        krb5_auth_con_free(conf->krb5.context, auth_ctx);
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        brix_log_access(ctx, c, "AUTH", "-", "krb5", 0, kXR_NotAuthorized,
                          "cannot map krb5 client principal", 0);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        *out = brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "cannot map krb5 client principal");
        return NGX_DONE;
    }

    krb5_free_ticket(conf->krb5.context, ticket);
    krb5_auth_con_free(conf->krb5.context, auth_ctx);

    ctx->login.auth_done = 1;
    ctx->token.auth = 0;
    ngx_cpystrn((u_char *) ctx->login.dn, (u_char *) cname,
                sizeof(ctx->login.dn));

    if (ctx->identity != NULL) {
        if (brix_identity_set_dn(ctx->identity, c->pool, ctx->login.dn,
                                   BRIX_AUTHN_KRB5) != NGX_OK)
        {
            *out = brix_send_error(ctx, c, kXR_NoMemory,
                                     "identity allocation failed");
            return NGX_DONE;
        }
    }

    brix_session_register(ctx->login.sessid, ctx->login.dn,
                            ctx->login.vo_list, 0);
    brix_krb5_track_identity(ctx);

    brix_sanitize_log_string(cname, safe_cname, sizeof(safe_cname));
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: krb5 auth OK principal=\"%s\"", safe_cname);

    brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 1);
    brix_log_access(ctx, c, "AUTH", "-", "krb5", 1, kXR_ok, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_AUTH);
    *out = brix_send_ok(ctx, c, NULL, 0);
    return NGX_DONE;
}
#endif

/*
 *
 * WHAT: Verify a client's krb5 AP_REQ credential and, on success, mark the
 *       stream session as authenticated under BRIX_AUTHN_KRB5.
 *
 * WHY: Called from the auth dispatch path when the negotiated mechanism is
 *      "krb5". This is the single point that decides whether a Kerberos client
 *      is granted access; every failure path must deny with kXR_NotAuthorized
 *      and emit a "0" auth metric, and every success must register the session.
 *
 * HOW: 1. Reject early if krb5 is unconfigured (no context/principal/keytab) or
 *         the payload is not the "krb5"-prefixed credential blob.
 *      2. krb5_auth_con_init, optionally bind the peer address when
 *         conf->krb5.ip_check is set.
 *      3. krb5_rd_req() validates the AP_REQ against the server principal and
 *         keytab, yielding the client ticket.
 *      4. Map the client principal to a name (brix_krb5_client_name) into
 *         ctx->login.dn, free ticket/auth context, set auth_done, populate the
 *         identity object, register the session, track metrics, and return OK.
 *      Stages 1, 2b, 3 and 4 are delegated to static helpers that emit their own
 *      wire error and signal NGX_DONE with the send result in `out`; the
 *      auth_con_init failure (2a) is handled inline. Returns the resulting
 *      brix_send_ok / brix_send_error value (NGX_*).
 *      Built without BRIX_HAVE_KRB5, it unconditionally denies.
 */
ngx_int_t
brix_handle_krb5_auth(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
#if (BRIX_HAVE_KRB5)
    brix_krb5_req_t   rq;
    krb5_auth_context auth_ctx;
    krb5_ticket      *ticket;
    krb5_error_code   rc;
    const char       *kmsg;
    ngx_int_t         out;

    rq.ctx = ctx;
    rq.c = c;
    rq.conf = conf;
    out = NGX_ERROR;

    if (brix_krb5_prechecks(&rq, &out) == NGX_DONE) {
        return out;
    }

    auth_ctx = NULL;
    ticket = NULL;

    rc = krb5_auth_con_init(conf->krb5.context, &auth_ctx);
    if (rc != 0) {
        kmsg = brix_krb5_error(conf, rc);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: krb5 auth context init failed: %s",
                      kmsg ? kmsg : "unknown");
        brix_krb5_free_error(conf, kmsg);
        BRIX_OP_ERR(ctx, BRIX_OP_AUTH);
        brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
        return brix_send_error(ctx, c, kXR_NotAuthorized,
                                 "krb5 authentication failed");
    }

    if (brix_krb5_bind_peer(&rq, auth_ctx, &out) == NGX_DONE) {
        return out;
    }

    if (brix_krb5_verify_req(&rq, &auth_ctx, &ticket, &out) == NGX_DONE) {
        return out;
    }

    brix_krb5_finalize(&rq, auth_ctx, ticket, &out);
    return out;
#else
    brix_metric_auth(BRIX_PROTO_ROOT, BRIX_AUTHN_KRB5, 0);
    BRIX_RETURN_ERR(ctx, c, BRIX_OP_AUTH, "AUTH", "-", "krb5",
                      kXR_NotAuthorized, "krb5 support is not compiled in");
#endif
}
