#ifndef BRIX_AUTH_KRB5_FORWARD_H
#define BRIX_AUTH_KRB5_FORWARD_H

#include "core/ngx_brix_module.h"

/*
 * forward.h — krb5 GSSAPI credential forwarding to the backend/origin.
 *
 * WHAT: One-shot helper that, given a forwardable delegated GSS credential
 *       captured during inbound krb5 auth (a gss_cred_id_t obtained with
 *       GSS_C_DELEG_FLAG), initiates a fresh GSSAPI security context to the
 *       upstream/origin service principal so this node acts AS the inbound user.
 *
 * WHY: Phase-70 §5.7 — krb5 is only backend-usable by EXCHANGE (GSSAPI
 *      forwarding). When the client presents a forwardable ticket the node
 *      receives a delegated credential and can re-authenticate to the origin on
 *      the user's behalf, with no admin pre-provisioning.
 *
 * HOW: brix_krb5_deleg_to_origin() imports the origin service principal name,
 *      acquires nothing (it uses the supplied delegated cred as the initiator
 *      identity) and calls gss_init_sec_context() ONCE, returning the initial
 *      output token to send to the origin. This is deliberately a single
 *      init-context step: the multi-leg GSSAPI negotiation loop (feeding origin
 *      replies back through gss_init_sec_context until GSS_S_COMPLETE) belongs to
 *      the origin-auth caller, which owns the wire exchange and the context
 *      handle lifetime. Availability is reported by brix_krb5_forward_available()
 *      so callers can fall back to SELECT when forwarding is not compiled in or
 *      not supported.
 */

/*
 * Return 1 if this build was compiled with krb5/GSSAPI support AND credential
 * forwarding is available; 0 otherwise (caller falls back to SELECT).
 */
int brix_krb5_forward_available(void);

/*
 * Initiate a GSSAPI security context to the origin as the delegated user.
 *
 * pool                 — token bytes are copied here; caller owns nothing else.
 * deleg_gss_cred       — gss_cred_id_t (as void*) captured with GSS_C_DELEG_FLAG
 *                        during inbound auth; the initiator identity. May be
 *                        GSS_C_NO_CREDENTIAL (NULL) to use the default cred.
 * origin_service_princ — target service principal, e.g. "host@origin.example".
 * out_token            — filled with the initial GSS token to send to the origin
 *                        (bytes copied into pool). Untouched on failure.
 * log                  — for gss-major/minor diagnostics.
 *
 * Returns NGX_OK with the first-leg token in *out_token, or NGX_ERROR (GSSAPI
 * major/minor logged). This performs ONE gss_init_sec_context() step only; the
 * caller drives any subsequent legs.
 */
ngx_int_t brix_krb5_deleg_to_origin(ngx_pool_t *pool, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token, ngx_log_t *log);

/*
 * Wire transceiver callback driving one negotiation leg (phase-70 §5.7 origin
 * wire). brix_krb5_deleg_negotiate() calls it every time the local
 * gss_init_sec_context() produces an output token that must reach the origin:
 *
 *   wire_ctx  — opaque caller state (the origin connection: kXR wire for
 *               origin_auth.c, an in-process acceptor for the live test).
 *   out_token — the token this leg produced (non-empty); send it to the origin.
 *   in_token  — filled with the origin's reply token. Set len==0 (data may be
 *               NULL) when the origin replied with none. Its bytes must stay
 *               valid until the next wire() call or until negotiate() returns
 *               (the engine copies nothing — it feeds them straight back into
 *               gss_init_sec_context as the next input token).
 *   done      — set to 1 iff the origin signalled the exchange is complete
 *               (kXR_ok, not kXR_authmore); else 0.
 *   log       — for diagnostics.
 *
 * Returns NGX_OK to continue the negotiation, NGX_ERROR to abort it (the origin
 * rejected the token or the transport failed — negotiate() then fails closed).
 */
typedef ngx_int_t (*brix_krb5_wire_fn)(void *wire_ctx,
    const ngx_str_t *out_token, ngx_str_t *in_token, int *done, ngx_log_t *log);

/*
 * Drive the FULL multi-leg GSSAPI negotiation to the origin AS the delegated
 * user (phase-70 §5.7). Where brix_krb5_deleg_to_origin() performs one
 * gss_init_sec_context() step, this owns the whole loop: it initialises the
 * security context, hands each output token to `wire` for delivery to the
 * origin, feeds the origin's reply back into gss_init_sec_context(), and repeats
 * until the local context reports GSS_S_COMPLETE. Mutual auth is requested, so
 * the origin's AP-REP is verified before success — a spoofed origin cannot
 * complete the exchange.
 *
 * pool                 — token bytes handed to `wire` are copied here.
 * deleg_gss_cred       — gss_cred_id_t (as void*) captured with GSS_C_DELEG_FLAG;
 *                        the initiator identity. GSS_C_NO_CREDENTIAL (NULL) uses
 *                        the process default cred.
 * origin_service_princ — target service principal (GSS_KRB5_NT_PRINCIPAL_NAME).
 * wire                 — transceiver invoked once per outbound token (above).
 * wire_ctx             — opaque state passed to `wire`.
 * log                  — for gss/major-minor diagnostics.
 *
 * Returns NGX_OK once the initiator context is GSS_S_COMPLETE (the origin
 * authenticated this node AS the delegated user), or NGX_ERROR — GSS failure,
 * a wire/transport error, or the origin closing the exchange before completion.
 * Never leaks the GSS context or target name on either path. Without krb5/GSSAPI
 * support this reports unavailable and returns NGX_ERROR.
 */
ngx_int_t brix_krb5_deleg_negotiate(ngx_pool_t *pool, void *deleg_gss_cred,
    const char *origin_service_princ, brix_krb5_wire_fn wire, void *wire_ctx,
    ngx_log_t *log);

/*
 * Build the origin service principal "host/<backend_fqdn>@<REALM>" for the
 * forwarded GSS context, deriving REALM from the gateway's own principal
 * (phase-70 §5.7 — derive-from-backend-host, no dedicated directive). Always
 * compiled (pure string assembly, no krb5). Returns NGX_OK with a NUL-terminated
 * principal in out[0..outlen), or NGX_ERROR on malformed input / overflow.
 */
ngx_int_t brix_krb5_origin_princ_from_host(const char *backend_fqdn,
    const char *gateway_princ, char *out, size_t outlen);

#endif /* BRIX_AUTH_KRB5_FORWARD_H */
