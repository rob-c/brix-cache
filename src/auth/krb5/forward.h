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

#endif /* BRIX_AUTH_KRB5_FORWARD_H */
