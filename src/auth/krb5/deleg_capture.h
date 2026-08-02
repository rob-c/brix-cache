#ifndef BRIX_AUTH_KRB5_DELEG_CAPTURE_H
#define BRIX_AUTH_KRB5_DELEG_CAPTURE_H

#include "core/ngx_brix_module.h"

/*
 * deleg_capture.h — inbound XrdSeckrb5 forwarded-TGT delegation-capture state
 * machine (phase-70 §5.7).
 *
 * WHAT: The server-side two-round exchange that turns a verified krb5 login into
 *       a forwardable initiator credential for the outbound origin leg. Round 1
 *       (in auth.c) verifies the AP_REQ, and — when brix_krb5_delegate is on —
 *       parks the round-1 session subkey + client principal (brix_krb5_deleg_park)
 *       and replies kXR_authmore "fwdtgt" (brix_krb5_send_fwdtgt) instead of
 *       finalizing. Round 2 receives the client's krb5_fwd_tgt_creds() KRB_CRED,
 *       decrypts it with the parked subkey, and serialises the captured TGT to a
 *       fresh 0600 FILE ccache whose path is stashed on ctx->krb5.ccache
 *       (brix_krb5_deleg_capture).
 *
 * WHY:  The origin auth engine (brix_cache_origin_auth_krb5) and the async-safe
 *       cred carry (carry.c) are already live; this is the missing front-door
 *       CAPTURE that feeds them. Its output (the parked ccache) is consumed at
 *       request time by brix_root_vfs_bind_deleg → brix_vfs_deleg_set_krb5, so the
 *       forwarded TGT re-authenticates the backend leg AS the inbound user.
 *
 * The capture crypto (brix_krb5_capture_fwd_cred) and the FILE-ccache export
 * (brix_krb5_cred_to_ccache) are proven live vs a real MIT KDC by
 * tests/test_krb5_forward_live.py; the synchronous seams here (the gate, the
 * round-2 payload framing, the origin-SPN derivation) are unit-tested by
 * tests/c/krb5_deleg_capture_test.c. All handles stay opaque behind void* on
 * brix_ctx_krb5_t so krb5.h never leaks into the widely-included ctx header.
 */

/* Is inbound krb5 TGT-forwarding delegation requested for this server? Pure gate
 * on conf->krb5.delegate; returns 1 when on, 0 otherwise. */
int brix_krb5_deleg_wanted(ngx_stream_brix_srv_conf_t *conf);

/* Strip the "krb5" credential prefix (and the optional trailing NUL the official
 * XrdSeckrb5 client appends) from a round-2 payload, yielding the raw forwarded
 * KRB_CRED bytes. Returns NGX_OK with cred and credlen set, NGX_ERROR if the
 * payload is too short or lacks the prefix. Pure — no krb5/nginx state. */
ngx_int_t brix_krb5_deleg_credbytes(const u_char *payload, size_t dlen,
    const u_char **cred, size_t *credlen);

/* Build + queue the round-1 kXR_authmore "fwdtgt" continuation that asks the
 * client to forward its TGT. Returns the brix_queue_response result. Always
 * compiled (pure wire assembly). */
ngx_int_t brix_krb5_send_fwdtgt(brix_ctx_t *ctx, ngx_connection_t *c);

/*
 * Request-time gate + origin service-principal derivation for the VFS delegation
 * bind. When a forwarded TGT was captured (ccache set), forwarding is armed
 * (backend_krb5_forwardable), and both the configured origin host and the
 * gateway's own principal (for the REALM) are present, derives
 * "host/<origin_host>@<REALM>" onto *pool and returns NGX_OK with *out_spn set.
 * Returns NGX_DECLINED when any gate is unmet (nothing to bind) and NGX_ERROR
 * when the derivation itself fails (fail closed — do not bind). Pure apart from
 * the pool allocation, so unit-testable with a throwaway pool. */
ngx_int_t brix_krb5_deleg_origin_spn(const ngx_str_t *ccache, int forwardable,
    const ngx_str_t *origin_host, const ngx_str_t *gateway_princ,
    ngx_pool_t *pool, ngx_str_t *out_spn);

#if (BRIX_HAVE_KRB5)
/* Round 1: park the session subkey (auth_ctx) + a COPY of the verified client
 * principal + the mapped local name on ctx->krb5, register a pool cleanup that
 * releases them and unlinks any captured ccache, and set round=1. On success
 * takes ownership of auth_ctx (freed at round 2 or connection close); the caller
 * must NOT free it. On NGX_ERROR nothing is parked and the caller still owns
 * auth_ctx. `client` is copied (caller keeps theirs). */
ngx_int_t brix_krb5_deleg_park(brix_ctx_t *ctx, ngx_connection_t *c,
    krb5_context kctx, krb5_auth_context auth_ctx, krb5_principal client,
    const char *cname);

/* Round 2: decrypt the forwarded KRB_CRED (from ctx->recv.payload) with the
 * parked subkey, serialise the captured TGT to a fresh 0600 FILE ccache, stash
 * its path on ctx->krb5.ccache, and release the round-1 handles. Fails closed —
 * on any error the round state is torn down and NGX_ERROR returned with no ccache
 * bound. Returns NGX_OK when the forwarded credential is captured and ready for
 * the request-time VFS bind. */
ngx_int_t brix_krb5_deleg_capture(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf);

/* Release any parked round-1 krb5 handles (auth_ctx + client principal) and drop
 * the round state. NULL/round-0 safe; used by the pool cleanup and after a
 * successful capture. Does not unlink the ccache (the cleanup owns that). */
void brix_krb5_deleg_release(brix_ctx_t *ctx, krb5_context kctx);
#endif

#endif /* BRIX_AUTH_KRB5_DELEG_CAPTURE_H */
