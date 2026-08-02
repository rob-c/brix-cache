/*
 * auth/krb5/kxr_wire.h — transport-agnostic kXR krb5 auth wire adapter (§5.7).
 *
 * WHAT: maps the multi-leg GSSAPI negotiation callback brix_krb5_wire_fn onto
 *       the XRootD kXR_auth / kXR_authmore credential-exchange frames. Each
 *       initiator token brix_krb5_deleg_negotiate() produces is framed as a
 *       kXR_auth request (credtype "krb5"); the origin's reply frame is read and
 *       classified — kXR_authmore feeds the reply token back for another round,
 *       kXR_ok settles the exchange, anything else fails it closed.
 *
 * WHY:  the byte transport is a function pair rather than a hard dependency on
 *       the nginx origin connection so the SAME codec (the same frame bytes)
 *       serves two callers: origin_auth.c (over a brix_cache_origin_conn_t) in
 *       production, and the live krb5 harness (over a socket vs a real GSSAPI
 *       acceptor) in tests. The production path and the tested path are then
 *       provably the same code — not an analogy.
 *
 * The frame layout is the byte-frozen kXR vocabulary (ClientAuthRequest is 24
 * bytes, ServerResponseHeader 8 bytes; see protocols/root/protocol) rendered
 * here without the XProtocol structs so this unit stays ngx-light and links into
 * the standalone harness with only the pool/log stubs.
 */
#ifndef BRIX_AUTH_KRB5_KXR_WIRE_H
#define BRIX_AUTH_KRB5_KXR_WIRE_H

#include <ngx_config.h>
#include <ngx_core.h>

#include "auth/krb5/forward.h"   /* brix_krb5_wire_fn contract */

/* Byte transport for the exchange. send() writes exactly len bytes; recv() reads
 * exactly len bytes (short reads are an error). Both return NGX_OK / NGX_ERROR.
 * io is opaque state: the origin connection in production, a socket fd in test. */
typedef ngx_int_t (*brix_kxr_send_fn)(void *io, const void *buf, size_t len);
typedef ngx_int_t (*brix_kxr_recv_fn)(void *io, void *buf, size_t len);

/* wire_ctx for brix_krb5_kxr_wire(). reply holds the current leg's origin token
 * (heap, freed on the next call so the borrowed pointer stays valid exactly one
 * leg — the brix_krb5_wire_fn contract); the caller frees the final leg's reply
 * after brix_krb5_deleg_negotiate() returns. max_body caps an origin reply token
 * (anti-OOM). */
typedef struct {
    brix_kxr_send_fn  send;
    brix_kxr_recv_fn  recv;
    void             *io;
    u_char           *reply;
    uint32_t          max_body;
} brix_krb5_kxr_wire_t;

/*
 * Classify one ServerResponseHeader status into the negotiation wire contract:
 *   kXR_authmore -> in_token = body (borrowed, may be empty), *done = 0, NGX_OK
 *   kXR_ok       -> in_token = body (borrowed, may be empty), *done = 1, NGX_OK
 *   anything else (incl. kXR_error) -> NGX_ERROR (fail closed)
 * Pure (no I/O, no allocation); shared by the wire loop and unit-tested directly.
 */
ngx_int_t brix_krb5_kxr_classify(uint16_t status, u_char *body, uint32_t dlen,
    ngx_str_t *in_token, int *done);

/*
 * brix_krb5_wire_fn over a brix_krb5_kxr_wire_t* (passed as wire_ctx): frame
 * out_token as a kXR_auth("krb5") request via wire->send, read the reply header
 * + body via wire->recv, and classify it. Returns NGX_OK to continue / settle
 * (see *done), NGX_ERROR on a transport failure or a rejecting origin.
 */
ngx_int_t brix_krb5_kxr_wire(void *wire_ctx, const ngx_str_t *out_token,
    ngx_str_t *in_token, int *done, ngx_log_t *log);

#endif /* BRIX_AUTH_KRB5_KXR_WIRE_H */
