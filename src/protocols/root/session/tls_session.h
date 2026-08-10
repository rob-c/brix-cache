/*
 * tls_session.h — §5.10 (xrootd.tlsreuse) TLS session-resumption policy for the
 * root:// in-protocol TLS context.
 *
 * Header-inline (no nginx types, pure OpenSSL) on purpose: brix_configure_tls
 * (nginx-coupled) applies it, and a self-contained OpenSSL unit test exercises
 * the SAME code by #including this header — without linking the nginx core the
 * TU otherwise drags in.
 */
#pragma once

#include <openssl/ssl.h>

/*
 * When session reuse is OFF, disable TLS session resumption on `ctx`: clear the
 * server session cache AND session tickets so every connection performs a full
 * handshake (per-connection forward secrecy; no resumption state to capture or
 * replay). Reuse ON (or a NULL ctx) leaves the OpenSSL/nginx defaults untouched,
 * so the knob is inert unless an operator opts out.
 */
static inline void
brix_tls_apply_session_reuse(SSL_CTX *ctx, int reuse_on)
{
    if (ctx == NULL || reuse_on) {
        return;
    }
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
}
