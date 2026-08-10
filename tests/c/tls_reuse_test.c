/*
 * tls_reuse_test.c — §5.10 (parity-fix wave 19): brix_tls_apply_session_reuse
 * disables TLS session resumption (session cache + tickets) when reuse is off,
 * and is inert (defaults untouched) when on.
 *
 * Self-contained: it #includes the header-inline policy and links ONLY OpenSSL —
 * no nginx core, no brix objects — so it exercises the exact code
 * brix_configure_tls runs, in isolation.
 *
 * See run_tls_reuse in tests/cmdscripts/c_auth_units_part2.py.
 */

#include <assert.h>
#include <stdio.h>

#include <openssl/ssl.h>

#include "protocols/root/session/tls_session.h"

int
main(void)
{
    int failures = 0;

    /* (1) reuse OFF — session cache disabled AND tickets suppressed, so every
     *     connection performs a full handshake. */
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        assert(ctx != NULL);
        brix_tls_apply_session_reuse(ctx, 0);
        if (SSL_CTX_get_session_cache_mode(ctx) != SSL_SESS_CACHE_OFF) {
            fprintf(stderr, "FAIL reuse-off: session cache not OFF\n");
            failures++;
        }
        if ((SSL_CTX_get_options(ctx) & SSL_OP_NO_TICKET) == 0) {
            fprintf(stderr, "FAIL reuse-off: SSL_OP_NO_TICKET not set\n");
            failures++;
        }
        SSL_CTX_free(ctx);
    }

    /* (2) reuse ON — the helper is inert: a fresh server context keeps its
     *     defaults (cache SERVER, not OFF; NO_TICKET not newly set). */
    {
        SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
        assert(ctx != NULL);
        long before = SSL_CTX_get_options(ctx);
        brix_tls_apply_session_reuse(ctx, 1);
        if (SSL_CTX_get_session_cache_mode(ctx) == SSL_SESS_CACHE_OFF) {
            fprintf(stderr, "FAIL reuse-on: session cache wrongly disabled\n");
            failures++;
        }
        if ((before & SSL_OP_NO_TICKET) == 0
            && (SSL_CTX_get_options(ctx) & SSL_OP_NO_TICKET) != 0) {
            fprintf(stderr, "FAIL reuse-on: NO_TICKET wrongly set\n");
            failures++;
        }
        SSL_CTX_free(ctx);
    }

    /* (3) NULL ctx is a safe no-op (never dereferenced). */
    brix_tls_apply_session_reuse(NULL, 0);

    if (failures == 0) {
        printf("tls_reuse: OK (off-disables + on-inert + null-safe)\n");
        return 0;
    }
    fprintf(stderr, "tls_reuse: %d assertion(s) failed\n", failures);
    return 1;
}
