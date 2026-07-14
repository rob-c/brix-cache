#ifndef BRIX_GSI_PARSE_X509_INTERNAL_H
#define BRIX_GSI_PARSE_X509_INTERNAL_H

#include "gsi_internal.h"

/*
 * parse_x509_internal.h — cross-file declarations for the GSI kXGC_cert parse
 * split. The kXGC_cert handler was split into three translation units:
 *   parse_x509.c          — includes + the helpers both paths share
 *   parse_x509_signed.c   — the signed-DH round-2 path
 *   parse_x509_unsigned.c — the unsigned round-2 path + top-level dispatcher
 * These declarations expose the symbols that cross the split boundary: the
 * helpers the signed and unsigned paths both call (session-cipher persist,
 * client rtag/full-proxy capture, plaintext chain parse, signing-key derive)
 * and the signed-DH sub-handler the dispatcher (unsigned file) tail-calls.
 * Types (brix_ctx_t, ngx_*, STACK_OF(X509), EVP_*) come from gsi_internal.h.
 */

void gsi_persist_session_cipher(brix_ctx_t *ctx, const char *name,
                                const u_char *key, int keylen, int use_iv);

void gsi_capture_client_rtag(brix_ctx_t *ctx, const u_char *plain,
                             size_t plain_len);

void gsi_capture_fullproxy(brix_ctx_t *ctx, const u_char *plain,
                           size_t plain_len);

STACK_OF(X509) *gsi_chain_from_plaintext(const u_char *plain, int plain_len,
                                         ngx_log_t *log);

int gsi_store_signing_key(brix_ctx_t *ctx, const unsigned char *secret,
                          size_t secret_len);

STACK_OF(X509) *brix_gsi_parse_x509_signed(brix_ctx_t *ctx,
                                           ngx_connection_t *c);

#endif /* BRIX_GSI_PARSE_X509_INTERNAL_H */
