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

/* Crypto helpers all three translation units call — defined in
 * parse_crypto_helpers.c */
BIGNUM *brix_gsi_parse_client_dh_public_key(ngx_connection_t *c, ngx_log_t *log,
    const u_char *public_key_blob, size_t public_key_blob_len);
void brix_gsi_select_cipher_name(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size);
EVP_PKEY *brix_gsi_build_peer_dh_key(ngx_log_t *log, EVP_PKEY *server_dh_key,
    BIGNUM *client_public_bn);

void gsi_persist_session_cipher(brix_ctx_t *ctx, const char *name,
                                const u_char *key, int keylen, int use_iv);

void gsi_capture_client_rtag(brix_ctx_t *ctx, const u_char *plain,
                             size_t plain_len);

void gsi_capture_fullproxy(brix_ctx_t *ctx, const u_char *plain,
                           size_t plain_len);

STACK_OF(X509) *gsi_chain_from_plaintext(const u_char *plain, int plain_len,
                                         ngx_log_t *log);

int gsi_arm_request_signing(brix_ctx_t *ctx);

STACK_OF(X509) *brix_gsi_parse_x509_signed(brix_ctx_t *ctx,
                                           ngx_connection_t *c);

#endif /* BRIX_GSI_PARSE_X509_INTERNAL_H */
