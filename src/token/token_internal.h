#ifndef XROOTD_TOKEN_INTERNAL_H
#define XROOTD_TOKEN_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>

#include "token.h"

EVP_PKEY *xrootd_token_rsa_pubkey_from_ne(const char *n_b64,
    size_t n_b64_len, const char *e_b64, size_t e_b64_len, ngx_log_t *log);

EVP_PKEY *xrootd_token_ec_pubkey_from_xy(const char *x_b64,
    size_t x_b64_len, const char *y_b64, size_t y_b64_len, ngx_log_t *log);

int xrootd_token_verify_rs256(const u_char *signed_data, size_t signed_len,
    const u_char *sig, size_t sig_len, EVP_PKEY *pkey);

int xrootd_token_verify_es256(const u_char *signed_data, size_t signed_len,
    const u_char *sig_p1363, size_t sig_len, EVP_PKEY *pkey);

#endif /* XROOTD_TOKEN_INTERNAL_H */
