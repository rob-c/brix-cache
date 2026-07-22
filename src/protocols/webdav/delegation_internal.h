/*
 * delegation_internal.h - shared internals for the WebDAV proxy-delegation
 * endpoints, split across delegation.c (shared cert-chain / storage helpers
 * + the Phase-2 T8 upload handler), delegation_store.c (the per-worker
 * pending-delegation store), delegation_gridsite_req.c (GridSite
 * getProxyReq) and delegation_gridsite_put.c (GridSite putProxy).
 *
 * Only symbols crossing a file boundary are declared here; helpers used in a
 * single translation unit stay static there.  Public entry points remain in
 * delegation.h.
 */

#ifndef BRIX_WEBDAV_DELEGATION_INTERNAL_H
#define BRIX_WEBDAV_DELEGATION_INTERNAL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include "webdav.h"   /* ngx_http_brix_webdav_req_ctx_t / _loc_conf_t */

/* Uploaded proxy PEM bodies are a handful of KB; reject anything larger. */
#define BRIX_DELEGATION_BODY_MAX (64 * 1024)

/* Delegation ids are CSPRNG bytes, hex-encoded; see brix_deleg_store_put. */
#define BRIX_DELEG_ID_BYTES   16
#define BRIX_DELEG_ID_HEXLEN  (BRIX_DELEG_ID_BYTES * 2)

/* ------------------------------------------------------------------------
 * Shared cert-chain / storage / reject helpers (delegation.c).  See the
 * definitions in delegation.c for the full WHAT/WHY/HOW of each.
 * ---------------------------------------------------------------------- */
int delegation_client_authenticated(
    const ngx_http_brix_webdav_req_ctx_t *ctx);
X509 *delegation_find_eec(STACK_OF(X509) *chain);
STACK_OF(X509) *delegation_parse_chain(const u_char *pem, size_t pem_len);
int delegation_chain_expired(STACK_OF(X509) *chain);
int delegation_eec_dn_matches(X509 *eec, const char *want_dn);
ngx_int_t delegation_chain_trusted(ngx_http_request_t *r,
    const ngx_http_brix_webdav_loc_conf_t *conf, STACK_OF(X509) *chain);
ngx_int_t delegation_store_pem(ngx_log_t *log, const ngx_str_t *dir,
    const char *key, const u_char *pem, size_t pem_len);
void delegation_reject(ngx_http_request_t *r, ngx_uint_t status,
    const char *msg);

/* ------------------------------------------------------------------------
 * Per-worker pending-delegation store (delegation_store.c).  Opaque to the
 * two-step handlers: they only ever hold a brix_deleg_store_t* and call the
 * three entry points below.  See delegation_store.c for the store doc-block.
 * ---------------------------------------------------------------------- */

/* Outcome of brix_deleg_store_take, distinguishing every caller-relevant
 * terminal state (the putProxy handler maps these to distinct HTTP statuses:
 * 404 / 410 / 403 / found). */
typedef enum {
    BRIX_DELEG_TAKE_NOT_FOUND = 0,
    BRIX_DELEG_TAKE_EXPIRED,
    BRIX_DELEG_TAKE_DN_MISMATCH,
    BRIX_DELEG_TAKE_OK
} brix_deleg_take_t;

typedef struct brix_deleg_store_s brix_deleg_store_t;

brix_deleg_store_t *brix_deleg_store(void);
ngx_int_t brix_deleg_store_put(brix_deleg_store_t *st, EVP_PKEY *fresh_key,
    const char *client_dn, char *id_out, size_t id_out_cap);
brix_deleg_take_t brix_deleg_store_take(brix_deleg_store_t *st,
    const char *id, const char *want_dn, EVP_PKEY **key_out);

#endif /* BRIX_WEBDAV_DELEGATION_INTERNAL_H */
