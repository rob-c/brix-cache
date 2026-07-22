/*
 * delegation_gridsite_put.c - Phase-3 T4 step 2: the GridSite putProxy half
 * of the two-step delegation handshake (PUT
 * /.well-known/brix-delegation/<id>).  Split out of delegation.c; the
 * getProxyReq half lives in delegation_gridsite_req.c, the pending-
 * delegation store in delegation_store.c, and the shared cert-chain /
 * storage helpers in delegation.c (declared in delegation_internal.h).  See
 * delegation_gridsite_req.c's doc-block for the full two-step WHAT/WHY/HOW.
 */

#include "webdav.h"
#include "delegation.h"
#include "delegation_internal.h"
#include "fs/backend/ucred.h"
#include "auth/gsi/proxy_req.h"
#include "core/compat/log_diag.h"
#include "core/http/http_body.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

/*
 * gsi_pem_export_one / gsi_pem_export_chain - serialise a single X509 or a
 * whole STACK_OF(X509) to a malloc'd, NUL-terminated PEM buffer.  Local
 * equivalents of src/auth/gsi/delegation.c's gsi_pem_export (that file's
 * helper is static to its own translation unit and not exposed to WebDAV,
 * and this file already carries its own X509/BIO includes, so a small
 * duplicate is simpler than threading a shared header through both wire
 * protocols for two output-only helper calls). Caller frees the result.
 */
static u_char *
gsi_pem_export_one(X509 *cert, size_t *len)
{
    BIO    *bio = BIO_new(BIO_s_mem());
    char   *data;
    long    n;
    u_char *out = NULL;

    if (bio != NULL && PEM_write_bio_X509(bio, cert) == 1) {
        n = BIO_get_mem_data(bio, &data);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, data, (size_t) n);
            out[n] = '\0';
            *len = (size_t) n;
        }
    }
    BIO_free(bio);
    return out;
}

static u_char *
gsi_pem_export_chain(STACK_OF(X509) *chain, size_t *len)
{
    BIO    *bio = BIO_new(BIO_s_mem());
    char   *data;
    long    n;
    u_char *out = NULL;
    int     i, ok = (bio != NULL);

    for (i = 0; ok && i < sk_X509_num(chain); i++) {
        if (PEM_write_bio_X509(bio, sk_X509_value(chain, i)) != 1) {
            ok = 0;
        }
    }
    if (ok) {
        n = BIO_get_mem_data(bio, &data);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, data, (size_t) n);
            out[n] = '\0';
            *len = (size_t) n;
        }
    }
    BIO_free(bio);
    return out;
}

/*
 * delegation_split_first_pem_block - split a PEM buffer into its first
 * X509 certificate block (the signed proxy) and everything after it (the
 * issuer/EEC chain).  brix_gsi_assemble_proxy's `proxy_pem` argument is
 * parsed with PEM_read_bio_X509, which reads only the FIRST PEM block off
 * the BIO — so the client-uploaded body (signed proxy followed by its EEC
 * chain, mirroring the wire-protocol delegation flow's signed_pem +
 * deleg_chain_pem split in src/auth/gsi/delegation.c) must be split at
 * that boundary before calling assemble.  Re-parses via
 * delegation_parse_chain (same PEM-loop helper T8 uses) then re-serialises
 * cert[0] alone and certs[1..] concatenated — this also gives "unparseable"
 * and "no certs at all" rejection for free, reusing the T8 parse path
 * rather than a bespoke byte-offset scan.
 *
 * On success returns NGX_OK with proxy_pem / proxy_pem_len (cert[0] only)
 * and chain_pem / chain_pem_len (certs[1..], possibly zero-length if the
 * client sent only the proxy with no chain) both malloc'd (caller frees
 * both).  NGX_ERROR on parse failure or an empty chain.
 */
static ngx_int_t
delegation_split_first_pem_block(const u_char *body, size_t body_len,
    u_char **proxy_pem, size_t *proxy_pem_len,
    u_char **chain_pem, size_t *chain_pem_len)
{
    STACK_OF(X509) *chain;
    X509            *first;
    size_t           n;

    chain = delegation_parse_chain(body, body_len);
    if (chain == NULL) {
        return NGX_ERROR;
    }
    n = (size_t) sk_X509_num(chain);
    first = sk_X509_value(chain, 0);

    *proxy_pem = gsi_pem_export_one(first, proxy_pem_len);
    if (n > 1) {
        STACK_OF(X509) *rest = sk_X509_new_null();
        size_t          i;

        if (rest == NULL) {
            free(*proxy_pem);
            *proxy_pem = NULL;
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }
        for (i = 1; i < n; i++) {
            sk_X509_push(rest, sk_X509_value(chain, (int) i));
        }
        *chain_pem = gsi_pem_export_chain(rest, chain_pem_len);
        sk_X509_free(rest);   /* shallow: certs still owned by `chain` */
    } else {
        *chain_pem = malloc(1);
        if (*chain_pem != NULL) {
            (*chain_pem)[0] = '\0';
        }
        *chain_pem_len = 0;
    }

    sk_X509_pop_free(chain, X509_free);
    if (*proxy_pem == NULL || *chain_pem == NULL) {
        free(*proxy_pem);
        free(*chain_pem);
        *proxy_pem = NULL;
        *chain_pem = NULL;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * delegation_extract_id - the trailing path segment of r->uri after
 * "/.well-known/brix-delegation/".  Returns NGX_OK with id / id_len
 * pointing into r->uri.data (borrowed, valid for the request's lifetime —
 * no copy needed), or NGX_ERROR if the segment is empty or implausibly
 * long (> BRIX_DELEG_ID_HEXLEN*2, generous slack over the real 32-char
 * ids so a legitimate id is never rejected while an absurd one short-
 * circuits before the store's strcmp scan).
 */
static ngx_int_t
delegation_extract_id(ngx_http_request_t *r, const u_char **id,
    size_t *id_len)
{
    static const char prefix[] = "/.well-known/brix-delegation/";
    size_t             plen = sizeof(prefix) - 1;

    if (r->uri.len <= plen) {
        return NGX_ERROR;
    }
    /* The id is whatever follows the LAST occurrence of the prefix — mirror
     * dispatch.c's routing, which matches on this same fixed prefix. */
    {
        ngx_uint_t i;
        const u_char *found = NULL;

        for (i = 0; i + plen <= r->uri.len; i++) {
            if (ngx_memcmp(r->uri.data + i, prefix, plen) == 0) {
                found = r->uri.data + i + plen;
            }
        }
        if (found == NULL) {
            return NGX_ERROR;
        }
        *id = found;
        *id_len = (size_t) (r->uri.data + r->uri.len - found);
    }
    if (*id_len == 0 || *id_len > (BRIX_DELEG_ID_HEXLEN * 2)) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
delegation_put_take_key(ngx_http_request_t *r,
    const ngx_http_brix_webdav_req_ctx_t *ctx, const char *id,
    EVP_PKEY **reqkey)
{
    brix_deleg_take_t take_rc;

    take_rc = brix_deleg_store_take(brix_deleg_store(), id, ctx->dn, reqkey);
    if (take_rc == BRIX_DELEG_TAKE_OK) {
        return NGX_OK;
    }
    if (take_rc == BRIX_DELEG_TAKE_NOT_FOUND) {
        delegation_reject(r, NGX_HTTP_NOT_FOUND, "unknown delegation id\n");
        return NGX_ERROR;
    }
    if (take_rc == BRIX_DELEG_TAKE_EXPIRED) {
        delegation_reject(r, 410, "delegation id expired\n");
        return NGX_ERROR;
    }

    {
        char dn_log[1024];

        brix_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_delegation: putProxy id=%s DN mismatch — authenticated"
            " as \"%s\" does not own this delegation", id, dn_log);
    }
    delegation_reject(r, NGX_HTTP_FORBIDDEN,
                      "delegation id does not belong to the"
                      " authenticated client\n");
    return NGX_ERROR;
}

static ngx_int_t
delegation_put_assemble(ngx_http_request_t *r, const char *id, EVP_PKEY *reqkey,
    const u_char *body, size_t body_len, uint8_t **out_pem, size_t *out_len)
{
    u_char *proxy_pem = NULL, *chain_pem = NULL;
    size_t  proxy_pem_len = 0, chain_pem_len = 0;
    char    err[160];

    if (delegation_split_first_pem_block(body, body_len, &proxy_pem,
            &proxy_pem_len, &chain_pem, &chain_pem_len) != NGX_OK)
    {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "unparseable signed proxy PEM\n");
        return NGX_ERROR;
    }

    err[0] = '\0';
    {
        const brix_gsi_blob_t proxy_blob = { proxy_pem, proxy_pem_len };
        const brix_gsi_blob_t chain_blob = { chain_pem, chain_pem_len };
        const brix_gsi_err_t  err_sink   = { err, sizeof(err) };
        brix_gsi_buf_t        cred_out   = { NULL, 0 };

        if (brix_gsi_assemble_proxy(&proxy_blob, reqkey, &chain_blob,
                &cred_out, &err_sink) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "brix_delegation: putProxy id=%s assemble failed: %s", id, err);
            free(proxy_pem);
            free(chain_pem);
            delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                              "signed proxy does not match the outstanding"
                              " delegation request\n");
            return NGX_ERROR;
        }
        *out_pem = cred_out.data;
        *out_len = cred_out.len;
    }

    free(proxy_pem);
    free(chain_pem);
    return NGX_OK;
}

static ngx_int_t
delegation_put_validate_chain(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const ngx_http_brix_webdav_req_ctx_t *ctx, const char *id,
    const uint8_t *out_pem, size_t out_len)
{
    STACK_OF(X509) *proxy_chain;
    X509           *eec;

    proxy_chain = delegation_parse_chain(out_pem, out_len);
    if (proxy_chain == NULL) {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "assembled proxy is unparseable\n");
        return NGX_ERROR;
    }
    eec = delegation_find_eec(proxy_chain);
    if (eec == NULL) {
        sk_X509_pop_free(proxy_chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "assembled proxy has no end-entity certificate\n");
        return NGX_ERROR;
    }
    if (delegation_chain_expired(proxy_chain)) {
        sk_X509_pop_free(proxy_chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "assembled proxy is expired\n");
        return NGX_ERROR;
    }
    if (delegation_chain_trusted(r, conf, proxy_chain) != NGX_OK) {
        sk_X509_pop_free(proxy_chain, X509_free);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "assembled proxy chain does not verify against a"
                          " trusted CA\n");
        return NGX_ERROR;
    }
    if (!delegation_eec_dn_matches(eec, ctx->dn)) {
        sk_X509_pop_free(proxy_chain, X509_free);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_delegation: putProxy id=%s assembled proxy identity"
            " mismatch (should be unreachable — DN was already checked at"
            " getreq/take time)", id);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "assembled proxy identity does not match"
                          " authenticated client\n");
        return NGX_ERROR;
    }
    sk_X509_pop_free(proxy_chain, X509_free);
    return NGX_OK;
}

static ngx_int_t
delegation_put_store(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const ngx_http_brix_webdav_req_ctx_t *ctx, const uint8_t *out_pem,
    size_t out_len, char *key, size_t key_len)
{
    if (brix_sd_ucred_key(ctx->dn, key, key_len) != NGX_OK) {
        delegation_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "credential key derivation failed\n");
        return NGX_ERROR;
    }
    if (delegation_store_pem(r->connection->log,
            &conf->common.storage_credential_dir, key, out_pem, out_len)
        == NGX_OK)
    {
        return NGX_OK;
    }
    delegation_reject(r, NGX_HTTP_INSUFFICIENT_STORAGE,
                      "failed to store credential\n");
    return NGX_ERROR;
}

void
webdav_delegation_put_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const u_char   *id_ptr;
    size_t          id_len;
    char            id[BRIX_DELEG_ID_HEXLEN * 2 + 1];
    u_char         *body = NULL;
    size_t          body_len = 0;
    EVP_PKEY       *reqkey = NULL;
    uint8_t        *out_pem = NULL;
    size_t          out_len = 0;
    char            key[BRIX_UCRED_KEY_MAX];

    if (!delegation_client_authenticated(ctx)) {
        delegation_reject(r, NGX_HTTP_UNAUTHORIZED,
                          "GSI client-certificate authentication"
                          " required\n");
        return;
    }

    if (delegation_extract_id(r, &id_ptr, &id_len) != NGX_OK) {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "missing or malformed delegation id\n");
        return;
    }
    ngx_memcpy(id, id_ptr, id_len);
    id[id_len] = '\0';

    if (brix_http_body_read_all(r, BRIX_DELEGATION_BODY_MAX, &body, &body_len)
            != NGX_OK
        || body == NULL || body_len == 0)
    {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "missing or oversized signed proxy body\n");
        return;
    }

    if (delegation_put_take_key(r, ctx, id, &reqkey) != NGX_OK) {
        return;
    }

    if (delegation_put_assemble(r, id, reqkey, body, body_len, &out_pem,
                                &out_len) != NGX_OK)
    {
        EVP_PKEY_free(reqkey);
        return;
    }
    EVP_PKEY_free(reqkey);

    /* Same validation strictness as T8's uploaded-chain path: every cert
     * unexpired, end-entity DN matches the authenticated client. */
    if (delegation_put_validate_chain(r, conf, ctx, id, out_pem, out_len)
        != NGX_OK)
    {
        free(out_pem);
        return;
    }

    if (delegation_put_store(r, conf, ctx, out_pem, out_len, key, sizeof(key))
        != NGX_OK)
    {
        free(out_pem);
        return;
    }
    free(out_pem);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_delegation: putProxy id=%s completed, stored proxy for key=%s",
        id, key);
    delegation_reject(r, NGX_HTTP_CREATED, "OK\n");
}
