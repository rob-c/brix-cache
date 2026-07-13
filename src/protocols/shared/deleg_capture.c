/*
 * deleg_capture.c — HTTP capture of a user-supplied full x509 proxy for backend
 * credential PASSTHROUGH (phase-70 §5.1). See deleg_capture.h for the contract.
 */
#include "deleg_capture.h"

#include "core/http/http_headers.h"
#include "auth/crypto/store_policy.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string.h>

#define BRIX_DELEG_PROXY_HEADER      "X-Brix-Delegate-Proxy"
#define BRIX_DELEG_PROXY_HEADER_LEN  (sizeof(BRIX_DELEG_PROXY_HEADER) - 1)

/* ---- deleg_proxy_leaf_dn ----------------------------------------------------
 *
 * WHAT: Extract the leaf (first) certificate's subject DN from a proxy PEM into
 *       `out` (NUL-terminated), using the same normalisation as the front-door
 *       DN (brix_x509_oneline). Returns 1 on success, 0 if the bytes do not
 *       parse as a PEM certificate.
 *
 * WHY:  §5.1 forbids a privilege swap: the supplied proxy's identity must equal
 *       the authenticated identity. Comparing the leaf DN to identity->dn with
 *       matching normalisation is the string-level identity binding (the
 *       cryptographic chain-trust check is enforced later in the VFS gate).
 *
 * HOW:  A BIO over the bytes → PEM_read_bio_X509 reads the first cert (the leaf,
 *       as written by the client's proxy chain); brix_x509_oneline renders its
 *       subject. Frees the cert + BIO. */
static int
deleg_proxy_leaf_dn(const u_char *pem, size_t len, char *out, size_t outsz)
{
    BIO  *bio;
    X509 *leaf;

    bio = BIO_new_mem_buf(pem, (int) len);
    if (bio == NULL) {
        return 0;
    }

    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (leaf == NULL) {
        return 0;
    }

    brix_x509_oneline(X509_get_subject_name(leaf), out, outsz);
    X509_free(leaf);
    return 1;
}

ngx_int_t
brix_proto_deleg_capture_proxy_header(ngx_http_request_t *r,
    const brix_identity_t *identity, ngx_str_t *out)
{
    ngx_table_elt_t *hdr;
    ngx_str_t         decoded;
    char              leaf_dn[1024];

    ngx_str_null(out);

    if (r == NULL) {
        return NGX_OK;
    }

    hdr = brix_http_find_header(r, BRIX_DELEG_PROXY_HEADER,
                                BRIX_DELEG_PROXY_HEADER_LEN);
    if (hdr == NULL || hdr->value.len == 0) {
        return NGX_OK;   /* no opt-in proxy supplied */
    }

    /* §6 secret hygiene: a private key must never ride cleartext. */
#if (NGX_HTTP_SSL)
    if (r->connection->ssl == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix: rejecting " BRIX_DELEG_PROXY_HEADER
            " over cleartext transport");
        return NGX_HTTP_FORBIDDEN;
    }
#else
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
        "brix: rejecting " BRIX_DELEG_PROXY_HEADER
        " (TLS support not compiled in)");
    return NGX_HTTP_FORBIDDEN;
#endif

    decoded.len  = ngx_base64_decoded_length(hdr->value.len);
    decoded.data = ngx_pnalloc(r->pool, decoded.len);
    if (decoded.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_decode_base64(&decoded, &hdr->value) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix: " BRIX_DELEG_PROXY_HEADER " is not valid base64");
        return NGX_HTTP_FORBIDDEN;
    }

    /* Leaf DN must equal the authenticated identity DN — no privilege swap. */
    if (!deleg_proxy_leaf_dn(decoded.data, decoded.len,
                             leaf_dn, sizeof(leaf_dn))) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix: " BRIX_DELEG_PROXY_HEADER
            " does not decode to a PEM certificate");
        return NGX_HTTP_FORBIDDEN;
    }

    if (identity == NULL || identity->dn.len == 0
        || identity->dn.len != ngx_strlen(leaf_dn)
        || ngx_strncmp(identity->dn.data, leaf_dn, identity->dn.len) != 0)
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix: rejecting " BRIX_DELEG_PROXY_HEADER
            " — proxy leaf DN does not match authenticated identity");
        return NGX_HTTP_FORBIDDEN;
    }

    *out = decoded;
    return NGX_OK;
}
