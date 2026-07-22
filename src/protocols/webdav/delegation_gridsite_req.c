/*
 * delegation_gridsite_req.c - Phase-3 T4 step 1: the GridSite getProxyReq
 * half of the two-step delegation handshake (GET
 * /.well-known/brix-delegation/request).  Split out of delegation.c; the
 * putProxy half lives in delegation_gridsite_put.c, the pending-delegation
 * store in delegation_store.c, and the shared cert-chain / storage helpers
 * in delegation.c (declared in delegation_internal.h).
 *
 * ======================= Phase-3 T4: two-step GridSite ====================
 * WHAT: The standard GridSite getProxyReq/putProxy handshake, adapted to
 *       plain HTTP: GET /.well-known/brix-delegation/request returns a
 *       fresh CSR + a delegation-id; the client signs the CSR with its own
 *       EEC key and PUTs the signed proxy back to
 *       /.well-known/brix-delegation/<id>, which assembles and stores the
 *       full delegated proxy exactly like the T8 upload path.
 *
 * WHY: T8's proxy-UPLOAD form requires the client to already hold a
 *      complete, signed proxy chain it is willing to hand over wholesale —
 *      fine for scripted/xrdcp-style clients but not how the reference
 *      GridSite delegation portType works, and not what some interop
 *      partners expect.  The two-step form lets the SERVER generate the
 *      keypair (never touching disk, never leaving the server) so the
 *      client only ever signs a request — the standard, narrower trust
 *      model this specification exists to support alongside T8, not to
 *      replace it.
 *
 * HOW: 1. brix_deleg_store — a bounded (256-entry), per-worker, in-memory
 *         table of pending {id, fresh EVP_PKEY*, client_dn, expires_at}
 *         entries, TTL 600s, swept lazily on every get/put (no background
 *         thread — see brix_deleg_store_sweep).  Per-worker, NOT SHM: the
 *         fresh private key must never leave the process that generated
 *         it, and this is a short interactive two-request handshake, not
 *         durable state — a multi-worker deployment needs sticky routing
 *         (an L7 proxy or client retry-on-same-worker) so both requests of
 *         one handshake land on the same worker.  Documented on
 *         brix_deleg_store_t below; NOT a design flaw for THIS store, since
 *         SHM would additionally require serialising an EVP_PKEY private
 *         key into shared memory, which trades one small operational
 *         constraint (stickiness) for a much larger one (private key
 *         material outside process-local heap).
 *      2. webdav_delegation_request_handle (GET .../request): reuse the
 *         SAME peer-cert access pattern as auth_cert.c's
 *         webdav_verify_proxy_cert() — SSL_get_peer_certificate(ssl) off
 *         r->connection->ssl->connection — PEM-export it as `parent_pem`,
 *         and call brix_gsi_build_pxyreq(parent_pem, ...) to get a fresh
 *         key + CSR (re-encoded request DER→PEM, mirroring
 *         src/auth/gsi/delegation.c's gsi_req_der_to_pem, since the CSR
 *         travels over HTTP as PEM here too — DER has no natural HTTP
 *         content-type and PEM is what a human/openssl workflow expects).
 *         Store the entry keyed by a CSPRNG id (RAND_bytes, 16 bytes / 32
 *         hex chars via brix_hex_encode); respond with the CSR PEM as the
 *         body and the id in X-Brix-Delegation-Id.  UNLIKE the other two
 *         entry points, this one runs SYNCHRONOUSLY inside the content
 *         phase (a GET has no body to read asynchronously) and therefore
 *         returns an ngx_int_t instead of self-finalizing — see
 *         delegation.h's doc comment on this function for why
 *         self-finalizing here would double-finalize the request and
 *         crash the worker (caught by testing: the two-step e2e test
 *         initially crashed a worker with SIGSEGV in
 *         ngx_http_set_lingering_close via a double
 *         ngx_http_finalize_request, fixed by returning the status through
 *         webdav_metrics_return() like every other synchronous handler
 *         instead of calling webdav_metrics_finalize_request).
 *      3. webdav_delegation_put_handle (PUT .../<id>): look up id (checked
 *         BEFORE sweeping the rest of the table, so an expired-but-present
 *         entry is reported as 410, distinct from a never-existed/already-
 *         consumed 404 — see brix_deleg_store_take); 404 if absent, 410 if
 *         expired, 403 (and DO NOT touch any file) if entry.client_dn !=
 *         ctx->dn.  Otherwise split the
 *         uploaded body into its first PEM block (the signed proxy —
 *         brix_gsi_assemble_proxy's `proxy_pem` parses only the first
 *         block via PEM_read_bio_X509) and the remainder (the client's EEC
 *         chain — passed verbatim as `chain_pem`, appended after the proxy
 *         with no further parsing, exactly as brix_gsi_assemble_proxy's
 *         implementation does).  Call brix_gsi_assemble_proxy(proxy_pem,
 *         reqkey, chain_pem, ...) — it verifies the signed proxy's pubkey
 *         matches the stored fresh key (this IS the delegation's proof of
 *         possession: only a client holding the matching CSR could produce
 *         a proxy whose key matches) and returns the assembled
 *         <proxy><chain><private key> PEM — the reqkey is serialized into
 *         the blob so the stored credential is complete and can
 *         authenticate downstream (proxy_ssl_certificate_key, TPC pull,
 *         origin auth all load key+chain from the one stored file).
 *         Validate every cert's notAfter is still in
 *         the future and the chain's end-entity DN matches ctx->dn (reuse
 *         delegation_chain_expired / delegation_eec_dn_matches, the SAME T8
 *         helpers — a two-step-assembled credential is validated exactly
 *         as strictly as an uploaded one).  On success, atomically store
 *         via delegation_store_pem (the SAME T8 helper) and drop the store
 *         entry.  One-shot policy (documented on brix_deleg_store_drop
 *         below): the entry is dropped and its EVP_PKEY freed on ANY
 *         terminal outcome of this call — success, DN mismatch, expired,
 *         malformed body, or assemble failure — never left pending for a
 *         retry.  This is the simplest policy that guarantees no EVP_PKEY
 *         leak on any path and closes the id after first use either way,
 *         matching the brief's documented default.
 */

#include "webdav.h"
#include "delegation.h"
#include "delegation_internal.h"
#include "auth/gsi/proxy_req.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

/*
 * delegation_get_peer_pem - PEM-export the TLS peer certificate off this
 * request's SSL connection.  Reuses the exact acquisition pattern
 * auth_cert.c's webdav_verify_proxy_cert() uses (SSL_get_peer_certificate
 * off r->connection->ssl->connection) — this endpoint runs strictly after
 * that same verification has already populated ctx->verified/ctx->dn, so a
 * peer cert is guaranteed present; this just re-fetches the X509* (the
 * verified req_ctx stores only the derived DN string, not the cert object)
 * and serialises it to PEM in memory for brix_gsi_build_pxyreq's
 * `parent_pem` argument.  Caller frees *pem via free() (malloc'd, matching
 * the ngx-free proxy_req.c/gsi delegation.c convention for PEM buffers).
 */
static ngx_int_t
delegation_get_peer_pem(ngx_http_request_t *r, u_char **pem, size_t *pem_len)
{
    SSL    *ssl;
    X509   *leaf;
    BIO    *bio;
    char   *data;
    long    n;

    if (r->connection->ssl == NULL) {
        return NGX_ERROR;
    }
    ssl = r->connection->ssl->connection;
    leaf = SSL_get_peer_certificate(ssl);
    if (leaf == NULL) {
        return NGX_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_X509(bio, leaf) != 1) {
        BIO_free(bio);
        X509_free(leaf);
        return NGX_ERROR;
    }
    X509_free(leaf);

    n = BIO_get_mem_data(bio, &data);
    *pem = malloc((size_t) n + 1);
    if (*pem == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }
    memcpy(*pem, data, (size_t) n);
    (*pem)[n] = '\0';
    *pem_len = (size_t) n;
    BIO_free(bio);
    return NGX_OK;
}

/*
 * delegation_req_der_to_pem - re-encode brix_gsi_build_pxyreq's DER
 * X509_REQ output as PEM.  The two-step flow travels the CSR over HTTP as
 * a body a human or `openssl req` workflow can consume directly, and
 * mirrors src/auth/gsi/delegation.c's gsi_req_der_to_pem (the wire-protocol
 * delegation path re-encodes for the exact same reason — the crypto core
 * emits DER, the transport wants PEM).  Returns a malloc'd NUL-terminated
 * PEM buffer (caller frees), or NULL on parse/encode failure.
 */
static u_char *
delegation_req_der_to_pem(const uint8_t *der, size_t der_len, size_t *pem_len)
{
    const unsigned char *p = der;
    X509_REQ             *req = d2i_X509_REQ(NULL, &p, (long) der_len);
    BIO                   *bio;
    char                  *data;
    long                   n;
    u_char                *out = NULL;

    if (req == NULL) {
        return NULL;
    }
    bio = BIO_new(BIO_s_mem());
    if (bio != NULL && PEM_write_bio_X509_REQ(bio, req) == 1) {
        n = BIO_get_mem_data(bio, &data);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, data, (size_t) n);
            out[n] = '\0';
            *pem_len = (size_t) n;
        }
    }
    BIO_free(bio);
    X509_REQ_free(req);
    return out;
}

/*
 * delegation_send_csr - build a 200 response with the CSR PEM as the body
 * and the delegation-id in X-Brix-Delegation-Id.  Content-Type: application/
 * x-pem-file (RFC-ish convention for a bare PEM payload; chosen over
 * text/plain so a client can distinguish "this response IS a PEM
 * document" from the plain-text error bodies delegation_reject sends).
 *
 * Returns the ngx_int_t status the CALLER must return up through
 * webdav_metrics_return() — this function does NOT call
 * ngx_http_send_header/ngx_http_output_filter's result into
 * webdav_metrics_finalize_request itself, unlike delegation_reject.
 * webdav_delegation_request_handle runs synchronously inside the content
 * phase (no async body read is in flight), so self-finalizing here would
 * double-finalize the request once nginx's content phase ALSO finalizes
 * whatever this handler returns — see delegation.h's doc comment on
 * webdav_delegation_request_handle for why that crashes the worker.
 */
static ngx_int_t
delegation_send_csr(ngx_http_request_t *r, const char *id,
    const u_char *pem, size_t pem_len)
{
    ngx_buf_t        *b;
    ngx_chain_t        out;
    ngx_table_elt_t  *h;
    u_char            *buf;
    ngx_str_t          id_str;
    u_char            *id_copy;

    buf = ngx_pnalloc(r->pool, pem_len);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf, pem, pem_len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = buf;
    b->last = buf + pem_len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    id_str.len = strlen(id);
    id_str.data = (u_char *) id;
    id_copy = ngx_pstrdup(r->pool, &id_str);
    if (id_copy == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "X-Brix-Delegation-Id");
    h->value.data = id_copy;
    h->value.len = id_str.len;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) pem_len;
    r->headers_out.content_type.data = (u_char *) "application/x-pem-file";
    r->headers_out.content_type.len = sizeof("application/x-pem-file") - 1;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (ngx_http_send_header(r) == NGX_ERROR || r->header_only) {
        return NGX_HTTP_OK;
    }
    return ngx_http_output_filter(r, &out);
}

/*
 * delegation_request_reject - build a small plain-text error response
 * WITHOUT finalizing (the synchronous-handler counterpart to
 * delegation_reject, which self-finalizes for the async PUT paths). Returns
 * the status the caller passes up through webdav_metrics_return().
 */
static ngx_int_t
delegation_request_reject(ngx_http_request_t *r, ngx_uint_t status,
    const char *msg)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    size_t       len = strlen(msg);
    u_char      *buf = ngx_pnalloc(r->pool, len);

    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf, msg, len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (ngx_http_send_header(r) == NGX_ERROR || r->header_only) {
        return status;
    }
    return ngx_http_output_filter(r, &out);
}

ngx_int_t
webdav_delegation_request_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    u_char    *parent_pem = NULL;
    size_t     parent_pem_len = 0;
    EVP_PKEY  *newkey = NULL;
    uint8_t   *req_der = NULL;
    size_t     req_der_len = 0;
    u_char    *req_pem = NULL;
    size_t     req_pem_len = 0;
    char       err[160];
    char       id[BRIX_DELEG_ID_HEXLEN + 1];
    ngx_int_t  rc;

    if (!delegation_client_authenticated(ctx)) {
        return delegation_request_reject(r, NGX_HTTP_UNAUTHORIZED,
                          "GSI client-certificate authentication"
                          " required\n");
    }

    if (delegation_get_peer_pem(r, &parent_pem, &parent_pem_len) != NGX_OK) {
        return delegation_request_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "cannot access client certificate\n");
    }

    err[0] = '\0';
    {
        const brix_gsi_blob_t parent_blob = { parent_pem, parent_pem_len };
        const brix_gsi_err_t  err_sink    = { err, sizeof(err) };
        brix_gsi_buf_t        req_out     = { NULL, 0 };

        if (brix_gsi_build_pxyreq(&parent_blob, &newkey, &req_out,
                &err_sink) != 0)
        {
            free(parent_pem);
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "brix_delegation: build_pxyreq failed: %s", err);
            return delegation_request_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              "cannot build proxy request\n");
        }
        req_der = req_out.data;
        req_der_len = req_out.len;
    }
    free(parent_pem);

    req_pem = delegation_req_der_to_pem(req_der, req_der_len, &req_pem_len);
    free(req_der);
    if (req_pem == NULL) {
        EVP_PKEY_free(newkey);
        return delegation_request_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "cannot encode proxy request\n");
    }

    if (brix_deleg_store_put(brix_deleg_store(), newkey, ctx->dn,
            id, sizeof(id)) != NGX_OK)
    {
        /* newkey ownership did NOT transfer on a failed put — free it here. */
        EVP_PKEY_free(newkey);
        free(req_pem);
        return delegation_request_reject(r, NGX_HTTP_SERVICE_UNAVAILABLE,
                          "too many pending delegations, try again later\n");
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_delegation: issued getProxyReq id=%s", id);
    rc = delegation_send_csr(r, id, req_pem, req_pem_len);
    free(req_pem);
    return rc;
}
