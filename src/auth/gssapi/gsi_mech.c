#include "gsi_mech.h"

#include "auth/gsi/proxy_req.h"
#include "auth/crypto/gsi_verify.h"

#include <openssl/bio.h>
#include <openssl/pem.h>

/*
 * gsi_mech.c — the mem-BIO GSI GSSAPI accept engine declared in gsi_mech.h.
 *
 * A single SSL object drives a TLS 1.2 handshake whose flights arrive/depart as
 * ADAT tokens through a pair of memory BIOs (rbio = tokens in, wbio = tokens
 * out).  Once the handshake completes we verify the client's proxy chain, then —
 * if delegating — run the GSI 'D' / proxy-request / signed-proxy sub-exchange as
 * application-data over the same SSL, reusing the RFC-3820 crypto in
 * proxy_req.c.  After completion the same SSL provides wrap/unwrap for the
 * RFC 2228 protected control channel.
 */

enum {
    ST_TLS = 0,     /* driving SSL_accept                         */
    ST_WAIT_D,      /* handshake done, awaiting the deleg 'D' tok */
    ST_WAIT_SIGNED, /* CSR sent, awaiting the signed proxy        */
    ST_DONE,
    ST_FAIL
};

struct brix_gssapi_srv_s {
    ngx_pool_t  *pool;
    ngx_log_t   *log;
    SSL         *ssl;
    BIO         *rbio;          /* network-in  (owned by ssl)  */
    BIO         *wbio;          /* network-out (owned by ssl)  */
    X509_STORE  *ca_store;
    unsigned     accept_deleg;
    int          state;

    EVP_PKEY    *req_key;       /* delegation request keypair  */
    ngx_str_t    proxy_pem;     /* assembled delegated cred    */
    ngx_str_t    dn;            /* verified end-entity DN       */
    int          verified;
};


/* Accept any presented client cert at the TLS layer; the real RFC-3820 proxy
 * verification runs post-handshake via brix_gsi_verify_chain (which OpenSSL's
 * default path-building would reject).  We only need the handshake to capture
 * the chain. */
static int
gss_verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    (void) preverify_ok;
    (void) ctx;
    return 1;
}


static void
gss_cleanup(void *data)
{
    brix_gssapi_srv_t *g = data;

    if (g->ssl != NULL) {
        SSL_free(g->ssl);           /* also frees rbio/wbio */
        g->ssl = NULL;
    }
    if (g->req_key != NULL) {
        EVP_PKEY_free(g->req_key);
        g->req_key = NULL;
    }
}


/* Drain all pending outbound TLS bytes from wbio into a pool buffer. */
static ngx_int_t
gss_drain(brix_gssapi_srv_t *g, ngx_str_t *out)
{
    int      pend;
    u_char  *buf;
    int      n;

    out->len = 0;
    out->data = NULL;

    pend = BIO_pending(g->wbio);
    if (pend <= 0) {
        return NGX_OK;
    }
    buf = ngx_palloc(g->pool, (size_t) pend);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    n = BIO_read(g->wbio, buf, pend);
    if (n <= 0) {
        return NGX_ERROR;
    }
    out->data = buf;
    out->len = (size_t) n;
    return NGX_OK;
}


/* Read all currently-available decrypted application data into a pool buffer
 * (up to `cap` bytes).  Returns NGX_OK with *out set (possibly empty). */
static ngx_int_t
gss_read_all(brix_gssapi_srv_t *g, size_t cap, ngx_str_t *out)
{
    u_char  *buf;
    size_t   off = 0;

    out->len = 0;
    out->data = NULL;

    buf = ngx_palloc(g->pool, cap);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    for ( ;; ) {
        int n = SSL_read(g->ssl, buf + off, (int) (cap - off));
        if (n > 0) {
            off += (size_t) n;
            if (off == cap) {
                break;                 /* full — commands/creds fit in cap */
            }
            continue;
        }
        break;                          /* WANT_READ / no more data */
    }
    out->data = buf;
    out->len = off;
    return NGX_OK;
}


/* PEM-encode a single certificate into a pool buffer. */
static ngx_int_t
gss_x509_pem(brix_gssapi_srv_t *g, X509 *x, ngx_str_t *out)
{
    BIO           *mem;
    char          *data;
    long           len;
    u_char        *copy;

    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        return NGX_ERROR;
    }
    if (!PEM_write_bio_X509(mem, x)) {
        BIO_free(mem);
        return NGX_ERROR;
    }
    len = BIO_get_mem_data(mem, &data);
    if (len <= 0) {
        BIO_free(mem);
        return NGX_ERROR;
    }
    copy = ngx_palloc(g->pool, (size_t) len);
    if (copy == NULL) {
        BIO_free(mem);
        return NGX_ERROR;
    }
    ngx_memcpy(copy, data, (size_t) len);
    out->data = copy;
    out->len = (size_t) len;
    BIO_free(mem);
    return NGX_OK;
}


/* PEM-encode every cert in a chain (leaf first) into one pool buffer. */
static ngx_int_t
gss_chain_pem(brix_gssapi_srv_t *g, STACK_OF(X509) *chain, ngx_str_t *out)
{
    BIO     *mem;
    char    *data;
    long     len;
    u_char  *copy;
    int      i;

    out->len = 0;
    out->data = NULL;
    if (chain == NULL) {
        return NGX_OK;
    }
    mem = BIO_new(BIO_s_mem());
    if (mem == NULL) {
        return NGX_ERROR;
    }
    for (i = 0; i < sk_X509_num(chain); i++) {
        if (!PEM_write_bio_X509(mem, sk_X509_value(chain, i))) {
            BIO_free(mem);
            return NGX_ERROR;
        }
    }
    len = BIO_get_mem_data(mem, &data);
    if (len > 0) {
        copy = ngx_palloc(g->pool, (size_t) len);
        if (copy == NULL) {
            BIO_free(mem);
            return NGX_ERROR;
        }
        ngx_memcpy(copy, data, (size_t) len);
        out->data = copy;
        out->len = (size_t) len;
    }
    BIO_free(mem);
    return NGX_OK;
}


/* Verify the client's proxy chain against ca_store and capture the EEC DN. */
static ngx_int_t
gss_verify_peer(brix_gssapi_srv_t *g)
{
    X509                      *leaf;
    STACK_OF(X509)            *chain;
    brix_gsi_verify_result_t   res;
    ngx_int_t                  rc;
    size_t                     dnlen;

    leaf = SSL_get_peer_certificate(g->ssl);        /* +1 ref */
    if (leaf == NULL) {
        ngx_log_error(NGX_LOG_ERR, g->log, 0,
                      "brix gsi_mech: client presented no certificate");
        return NGX_ERROR;
    }
    chain = SSL_get_peer_cert_chain(g->ssl);         /* borrowed */

    rc = brix_gsi_verify_chain(g->log, g->ca_store, leaf, chain, 0, &res, 0);
    if (rc == NGX_OK) {
        dnlen = ngx_strlen(res.dn_buf);
        g->dn.data = ngx_pnalloc(g->pool, dnlen);
        if (g->dn.data == NULL) {
            X509_free(leaf);
            return NGX_ERROR;
        }
        ngx_memcpy(g->dn.data, res.dn_buf, dnlen);
        g->dn.len = dnlen;
        g->verified = 1;
    }
    X509_free(leaf);
    return rc;
}


/* On 'D', build a proxy-cert request for the client's leaf and send it. */
static brix_gss_status_e
gss_send_proxy_req(brix_gssapi_srv_t *g, ngx_str_t *out)
{
    X509              *leaf;
    ngx_str_t          parent_pem;
    brix_gsi_blob_t    parent;
    brix_gsi_buf_t     req_der = { 0 };
    char               errbuf[160];
    brix_gsi_err_t     err = { errbuf, sizeof(errbuf) };

    leaf = SSL_get_peer_certificate(g->ssl);
    if (leaf == NULL || gss_x509_pem(g, leaf, &parent_pem) != NGX_OK) {
        if (leaf) { X509_free(leaf); }
        return BRIX_GSS_FAILED;
    }
    X509_free(leaf);

    parent.data = parent_pem.data;
    parent.len = parent_pem.len;
    if (brix_gsi_build_pxyreq(&parent, &g->req_key, &req_der, &err) != 0) {
        ngx_log_error(NGX_LOG_ERR, g->log, 0,
                      "brix gsi_mech: build proxy request failed: %s", errbuf);
        return BRIX_GSS_FAILED;
    }

    if (SSL_write(g->ssl, req_der.data, (int) req_der.len) <= 0) {
        OPENSSL_free(req_der.data);
        return BRIX_GSS_FAILED;
    }
    OPENSSL_free(req_der.data);

    if (gss_drain(g, out) != NGX_OK) {
        return BRIX_GSS_FAILED;
    }
    g->state = ST_WAIT_SIGNED;
    return BRIX_GSS_CONTINUE;
}


/* On the signed proxy, assemble the delegated credential. */
static brix_gss_status_e
gss_recv_signed(brix_gssapi_srv_t *g, ngx_str_t *out)
{
    ngx_str_t          signed_der;
    const u_char      *p;
    X509              *proxy;
    ngx_str_t          proxy_pem, chain_pem;
    brix_gsi_blob_t    proxy_blob, chain_blob;
    brix_gsi_buf_t     cred = { 0 };
    char               errbuf[160];
    brix_gsi_err_t     err = { errbuf, sizeof(errbuf) };

    if (gss_read_all(g, 16384, &signed_der) != NGX_OK || signed_der.len == 0) {
        return BRIX_GSS_FAILED;
    }
    p = signed_der.data;
    proxy = d2i_X509(NULL, &p, (long) signed_der.len);   /* first cert = proxy */
    if (proxy == NULL) {
        ngx_log_error(NGX_LOG_ERR, g->log, 0,
                      "brix gsi_mech: signed proxy is not a valid certificate");
        return BRIX_GSS_FAILED;
    }
    if (gss_x509_pem(g, proxy, &proxy_pem) != NGX_OK) {
        X509_free(proxy);
        return BRIX_GSS_FAILED;
    }
    X509_free(proxy);

    if (gss_chain_pem(g, SSL_get_peer_cert_chain(g->ssl), &chain_pem)
        != NGX_OK)
    {
        return BRIX_GSS_FAILED;
    }

    proxy_blob.data = proxy_pem.data;  proxy_blob.len = proxy_pem.len;
    chain_blob.data = chain_pem.data;  chain_blob.len = chain_pem.len;
    if (brix_gsi_assemble_proxy(&proxy_blob, g->req_key, &chain_blob, &cred,
                                &err) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, g->log, 0,
                      "brix gsi_mech: assemble delegated proxy failed: %s",
                      errbuf);
        return BRIX_GSS_FAILED;
    }
    g->proxy_pem.data = ngx_pnalloc(g->pool, cred.len);
    if (g->proxy_pem.data == NULL) {
        OPENSSL_free(cred.data);
        return BRIX_GSS_FAILED;
    }
    ngx_memcpy(g->proxy_pem.data, cred.data, cred.len);
    g->proxy_pem.len = cred.len;
    OPENSSL_free(cred.data);

    g->state = ST_DONE;
    return gss_drain(g, out) == NGX_OK ? BRIX_GSS_COMPLETE : BRIX_GSS_FAILED;
}


brix_gssapi_srv_t *
brix_gssapi_srv_create(ngx_pool_t *pool, ngx_log_t *log, SSL_CTX *ssl_ctx,
    X509_STORE *ca_store, unsigned accept_deleg)
{
    brix_gssapi_srv_t   *g;
    ngx_pool_cleanup_t  *cln;

    g = ngx_pcalloc(pool, sizeof(*g));
    if (g == NULL) {
        return NULL;
    }
    g->pool = pool;
    g->log = log;
    g->ca_store = ca_store;
    g->accept_deleg = accept_deleg;
    g->state = ST_TLS;

    g->ssl = SSL_new(ssl_ctx);
    if (g->ssl == NULL) {
        return NULL;
    }
    g->rbio = BIO_new(BIO_s_mem());
    g->wbio = BIO_new(BIO_s_mem());
    if (g->rbio == NULL || g->wbio == NULL) {
        if (g->rbio) { BIO_free(g->rbio); }
        if (g->wbio) { BIO_free(g->wbio); }
        SSL_free(g->ssl);
        g->ssl = NULL;
        return NULL;
    }
    SSL_set_bio(g->ssl, g->rbio, g->wbio);   /* ssl takes ownership of BIOs */
    SSL_set_accept_state(g->ssl);
    /* Pin TLS 1.2: the GSI ADAT state machine expects the acceptor's
     * CCS+Finished as the final 335/235 token; TLS 1.3's flight shape breaks it. */
    SSL_set_max_proto_version(g->ssl, TLS1_2_VERSION);
    SSL_set_verify(g->ssl, SSL_VERIFY_PEER, gss_verify_cb);

    cln = ngx_pool_cleanup_add(pool, 0);
    if (cln == NULL) {
        SSL_free(g->ssl);
        g->ssl = NULL;
        return NULL;
    }
    cln->handler = gss_cleanup;
    cln->data = g;

    return g;
}


brix_gss_status_e
brix_gssapi_srv_step(brix_gssapi_srv_t *g, const u_char *in, size_t in_len,
    ngx_str_t *out)
{
    int  r, e;

    out->len = 0;
    out->data = NULL;

    if (g->state == ST_FAIL || g->state == ST_DONE) {
        return g->state == ST_DONE ? BRIX_GSS_COMPLETE : BRIX_GSS_FAILED;
    }

    if (in_len > 0 && BIO_write(g->rbio, in, (int) in_len) <= 0) {
        g->state = ST_FAIL;
        return BRIX_GSS_FAILED;
    }

    if (g->state == ST_TLS) {
        r = SSL_accept(g->ssl);
        if (r == 1) {
            if (gss_verify_peer(g) != NGX_OK) {
                g->state = ST_FAIL;
                return BRIX_GSS_FAILED;
            }
            if (gss_drain(g, out) != NGX_OK) {   /* server's final flight */
                g->state = ST_FAIL;
                return BRIX_GSS_FAILED;
            }
            if (g->accept_deleg) {
                g->state = ST_WAIT_D;
                return BRIX_GSS_CONTINUE;         /* 335: deliver flight, await 'D' */
            }
            g->state = ST_DONE;
            return BRIX_GSS_COMPLETE;
        }
        e = SSL_get_error(g->ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            if (gss_drain(g, out) != NGX_OK) {
                g->state = ST_FAIL;
                return BRIX_GSS_FAILED;
            }
            return BRIX_GSS_CONTINUE;
        }
        ngx_log_error(NGX_LOG_ERR, g->log, 0,
                      "brix gsi_mech: TLS handshake failed (SSL_error=%d)", e);
        g->state = ST_FAIL;
        return BRIX_GSS_FAILED;
    }

    if (g->state == ST_WAIT_D) {
        ngx_str_t  dbuf;
        if (gss_read_all(g, 8, &dbuf) != NGX_OK || dbuf.len == 0
            || dbuf.data[0] != 'D')
        {
            ngx_log_error(NGX_LOG_ERR, g->log, 0,
                          "brix gsi_mech: expected delegation 'D' marker");
            g->state = ST_FAIL;
            return BRIX_GSS_FAILED;
        }
        if (gss_send_proxy_req(g, out) != BRIX_GSS_CONTINUE) {
            g->state = ST_FAIL;
            return BRIX_GSS_FAILED;
        }
        return BRIX_GSS_CONTINUE;
    }

    if (g->state == ST_WAIT_SIGNED) {
        brix_gss_status_e s = gss_recv_signed(g, out);
        if (s != BRIX_GSS_COMPLETE) {
            g->state = ST_FAIL;
        }
        return s;
    }

    g->state = ST_FAIL;
    return BRIX_GSS_FAILED;
}


ngx_int_t
brix_gssapi_srv_peer(brix_gssapi_srv_t *g, ngx_str_t *dn_out,
    ngx_str_t *proxy_pem_out)
{
    if (dn_out != NULL) {
        *dn_out = g->dn;
    }
    if (proxy_pem_out != NULL) {
        *proxy_pem_out = g->proxy_pem;
    }
    return g->verified ? NGX_OK : NGX_ERROR;
}


ngx_int_t
brix_gssapi_srv_peer_cert_pem(brix_gssapi_srv_t *g, ngx_str_t *out)
{
    X509      *leaf;
    ngx_int_t  rc;

    out->len = 0;
    out->data = NULL;
    if (g->ssl == NULL) {
        return NGX_ERROR;
    }
    leaf = SSL_get_peer_certificate(g->ssl);      /* +1 ref */
    if (leaf == NULL) {
        return NGX_ERROR;
    }
    rc = gss_x509_pem(g, leaf, out);
    X509_free(leaf);
    return rc;
}


ngx_int_t
brix_gssapi_wrap(brix_gssapi_srv_t *g, const u_char *in, size_t in_len,
    ngx_str_t *out)
{
    if (SSL_write(g->ssl, in, (int) in_len) <= 0) {
        return NGX_ERROR;
    }
    return gss_drain(g, out);
}


ngx_int_t
brix_gssapi_unwrap(brix_gssapi_srv_t *g, const u_char *in, size_t in_len,
    ngx_str_t *out)
{
    if (in_len > 0 && BIO_write(g->rbio, in, (int) in_len) <= 0) {
        return NGX_ERROR;
    }
    return gss_read_all(g, 16384, out);
}


void
brix_gssapi_srv_free(brix_gssapi_srv_t *g)
{
    if (g != NULL) {
        gss_cleanup(g);
    }
}
