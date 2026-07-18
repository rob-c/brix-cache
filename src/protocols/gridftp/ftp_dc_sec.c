#include "ftp_dc_sec.h"

#include "auth/crypto/gsi_verify.h"

#include <openssl/pem.h>
#include <openssl/evp.h>

/*
 * ftp_dc_sec.c — GridFTP data-channel GSI security core (see ftp_dc_sec.h).
 * The cert/identity logic (delegated-credential load, data-channel TLS policy,
 * post-handshake proxy-chain verify + DN pin) used by the ev/ tree's PROT P data
 * channel, factored out here as one data-channel security boundary independent of
 * how the handshake is driven.
 */


/* Accept any presented cert at the TLS layer; the RFC 3820 proxy chain is
 * verified post-handshake in brix_ftp_dc_gsi_check, mirroring the control-channel
 * accept engine. */
static int
brix_ftp_dc_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    (void) ok;
    (void) ctx;
    return 1;
}


ngx_int_t
brix_ftp_dc_load_deleg(const brix_ftp_dc_sec_t *sec, SSL *ssl)
{
    BIO       *bio;
    X509      *leaf;
    X509      *ca;
    EVP_PKEY  *key;

    if (sec->deleg_proxy.len == 0) {
        ngx_log_error(NGX_LOG_ERR, sec->log, 0,
                      "brix: gsiftp PROT P needs a delegated credential (none)");
        return NGX_ERROR;
    }

    bio = BIO_new_mem_buf(sec->deleg_proxy.data, (int) sec->deleg_proxy.len);
    if (bio == NULL) {
        return NGX_ERROR;
    }

    /* certs first: leaf proxy, then the issuer chain (EEC + upstream proxies). */
    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (leaf == NULL || SSL_use_certificate(ssl, leaf) != 1) {
        X509_free(leaf);
        BIO_free(bio);
        return NGX_ERROR;
    }
    X509_free(leaf);

    SSL_clear_chain_certs(ssl);

    /* The delegated proxy's direct issuer is the client's control-channel leaf
     * (the proxy it authenticated with).  Server-side SSL_get_peer_cert_chain()
     * excludes the peer leaf, so it is absent from the assembled deleg PEM chain;
     * prepend it here so the presented path is complete for the client to verify. */
    if (sec->ctrl_leaf_pem.len > 0) {
        BIO *lbio = BIO_new_mem_buf(sec->ctrl_leaf_pem.data,
                                    (int) sec->ctrl_leaf_pem.len);
        if (lbio == NULL) {
            BIO_free(bio);
            return NGX_ERROR;
        }
        ca = PEM_read_bio_X509(lbio, NULL, NULL, NULL);
        BIO_free(lbio);
        if (ca == NULL || SSL_add1_chain_cert(ssl, ca) != 1) {
            X509_free(ca);
            BIO_free(bio);
            return NGX_ERROR;
        }
        X509_free(ca);
    }

    while ((ca = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (SSL_add1_chain_cert(ssl, ca) != 1) {
            X509_free(ca);
            BIO_free(bio);
            return NGX_ERROR;
        }
        X509_free(ca);
    }
    BIO_free(bio);

    /* the private key is serialized last in the same PEM (fresh BIO to read it) */
    bio = BIO_new_mem_buf(sec->deleg_proxy.data, (int) sec->deleg_proxy.len);
    if (bio == NULL) {
        return NGX_ERROR;
    }
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (key == NULL || SSL_use_PrivateKey(ssl, key) != 1) {
        EVP_PKEY_free(key);
        return NGX_ERROR;
    }
    EVP_PKEY_free(key);

    if (SSL_check_private_key(ssl) != 1) {
        ngx_log_error(NGX_LOG_ERR, sec->log, 0,
                      "brix: gsiftp delegated cred cert/key mismatch");
        return NGX_ERROR;
    }
    return NGX_OK;
}


void
brix_ftp_dc_apply_policy(SSL *ssl)
{
    SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
    /* GridFTP stream mode signals end-of-data by closing the data connection,
     * and globus does so without a TLS close_notify.  Treat that abrupt close as
     * a clean EOF (SSL_ERROR_ZERO_RETURN) instead of SSL_R_UNEXPECTED_EOF — a
     * STOR receiver otherwise fails the transfer after the last block. */
    SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
    SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                   brix_ftp_dc_verify_cb);
}


/* GSI identity match: does the peer's leaf DN name the same subject as the
 * control-channel DN?  In GSI a proxy's subject is exactly the delegator's
 * subject plus one `/CN=<value>` component per delegation step, so the peer DN
 * matches when it either equals the control DN (a plain client transfer, where
 * the data peer presents the same proxy) or extends it by one or more trailing
 * `/CN=` proxy components (a gsiftp<->gsiftp TPC leg, where the other server
 * presents a proxy further delegated from the control identity).  The chain has
 * already been PKIX-verified as a well-formed RFC 3820 proxy chain, so any such
 * extension is a genuine sub-proxy — the prefix cannot be forged without the
 * control identity's key.  Returns 1 on match, 0 otherwise. */
static int
brix_ftp_dc_dn_matches(const char *peer, const u_char *base, size_t blen)
{
    size_t plen = ngx_strlen(peer);
    const char *p;

    if (blen == 0 || plen < blen || ngx_strncmp(peer, base, blen) != 0) {
        return 0;
    }
    if (plen == blen) {
        return 1;                                  /* exact identity */
    }
    if (peer[blen] != '/') {
        return 0;                                  /* prefix not at an RDN boundary */
    }
    /* Every trailing RDN past the control DN must be a `CN=` proxy component. */
    for (p = peer + blen; *p == '/'; ) {
        p++;
        if (ngx_strncmp(p, "CN=", 3) != 0) {
            return 0;
        }
        while (*p != '\0' && *p != '/') {
            p++;
        }
    }
    return *p == '\0';
}


ngx_int_t
brix_ftp_dc_gsi_check(const brix_ftp_dc_sec_t *sec, SSL *ssl)
{
    X509                      *leaf;
    STACK_OF(X509)            *chain;
    brix_gsi_verify_result_t   res;
    ngx_int_t                  rc;

    leaf = SSL_get_peer_certificate(ssl);        /* +1 ref */
    if (leaf == NULL) {
        return NGX_ERROR;
    }
    chain = SSL_get_peer_cert_chain(ssl);         /* borrowed */
    ngx_memzero(&res, sizeof(res));
    rc = brix_gsi_verify_chain(sec->log, sec->ca_store, leaf, chain,
                               0, &res, 0);
    X509_free(leaf);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, sec->log, 0,
                      "brix: gsiftp data-channel proxy chain verify failed");
        return NGX_ERROR;
    }

    if (!brix_ftp_dc_dn_matches(res.dn_buf, sec->ctrl_dn.data, sec->ctrl_dn.len)) {
        ngx_log_error(NGX_LOG_ERR, sec->log, 0,
                      "brix: gsiftp data-channel DN \"%s\" != control DN \"%V\"",
                      res.dn_buf, &sec->ctrl_dn);
        return NGX_ERROR;
    }
    return NGX_OK;
}
