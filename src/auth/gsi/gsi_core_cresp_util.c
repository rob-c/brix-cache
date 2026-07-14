/*
 * gsi_core_cresp_util.c — round-2 XrdSecgsi cert-response leaf helpers.
 *
 * WHAT: The self-contained, stateless helpers the round-2 cert-response builder
 *       (gsi_core_cresp.c) leans on: extract a peer certificate's public key
 *       from a PEM bucket (gsi_cresp_cert_pubkey), export an EVP_PKEY public
 *       part as PEM SubjectPublicKeyInfo (gsi_cresp_export_pubkey_pem), choose
 *       the kXRS_md_alg digest to echo back (gsi_cresp_pick_md_alg), free the
 *       whole owned-resource set on the single error/success path
 *       (gsi_cresp_fail, operating on gsi_cresp_ctx), and the opt-in full-proxy
 *       passthrough bucket (gsi_add_fullproxy_bucket).
 *
 * WHY:  gsi_core.c carried the entire round-2 exchange and exceeded the ~500-line
 *       file-size guard, so the leaf helpers were carved out here and the state
 *       machine into gsi_core_cresp.c (phase-79). These five functions are
 *       leaves — they take inputs and return outputs (or free a passed context)
 *       without touching the gsi_cresp_state_t aggregate — so they belong in
 *       their own translation unit. Splitting moves no logic, changes no OpenSSL
 *       call order and no emitted bytes: the DH exchange, cert/response build,
 *       and signature crypto are byte-for-byte unchanged from the original.
 *
 * HOW:  All entry points cross a TU boundary into gsi_core_cresp.c and are
 *       declared non-static in gsi_core_internal.h, the shared private contract
 *       both files include.
 */
#include "gsi_core_internal.h"


/* Public key of the first X.509 cert in a PEM bucket (the peer's EEC). */
EVP_PKEY *
gsi_cresp_cert_pubkey(const uint8_t *pem, size_t len)
{
    BIO      *bio = BIO_new_mem_buf(pem, (int) len);
    X509     *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    EVP_PKEY *pk = cert ? X509_get_pubkey(cert) : NULL;

    X509_free(cert);
    BIO_free(bio);
    return pk;
}


/* Export an EVP_PKEY public part as PEM SubjectPublicKeyInfo
 * (XrdCryptosslRSA::ExportPublic = PEM_write_bio_PUBKEY).  malloc'd,
 * NUL-terminated, *outlen = strlen.  The signed-DH path sends this as kXRS_puk so
 * the server can verify our signed DH before it has decrypted our cert chain. */
char *
gsi_cresp_export_pubkey_pem(EVP_PKEY *key, size_t *outlen)
{
    BIO  *bio = BIO_new(BIO_s_mem());
    char *pem = NULL, *out = NULL;
    long  len;

    if (bio != NULL && PEM_write_bio_PUBKEY(bio, key) == 1) {
        len = BIO_get_mem_data(bio, &pem);
        out = malloc((size_t) len + 1);
        if (out != NULL) {
            memcpy(out, pem, (size_t) len);
            out[len] = '\0';
            *outlen = (size_t) len;
        }
    }
    BIO_free(bio);
    return out;
}


/* Choose the kXRS_md_alg digest to echo back: prefer "sha256" when the server
 * offers it (it matches our SHA256(secret) key derivation), else the server's
 * first ':'-separated token, else "sha256".  dCache rejects the handshake if the
 * reply names a digest it did not advertise. */
size_t
gsi_cresp_pick_md_alg(const uint8_t *sbody, uint32_t slen, char *out, size_t outcap)
{
    const uint8_t *list = NULL;
    size_t         listlen = 0, n = 0;

    if (brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_md_alg,
                               &list, &listlen) == 0 && listlen > 0) {
        if (listlen >= 6) {
            for (size_t i = 0; i + 6 <= listlen; i++) {
                if (memcmp(list + i, "sha256", 6) == 0) {
                    memcpy(out, "sha256", 6);
                    out[6] = '\0';
                    return 6;
                }
            }
        }
        while (n < listlen && n + 1 < outcap && list[n] != ':') {
            out[n] = (char) list[n];
            n++;
        }
    }
    if (n == 0) {
        memcpy(out, "sha256", 6);
        n = 6;
    }
    out[n] = '\0';
    return n;
}


/*
 * gsi_cresp_ctx — owned resources for the round-2 response, freed once by
 * gsi_cresp_cleanup (single NULL-safe destructor, no goto).  proxy_pem and the
 * proxy private key are NOT held here — they are borrowed from the caller.
 */
int
gsi_cresp_fail(gsi_cresp_ctx *x, char *err, size_t errcap, const char *msg)
{
    if (err != NULL && errcap > 0 && msg != NULL) {
        snprintf(err, errcap, "%s", msg);
    }
    free(x->peerblob);
    free(x->signed_rtag);
    free(x->signed_cpub);
    free(x->pubpem);
    free(x->enc);
    free(x->cpub);
    EVP_PKEY_free(x->mine);
    EVP_PKEY_free(x->peer);
    EVP_PKEY_free(x->servpub);
    brix_gbuf_free(&x->inner);
    brix_gbuf_free(&x->outer);
    return -1;
}


/*
 * gsi_add_fullproxy_bucket — OPT-IN client full-proxy passthrough (phase-70
 * §5.1). When XRD_DELEGATEFULLPROXY is set, load the FULL proxy (cert chain +
 * private key PEM) from $X509_USER_PROXY and append it as a kXRS_x509_fullproxy
 * bucket in the encrypted inner buffer, so a delegation-enabled node can present
 * the user's own proxy upstream. STRICTLY off by default: no env ⇒ no-op, so
 * the shared kernel's server/TPC callers (which never set the var) are inert.
 * Best-effort — a load failure silently omits the bucket (login still succeeds
 * with the normal chain-only kXRS_x509). The bytes carry a private key: the
 * caller encrypts the whole inner buffer, so they never cross the wire in clear,
 * and the server accepts them only under TLS.
 */
void
gsi_add_fullproxy_bucket(brix_gbuf *inner)
{
    const char *proxy;
    FILE       *fp;
    uint8_t     buf[16384];
    size_t      total;

    if (getenv("XRD_DELEGATEFULLPROXY") == NULL) {
        return;
    }
    proxy = getenv("X509_USER_PROXY");
    if (proxy == NULL || proxy[0] == '\0') {
        return;
    }

    fp = fopen(proxy, "r");
    if (fp == NULL) {
        return;
    }
    /* A grid proxy file stores the proxy cert chain followed by its private key
     * in PEM — forward it verbatim as the full proxy (chain + key). Capped at
     * buf[]; a proxy larger than that omits the bucket rather than truncating. */
    total = fread(buf, 1, sizeof(buf), fp);
    if (total > 0 && total < sizeof(buf)) {
        brix_gbuf_bucket(inner, (uint32_t) kXRS_x509_fullproxy, buf, total);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    (void) fclose(fp); /* phase74-fp: read-only stream, close failure cannot lose data */
}
