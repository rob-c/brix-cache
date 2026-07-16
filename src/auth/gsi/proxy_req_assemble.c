/* File: proxy_req_assemble.c — GSI delegated-credential assembly (phase-57 §F6)
 * WHAT: brix_gsi_assemble_proxy() ASSEMBLES the usable delegated credential:
 *   given the client-signed proxy cert (PEM), the request private key we
 *   generated in brix_gsi_build_pxyreq() (reqkey), and the signer's EEC chain
 *   (PEM), it verifies the proxy's public key matches reqkey and concatenates
 *   proxy (leaf) + chain + reqkey into one malloc'd NUL-terminated PEM blob.
 *
 * WHY: This is the GSI server / TPC destination's final step after kXGC_sigpxy —
 *   it turns the signed proxy back into a credential the destination can present
 *   as the user. The private key MUST be in the blob: every downstream consumer
 *   (TPC pull, proxy_ssl_certificate_key, ucred/origin-auth) loads cert chain
 *   AND key from the one stored PEM, and reqkey exists only in this process —
 *   omitting it makes the credential unable to authenticate anything. Split out
 *   of proxy_req.c (phase-79 file-size guard) as one cohesive unit; the request
 *   build stays in proxy_req.c and the issuance/signing lives in
 *   proxy_req_sign.c.
 *
 * HOW: parse the signed proxy PEM → compare its pubkey to reqkey (a mismatch
 *   would be someone else's credential) → PEM-export reqkey → overflow-guard the
 *   PEM lengths (proxy_pem_len is wire-supplied) → malloc + copy proxy, chain,
 *   key, NUL-terminate. No goto: each helper owns and frees its own temporaries
 *   linearly. The overflow-checked brix_size_add comes from
 *   <core/compat/safe_size.h> via proxy_req_internal.h. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "proxy_req_internal.h"

/* File-local argument pack for the assemble helpers: the input PEM blobs
 * plus the caller's error buffer (keeps every helper at <=5 parameters).
 * key_pem is populated by asm_export_key() before asm_concat_pem() runs. */
typedef struct {
    const uint8_t *proxy_pem;
    size_t         proxy_pem_len;
    const uint8_t *chain_pem;
    size_t         chain_pem_len;
    const uint8_t *key_pem;
    size_t         key_pem_len;
    char          *err;
    size_t         errcap;
} asm_args;

/* Parse the signed proxy PEM and verify its public key matches the request
 * key we generated (a mismatched proxy would be someone else's credential).
 * 0 on success; -1 with a->err set on parse failure or key mismatch. */
static int
asm_check_key_match(const asm_args *a, EVP_PKEY *reqkey)
{
    BIO      *pbio;
    X509     *proxy;
    EVP_PKEY *ppub;
    int       match;

    pbio = BIO_new_mem_buf(a->proxy_pem, (int) a->proxy_pem_len);
    proxy = pbio ? PEM_read_bio_X509(pbio, NULL, NULL, NULL) : NULL;
    if (proxy == NULL) {
        BIO_free(pbio);
        if (a->err) snprintf(a->err, a->errcap,
                             "gsi assemble: cannot parse signed proxy");
        return -1;
    }

    ppub = X509_get_pubkey(proxy);
    match = (ppub != NULL && EVP_PKEY_eq(ppub, reqkey) == 1);
    EVP_PKEY_free(ppub);
    X509_free(proxy);
    BIO_free(pbio);
    if (!match) {
        if (a->err) snprintf(a->err, a->errcap,
                             "gsi assemble: proxy key does not match request key");
        return -1;
    }
    return 0;
}

/* PEM-serialize the request private key into a malloc'd buffer so it can be
 * embedded in the assembled credential. Returns the buffer (caller cleanses
 * and frees) with *len set, or NULL with a->err set. */
static uint8_t *
asm_export_key(const asm_args *a, EVP_PKEY *reqkey, size_t *len)
{
    BIO     *kb;
    char    *kd = NULL;
    long     kl;
    uint8_t *out = NULL;

    kb = BIO_new(BIO_s_mem());
    if (kb == NULL
        || PEM_write_bio_PrivateKey(kb, reqkey, NULL, NULL, 0, NULL, NULL) != 1)
    {
        BIO_free(kb);
        if (a->err) snprintf(a->err, a->errcap,
                             "gsi assemble: cannot export request key");
        return NULL;
    }
    kl = BIO_get_mem_data(kb, &kd);
    if (kl > 0) {
        out = malloc((size_t) kl);
    }
    if (out != NULL) {
        memcpy(out, kd, (size_t) kl);
        *len = (size_t) kl;
    } else if (a->err) {
        snprintf(a->err, a->errcap, "gsi assemble: cannot export request key");
    }
    BIO_free(kb);
    return out;
}

/* Concatenate proxy (leaf) + signer chain + request key into one malloc'd
 * NUL-terminated PEM blob. Order: certs first, key last — a cert-reader stops
 * cleanly at the trailing key block while a key-reader skips the cert blocks.
 * proxy_pem_len is wire-supplied (client-sent kXGC_sigpxy) so the length
 * additions are overflow-guarded. 0 on success; -1 with a->err set. */
static int
asm_concat_pem(const asm_args *a, uint8_t **out_pem, size_t *out_len)
{
    size_t   total, need;
    uint8_t *out;

    if (brix_size_add(a->proxy_pem_len, a->chain_pem_len, &total) != NGX_OK
        || brix_size_add(total, a->key_pem_len, &total) != NGX_OK
        || brix_size_add(total, 1, &need) != NGX_OK) {
        if (a->err) snprintf(a->err, a->errcap,
                             "gsi assemble: PEM length overflow");
        return -1;
    }
    out = malloc(need);
    if (out == NULL) {
        if (a->err) snprintf(a->err, a->errcap, "gsi assemble: out of memory");
        return -1;
    }
    memcpy(out, a->proxy_pem, a->proxy_pem_len);
    memcpy(out + a->proxy_pem_len, a->chain_pem, a->chain_pem_len);
    memcpy(out + a->proxy_pem_len + a->chain_pem_len, a->key_pem,
           a->key_pem_len);
    out[total] = '\0';
    *out_pem = out;
    *out_len = total;
    return 0;
}

int
brix_gsi_assemble_proxy(const brix_gsi_blob_t *proxy_pem, EVP_PKEY *reqkey,
                          const brix_gsi_blob_t *chain_pem,
                          brix_gsi_buf_t *out_pem, const brix_gsi_err_t *err)
{
    asm_args a;
    char    *ebuf = (err != NULL) ? err->buf : NULL;
    size_t   ecap = (err != NULL) ? err->cap : 0;

    if (proxy_pem == NULL || proxy_pem->data == NULL || reqkey == NULL
        || chain_pem == NULL || chain_pem->data == NULL || out_pem == NULL) {
        if (ebuf) snprintf(ebuf, ecap, "gsi assemble: bad arguments");
        return -1;
    }

    a.proxy_pem     = proxy_pem->data;
    a.proxy_pem_len = proxy_pem->len;
    a.chain_pem     = chain_pem->data;
    a.chain_pem_len = chain_pem->len;
    a.key_pem       = NULL;
    a.key_pem_len   = 0;
    a.err           = ebuf;
    a.errcap        = ecap;

    /* The signed proxy's public key MUST match the request key we generated. */
    if (asm_check_key_match(&a, reqkey) != 0) {
        return -1;
    }

    /* Delegated credential PEM = proxy (leaf), signer chain, then the request
     * private key — the complete credential the holder can authenticate with. */
    {
        uint8_t *keybuf;
        size_t   keylen = 0;
        int      rc;

        keybuf = asm_export_key(&a, reqkey, &keylen);
        if (keybuf == NULL) {
            return -1;
        }
        a.key_pem     = keybuf;
        a.key_pem_len = keylen;
        rc = asm_concat_pem(&a, &out_pem->data, &out_pem->len);
        OPENSSL_cleanse(keybuf, keylen);
        free(keybuf);
        return rc;
    }
}
