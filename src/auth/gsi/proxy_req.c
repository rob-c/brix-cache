/* File: proxy_req.c — RFC-3820 GSI proxy-request crypto (phase-57 §F6)
 * WHAT: brix_gsi_build_pxyreq() generates the proxy-certificate REQUEST a GSI
 *   server sends to a delegating client (the kXGS_pxyreq main payload): a fresh
 *   RSA keypair + a self-signed X509_REQ whose subject is the parent's plus a
 *   random /CN=<serial> and which carries a critical proxyCertInfo extension.
 *
 * WHY: F6 multi-hop delegation — our destination, acting as the GSI server on the
 *   client→dest login, must request the client's proxy so it can later pull from
 *   the source as the USER. This is the exact request a stock XrdSecgsi client
 *   knows how to sign; getting it byte-faithful is what lets a real delegating
 *   client (XrdSecGSIDELEGPROXY) interoperate. Ported from stock XrdSecgsi
 *   XrdCrypto/XrdCryptosslgsiAux.cc::XrdCryptosslX509CreateProxyReq.
 *
 * HOW: PEM→X509 parent → RSA keygen(bits>=parent,>=2048,e=65537) → subject =
 *   dup(parent) + /CN=<rand serial> → proxyCertInfo (impersonation policy, pathlen
 *   from parent) → copy parent extensions except SAN/proxyCertInfo → push critical
 *   proxyCertInfo → X509_REQ_{set_pubkey,set_subject_name,add_extensions} →
 *   X509_REQ_sign(SHA256) → i2d_X509_REQ. No goto: a single NULL-safe cleanup
 *   (pxr_fail) frees everything not yet handed to the caller; ownership-transferred
 *   fields are NULLed in the ctx first. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

/* Shared GSI OID / RSA-strength constants, the standalone-build shim +
 * <core/compat/safe_size.h> include, and the cross-file pxr_make_pci_ext()
 * declaration all live in proxy_req_internal.h so the three-way split
 * (proxy_req.c / proxy_req_sign.c / proxy_req_assemble.c) shares one copy. */
#include "proxy_req_internal.h"

/* Owned resources for one request build; freed once by pxr_fail (no goto).
 * err/errcap ride along so every helper can report through pxr_fail without
 * growing its parameter list. */
typedef struct {
    X509                      *parent;
    BIO                       *pbio;
    EVP_PKEY                  *key;
    X509_NAME                 *subj;
    PROXY_CERT_INFO_EXTENSION *pci;
    STACK_OF(X509_EXTENSION)  *exts;
    X509_EXTENSION            *ext;
    X509_REQ                  *req;
    char                      *err;
    size_t                     errcap;
} pxr_ctx;

/* Record msg in the caller's error buffer, free every owned resource, and
 * return -1 — the single cleanup tail for the whole request build (no goto).
 * Called with msg == NULL on the success path purely to free leftovers. */
static int
pxr_fail(pxr_ctx *x, const char *msg)
{
    if (x->err != NULL && x->errcap > 0 && msg != NULL) {
        snprintf(x->err, x->errcap, "%s", msg);
    }
    if (x->parent) X509_free(x->parent);
    if (x->pbio)   BIO_free(x->pbio);
    if (x->key)    EVP_PKEY_free(x->key);
    if (x->subj)   X509_NAME_free(x->subj);
    if (x->pci)    PROXY_CERT_INFO_EXTENSION_free(x->pci);
    if (x->exts)   sk_X509_EXTENSION_pop_free(x->exts, X509_EXTENSION_free);
    if (x->ext)    X509_EXTENSION_free(x->ext);
    if (x->req)    X509_REQ_free(x->req);
    return -1;
}

/* Path-length constraint of the parent's proxyCertInfo, or -1 if none. */
static int
pxr_parent_pathlen(X509 *parent)
{
    int n = X509_get_ext_count(parent);
    int i;

    for (i = 0; i < n; i++) {
        X509_EXTENSION *e = X509_get_ext(parent, i);
        char            oid[128];
        int             is_new, is_old;

        OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(e), 1);
        is_new = (strcmp(oid, GSI_PROXYCERTINFO_OID) == 0);
        is_old = (strcmp(oid, GSI_PROXYCERTINFO_OLD_OID) == 0);
        if (is_new || is_old) {
            const unsigned char       *p =
                ASN1_STRING_get0_data(X509_EXTENSION_get_data(e));
            int                        len =
                ASN1_STRING_length(X509_EXTENSION_get_data(e));
            PROXY_CERT_INFO_EXTENSION *in = is_new
                ? d2i_PROXY_CERT_INFO_EXTENSION(NULL, &p, len)
                : NULL;
            int depth = -1;

            if (in != NULL) {
                if (in->pcPathLengthConstraint != NULL) {
                    depth = (int) ASN1_INTEGER_get(in->pcPathLengthConstraint);
                }
                PROXY_CERT_INFO_EXTENSION_free(in);
            }
            return depth;
        }
    }
    return -1;
}

/* Copy parent extensions (minus SAN / proxyCertInfo) into the request stack. */
static int
pxr_copy_parent_exts(X509 *parent, STACK_OF(X509_EXTENSION) *dst)
{
    int n = X509_get_ext_count(parent);
    int i;

    for (i = 0; i < n; i++) {
        X509_EXTENSION *e = X509_get_ext(parent, i);
        char            oid[128];
        X509_EXTENSION *dup;

        OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(e), 1);
        if (strcmp(oid, GSI_SUBJ_ALT_NAME_OID) == 0
            || strcmp(oid, GSI_PROXYCERTINFO_OID) == 0
            || strcmp(oid, GSI_PROXYCERTINFO_OLD_OID) == 0) {
            continue;
        }
        dup = X509_EXTENSION_dup(e);
        if (dup == NULL || sk_X509_EXTENSION_push(dst, dup) == 0) {
            X509_EXTENSION_free(dup);
            return -1;
        }
    }
    return 0;
}

/* Generate the RSA proxy key: >= parent bits, >= 2048, public exponent 65537. */
static EVP_PKEY *
pxr_keygen(X509 *parent)
{
    EVP_PKEY     *ppub = X509_get_pubkey(parent);
    int           bits = (ppub != NULL) ? EVP_PKEY_bits(ppub) : GSI_MIN_RSA_BITS;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *key = NULL;
    BIGNUM       *e;

    EVP_PKEY_free(ppub);
    if (bits < GSI_MIN_RSA_BITS) {
        bits = GSI_MIN_RSA_BITS;
    }
    e = BN_new();
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (e == NULL || ctx == NULL || !BN_set_word(e, 0x10001)
        || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0
        || EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) <= 0
        || EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    BN_free(e);
    return key;
}

/* DER-encode a fresh proxyCertInfo (impersonation policy + optional pathlen
 * derived from the parent's, decremented once, floored at 0) into a malloc'd
 * buffer; *len gets the DER length. NULL on any allocation/encode failure. */
static unsigned char *
pxr_pci_encode_der(int parent_pathlen, int *len)
{
    PROXY_CERT_INFO_EXTENSION *pci = PROXY_CERT_INFO_EXTENSION_new();
    unsigned char             *der = NULL;

    if (pci == NULL) {
        return NULL;
    }
    pci->proxyPolicy->policyLanguage =
        OBJ_txt2obj(GSI_PROXYPOLICY_IMPERSONATION, 1);
    if (parent_pathlen > -1) {
        int depth = (parent_pathlen > 0) ? (parent_pathlen - 1) : 0;
        pci->pcPathLengthConstraint = ASN1_INTEGER_new();
        if (pci->pcPathLengthConstraint == NULL
            || !ASN1_INTEGER_set(pci->pcPathLengthConstraint, depth)) {
            PROXY_CERT_INFO_EXTENSION_free(pci);
            return NULL;
        }
    }

    *len = i2d_PROXY_CERT_INFO_EXTENSION(pci, NULL);
    if (*len > 0) {
        unsigned char *pp;

        der = malloc((size_t) *len);
        pp = der;
        if (der == NULL || i2d_PROXY_CERT_INFO_EXTENSION(pci, &pp) <= 0) {
            free(der);
            der = NULL;
        }
    }
    PROXY_CERT_INFO_EXTENSION_free(pci);
    return der;
}

/* Wrap a DER proxyCertInfo payload into a critical X509_EXTENSION carrying
 * the RFC-3820 OID. NULL on failure; never takes ownership of der. */
static X509_EXTENSION *
pxr_pci_ext_from_der(const unsigned char *der, int len)
{
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    X509_EXTENSION    *ext = X509_EXTENSION_new();
    ASN1_OBJECT       *obj = OBJ_txt2obj(GSI_PROXYCERTINFO_OID, 1);

    if (os != NULL && ext != NULL && obj != NULL
        && ASN1_OCTET_STRING_set(os, der, len)
        && X509_EXTENSION_set_object(ext, obj) == 1
        && X509_EXTENSION_set_critical(ext, 1) == 1
        && X509_EXTENSION_set_data(ext, os) == 1) {
        /* success */
    } else {
        X509_EXTENSION_free(ext);
        ext = NULL;
    }
    ASN1_OCTET_STRING_free(os);
    ASN1_OBJECT_free(obj);
    return ext;
}

/* Build the critical proxyCertInfo X509_EXTENSION (impersonation, pathlen).
 * Non-static + declared in proxy_req_internal.h: proxy_req_sign.c calls this
 * across the phase-79 split when it adds the proxy's proxyCertInfo. */
X509_EXTENSION *
pxr_make_pci_ext(int parent_pathlen)
{
    X509_EXTENSION *ext;
    unsigned char  *der;
    int             len = 0;

    der = pxr_pci_encode_der(parent_pathlen, &len);
    if (der == NULL) {
        return NULL;
    }
    ext = pxr_pci_ext_from_der(der, len);
    free(der);
    return ext;
}

/* Parse the parent EEC/proxy PEM into x->parent and generate the fresh proxy
 * key into x->key. 0 on success; -1 via pxr_fail (everything freed) on error. */
static int
pxr_load_parent_and_key(pxr_ctx *x, const uint8_t *parent_pem,
                        size_t parent_pem_len)
{
    /* Parent EEC/proxy. */
    x->pbio = BIO_new_mem_buf(parent_pem, (int) parent_pem_len);
    x->parent = x->pbio ? PEM_read_bio_X509(x->pbio, NULL, NULL, NULL) : NULL;
    if (x->parent == NULL) {
        return pxr_fail(x, "gsi pxyreq: cannot parse parent cert");
    }

    /* Fresh proxy key. */
    x->key = pxr_keygen(x->parent);
    if (x->key == NULL) {
        return pxr_fail(x, "gsi pxyreq: key generation failed");
    }
    return 0;
}

/* Build x->subj = parent subject + /CN=<random serial> (serial reused as the
 * CN, matching stock XrdSecgsi). 0 on success; -1 via pxr_fail on error. */
static int
pxr_build_subject(pxr_ctx *x)
{
    unsigned int  serial;
    unsigned char sn[24];

    if (RAND_bytes((unsigned char *) &serial, sizeof(serial)) != 1) {
        return pxr_fail(x, "gsi pxyreq: RNG failed");
    }
    x->subj = X509_NAME_dup(X509_get_subject_name(x->parent));
    if (x->subj == NULL) {
        return pxr_fail(x, "gsi pxyreq: cannot dup subject");
    }
    snprintf((char *) sn, sizeof(sn), "%u", serial);
    if (!X509_NAME_add_entry_by_txt(x->subj, "CN", MBSTRING_ASC, sn,
                                    -1, -1, 0)) {
        return pxr_fail(x, "gsi pxyreq: cannot add CN");
    }
    return 0;
}

/* Fill x->exts with copies of the parent's extensions (minus SAN/pci) plus a
 * fresh critical proxyCertInfo whose pathlen derives from the parent's.
 * 0 on success; -1 via pxr_fail on error. */
static int
pxr_build_extstack(pxr_ctx *x)
{
    int parent_pathlen = pxr_parent_pathlen(x->parent);

    x->exts = sk_X509_EXTENSION_new_null();
    if (x->exts == NULL || pxr_copy_parent_exts(x->parent, x->exts) != 0) {
        return pxr_fail(x, "gsi pxyreq: cannot copy extensions");
    }
    x->ext = pxr_make_pci_ext(parent_pathlen);
    if (x->ext == NULL || sk_X509_EXTENSION_push(x->exts, x->ext) == 0) {
        return pxr_fail(x, "gsi pxyreq: cannot build proxyCertInfo");
    }
    x->ext = NULL;                      /* ownership → x->exts */
    return 0;
}

/* Assemble the X509_REQ from x->{key,subj,exts}, self-sign it (SHA256) and
 * DER-encode it into a malloc'd buffer returned via req_der/req_len.
 * 0 on success; -1 via pxr_fail on error. */
static int
pxr_sign_and_encode_req(pxr_ctx *x, uint8_t **req_der, size_t *req_len)
{
    int            der_len;
    unsigned char *out, *pp;

    x->req = X509_REQ_new();
    if (x->req == NULL
        || X509_REQ_set_pubkey(x->req, x->key) != 1
        || X509_REQ_set_subject_name(x->req, x->subj) != 1
        || X509_REQ_add_extensions(x->req, x->exts) != 1
        || X509_REQ_sign(x->req, x->key, EVP_sha256()) <= 0) {
        return pxr_fail(x, "gsi pxyreq: cannot sign request");
    }

    der_len = i2d_X509_REQ(x->req, NULL);
    if (der_len <= 0) {
        return pxr_fail(x, "gsi pxyreq: DER encode failed");
    }
    out = malloc((size_t) der_len);
    if (out == NULL) {
        return pxr_fail(x, "gsi pxyreq: out of memory");
    }
    pp = out;
    if (i2d_X509_REQ(x->req, &pp) <= 0) {
        free(out);
        return pxr_fail(x, "gsi pxyreq: DER encode failed");
    }

    *req_der = out;
    *req_len = (size_t) der_len;
    return 0;
}

int
brix_gsi_build_pxyreq(const brix_gsi_blob_t *parent_pem, EVP_PKEY **newkey,
                        brix_gsi_buf_t *req_der, const brix_gsi_err_t *err)
{
    pxr_ctx x;

    memset(&x, 0, sizeof(x));
    if (err != NULL) {
        x.err    = err->buf;
        x.errcap = err->cap;
    }
    if (parent_pem == NULL || parent_pem->data == NULL || newkey == NULL
        || req_der == NULL) {
        return pxr_fail(&x, "gsi pxyreq: bad arguments");
    }

    if (pxr_load_parent_and_key(&x, parent_pem->data, parent_pem->len) != 0
        || pxr_build_subject(&x) != 0
        || pxr_build_extstack(&x) != 0
        || pxr_sign_and_encode_req(&x, &req_der->data, &req_der->len) != 0) {
        return -1;                      /* helpers already freed via pxr_fail */
    }

    *newkey = x.key;
    x.key   = NULL;                     /* ownership → caller */
    (void) pxr_fail(&x, NULL);          /* free everything else */
    return 0;
}
