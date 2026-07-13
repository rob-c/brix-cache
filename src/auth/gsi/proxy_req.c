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

#include "proxy_req.h"

/* Overflow-checked size arithmetic (wire-length guard in brix_gsi_assemble_proxy).
 * Two builds compile this file without nginx headers: the standalone unit test
 * (proxy_req_unittest.c, which defines BRIX_SAFE_SIZE_STANDALONE) and the
 * libxrdproto client core (built with XRDPROTO_NO_NGX). Both must make
 * safe_size.h skip its <ngx_config.h>/<ngx_core.h> includes AND supply the
 * minimal shims its inline helpers need — so the ngx-free client build implies
 * the standalone path. */
#if defined(XRDPROTO_NO_NGX) && !defined(BRIX_SAFE_SIZE_STANDALONE)
#  define BRIX_SAFE_SIZE_STANDALONE 1
#endif
#ifdef BRIX_SAFE_SIZE_STANDALONE
typedef long              ngx_int_t;
typedef struct ngx_pool_s ngx_pool_t;
typedef struct ngx_log_s  ngx_log_t;
#  define NGX_OK    0
#  define NGX_ERROR (-1)
#  define ngx_inline inline    /* safe_size.h writes "static ngx_inline"; not "static static" */
static inline void *ngx_palloc(ngx_pool_t *p, size_t n)  { (void)p; return malloc(n);    }
static inline void *ngx_pcalloc(ngx_pool_t *p, size_t n) { (void)p; return calloc(1, n); }
static inline void *ngx_alloc(size_t n, ngx_log_t *l)    { (void)l; return malloc(n);    }
#endif
#include "core/compat/safe_size.h"

#define GSI_PROXYCERTINFO_OID          "1.3.6.1.5.5.7.1.14"
#define GSI_PROXYCERTINFO_OLD_OID      "1.3.6.1.4.1.3536.1.222"
#define GSI_PROXYPOLICY_IMPERSONATION  "1.3.6.1.5.5.7.21.1"
#define GSI_KEY_USAGE_OID              "2.5.29.15"
#define GSI_SUBJ_ALT_NAME_OID          "2.5.29.17"
#define GSI_MIN_RSA_BITS               2048

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

/* Build the critical proxyCertInfo X509_EXTENSION (impersonation, pathlen). */
static X509_EXTENSION *
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


/* pcPathLengthConstraint of an X509_REQ's proxyCertInfo, or -1 if none. */
static int
pxr_req_pathlen(X509_REQ *req)
{
    STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
    int depth = -1, i;

    for (i = 0; exts != NULL && i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION *e = sk_X509_EXTENSION_value(exts, i);
        char            oid[128];

        OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(e), 1);
        if (strcmp(oid, GSI_PROXYCERTINFO_OID) == 0) {
            const unsigned char       *p =
                ASN1_STRING_get0_data(X509_EXTENSION_get_data(e));
            int                        len =
                ASN1_STRING_length(X509_EXTENSION_get_data(e));
            PROXY_CERT_INFO_EXTENSION *in =
                d2i_PROXY_CERT_INFO_EXTENSION(NULL, &p, len);

            if (in != NULL) {
                if (in->pcPathLengthConstraint != NULL) {
                    depth = (int) ASN1_INTEGER_get(in->pcPathLengthConstraint);
                }
                PROXY_CERT_INFO_EXTENSION_free(in);
            }
            break;
        }
    }
    if (exts != NULL) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    return depth;
}

/* Owned resources for one proxy issuance; freed once by sgn_fail (no goto).
 * err/errcap ride along so every helper can report through sgn_fail without
 * growing its parameter list. */
typedef struct {
    BIO            *sbio;
    X509           *signer;
    X509_REQ       *req;
    EVP_PKEY       *reqpub;
    X509           *proxy;
    X509_EXTENSION *pciext;
    BIO            *obio;
    char           *err;
    size_t          errcap;
} sgn_ctx;

/* Record msg in the caller's error buffer, free every owned resource, and
 * return -1 — the single cleanup tail for the whole issuance (no goto).
 * Called with msg == NULL on the success path purely to free leftovers. */
static int
sgn_fail(sgn_ctx *x, const char *msg)
{
    if (x->err != NULL && x->errcap > 0 && msg != NULL) {
        snprintf(x->err, x->errcap, "%s", msg);
    }
    if (x->sbio)   BIO_free(x->sbio);
    if (x->signer) X509_free(x->signer);
    if (x->req)    X509_REQ_free(x->req);
    if (x->reqpub) EVP_PKEY_free(x->reqpub);
    if (x->proxy)  X509_free(x->proxy);
    if (x->pciext) X509_EXTENSION_free(x->pciext);
    if (x->obio)   BIO_free(x->obio);
    return -1;
}

/* Copy the signer's extensions into the proxy (keyUsage required, SAN rejected,
 * proxyCertInfo skipped); report the signer's pci pathlen via *indepth. -1 err. */
static int
sgn_copy_signer_exts(X509 *signer, X509 *proxy, int *indepth, int *haskeyusage)
{
    int n = X509_get_ext_count(signer);
    int i;

    *indepth = -1;
    *haskeyusage = 0;
    for (i = 0; i < n; i++) {
        X509_EXTENSION *e = X509_get_ext(signer, i);
        char            oid[128];

        OBJ_obj2txt(oid, sizeof(oid), X509_EXTENSION_get_object(e), 1);
        if (strcmp(oid, GSI_PROXYCERTINFO_OID) == 0
            || strcmp(oid, GSI_PROXYCERTINFO_OLD_OID) == 0) {
            const unsigned char       *p =
                ASN1_STRING_get0_data(X509_EXTENSION_get_data(e));
            int                        len =
                ASN1_STRING_length(X509_EXTENSION_get_data(e));
            PROXY_CERT_INFO_EXTENSION *in =
                d2i_PROXY_CERT_INFO_EXTENSION(NULL, &p, len);

            if (in != NULL) {
                if (in->pcPathLengthConstraint != NULL) {
                    *indepth = (int) ASN1_INTEGER_get(in->pcPathLengthConstraint);
                }
                PROXY_CERT_INFO_EXTENSION_free(in);
            }
            continue;                       /* do not copy the pci */
        }
        if (strcmp(oid, GSI_SUBJ_ALT_NAME_OID) == 0) {
            return -1;                      /* SAN not allowed in a proxy */
        }
        if (strcmp(oid, GSI_KEY_USAGE_OID) == 0) {
            *haskeyusage = 1;
        }
        if (X509_add_ext(proxy, e, -1) == 0) {  /* X509_add_ext dups */
            return -1;
        }
    }
    return 0;
}

/* Parse the signer cert (PEM) into x->signer and the request (DER) into
 * x->req. 0 on success; -1 via sgn_fail (everything freed) on error. */
static int
sgn_parse_inputs(sgn_ctx *x, const uint8_t *signer_pem, size_t signer_pem_len,
                 const uint8_t *req_der, size_t req_len)
{
    const unsigned char *p;

    x->sbio = BIO_new_mem_buf(signer_pem, (int) signer_pem_len);
    x->signer = x->sbio ? PEM_read_bio_X509(x->sbio, NULL, NULL, NULL) : NULL;
    if (x->signer == NULL) {
        return sgn_fail(x, "gsi sign: cannot parse signer cert");
    }
    p = req_der;
    x->req = d2i_X509_REQ(NULL, &p, (long) req_len);
    if (x->req == NULL) {
        return sgn_fail(x, "gsi sign: cannot parse request");
    }
    return 0;
}

/* Enforce that the request subject is exactly '<signer subject>/CN=<serial>'
 * and extract the serial. 0 on success; -1 via sgn_fail on error. */
static int
sgn_check_subject(sgn_ctx *x, long *serial)
{
    char    sname[1024], rname[1024];
    size_t  slen;
    char   *endp;

    if (X509_NAME_oneline(X509_get_subject_name(x->signer), sname,
                          sizeof(sname)) == NULL
        || X509_NAME_oneline(X509_REQ_get_subject_name(x->req), rname,
                             sizeof(rname)) == NULL) {
        return sgn_fail(x, "gsi sign: subject undefined");
    }
    slen = strlen(sname);
    if (strncmp(rname, sname, slen) != 0
        || strncmp(rname + slen, "/CN=", 4) != 0) {
        return sgn_fail(x,
                        "gsi sign: request subject not '<signer>/CN=<serial>'");
    }
    *serial = strtol(rname + slen + 4, &endp, 10);
    if (endp == rname + slen + 4 || *endp != '\0' || *serial < 0) {
        return sgn_fail(x, "gsi sign: bad serial in request CN");
    }
    return 0;
}

/* The signer must not be expired; *timeleft gets its remaining lifetime in
 * seconds (the proxy inherits it). 0 on success; -1 via sgn_fail on error. */
static int
sgn_check_signer_validity(sgn_ctx *x, int *timeleft)
{
    int days = 0, secs = 0;

    /* seconds left = diff(now, signer notAfter) */
    if (ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(x->signer)) != 1) {
        return sgn_fail(x, "gsi sign: cannot read signer expiry");
    }
    *timeleft = days * 86400 + secs;
    if (*timeleft <= 0) {
        return sgn_fail(x, "gsi sign: signer certificate expired");
    }
    return 0;
}

/* Verify the request's self-signature (leaves the pubkey in x->reqpub for the
 * proxy build). 0 on success; -1 via sgn_fail on error. */
static int
sgn_verify_req_signature(sgn_ctx *x)
{
    x->reqpub = X509_REQ_get_pubkey(x->req);
    if (x->reqpub == NULL || X509_REQ_verify(x->req, x->reqpub) != 1) {
        return sgn_fail(x, "gsi sign: request self-signature invalid");
    }
    return 0;
}

/* Build the skeleton proxy cert in x->proxy: version 3, serial from the CN,
 * subject from the request, issuer = signer, request pubkey, validity
 * [now, now+timeleft]. 0 on success; -1 via sgn_fail on error. */
static int
sgn_populate_proxy(sgn_ctx *x, long serial, int timeleft)
{
    x->proxy = X509_new();
    if (x->proxy == NULL
        || X509_set_version(x->proxy, 2L) != 1
        || ASN1_INTEGER_set(X509_get_serialNumber(x->proxy),
                            (long) serial) != 1
        || X509_set_subject_name(x->proxy,
                                 X509_REQ_get_subject_name(x->req)) != 1
        || X509_set_issuer_name(x->proxy, X509_get_subject_name(x->signer)) != 1
        || X509_set_pubkey(x->proxy, x->reqpub) != 1
        || X509_gmtime_adj(X509_getm_notBefore(x->proxy), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x->proxy), timeleft) == NULL) {
        return sgn_fail(x, "gsi sign: cannot populate proxy");
    }
    return 0;
}

/* Copy the signer's extensions into the proxy (keyUsage required, SAN
 * rejected) and add a fresh critical proxyCertInfo whose path length is the
 * RFC-3820 monotonic min(request, signer-1) — pxr_make_pci_ext decrements
 * once more. 0 on success; -1 via sgn_fail on error. */
static int
sgn_add_extensions(sgn_ctx *x)
{
    int indepth, reqdepth, outdepth, haskeyusage;

    if (sgn_copy_signer_exts(x->signer, x->proxy, &indepth, &haskeyusage) != 0) {
        return sgn_fail(x,
                        "gsi sign: bad signer extensions (SAN, or copy failed)");
    }
    if (!haskeyusage) {
        return sgn_fail(x, "gsi sign: signer lacks keyUsage");
    }

    /* Path-length: min(req, signer-1); the helper decrements once more. */
    reqdepth = pxr_req_pathlen(x->req);
    outdepth = (reqdepth < indepth) ? reqdepth : (indepth - 1);
    x->pciext = pxr_make_pci_ext(outdepth);
    if (x->pciext == NULL || X509_add_ext(x->proxy, x->pciext, -1) == 0) {
        return sgn_fail(x, "gsi sign: cannot add proxyCertInfo");
    }
    return 0;
}

/* PEM-export the signed proxy into a malloc'd NUL-terminated buffer for the
 * caller. 0 on success; -1 via sgn_fail on error. */
static int
sgn_export_pem(sgn_ctx *x, uint8_t **proxy_pem, size_t *proxy_len)
{
    char *pem = NULL;
    long  pemlen;

    x->obio = BIO_new(BIO_s_mem());
    if (x->obio == NULL || PEM_write_bio_X509(x->obio, x->proxy) != 1) {
        return sgn_fail(x, "gsi sign: PEM export failed");
    }
    pemlen = BIO_get_mem_data(x->obio, &pem);
    *proxy_pem = malloc((size_t) pemlen + 1);
    if (*proxy_pem == NULL) {
        return sgn_fail(x, "gsi sign: out of memory");
    }
    memcpy(*proxy_pem, pem, (size_t) pemlen);
    (*proxy_pem)[pemlen] = '\0';
    *proxy_len = (size_t) pemlen;
    return 0;
}

/* Non-NULL shape check for the issuance entry point (inputs present and the
 * output slot supplied). 1 = usable, 0 = reject as bad arguments. */
static int
sgn_args_ok(const brix_gsi_blob_t *signer_pem, EVP_PKEY *signer_key,
            const brix_gsi_blob_t *req_der, const brix_gsi_buf_t *proxy_pem)
{
    return signer_pem != NULL && signer_pem->data != NULL
        && signer_key != NULL && req_der != NULL && req_der->data != NULL
        && proxy_pem != NULL;
}

int
brix_gsi_sign_pxyreq(const brix_gsi_blob_t *signer_pem, EVP_PKEY *signer_key,
                       const brix_gsi_blob_t *req_der,
                       brix_gsi_buf_t *proxy_pem, const brix_gsi_err_t *err)
{
    sgn_ctx x;
    long    serial = 0;
    int     timeleft = 0;

    memset(&x, 0, sizeof(x));
    if (err != NULL) {
        x.err    = err->buf;
        x.errcap = err->cap;
    }
    if (!sgn_args_ok(signer_pem, signer_key, req_der, proxy_pem)) {
        return sgn_fail(&x, "gsi sign: bad arguments");
    }

    if (sgn_parse_inputs(&x, signer_pem->data, signer_pem->len,
                         req_der->data, req_der->len) != 0
        || sgn_check_subject(&x, &serial) != 0
        || sgn_check_signer_validity(&x, &timeleft) != 0
        || sgn_verify_req_signature(&x) != 0
        || sgn_populate_proxy(&x, serial, timeleft) != 0
        || sgn_add_extensions(&x) != 0) {
        return -1;                      /* helpers already freed via sgn_fail */
    }

    /* Sign with the issuer's key. */
    if (X509_sign(x.proxy, signer_key, EVP_sha256()) <= 0) {
        return sgn_fail(&x, "gsi sign: signing failed");
    }

    if (sgn_export_pem(&x, &proxy_pem->data, &proxy_pem->len) != 0) {
        return -1;
    }
    (void) sgn_fail(&x, NULL);
    return 0;
}


/* File-local argument pack for the assemble helpers: the two input PEM blobs
 * plus the caller's error buffer (keeps every helper at <=5 parameters). */
typedef struct {
    const uint8_t *proxy_pem;
    size_t         proxy_pem_len;
    const uint8_t *chain_pem;
    size_t         chain_pem_len;
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

/* Concatenate proxy (leaf) + signer chain into one malloc'd NUL-terminated
 * PEM blob. proxy_pem_len is wire-supplied (client-sent kXGC_sigpxy) so the
 * length additions are overflow-guarded. 0 on success; -1 with a->err set. */
static int
asm_concat_pem(const asm_args *a, uint8_t **out_pem, size_t *out_len)
{
    size_t   total, need;
    uint8_t *out;

    if (brix_size_add(a->proxy_pem_len, a->chain_pem_len, &total) != NGX_OK
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
    a.err           = ebuf;
    a.errcap        = ecap;

    /* The signed proxy's public key MUST match the request key we generated. */
    if (asm_check_key_match(&a, reqkey) != 0) {
        return -1;
    }

    /* Delegated credential chain PEM = proxy (leaf) followed by the signer
     * chain. */
    return asm_concat_pem(&a, &out_pem->data, &out_pem->len);
}
