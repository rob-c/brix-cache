/* File: proxy_req_sign.c — RFC-3820 GSI proxy issuance/signing (phase-57 §F6)
 * WHAT: brix_gsi_sign_pxyreq() ISSUES a proxy certificate: given the delegating
 *   client's signer EEC/proxy (PEM) + private key and a DER X509_REQ produced by
 *   brix_gsi_build_pxyreq(), it validates the request, builds an X.509 v3 proxy
 *   (serial = request CN, subject = request subject, issuer = signer, request
 *   pubkey, validity = signer's remaining lifetime, keyUsage inherited, critical
 *   proxyCertInfo with the RFC-3820 monotonic path length) and self-signs it with
 *   the signer key (SHA-256), returning the malloc'd proxy PEM.
 *
 * WHY: This is the delegating client's half of F6 multi-hop delegation — the
 *   kXGC_sigpxy step that turns the server's request into a usable proxy. Split
 *   out of proxy_req.c (phase-79 file-size guard) as one cohesive unit; the
 *   request build stays in proxy_req.c and the delegated-chain assembly lives in
 *   proxy_req_assemble.c. Ported faithfully from stock XrdSecgsi
 *   XrdCrypto/XrdCryptosslgsiAux.cc::XrdCryptosslX509SignProxyReq.
 *
 * HOW: parse signer PEM + request DER → subject must be '<signer>/CN=<serial>' →
 *   signer must be unexpired (proxy inherits its remaining lifetime) → verify the
 *   request self-signature → populate the v3 proxy skeleton → copy the signer's
 *   non-SAN/non-pci extensions (keyUsage required, SAN rejected) and add a fresh
 *   critical proxyCertInfo whose path length is min(request, signer-1) → X509_sign
 *   → PEM export. No goto: a single NULL-safe cleanup (sgn_fail) frees everything
 *   not handed to the caller. The shared proxyCertInfo builder pxr_make_pci_ext()
 *   and the GSI OID constants come from proxy_req_internal.h. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>

#include "proxy_req_internal.h"

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
