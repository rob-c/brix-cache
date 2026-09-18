/*
 * shared/voms/voms_ac.h — native VOMS attribute-certificate decoder and verifier
 *
 * WHAT: Decodes the VOMS extension (OID 1.3.6.1.4.1.8005.100.100.5) of an
 *       X.509 proxy into per-VO entries (VO name, server URI, FQANs, generic
 *       attributes, validity, issuer DNs) and verifies every entry the way
 *       libvomsapi did: holder binding to the end-entity certificate, validity
 *       window, AC signature by the embedded VOMS server certificate, issuer
 *       name match, the server certificate's chain against a trust store, and
 *       the vomsdir/<vo>/<host>.lsc (or legacy certificate) match.
 * WHY:  The project must not depend on the HEP-specific VOMS library: this is
 *       plain C over OpenSSL (>= 3.0), shared by the nginx module and the native
 *       client. RFC 5755 attribute certificates, VOMS extensions as encoded by
 *       voms-proxy-init and libvoms.
 * HOW:  OpenSSL ASN.1 templates (voms_asn1.c) give a strict DER decoder; the
 *       verifier works on the decoded structures and reports one typed error
 *       per failure. Nothing here logs or allocates from nginx pools.
 *
 * Every function is safe to call from any thread with distinct arguments.
 */

#ifndef BRIX_SHARED_VOMS_AC_H
#define BRIX_SHARED_VOMS_AC_H

#include <stddef.h>
#include <time.h>
#include <openssl/x509.h>

/* The VOMS extension carrying the attribute certificates (AC_SEQ). */
#define BRIX_VOMS_OID_ACSEQ      "1.3.6.1.4.1.8005.100.100.5"
/* The attribute type whose values are the FQANs. */
#define BRIX_VOMS_OID_FQAN       "1.3.6.1.4.1.8005.100.100.4"
/* AC extension: the VOMS server certificate chain (SEQUENCE OF SEQUENCE OF Certificate). */
#define BRIX_VOMS_OID_CERTS      "1.3.6.1.4.1.8005.100.100.10"
/* AC extension: generic attributes (name/qualifier/value triples per grantor). */
#define BRIX_VOMS_OID_ATTRIBUTES "1.3.6.1.4.1.8005.100.100.11"

#define BRIX_VOMS_MAX_VO      128
#define BRIX_VOMS_MAX_URI     256
#define BRIX_VOMS_MAX_DN      512
#define BRIX_VOMS_MAX_FQAN    512
#define BRIX_VOMS_MAX_ENTRIES 32
#define BRIX_VOMS_MAX_FQANS   256

typedef enum {
    BRIX_VOMS_OK = 0,
    BRIX_VOMS_ERR_NOEXT,        /* no VOMS extension in the chain */
    BRIX_VOMS_ERR_DECODE,       /* the extension is not a valid AC_SEQ */
    BRIX_VOMS_ERR_VERSION,      /* an AC is not version 2 */
    BRIX_VOMS_ERR_HOLDER,       /* holder does not name the end-entity certificate */
    BRIX_VOMS_ERR_NOTYET,       /* AC validity has not started */
    BRIX_VOMS_ERR_EXPIRED,      /* AC validity has ended */
    BRIX_VOMS_ERR_NOSIGNER,     /* no VOMS server certificate to verify with */
    BRIX_VOMS_ERR_SIGALG,       /* signature algorithm rejected (MD5 class, or inner != outer) */
    BRIX_VOMS_ERR_SIGNATURE,    /* signature does not verify */
    BRIX_VOMS_ERR_ISSUER,       /* AC issuer name is not the signer certificate's subject */
    BRIX_VOMS_ERR_UNTRUSTED,    /* signer chain fails the trust store */
    BRIX_VOMS_ERR_LSC,          /* vomsdir has no matching LSC or certificate for the VO */
    BRIX_VOMS_ERR_TARGET,       /* AC targets exclude this host */
    BRIX_VOMS_ERR_EXTENSION,    /* an unknown extension is marked critical */
    BRIX_VOMS_ERR_ATTRS,        /* no usable FQAN attribute */
    BRIX_VOMS_ERR_NOMEM,
    BRIX_VOMS_ERR_ARGS
} brix_voms_status_t;

/* One generic (non-FQAN) attribute: name, value and qualifier, NUL-terminated. */
typedef struct {
    char *name;
    char *value;
    char *qualifier;
} brix_voms_attr_t;

/* One attribute certificate: one VO. Strings are NUL-terminated; DNs are in
 * the OpenSSL one-line form (/DC=ch/DC=cern/...) matching LSC files. */
typedef struct {
    char               vo[BRIX_VOMS_MAX_VO];
    char               uri[BRIX_VOMS_MAX_URI];
    char               issuer_dn[BRIX_VOMS_MAX_DN];     /* AC issuer / signer subject */
    char               issuer_ca_dn[BRIX_VOMS_MAX_DN];  /* signer's issuer, "" when unknown */
    char               holder_dn[BRIX_VOMS_MAX_DN];     /* holder baseCertificateID issuer */
    time_t             not_before;
    time_t             not_after;
    char             **fqans;
    int                nfqans;
    brix_voms_attr_t  *attrs;
    int                nattrs;
    char               digest[32];   /* signature digest, e.g. "sha256" (after verify) */
    int                carrier;      /* index of the certificate carrying the AC:
                                        0 = leaf, i+1 = chain[i] (brix_voms_retrieve) */
    brix_voms_status_t verdict;   /* per-entry result of brix_voms_verify */
    void              *ac;        /* decoded VOMS_AC (private to the library) */
} brix_voms_entry_t;

typedef struct {
    brix_voms_entry_t *entries;
    int                n;
    void             **seqs;      /* decoded VOMS_AC_SEQ objects (private) */
    int                nseqs;
} brix_voms_result_t;

/* Trust inputs for brix_voms_verify. `store` is optional: NULL skips the chain
 * check (the caller accepts an unverified signer — client diagnostics only).
 * `vomsdir` is optional the same way. `now` of 0 means time(NULL). */
typedef struct {
    X509_STORE *store;
    const char *vomsdir;
    time_t      now;
    int         skew_seconds;   /* tolerance for a notBefore in the near future */
} brix_voms_trust_t;

/**
 * Locate the VOMS extension. Searches `leaf` first, then every certificate of
 * `chain` (leaf-first order). *holder receives the certificate that carries
 * it and der and len its DER value (borrowed; valid while the certificate is).
 * @return BRIX_VOMS_OK or BRIX_VOMS_ERR_NOEXT
 */
brix_voms_status_t brix_voms_find_extension(X509 *leaf, STACK_OF(X509) *chain,
    X509 **holder, const unsigned char **der, int *len);

/**
 * The certificate at `index` of the leaf-first sequence (0 = leaf, i+1 =
 * chain[i]) when it carries the VOMS extension; NULL otherwise or past the
 * end (index >= 1 + chain length). Lets a caller walk every carrier.
 */
X509 *brix_voms_carrier_at(X509 *leaf, STACK_OF(X509) *chain, int index,
    const unsigned char **der, int *len);

/**
 * Decode an AC_SEQ DER value into a result (no verification; every entry's
 * verdict is BRIX_VOMS_OK only after brix_voms_verify). Owned by the caller:
 * brix_voms_result_free.
 */
brix_voms_status_t brix_voms_decode(const unsigned char *der, int len,
    brix_voms_result_t **out);

/**
 * Verify every entry against the certificate that carries the extension
 * (`holder`, from brix_voms_find_extension) and its chain. Each entry's
 * `verdict` records its own result; the return value is BRIX_VOMS_OK when at
 * least one entry verified, else the first failure.
 */
brix_voms_status_t brix_voms_verify(brix_voms_result_t *res, X509 *holder,
    STACK_OF(X509) *chain, const brix_voms_trust_t *trust);

/**
 * Decode and verify every AC of every certificate in the chain that carries
 * the extension (a delegated proxy keeps its parent's AC): the module's and
 * the client's entry point. `carrier` on each entry says which certificate
 * it came from. NOEXT when no certificate carries the extension.
 */
brix_voms_status_t brix_voms_retrieve(X509 *leaf, STACK_OF(X509) *chain,
    const brix_voms_trust_t *trust, brix_voms_result_t **out);

void brix_voms_result_free(brix_voms_result_t *res);

/**
 * The end-entity certificate of a proxy chain: walk the issuer links up from
 * `leaf` through every proxy (RFC 3820 proxyCertInfo, or the legacy GT2 shape
 * subject = issuer + one CN) to the first non-proxy certificate. Order of
 * `chain` does not matter. `leaf` itself when the walk finds nothing better.
 */
X509 *brix_voms_find_eec(X509 *leaf, STACK_OF(X509) *chain);

/** 1 when `cert` is a proxy certificate (RFC 3820 or legacy GT2 shape). */
int brix_voms_is_proxy(X509 *cert);

/** The parent of `cert` in `chain` (subject == cert's issuer, not cert itself), or NULL. */
X509 *brix_voms_parent(X509 *cert, STACK_OF(X509) *chain);

const char *brix_voms_strerror(brix_voms_status_t status);

/** The short token of a status: "ok", "noext", "decode", ... "attrs". */
const char *brix_voms_status_name(brix_voms_status_t status);

/** "/DC=..." one-line rendering into buf; returns buf (empty on failure). */
char *brix_voms_dn_oneline(const X509_NAME *name, char *buf, size_t cap);

#endif /* BRIX_SHARED_VOMS_AC_H */
