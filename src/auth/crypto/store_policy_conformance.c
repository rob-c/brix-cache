/*
 * store_policy_conformance.c — RFC 3820 proxy classification + delegation
 * monotonicity and the per-certificate WLCG/IGTF conformance policy.
 *
 * Split verbatim out of store_policy.c (see store_policy.h for the contract).
 * Depends only on OpenSSL + libc; no ngx symbols.
 */
#include "auth/crypto/store_policy.h"
#include "store_policy_internal.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* -- proxy classification + monotonicity ---------------------------------- */

/* Globus limited-proxy policy language OID: 1.3.6.1.4.1.3536.1.1.1.9. */
static const char *BRIX_PX_LIMITED_OID = "1.3.6.1.4.1.3536.1.1.1.9";

brix_px_kind_t
brix_px_classify(X509 *cert)
{
    PROXY_CERT_INFO_EXTENSION *pci;
    brix_px_kind_t             kind = BRIX_PX_NONE;

    if (X509_get_extension_flags(cert) & EXFLAG_PROXY) {
        kind = BRIX_PX_FULL;
        pci = X509_get_ext_d2i(cert, NID_proxyCertInfo, NULL, NULL);
        if (pci != NULL) {
            char oid[128];
            int  n = OBJ_obj2txt(oid, sizeof(oid),
                                 pci->proxyPolicy->policyLanguage, 1);
            if (n > 0 && strcmp(oid, BRIX_PX_LIMITED_OID) == 0) {
                kind = BRIX_PX_LIMITED;
            }
            PROXY_CERT_INFO_EXTENSION_free(pci);
        }
        return kind;
    }

    /* Legacy Globus proxy: last RDN is CN=proxy or CN=limited proxy. */
    {
        X509_NAME *nm = X509_get_subject_name(cert);
        int        last = X509_NAME_entry_count(nm) - 1;
        if (last >= 0) {
            X509_NAME_ENTRY     *e = X509_NAME_get_entry(nm, last);
            ASN1_STRING         *v = X509_NAME_ENTRY_get_data(e);
            const unsigned char *s = ASN1_STRING_get0_data(v);
            int                  len = ASN1_STRING_length(v);
            if (len == (int) sizeof("limited proxy") - 1
                && strncasecmp((const char *) s, "limited proxy", len) == 0)
            {
                return BRIX_PX_LIMITED;
            }
            if (len == (int) sizeof("proxy") - 1
                && strncasecmp((const char *) s, "proxy", len) == 0)
            {
                return BRIX_PX_FULL;
            }
        }
    }
    return BRIX_PX_NONE;
}

int
brix_proxy_chain_ok(STACK_OF(X509) *chain)
{
    int n, i;
    int seen_limited = 0;

    if (chain == NULL) {
        return 1;
    }

    n = sk_X509_num(chain);
    for (i = n - 1; i >= 0; i--) {   /* root .. leaf */
        brix_px_kind_t kind = brix_px_classify(sk_X509_value(chain, i));

        if (kind == BRIX_PX_LIMITED) {
            seen_limited = 1;
        } else if (kind == BRIX_PX_FULL && seen_limited) {
            return 0;   /* full proxy beneath a limited one — escalation */
        }
    }
    return 1;
}

/* -- per-cert conformance policy ------------------------------------------ */

/* Recognised RFC 3820 / Globus proxy policy-language OIDs. */
static const char *BRIX_PX_OID_IMPERSONATION = "1.3.6.1.5.5.7.21.1";
static const char *BRIX_PX_OID_INDEPENDENT   = "1.3.6.1.5.5.7.21.2";
/* BRIX_PX_LIMITED_OID (Globus limited) is defined above. */

static int
brix_dn_has_control_bytes(X509_NAME *nm)
{
    int i, n = X509_NAME_entry_count(nm);
    for (i = 0; i < n; i++) {
        X509_NAME_ENTRY     *e = X509_NAME_get_entry(nm, i);
        ASN1_STRING         *v = X509_NAME_ENTRY_get_data(e);
        const unsigned char *s = ASN1_STRING_get0_data(v);
        int                  len = ASN1_STRING_length(v);
        int                  j;
        for (j = 0; j < len; j++) {
            if (s[j] < 0x20 || s[j] == 0x7f) {
                return 1;   /* embedded control or NUL byte */
            }
        }
    }
    return 0;
}

/*
 * WHAT: reject a public key weaker than the IGTF floor (RSA/DSA >= 2048 bits,
 *       EC >= 256 bits).
 * WHY:  weak keys are trivially forgeable; the floor is the same one XRootD and
 *       the IGTF profile enforce.  Unknown key types carry no verdict (0).
 * HOW:  read the key's base id + bit count once and apply the per-family floor;
 *       a cert with no extractable key is not judged here (0).
 */
static int
brix_key_strength_violation(X509 *cert)
{
    EVP_PKEY *pk = X509_get0_pubkey(cert);
    int       id;
    int       bits;

    if (pk == NULL) {
        return 0;
    }
    id = EVP_PKEY_base_id(pk);
    bits = EVP_PKEY_bits(pk);
    if ((id == EVP_PKEY_RSA || id == EVP_PKEY_RSA2 || id == EVP_PKEY_DSA)
        && bits < 2048) {
        return 1;
    }
    if (id == EVP_PKEY_EC && bits < 256) {
        return 1;
    }
    return 0;
}

/*
 * WHAT: reject a certificate signed with a broken message digest (MD2/MD4/MD5
 *       or SHA-1).
 * WHY:  collision attacks make these digests unsafe for signatures; XRootD's
 *       hardened profile refuses them too.  A signature algorithm we cannot
 *       decompose carries no verdict (0).
 * HOW:  map the signature OID to its digest NID and compare against the
 *       forbidden set.
 */
static int
brix_sig_alg_violation(X509 *cert)
{
    int sig_nid = X509_get_signature_nid(cert);
    int md_nid = NID_undef, pk_nid = NID_undef;

    if (!OBJ_find_sigid_algs(sig_nid, &md_nid, &pk_nid)) {
        return 0;
    }
    if (md_nid == NID_md5 || md_nid == NID_sha1 || md_nid == NID_md2
        || md_nid == NID_md4) {
        return 1;
    }
    return 0;
}

/*
 * WHAT: reject a serial number that is zero, negative, or (for a non-proxy)
 *       longer than 20 octets (RFC 5280 §4.1.2.2).
 * WHY:  a non-positive serial is malformed; the 20-octet ceiling is the RFC
 *       cap.  Proxies are exempt from the ceiling because grid proxies derive
 *       large serials.  A serial we cannot parse carries no verdict (0).
 * HOW:  convert the serial to a BIGNUM, test the three conditions, free.
 */
static int
brix_serial_violation(X509 *cert, int is_proxy)
{
    const ASN1_INTEGER *sn = X509_get0_serialNumber(cert);
    BIGNUM             *bn = ASN1_INTEGER_to_BN(sn, NULL);
    int                 bad;

    if (bn == NULL) {
        return 0;
    }
    bad = BN_is_zero(bn) || BN_is_negative(bn)
          || (!is_proxy && BN_num_bytes(bn) > 20);
    BN_free(bn);
    return bad ? 1 : 0;
}

int
brix_cert_policy_violation(X509 *cert)
{
    int is_proxy = (X509_get_extension_flags(cert) & EXFLAG_PROXY) != 0;

    /* Key strength (IGTF: RSA >= 2048, EC >= 256). */
    if (brix_key_strength_violation(cert)) {
        return 1;
    }

    /* Signature algorithm: reject MD5 and SHA-1 based signatures. */
    if (brix_sig_alg_violation(cert)) {
        return 1;
    }

    /* Serial number: positive and <= 20 octets (RFC 5280 §4.1.2.2).  Proxies
     * are exempt from the ceiling — grid proxies use large derived serials. */
    if (brix_serial_violation(cert, is_proxy)) {
        return 1;
    }

    /* DN sanity: no embedded control/NUL bytes (RFC 5280 §4.1.2.6). */
    if (brix_dn_has_control_bytes(X509_get_subject_name(cert))
        || brix_dn_has_control_bytes(X509_get_issuer_name(cert))) {
        return 1;
    }

    return 0;
}

int
brix_leaf_purpose_violation(X509 *leaf)
{
    /* extendedKeyUsage: if present, must allow client auth. */
    EXTENDED_KEY_USAGE *eku = X509_get_ext_d2i(leaf, NID_ext_key_usage, NULL,
                                               NULL);
    if (eku != NULL) {
        int i, ok = 0;
        for (i = 0; i < sk_ASN1_OBJECT_num(eku); i++) {
            int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i));
            if (nid == NID_client_auth || nid == NID_anyExtendedKeyUsage) {
                ok = 1;
                break;
            }
        }
        sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
        if (!ok) {
            return 1;
        }
    }

    /* keyUsage: if present, must assert digitalSignature (RSA/ECDSA client
     * auth) OR keyAgreement (fixed-ECDH client auth). */
    {
        uint32_t flags = X509_get_key_usage(leaf);   /* UINT32_MAX if absent */
        if (flags != UINT32_MAX
            && !(flags & (KU_DIGITAL_SIGNATURE | KU_KEY_AGREEMENT))) {
            return 1;
        }
    }
    return 0;
}

int
brix_proxy_pci_ok(STACK_OF(X509) *chain)
{
    int n, i;

    if (chain == NULL) {
        return 1;
    }
    n = sk_X509_num(chain);
    for (i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);
        int   loc = X509_get_ext_by_NID(cert, NID_proxyCertInfo, -1);
        X509_EXTENSION *ext;
        PROXY_CERT_INFO_EXTENSION *pci;
        char oid[128];
        int  ok_oid;

        if (loc < 0) {
            continue;   /* no proxyCertInfo — legacy/EEC handled elsewhere */
        }
        ext = X509_get_ext(cert, loc);
        if (!X509_EXTENSION_get_critical(ext)) {
            return 0;   /* proxyCertInfo present but not critical (RFC 3820 §3.1) */
        }
        pci = X509_get_ext_d2i(cert, NID_proxyCertInfo, NULL, NULL);
        if (pci == NULL) {
            return 0;   /* malformed proxyCertInfo */
        }
        oid[0] = '\0';
        OBJ_obj2txt(oid, sizeof(oid), pci->proxyPolicy->policyLanguage, 1);
        PROXY_CERT_INFO_EXTENSION_free(pci);
        ok_oid = (strcmp(oid, BRIX_PX_OID_IMPERSONATION) == 0)
                 || (strcmp(oid, BRIX_PX_OID_INDEPENDENT) == 0)
                 || (strcmp(oid, BRIX_PX_LIMITED_OID) == 0);
        if (!ok_oid) {
            return 0;   /* unrecognised proxy policy language (RFC 3820 §3.2) */
        }
    }
    return 1;
}
