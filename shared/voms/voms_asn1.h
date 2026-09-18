/*
 * shared/voms/voms_asn1.h — ASN.1 structures of a VOMS attribute certificate
 *
 * WHAT: RFC 5755 AttributeCertificate (v2) and the VOMS-specific values it
 *       carries, as OpenSSL ASN.1 templates: the decoder is d2i_*, generated
 *       by voms_asn1.c, and validates DER structure strictly.
 * WHY:  OpenSSL grew X509_ACERT only in 3.4; the project floor is 3.0, so the
 *       library carries its own templates (the same shapes libvoms defines).
 * HOW:  RFC 5755 module semantics are IMPLICIT TAGS: [0] on the holder's
 *       baseCertificateID and on v2Form replace the SEQUENCE tag.
 *       Private to shared/voms/.
 */

#ifndef BRIX_SHARED_VOMS_ASN1_H
#define BRIX_SHARED_VOMS_ASN1_H

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* ObjectDigestInfo ::= SEQUENCE { digestedObjectType ENUMERATED,
 *   otherObjectTypeID OBJECT IDENTIFIER OPTIONAL,
 *   digestAlgorithm AlgorithmIdentifier, objectDigest BIT STRING } */
typedef struct {
    ASN1_ENUMERATED *digested_object_type;
    ASN1_OBJECT     *other_object_type_id;
    X509_ALGOR      *digest_algorithm;
    ASN1_BIT_STRING *object_digest;
} VOMS_OBJECT_DIGEST_INFO;

/* IssuerSerial ::= SEQUENCE { issuer GeneralNames, serial INTEGER,
 *   issuerUID BIT STRING OPTIONAL } */
typedef struct {
    GENERAL_NAMES   *issuer;
    ASN1_INTEGER    *serial;
    ASN1_BIT_STRING *issuer_uid;
} VOMS_ISSUER_SERIAL;

/* Holder ::= SEQUENCE { baseCertificateID [0] IssuerSerial OPTIONAL,
 *   entityName [1] GeneralNames OPTIONAL,
 *   objectDigestInfo [2] ObjectDigestInfo OPTIONAL } */
typedef struct {
    VOMS_ISSUER_SERIAL      *base_certificate_id;
    GENERAL_NAMES           *entity_name;
    VOMS_OBJECT_DIGEST_INFO *object_digest_info;
} VOMS_HOLDER;

/* V2Form ::= SEQUENCE { issuerName GeneralNames OPTIONAL,
 *   baseCertificateID [0] IssuerSerial OPTIONAL,
 *   objectDigestInfo [1] ObjectDigestInfo OPTIONAL } */
typedef struct {
    GENERAL_NAMES           *issuer_name;
    VOMS_ISSUER_SERIAL      *base_certificate_id;
    VOMS_OBJECT_DIGEST_INFO *object_digest_info;
} VOMS_V2FORM;

/* AttCertIssuer ::= CHOICE { v1Form GeneralNames, v2Form [0] V2Form } */
typedef struct {
    int type;
    union {
        GENERAL_NAMES *v1form;
        VOMS_V2FORM   *v2form;
    } d;
} VOMS_ATTCERT_ISSUER;

#define VOMS_ISSUER_V1FORM 0
#define VOMS_ISSUER_V2FORM 1

/* AttCertValidityPeriod ::= SEQUENCE { notBeforeTime GeneralizedTime,
 *   notAfterTime GeneralizedTime } */
typedef struct {
    ASN1_GENERALIZEDTIME *not_before;
    ASN1_GENERALIZEDTIME *not_after;
} VOMS_VALIDITY;

/* AttributeCertificateInfo ::= SEQUENCE { version INTEGER, holder Holder,
 *   issuer AttCertIssuer, signature AlgorithmIdentifier, serialNumber INTEGER,
 *   attrCertValidityPeriod, attributes SEQUENCE OF Attribute,
 *   issuerUniqueID BIT STRING OPTIONAL, extensions Extensions OPTIONAL }
 * `enc` keeps the original DER so the signature is checked over the bytes
 * the VOMS server signed, never over a re-encoding. */
typedef struct {
    ASN1_INTEGER               *version;
    VOMS_HOLDER                *holder;
    VOMS_ATTCERT_ISSUER        *issuer;
    X509_ALGOR                 *signature;
    ASN1_INTEGER               *serial;
    VOMS_VALIDITY              *validity;
    STACK_OF(X509_ATTRIBUTE)   *attributes;
    ASN1_BIT_STRING            *issuer_uid;
    STACK_OF(X509_EXTENSION)   *extensions;
    ASN1_ENCODING               enc;
} VOMS_AC_INFO;

/* AttributeCertificate ::= SEQUENCE { acinfo, signatureAlgorithm, signatureValue BIT STRING } */
typedef struct {
    VOMS_AC_INFO    *acinfo;
    X509_ALGOR      *sig_alg;
    ASN1_BIT_STRING *signature;
} VOMS_AC;

DEFINE_STACK_OF(VOMS_AC)

/* AC_SEQ ::= SEQUENCE OF AttributeCertificate — the VOMS extension value. */
typedef struct {
    STACK_OF(VOMS_AC) *acs;
} VOMS_AC_SEQ;

/* IetfAttrSyntax ::= SEQUENCE { policyAuthority [0] GeneralNames OPTIONAL,
 *   values SEQUENCE OF CHOICE { octets OCTET STRING, oid OBJECT IDENTIFIER,
 *   string UTF8String } } — the FQAN attribute value. */
typedef struct {
    int type;
    union {
        ASN1_OCTET_STRING *octets;
        ASN1_OBJECT       *oid;
        ASN1_UTF8STRING   *string;
    } d;
} VOMS_IETF_ATTR_VALUE;

#define VOMS_IETF_VALUE_OCTETS 0
#define VOMS_IETF_VALUE_OID    1
#define VOMS_IETF_VALUE_STRING 2

DEFINE_STACK_OF(VOMS_IETF_ATTR_VALUE)

typedef struct {
    GENERAL_NAMES                   *policy_authority;
    STACK_OF(VOMS_IETF_ATTR_VALUE)  *values;
} VOMS_IETF_ATTR;

/* The certs extension value, as libvoms encodes it:
 *   SEQUENCE { SEQUENCE OF Certificate }   (the signer first, then its chain) */
typedef struct {
    STACK_OF(X509) *certs;
} VOMS_CERTS;

/* Generic attributes: SEQUENCE OF { grantor GeneralNames,
 *   attributes SEQUENCE OF { name, qualifier, value OCTET STRING } } */
typedef struct {
    ASN1_OCTET_STRING *name;
    ASN1_OCTET_STRING *qualifier;
    ASN1_OCTET_STRING *value;
} VOMS_GENERIC_ATTR;

DEFINE_STACK_OF(VOMS_GENERIC_ATTR)

typedef struct {
    GENERAL_NAMES               *grantor;
    STACK_OF(VOMS_GENERIC_ATTR) *attributes;
} VOMS_ATTR_HOLDER;

DEFINE_STACK_OF(VOMS_ATTR_HOLDER)

typedef struct {
    STACK_OF(VOMS_ATTR_HOLDER) *providers;
} VOMS_FULL_ATTRIBUTES;

/* Target ::= CHOICE { targetName [0] GeneralName, targetGroup [1] GeneralName,
 *   targetCert [2] ... } ; the extension value is SEQUENCE { SEQUENCE OF Target }
 *   as libvoms encodes it. targetCert is not decoded (VOMS never emits it);
 *   such a target simply never matches. */
typedef struct {
    int type;
    union {
        GENERAL_NAME *name;
        GENERAL_NAME *group;
        ASN1_SEQUENCE_ANY *cert;
    } d;
} VOMS_TARGET;

DEFINE_STACK_OF(VOMS_TARGET)

typedef struct {
    STACK_OF(VOMS_TARGET) *targets;
} VOMS_TARGETS;

DECLARE_ASN1_FUNCTIONS(VOMS_AC_INFO)
DECLARE_ASN1_FUNCTIONS(VOMS_AC)
DECLARE_ASN1_FUNCTIONS(VOMS_AC_SEQ)
DECLARE_ASN1_FUNCTIONS(VOMS_IETF_ATTR)
DECLARE_ASN1_FUNCTIONS(VOMS_CERTS)
DECLARE_ASN1_FUNCTIONS(VOMS_FULL_ATTRIBUTES)
DECLARE_ASN1_FUNCTIONS(VOMS_TARGETS)

/* Decode one extension value (an OCTET STRING's contents) as the given item. */
VOMS_CERTS *voms_ext_certs(X509_EXTENSION *ext);
VOMS_FULL_ATTRIBUTES *voms_ext_attributes(X509_EXTENSION *ext);
VOMS_TARGETS *voms_ext_targets(X509_EXTENSION *ext);

/* The X509_EXTENSION of `acinfo` whose type is the dotted `oid`, or NULL. */
X509_EXTENSION *voms_acinfo_extension(const VOMS_AC_INFO *acinfo, const char *oid);

#endif /* BRIX_SHARED_VOMS_ASN1_H */
