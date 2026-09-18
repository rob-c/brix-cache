/*
 * shared/voms/voms_verify.c — verify decoded VOMS attribute certificates
 *
 * WHAT: brix_voms_verify and brix_voms_retrieve of voms_ac.h.
 * WHY:  An AC is a signed claim by a VOMS server about the holder of a
 *       certificate; every check libvomsapi made is made here, in this order:
 *         1. version 2;
 *         2. holder binding: baseCertificateID names the end-entity
 *            certificate (its subject — the proxy's issuer — or its issuer)
 *            and carries its serial number;
 *         3. validity window (a small skew for notBefore only);
 *         4. a VOMS server certificate is embedded (certs extension);
 *         5. signature algorithm: inner equals outer, no MD2/MD4/MD5;
 *         6. the signature verifies over the original TBS bytes;
 *         7. the AC issuer name is the server certificate's subject;
 *         8. AC targets, when present, include this host;
 *         9. the server certificate chains to the trust store (CRL and
 *            signing-policy rules are whatever the store carries);
 *        10. vomsdir/<vo>/<host>.lsc (or a legacy certificate copy) names it.
 * HOW:  Pure functions over the decoded structures; the first failing check
 *       is the entry's verdict.
 */

#include "voms_ac.h"
#include "voms_asn1.h"
#include "voms_lsc.h"

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>

/* --- 2. holder ------------------------------------------------------------ */

/* Does the holder's baseCertificateID name `cert` (its subject or issuer
 * name, and its serial)? X509_NAME_cmp works on the canonical form, so a
 * UTF8String and a PrintableString spelling of one DN compare equal. */
static int
voms_holder_names(const VOMS_ISSUER_SERIAL *id, X509 *cert)
{
    GENERAL_NAME *gn;

    if (sk_GENERAL_NAME_num(id->issuer) != 1) {
        return 0;
    }
    gn = sk_GENERAL_NAME_value(id->issuer, 0);
    if (gn->type != GEN_DIRNAME) {
        return 0;
    }
    if (X509_NAME_cmp(gn->d.directoryName, X509_get_subject_name(cert)) != 0
        && X509_NAME_cmp(gn->d.directoryName, X509_get_issuer_name(cert)) != 0)
    {
        return 0;
    }
    return ASN1_INTEGER_cmp(id->serial, X509_get0_serialNumber(cert)) == 0;
}

/* The holder must name a certificate on the proxy path from the carrier up to
 * the end-entity certificate (VOMS names the EEC; every proxy in between is
 * the same identity). Never a CA. */
static brix_voms_status_t
voms_check_holder(const VOMS_AC_INFO *info, X509 *carrier, STACK_OF(X509) *chain)
{
    const VOMS_ISSUER_SERIAL *id = info->holder->base_certificate_id;
    X509                     *cur = carrier;
    int                       hops, limit = 1 + (chain ? sk_X509_num(chain) : 0);

    if (id == NULL) {
        return BRIX_VOMS_ERR_HOLDER;   /* entityName / objectDigestInfo holders: not VOMS */
    }
    for (hops = 0; cur != NULL && hops <= limit; hops++) {
        if (voms_holder_names(id, cur)) {
            return BRIX_VOMS_OK;
        }
        if (!brix_voms_is_proxy(cur)) {
            break;   /* reached the EEC without a match */
        }
        cur = brix_voms_parent(cur, chain);
    }
    return BRIX_VOMS_ERR_HOLDER;
}

/* --- 3. validity ---------------------------------------------------------- */

static brix_voms_status_t
voms_check_validity(const VOMS_AC_INFO *info, time_t now, int skew)
{
    time_t latest_start = now + skew;

    if (X509_cmp_time(info->validity->not_before, &latest_start) > 0) {
        return BRIX_VOMS_ERR_NOTYET;
    }
    if (X509_cmp_time(info->validity->not_after, &now) < 0) {
        return BRIX_VOMS_ERR_EXPIRED;
    }
    return BRIX_VOMS_OK;
}

/* --- 4. signer ------------------------------------------------------------ */

/* The embedded server chain: signer first. Caller frees the stack (certs are
 * up-referenced so the decoded extension can be released). */
static STACK_OF(X509) *
voms_signer_chain(const VOMS_AC_INFO *info)
{
    VOMS_CERTS     *certs = voms_ext_certs(voms_acinfo_extension(info, BRIX_VOMS_OID_CERTS));
    STACK_OF(X509) *chain = NULL;
    int             i;

    if (certs == NULL) {
        return NULL;
    }
    chain = sk_X509_new_null();
    for (i = 0; chain != NULL && i < sk_X509_num(certs->certs); i++) {
        X509 *c = sk_X509_value(certs->certs, i);

        if (!X509_up_ref(c) || !sk_X509_push(chain, c)) {
            X509_free(c);
            sk_X509_pop_free(chain, X509_free);
            chain = NULL;
        }
    }
    VOMS_CERTS_free(certs);
    if (chain != NULL && sk_X509_num(chain) == 0) {
        sk_X509_free(chain);
        chain = NULL;
    }
    return chain;
}

/* --- 5 & 6. signature ----------------------------------------------------- */

static brix_voms_status_t
voms_check_signature(VOMS_AC *ac, X509 *signer, char *digest, size_t digest_cap)
{
    int       sig_nid, digest_nid = NID_undef, pkey_nid = NID_undef;
    EVP_PKEY *pkey;
    int       ok;

    if (X509_ALGOR_cmp(ac->sig_alg, ac->acinfo->signature) != 0) {
        return BRIX_VOMS_ERR_SIGALG;
    }
    sig_nid = OBJ_obj2nid(ac->sig_alg->algorithm);
    if (sig_nid == NID_undef
        || !OBJ_find_sigid_algs(sig_nid, &digest_nid, &pkey_nid))
    {
        return BRIX_VOMS_ERR_SIGALG;
    }
    if (digest_nid == NID_md5 || digest_nid == NID_md4 || digest_nid == NID_md2) {
        return BRIX_VOMS_ERR_SIGALG;
    }
    /* Ed25519 and RSA-PSS report no digest nid; name the signature scheme.
     * Lower-cased so callers and tests see one stable spelling ("sha256"). */
    snprintf(digest, digest_cap, "%s",
             OBJ_nid2sn(digest_nid != NID_undef ? digest_nid : sig_nid));
    for (size_t i = 0; digest[i] != '\0'; i++) {
        digest[i] = (char) tolower((unsigned char) digest[i]);
    }
    pkey = X509_get_pubkey(signer);
    if (pkey == NULL) {
        return BRIX_VOMS_ERR_NOSIGNER;
    }
    ok = ASN1_item_verify(ASN1_ITEM_rptr(VOMS_AC_INFO), ac->sig_alg,
                          ac->signature, ac->acinfo, pkey);
    EVP_PKEY_free(pkey);
    return (ok == 1) ? BRIX_VOMS_OK : BRIX_VOMS_ERR_SIGNATURE;
}

/* --- 7. issuer ------------------------------------------------------------ */

/* The AC issuer names (v2Form issuerName, or the v1Form list). */
static const GENERAL_NAMES *
voms_issuer_names(const VOMS_AC_INFO *info)
{
    return (info->issuer->type == VOMS_ISSUER_V2FORM)
           ? info->issuer->d.v2form->issuer_name : info->issuer->d.v1form;
}

static int
voms_issuer_names_cert(const VOMS_AC_INFO *info, X509 *cert)
{
    const GENERAL_NAMES *names = voms_issuer_names(info);
    int                  i, n = names ? sk_GENERAL_NAME_num(names) : 0;

    for (i = 0; i < n; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);

        if (gn->type == GEN_DIRNAME
            && X509_NAME_cmp(gn->d.directoryName, X509_get_subject_name(cert)) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/* The embedded certificate the AC issuer name designates, moved to the front
 * of `signers`; -1 when none matches (the AC names a server it did not embed). */
static int
voms_select_signer(const VOMS_AC_INFO *info, STACK_OF(X509) *signers)
{
    int i, n = sk_X509_num(signers);

    for (i = 0; i < n; i++) {
        if (voms_issuer_names_cert(info, sk_X509_value(signers, i))) {
            if (i != 0) {
                X509 *c = sk_X509_delete(signers, i);

                sk_X509_insert(signers, c, 0);
            }
            return 0;
        }
    }
    return -1;
}

/* When the AC carries an authorityKeyIdentifier keyid and the signer a
 * subjectKeyIdentifier, they must agree. */
static brix_voms_status_t
voms_check_aki(const VOMS_AC_INFO *info, X509 *signer)
{
    X509_EXTENSION          *ext = voms_acinfo_extension(info, "2.5.29.35");
    AUTHORITY_KEYID         *akid;
    const ASN1_OCTET_STRING *ski;
    int                      same = 1;

    if (ext == NULL) {
        return BRIX_VOMS_OK;
    }
    akid = X509V3_EXT_d2i(ext);
    if (akid == NULL) {
        return BRIX_VOMS_ERR_EXTENSION;   /* an AKI that does not decode */
    }
    ski = X509_get0_subject_key_id(signer);
    if (akid->keyid != NULL && ski != NULL) {
        same = (ASN1_OCTET_STRING_cmp(akid->keyid, ski) == 0);
    }
    AUTHORITY_KEYID_free(akid);
    return same ? BRIX_VOMS_OK : BRIX_VOMS_ERR_ISSUER;
}

/* --- extensions: nothing unknown may be critical ------------------------- */

static int
voms_extension_known(const char *oid)
{
    static const char *const known[] = {
        BRIX_VOMS_OID_CERTS, BRIX_VOMS_OID_ATTRIBUTES,
        "2.5.29.35",   /* authorityKeyIdentifier */
        "2.5.29.55",   /* targetInformation */
        "2.5.29.56",   /* noRevAvail */
    };
    size_t i;

    for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (strcmp(oid, known[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static brix_voms_status_t
voms_check_extensions(const VOMS_AC_INFO *info)
{
    char txt[80];
    int  i, n = info->extensions ? sk_X509_EXTENSION_num(info->extensions) : 0;

    for (i = 0; i < n; i++) {
        X509_EXTENSION *ext = sk_X509_EXTENSION_value(info->extensions, i);

        if (!X509_EXTENSION_get_critical(ext)) {
            continue;
        }
        if (OBJ_obj2txt(txt, sizeof(txt), X509_EXTENSION_get_object(ext), 1) <= 0
            || !voms_extension_known(txt))
        {
            return BRIX_VOMS_ERR_EXTENSION;
        }
    }
    return BRIX_VOMS_OK;
}

/* --- 8. targets ----------------------------------------------------------- */

static int
voms_target_names_host(const GENERAL_NAME *gn, const char *host)
{
    const ASN1_STRING *s;

    if (gn == NULL) {
        return 0;
    }
    if (gn->type == GEN_DNS) {
        s = gn->d.dNSName;
    } else if (gn->type == GEN_URI) {
        s = gn->d.uniformResourceIdentifier;
    } else {
        return 0;
    }
    return (size_t) ASN1_STRING_length(s) == strlen(host)
           && strncasecmp((const char *) ASN1_STRING_get0_data(s), host,
                          strlen(host)) == 0;
}

static brix_voms_status_t
voms_check_targets(const VOMS_AC_INFO *info)
{
    VOMS_TARGETS *targets;
    char          host[256];
    int           i, matched = 0, seen = 0;

    targets = voms_ext_targets(voms_acinfo_extension(info, "2.5.29.55"));
    if (targets == NULL) {
        return BRIX_VOMS_OK;   /* no targets: valid everywhere */
    }
    if (gethostname(host, sizeof(host)) != 0) {
        host[0] = '\0';
    }
    host[sizeof(host) - 1] = '\0';
    for (i = 0; i < sk_VOMS_TARGET_num(targets->targets); i++) {
        VOMS_TARGET *t = sk_VOMS_TARGET_value(targets->targets, i);

        seen++;
        if (t->type == 0 && voms_target_names_host(t->d.name, host)) {
            matched++;
        }
    }
    VOMS_TARGETS_free(targets);
    return (seen == 0 || matched > 0) ? BRIX_VOMS_OK : BRIX_VOMS_ERR_TARGET;
}

/* --- 9. trust chain ------------------------------------------------------- */

static brix_voms_status_t
voms_check_chain(X509_STORE *store, X509 *signer, STACK_OF(X509) *embedded)
{
    X509_STORE_CTX *ctx;
    int             ok;

    if (store == NULL) {
        return BRIX_VOMS_OK;   /* caller opted out of the chain check */
    }
    ctx = X509_STORE_CTX_new();
    if (ctx == NULL || !X509_STORE_CTX_init(ctx, store, signer, embedded)) {
        X509_STORE_CTX_free(ctx);
        return BRIX_VOMS_ERR_NOMEM;
    }
    ok = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    return (ok == 1) ? BRIX_VOMS_OK : BRIX_VOMS_ERR_UNTRUSTED;
}

/* --- one entry ------------------------------------------------------------ */

static brix_voms_status_t
voms_verify_signed(brix_voms_entry_t *e, const brix_voms_trust_t *trust)
{
    VOMS_AC            *ac = e->ac;
    STACK_OF(X509)     *signers;
    X509               *signer;
    brix_voms_status_t  rc;

    signers = voms_signer_chain(ac->acinfo);
    if (signers == NULL) {
        return BRIX_VOMS_ERR_NOSIGNER;
    }
    if (voms_select_signer(ac->acinfo, signers) != 0) {
        sk_X509_pop_free(signers, X509_free);
        return BRIX_VOMS_ERR_ISSUER;
    }
    signer = sk_X509_value(signers, 0);
    brix_voms_dn_oneline(X509_get_issuer_name(signer), e->issuer_ca_dn,
                         sizeof(e->issuer_ca_dn));
    rc = voms_check_signature(ac, signer, e->digest, sizeof(e->digest));
    if (rc == BRIX_VOMS_OK) {
        rc = voms_check_aki(ac->acinfo, signer);
    }
    if (rc == BRIX_VOMS_OK) {
        rc = voms_check_targets(ac->acinfo);
    }
    if (rc == BRIX_VOMS_OK) {
        rc = voms_check_chain(trust->store, signer, signers);
    }
    if (rc == BRIX_VOMS_OK && trust->vomsdir != NULL && trust->vomsdir[0] != '\0'
        && !brix_voms_lsc_match(trust->vomsdir, e->vo, signers))
    {
        rc = BRIX_VOMS_ERR_LSC;
    }
    sk_X509_pop_free(signers, X509_free);
    return rc;
}

static brix_voms_status_t
voms_verify_entry(brix_voms_entry_t *e, X509 *carrier, STACK_OF(X509) *chain,
    const brix_voms_trust_t *trust, time_t now)
{
    VOMS_AC            *ac = e->ac;
    brix_voms_status_t  rc;

    if (ASN1_INTEGER_get(ac->acinfo->version) != 1) {
        return BRIX_VOMS_ERR_VERSION;
    }
    rc = voms_check_extensions(ac->acinfo);
    if (rc == BRIX_VOMS_OK) {
        rc = voms_check_holder(ac->acinfo, carrier, chain);
    }
    if (rc == BRIX_VOMS_OK) {
        rc = voms_check_validity(ac->acinfo, now, trust->skew_seconds);
    }
    if (rc != BRIX_VOMS_OK) {
        return rc;
    }
    return voms_verify_signed(e, trust);
}

brix_voms_status_t
brix_voms_verify(brix_voms_result_t *res, X509 *holder, STACK_OF(X509) *chain,
    const brix_voms_trust_t *trust)
{
    brix_voms_trust_t   defaults = { NULL, NULL, 0, 0 };
    brix_voms_status_t  first = BRIX_VOMS_ERR_ARGS;
    time_t              now;
    int                 i, verified = 0;

    if (res == NULL || holder == NULL) {
        return BRIX_VOMS_ERR_ARGS;
    }
    if (trust == NULL) {
        trust = &defaults;
    }
    now = trust->now ? trust->now : time(NULL);
    for (i = 0; i < res->n; i++) {
        brix_voms_entry_t *e = &res->entries[i];

        e->verdict = voms_verify_entry(e, holder, chain, trust, now);
        if (e->verdict == BRIX_VOMS_OK) {
            verified++;
        } else if (first == BRIX_VOMS_ERR_ARGS) {
            first = e->verdict;
        }
    }
    return verified > 0 ? BRIX_VOMS_OK : first;
}

/* Move every entry and sequence of `src` into `dst`; `src` is consumed. */
static brix_voms_status_t
voms_result_merge(brix_voms_result_t *dst, brix_voms_result_t *src, int carrier)
{
    brix_voms_entry_t *entries;
    void             **seqs;
    int                i;

    entries = realloc(dst->entries, sizeof(*entries) * (size_t) (dst->n + src->n));
    if (entries == NULL) {
        brix_voms_result_free(src);
        return BRIX_VOMS_ERR_NOMEM;
    }
    dst->entries = entries;
    seqs = realloc(dst->seqs, sizeof(*seqs) * (size_t) (dst->nseqs + src->nseqs));
    if (seqs == NULL) {
        brix_voms_result_free(src);
        return BRIX_VOMS_ERR_NOMEM;
    }
    dst->seqs = seqs;
    for (i = 0; i < src->n; i++) {
        src->entries[i].carrier = carrier;
        dst->entries[dst->n++] = src->entries[i];
    }
    for (i = 0; i < src->nseqs; i++) {
        dst->seqs[dst->nseqs++] = src->seqs[i];
    }
    free(src->entries);   /* the entries' strings now belong to dst */
    free(src->seqs);
    free(src);
    return BRIX_VOMS_OK;
}

brix_voms_status_t
brix_voms_retrieve(X509 *leaf, STACK_OF(X509) *chain,
    const brix_voms_trust_t *trust, brix_voms_result_t **out)
{
    brix_voms_result_t *all = NULL;
    brix_voms_status_t  status = BRIX_VOMS_ERR_NOEXT, rc;
    int                 i, n = chain ? sk_X509_num(chain) : 0, verified = 0;

    *out = NULL;
    for (i = 0; i <= n; i++) {
        const unsigned char *der = NULL;
        int                  len = 0;
        X509                *carrier = brix_voms_carrier_at(leaf, chain, i, &der, &len);
        brix_voms_result_t  *one = NULL;

        if (carrier == NULL) {
            continue;
        }
        rc = brix_voms_decode(der, len, &one);
        if (rc != BRIX_VOMS_OK) {
            if (status == BRIX_VOMS_ERR_NOEXT) {
                status = rc;   /* the first failure, unless something verifies */
            }
            continue;
        }
        rc = brix_voms_verify(one, carrier, chain, trust);
        if (rc == BRIX_VOMS_OK) {
            verified++;
        } else if (status == BRIX_VOMS_ERR_NOEXT) {
            status = rc;
        }
        if (all == NULL) {
            all = one;
            for (int k = 0; k < all->n; k++) {
                all->entries[k].carrier = i;
            }
        } else if ((rc = voms_result_merge(all, one, i)) != BRIX_VOMS_OK) {
            brix_voms_result_free(all);
            return rc;
        }
    }
    *out = all;
    return verified > 0 ? BRIX_VOMS_OK : status;
}
