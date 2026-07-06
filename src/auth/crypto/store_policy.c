/*
 * store_policy.c — signing_policy table + X509_STORE ex_data binding.
 *
 * See store_policy.h for the contract.  Depends only on OpenSSL + libc +
 * signing_policy.h; no ngx symbols (logging is via a caller callback).
 */
#include "auth/crypto/store_policy.h"

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

/* One parsed signing_policy file, keyed by the CA subject hash in its name. */
typedef struct {
    unsigned long      hash;      /* from the <hash>.signing_policy stem */
    int                have_hash; /* stem parsed as hex */
    int                malformed; /* file present but failed to parse */
    brix_sp_policy_t  *policy;    /* NULL when malformed */
} brix_sp_entry_t;

struct brix_sp_table_s {
    brix_sp_entry_t *ents;
    size_t           nents;
    size_t           cap;
};

/* Attached to the X509_STORE as a single ex_data blob. */
typedef struct {
    brix_sp_table_t *table;
    brix_sp_mode_t   sp_mode;
    int              crl_mode;
} brix_store_policy_t;

#define BRIX_SP_FILE_MAX (256 * 1024)

/* -- shared DN canonicaliser ---------------------------------------------- */

char *
brix_x509_oneline(X509_NAME *name, char *buf, size_t buflen)
{
    char *s;

    if (buflen == 0) {
        return buf;
    }
    buf[0] = '\0';
    if (name == NULL) {
        return buf;
    }
    s = X509_NAME_oneline(name, NULL, 0);
    if (s != NULL) {
        size_t n = strlen(s);
        if (n >= buflen) {
            n = buflen - 1;
        }
        memcpy(buf, s, n);
        buf[n] = '\0';
        OPENSSL_free(s);
    }
    return buf;
}

/* -- table build ----------------------------------------------------------- */

static int
sp_entry_push(brix_sp_table_t *t, brix_sp_entry_t e)
{
    if (t->nents == t->cap) {
        size_t ncap = t->cap ? t->cap * 2 : 8;
        brix_sp_entry_t *ne = realloc(t->ents, ncap * sizeof(*ne));
        if (ne == NULL) {
            return -1;
        }
        t->ents = ne;
        t->cap = ncap;
    }
    t->ents[t->nents++] = e;
    return 0;
}

/* Read up to BRIX_SP_FILE_MAX bytes of path into a malloc'd buffer. */
static char *
sp_read_file(const char *path, size_t *out_len)
{
    struct stat st;
    int         fd;
    char       *buf;
    ssize_t     n;
    size_t      total = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return NULL;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)
        || st.st_size > BRIX_SP_FILE_MAX)
    {
        close(fd);
        return NULL;
    }
    buf = malloc((size_t) st.st_size + 1);
    if (buf == NULL) {
        close(fd);
        return NULL;
    }
    while (total < (size_t) st.st_size) {
        n = read(fd, buf + total, (size_t) st.st_size - total);
        if (n < 0) {
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) {
            break;
        }
        total += (size_t) n;
    }
    close(fd);
    buf[total] = '\0';
    *out_len = total;
    return buf;
}

static void
sp_log(void *log, brix_sp_log_fn fn, int level, const char *msg)
{
    if (fn != NULL) {
        fn(log, level, msg);
    }
}

brix_sp_table_t *
brix_sp_table_build(const char *cadir, void *log, brix_sp_log_fn log_fn)
{
    brix_sp_table_t *t;
    DIR             *dir;
    struct dirent   *ent;

    t = calloc(1, sizeof(*t));
    if (t == NULL) {
        return NULL;
    }
    if (cadir == NULL) {
        return t;   /* empty table: nothing is ever "present" */
    }

    dir = opendir(cadir);
    if (dir == NULL) {
        return t;
    }

    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t      nlen = strlen(name);
        const char *suf  = ".signing_policy";
        size_t      slen = strlen(suf);
        char        path[PATH_MAX];
        char       *fbuf;
        size_t      flen;
        char        errbuf[256];
        brix_sp_entry_t e;
        char       *endp;
        int         n;

        if (nlen <= slen || strcmp(name + nlen - slen, suf) != 0) {
            continue;
        }

        n = snprintf(path, sizeof(path), "%s/%s", cadir, name);
        if (n < 0 || (size_t) n >= sizeof(path)) {
            continue;
        }

        memset(&e, 0, sizeof(e));
        e.hash = strtoul(name, &endp, 16);
        e.have_hash = (endp != name && *endp == '.');

        fbuf = sp_read_file(path, &flen);
        if (fbuf == NULL) {
            e.malformed = 1;
            sp_log(log, log_fn, BRIX_SP_LOG_WARN,
                   "signing_policy: unreadable file (rejecting its CA)");
        } else {
            e.policy = brix_sp_parse(fbuf, flen, errbuf, sizeof(errbuf));
            free(fbuf);
            if (e.policy == NULL) {
                e.malformed = 1;
                sp_log(log, log_fn, BRIX_SP_LOG_WARN,
                       "signing_policy: malformed file (rejecting its CA)");
            }
        }

        if (sp_entry_push(t, e) != 0) {
            if (e.policy != NULL) {
                brix_sp_free(e.policy);
            }
        }
    }

    closedir(dir);
    return t;
}

void
brix_sp_table_free(brix_sp_table_t *t)
{
    if (t == NULL) {
        return;
    }
    for (size_t i = 0; i < t->nents; i++) {
        if (t->ents[i].policy != NULL) {
            brix_sp_free(t->ents[i].policy);
        }
    }
    free(t->ents);
    free(t);
}

/* -- check ----------------------------------------------------------------- */

/*
 * Resolve the table entry (if any) whose stem hash matches this CA, trying the
 * canonical (new) then the legacy (old) subject-name hash.
 */
static const brix_sp_entry_t *
sp_find_by_hash(const brix_sp_table_t *t, X509 *ca)
{
    unsigned long h_new = X509_subject_name_hash(ca);
    unsigned long h_old = X509_subject_name_hash_old(ca);

    for (size_t i = 0; i < t->nents; i++) {
        if (t->ents[i].have_hash
            && (t->ents[i].hash == h_new || t->ents[i].hash == h_old))
        {
            return &t->ents[i];
        }
    }
    return NULL;
}

/*
 * Fallback: some parsed policy names this CA DN even if its file was oddly
 * named (stem not hex).  Returns the entry, or NULL.
 */
static const brix_sp_entry_t *
sp_find_by_dn(const brix_sp_table_t *t, const char *ca_dn)
{
    for (size_t i = 0; i < t->nents; i++) {
        if (t->ents[i].policy != NULL
            && brix_sp_ca_dn_present(t->ents[i].policy, ca_dn))
        {
            return &t->ents[i];
        }
    }
    return NULL;
}

int
brix_sp_table_check(const brix_sp_table_t *t, brix_sp_mode_t mode,
                    X509 *ca, X509 *subject)
{
    const brix_sp_entry_t *e;
    char ca_dn[1024];
    char subj_dn[1024];

    if (mode == BRIX_SP_MODE_OFF || t == NULL || ca == NULL || subject == NULL) {
        return 1;
    }

    brix_x509_oneline(X509_get_subject_name(ca), ca_dn, sizeof(ca_dn));

    e = sp_find_by_hash(t, ca);
    if (e == NULL) {
        e = sp_find_by_dn(t, ca_dn);
    }

    if (e == NULL) {
        /* No policy file present for this CA. */
        return mode == BRIX_SP_MODE_REQUIRE ? 0 : 1;
    }

    if (e->malformed || e->policy == NULL) {
        return 0;   /* present but unusable → fail closed */
    }

    if (!brix_sp_ca_dn_present(e->policy, ca_dn)) {
        return 0;   /* file present but names the wrong CA → fail closed */
    }

    brix_x509_oneline(X509_get_subject_name(subject), subj_dn, sizeof(subj_dn));
    return brix_sp_subject_allowed(e->policy, ca_dn, subj_dn) ? 1 : 0;
}

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

int
brix_cert_policy_violation(X509 *cert)
{
    EVP_PKEY *pk;
    int       is_proxy = (X509_get_extension_flags(cert) & EXFLAG_PROXY) != 0;

    /* Key strength (IGTF: RSA >= 2048, EC >= 256). */
    pk = X509_get0_pubkey(cert);
    if (pk != NULL) {
        int id = EVP_PKEY_base_id(pk);
        int bits = EVP_PKEY_bits(pk);
        if ((id == EVP_PKEY_RSA || id == EVP_PKEY_RSA2 || id == EVP_PKEY_DSA)
            && bits < 2048) {
            return 1;
        }
        if (id == EVP_PKEY_EC && bits < 256) {
            return 1;
        }
    }

    /* Signature algorithm: reject MD5 and SHA-1 based signatures. */
    {
        int sig_nid = X509_get_signature_nid(cert);
        int md_nid = NID_undef, pk_nid = NID_undef;
        if (OBJ_find_sigid_algs(sig_nid, &md_nid, &pk_nid)) {
            if (md_nid == NID_md5 || md_nid == NID_sha1 || md_nid == NID_md2
                || md_nid == NID_md4) {
                return 1;
            }
        }
    }

    /* Serial number: positive and <= 20 octets (RFC 5280 §4.1.2.2).  Proxies
     * are exempt from the ceiling — grid proxies use large derived serials. */
    {
        const ASN1_INTEGER *sn = X509_get0_serialNumber(cert);
        BIGNUM             *bn = ASN1_INTEGER_to_BN(sn, NULL);
        if (bn != NULL) {
            int bad = BN_is_zero(bn) || BN_is_negative(bn)
                      || (!is_proxy && BN_num_bytes(bn) > 20);
            BN_free(bn);
            if (bad) {
                return 1;
            }
        }
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

/* -- store configuration (shared by production + oracle) ------------------ */

/*
 * WHAT: check_issued override accepting a name-matching issuer for an RFC 3820
 *       proxy subject even when its authorityKeyIdentifier does not match the
 *       issuer's subjectKeyIdentifier.
 * WHY:  xrdgsiproxy/voms-proxy-init copy the EEC's own AKID into the delegated
 *       proxy, so OpenSSL's default check_issued rejects the signing EEC as the
 *       proxy's issuer (AKID_SKID_MISMATCH) and reports "unable to get local
 *       issuer".  The reference XRootD chain selects issuers by subject name +
 *       signature; match that.
 * HOW:  defer to X509_check_issued; on the AKID objections, accept when the
 *       subject is a recognised proxy (EXFLAG_PROXY).  The RSA signature is
 *       still verified afterwards, so this relaxes selection, not trust.
 */
static int
brix_sp_proxy_check_issued(X509_STORE_CTX *ctx, X509 *subject, X509 *issuer)
{
    int rv;

    (void) ctx;

    rv = X509_check_issued(issuer, subject);
    if (rv == X509_V_OK) {
        return 1;
    }
    /*
     * The authorityKeyIdentifier is advisory (RFC 5280 §4.2.1.1): a mismatch
     * must not prevent selecting a name-matching issuer.  Accept the AKID/SKID
     * and AKID issuer-serial objections for ANY subject (not just proxies) —
     * the issuer's signature over the subject is still verified afterwards by
     * X509_verify_cert, so this relaxes issuer *selection*, never trust.  This
     * also covers delegated grid proxies whose copied AKID points at the CA.
     */
    if (rv == X509_V_ERR_AKID_SKID_MISMATCH
        || rv == X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH)
    {
        return 1;
    }
    return 0;
}

/*
 * WHAT: verify callback used only in BRIX_CRL_MODE_TRY.
 * WHY:  "try" checks revocation where a CRL exists but tolerates a CA that has
 *       none; a stale (expired) CRL stays fatal (staleness is evidence).
 * HOW:  downgrade only X509_V_ERR_UNABLE_TO_GET_CRL to success; every other
 *       verdict (CRL_HAS_EXPIRED, CERT_REVOKED, ...) stands.
 */
static int
brix_crl_try_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    if (ok) {
        return 1;
    }
    if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_UNABLE_TO_GET_CRL) {
        return 1;
    }
    return 0;
}

int
brix_store_configure(X509_STORE *store, const char *cadir,
                     unsigned long extra_flags, int crl_count,
                     brix_sp_mode_t sp_mode, int crl_mode,
                     void *log, brix_sp_log_fn log_fn)
{
    brix_sp_table_t *table;

    if (store == NULL) {
        return -1;
    }

    if (extra_flags != 0) {
        X509_STORE_set_flags(store, extra_flags);
    }
    /* AKID is advisory: tolerate an AKID mismatch when selecting a name-matching
     * issuer on every store (webdav and GSI); the signature is still verified. */
    X509_STORE_set_check_issued(store, brix_sp_proxy_check_issued);

    if (crl_mode == BRIX_CRL_MODE_REQUIRE
        || (crl_mode == BRIX_CRL_MODE_TRY && crl_count > 0))
    {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK
            | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_USE_DELTAS);
    }
    if (crl_mode == BRIX_CRL_MODE_TRY) {
        X509_STORE_set_verify_cb(store, brix_crl_try_verify_cb);
    }

    if (cadir == NULL && sp_mode == BRIX_SP_MODE_REQUIRE) {
        sp_log(log, log_fn, BRIX_SP_LOG_WARN,
               "signing_policy: \"require\" needs a hashed CA directory, not a "
               "bundle file");
        return -1;
    }

    table = brix_sp_table_build(cadir, log, log_fn);
    if (table == NULL) {
        return -1;
    }
    if (!brix_store_policy_attach(store, table, sp_mode, crl_mode)) {
        brix_sp_table_free(table);
        return -1;
    }
    return 0;
}

/* -- X509_STORE ex_data glue ---------------------------------------------- */

/*
 * ex_data free callback: released by OpenSSL when the store is freed, so the
 * attached blob (and the table it owns) never leaks across a store rebuild.
 */
static void
sp_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx,
           long argl, void *argp)
{
    brix_store_policy_t *sp = ptr;

    (void) parent; (void) ad; (void) idx; (void) argl; (void) argp;

    if (sp == NULL) {
        return;
    }
    brix_sp_table_free(sp->table);
    free(sp);
}

static int
sp_store_ex_index(void)
{
    static int idx = -1;
    if (idx < 0) {
        idx = X509_STORE_get_ex_new_index(0, NULL, NULL, NULL, sp_ex_free);
    }
    return idx;
}

int
brix_store_policy_attach(X509_STORE *store, brix_sp_table_t *table,
                         brix_sp_mode_t sp_mode, int crl_mode)
{
    brix_store_policy_t *sp;
    int                  idx = sp_store_ex_index();

    if (store == NULL || idx < 0) {
        return 0;
    }
    sp = calloc(1, sizeof(*sp));
    if (sp == NULL) {
        return 0;
    }
    sp->table = table;
    sp->sp_mode = sp_mode;
    sp->crl_mode = crl_mode;

    if (!X509_STORE_set_ex_data(store, idx, sp)) {
        free(sp);
        return 0;
    }
    return 1;
}

static brix_store_policy_t *
sp_from_ctx(X509_STORE_CTX *ctx)
{
    X509_STORE *store;
    int         idx = sp_store_ex_index();

    if (ctx == NULL || idx < 0) {
        return NULL;
    }
    store = X509_STORE_CTX_get0_store(ctx);
    if (store == NULL) {
        return NULL;
    }
    return X509_STORE_get_ex_data(store, idx);
}

brix_sp_table_t *
brix_store_policy_table(X509_STORE_CTX *ctx)
{
    brix_store_policy_t *sp = sp_from_ctx(ctx);
    return sp ? sp->table : NULL;
}

brix_sp_mode_t
brix_store_policy_mode(X509_STORE_CTX *ctx)
{
    brix_store_policy_t *sp = sp_from_ctx(ctx);
    return sp ? sp->sp_mode : BRIX_SP_MODE_OFF;
}

int
brix_store_crl_mode(X509_STORE_CTX *ctx)
{
    brix_store_policy_t *sp = sp_from_ctx(ctx);
    return sp ? sp->crl_mode : BRIX_CRL_MODE_OFF;
}
