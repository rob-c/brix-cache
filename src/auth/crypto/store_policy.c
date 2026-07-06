/*
 * store_policy.c — signing_policy table + X509_STORE ex_data binding.
 *
 * See store_policy.h for the contract.  Depends only on OpenSSL + libc +
 * signing_policy.h; no ngx symbols (logging is via a caller callback).
 */
#include "auth/crypto/store_policy.h"

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
