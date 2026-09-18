/*
 * shared/voms/voms_decode.c — locate and decode the VOMS extension
 *
 * WHAT: brix_voms_find_extension, brix_voms_decode, brix_voms_find_eec, the
 *       result allocator/free and the status strings of voms_ac.h.
 * WHY:  Decoding is separated from verification so a diagnostic tool can show
 *       what a proxy claims while the module decides what it trusts.
 * HOW:  d2i_VOMS_AC_SEQ over the extension value, then one brix_voms_entry_t
 *       per AC: the VO and server URI from the FQAN attribute's
 *       policyAuthority ("vo://host:port"), the FQANs from its OCTET STRING
 *       values, DNs rendered one-line, times through ASN1_TIME_to_tm.
 */

#include "voms_ac.h"
#include "voms_asn1.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>

char *
brix_voms_dn_oneline(const X509_NAME *name, char *buf, size_t cap)
{
    if (buf == NULL || cap == 0) {
        return buf;
    }
    buf[0] = '\0';
    if (name != NULL) {
        X509_NAME_oneline(name, buf, (int) cap);
        buf[cap - 1] = '\0';
    }
    return buf;
}

/* One row per status: the short token the harness prints and the sentence
 * the module logs. */
typedef struct {
    const char *token;
    const char *text;
} voms_status_row_t;

static const voms_status_row_t voms_status_rows[] = {
    [BRIX_VOMS_OK]            = { "ok",        "ok" },
    [BRIX_VOMS_ERR_NOEXT]     = { "noext",     "no VOMS extension in the certificate chain" },
    [BRIX_VOMS_ERR_DECODE]    = { "decode",    "VOMS extension is not a valid attribute certificate sequence" },
    [BRIX_VOMS_ERR_VERSION]   = { "version",   "attribute certificate is not version 2" },
    [BRIX_VOMS_ERR_HOLDER]    = { "holder",    "attribute certificate holder does not match the end-entity certificate" },
    [BRIX_VOMS_ERR_NOTYET]    = { "notyet",    "attribute certificate is not yet valid" },
    [BRIX_VOMS_ERR_EXPIRED]   = { "expired",   "attribute certificate has expired" },
    [BRIX_VOMS_ERR_NOSIGNER]  = { "nosigner",  "attribute certificate carries no VOMS server certificate" },
    [BRIX_VOMS_ERR_SIGALG]    = { "sigalg",    "attribute certificate signature algorithm rejected" },
    [BRIX_VOMS_ERR_SIGNATURE] = { "signature", "attribute certificate signature does not verify" },
    [BRIX_VOMS_ERR_ISSUER]    = { "issuer",    "attribute certificate issuer is not the VOMS server certificate subject" },
    [BRIX_VOMS_ERR_UNTRUSTED] = { "untrusted", "VOMS server certificate chain is not trusted" },
    [BRIX_VOMS_ERR_LSC]       = { "lsc",       "no vomsdir LSC file or certificate matches the VOMS server" },
    [BRIX_VOMS_ERR_TARGET]    = { "target",    "attribute certificate targets exclude this host" },
    [BRIX_VOMS_ERR_EXTENSION] = { "extension", "attribute certificate carries an unknown critical extension" },
    [BRIX_VOMS_ERR_ATTRS]     = { "attrs",     "attribute certificate carries no FQAN" },
    [BRIX_VOMS_ERR_NOMEM]     = { "nomem",     "out of memory" },
    [BRIX_VOMS_ERR_ARGS]      = { "args",      "invalid arguments" },
};

static const voms_status_row_t *
voms_status_row(brix_voms_status_t status)
{
    size_t n = sizeof(voms_status_rows) / sizeof(voms_status_rows[0]);

    return ((size_t) status < n && voms_status_rows[status].token != NULL)
           ? &voms_status_rows[status] : NULL;
}

const char *
brix_voms_strerror(brix_voms_status_t status)
{
    const voms_status_row_t *row = voms_status_row(status);

    return row ? row->text : "unknown VOMS status";
}

const char *
brix_voms_status_name(brix_voms_status_t status)
{
    const voms_status_row_t *row = voms_status_row(status);

    return row ? row->token : "unknown";
}

/* The VOMS extension index in `cert`, or -1. */
static int
voms_ext_index(X509 *cert)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(BRIX_VOMS_OID_ACSEQ, 1);
    int          idx = -1;

    if (obj != NULL) {
        idx = X509_get_ext_by_OBJ(cert, obj, -1);
        ASN1_OBJECT_free(obj);
    }
    return idx;
}

X509 *
brix_voms_carrier_at(X509 *leaf, STACK_OF(X509) *chain, int index,
    const unsigned char **der, int *len)
{
    int   n = chain ? sk_X509_num(chain) : 0;
    X509 *cert;
    int   idx;

    if (index < 0 || index > n) {
        return NULL;
    }
    cert = (index == 0) ? leaf : sk_X509_value(chain, index - 1);
    if (cert == NULL) {
        return NULL;
    }
    idx = voms_ext_index(cert);
    if (idx < 0) {
        return NULL;
    }
    {
        ASN1_OCTET_STRING *data = X509_EXTENSION_get_data(X509_get_ext(cert, idx));

        *der = ASN1_STRING_get0_data(data);
        *len = ASN1_STRING_length(data);
    }
    return cert;
}

brix_voms_status_t
brix_voms_find_extension(X509 *leaf, STACK_OF(X509) *chain, X509 **holder,
    const unsigned char **der, int *len)
{
    int i, n = chain ? sk_X509_num(chain) : 0;

    for (i = 0; i <= n; i++) {
        X509 *cert = brix_voms_carrier_at(leaf, chain, i, der, len);

        if (cert != NULL) {
            *holder = cert;
            return BRIX_VOMS_OK;
        }
    }
    return BRIX_VOMS_ERR_NOEXT;
}

/* The legacy GT2 proxy shape: subject = issuer + exactly one trailing CN. */
static int
voms_legacy_proxy_shape(X509 *cert)
{
    const X509_NAME *subject = X509_get_subject_name(cert);
    const X509_NAME *issuer = X509_get_issuer_name(cert);
    int              ns = X509_NAME_entry_count(subject);
    int              ni = X509_NAME_entry_count(issuer);
    X509_NAME       *prefix;
    int              i, same;

    if (ns != ni + 1 || ni == 0) {
        return 0;
    }
    if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, ns - 1)))
        != NID_commonName)
    {
        return 0;
    }
    prefix = X509_NAME_new();
    if (prefix == NULL) {
        return 0;
    }
    for (i = 0; i < ni; i++) {
        X509_NAME_add_entry(prefix, X509_NAME_get_entry(subject, i), -1, 0);
    }
    same = (X509_NAME_cmp(prefix, issuer) == 0);
    X509_NAME_free(prefix);
    return same;
}

int
brix_voms_is_proxy(X509 *cert)
{
    if (cert == NULL) {
        return 0;
    }
    if (X509_get_extension_flags(cert) & EXFLAG_PROXY) {
        return 1;
    }
    return voms_legacy_proxy_shape(cert);
}

X509 *
brix_voms_parent(X509 *cert, STACK_OF(X509) *chain)
{
    int i, n = chain ? sk_X509_num(chain) : 0;

    for (i = 0; i < n; i++) {
        X509 *c = sk_X509_value(chain, i);

        if (c != cert && X509_NAME_cmp(X509_get_subject_name(c),
                                       X509_get_issuer_name(cert)) == 0)
        {
            return c;
        }
    }
    return NULL;
}

X509 *
brix_voms_find_eec(X509 *leaf, STACK_OF(X509) *chain)
{
    X509 *cur = leaf;
    int   hops, limit = 1 + (chain ? sk_X509_num(chain) : 0);

    for (hops = 0; cur != NULL && hops <= limit; hops++) {
        X509 *parent;

        if (!brix_voms_is_proxy(cur)) {
            return cur;
        }
        parent = brix_voms_parent(cur, chain);
        if (parent == NULL) {
            return cur;   /* the chain ends in a proxy: best available */
        }
        cur = parent;
    }
    return leaf;
}

/* Copy an ASN.1 string's bytes as a NUL-terminated C string (NULL on OOM). */
static char *
voms_strdup_asn1(const ASN1_STRING *s)
{
    int   n = ASN1_STRING_length(s);
    char *out = malloc((size_t) n + 1);

    if (out != NULL) {
        memcpy(out, ASN1_STRING_get0_data(s), (size_t) n);
        out[n] = '\0';
    }
    return out;
}

/* The first directoryName of `names`, or NULL. */
static X509_NAME *
voms_first_dirname(const GENERAL_NAMES *names)
{
    int i, n = names ? sk_GENERAL_NAME_num(names) : 0;

    for (i = 0; i < n; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(names, i);

        if (gn->type == GEN_DIRNAME) {
            return gn->d.directoryName;
        }
    }
    return NULL;
}

static time_t
voms_asn1_time(const ASN1_TIME *t)
{
    struct tm tm;

    memset(&tm, 0, sizeof(tm));
    if (t == NULL || !ASN1_TIME_to_tm(t, &tm)) {
        return 0;
    }
    return timegm(&tm);
}

/* "vo://host:port" -> entry->vo, entry->uri. 1 when a VO name was set. */
static int
voms_split_policy_uri(brix_voms_entry_t *e, const char *uri, size_t len)
{
    const char *sep = memmem(uri, len, "://", 3);
    size_t      vo_len;

    if (sep == NULL) {
        return 0;
    }
    vo_len = (size_t) (sep - uri);
    if (vo_len == 0 || vo_len >= sizeof(e->vo)) {
        return 0;
    }
    memcpy(e->vo, uri, vo_len);
    e->vo[vo_len] = '\0';
    len -= vo_len + 3;
    if (len >= sizeof(e->uri)) {
        len = sizeof(e->uri) - 1;
    }
    memcpy(e->uri, sep + 3, len);
    e->uri[len] = '\0';
    return 1;
}

/* The VO of an FQAN is its first path component: "/cms/..." -> "cms". */
static void
voms_vo_from_fqan(brix_voms_entry_t *e, const char *fqan)
{
    const char *end;
    size_t      n;

    if (e->vo[0] != '\0' || fqan[0] != '/') {
        return;
    }
    end = strchr(fqan + 1, '/');
    n = end ? (size_t) (end - fqan - 1) : strlen(fqan + 1);
    if (n > 0 && n < sizeof(e->vo)) {
        memcpy(e->vo, fqan + 1, n);
        e->vo[n] = '\0';
    }
}

/* An FQAN is "/vo[/group...][/Role=r][/Capability=c]": printable ASCII, no
 * whitespace, no ',' (the identity layer's CSV separator). */
static int
voms_fqan_is_wellformed(const unsigned char *s, int n)
{
    int i;

    if (n <= 1 || s[0] != '/') {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (s[i] < 0x21 || s[i] > 0x7e || s[i] == ',') {
            return 0;
        }
    }
    return 1;
}

/* Append one FQAN (bounded, NUL-terminated); a malformed value is dropped. */
static brix_voms_status_t
voms_add_fqan(brix_voms_entry_t *e, const ASN1_STRING *value)
{
    char  *copy;
    char **grown;

    if (e->nfqans >= BRIX_VOMS_MAX_FQANS
        || ASN1_STRING_length(value) >= BRIX_VOMS_MAX_FQAN
        || !voms_fqan_is_wellformed(ASN1_STRING_get0_data(value),
                                    ASN1_STRING_length(value)))
    {
        return BRIX_VOMS_OK;   /* over the cap or malformed: skip, never truncate */
    }
    copy = voms_strdup_asn1(value);
    grown = realloc(e->fqans, sizeof(char *) * ((size_t) e->nfqans + 2));
    if (copy == NULL || grown == NULL) {
        free(copy);
        return BRIX_VOMS_ERR_NOMEM;
    }
    e->fqans = grown;
    e->fqans[e->nfqans++] = copy;
    e->fqans[e->nfqans] = NULL;
    voms_vo_from_fqan(e, copy);
    return BRIX_VOMS_OK;
}

/* One IetfAttrSyntax value of the FQAN attribute: policy authority + FQANs. */
static brix_voms_status_t
voms_read_ietf_attr(brix_voms_entry_t *e, const ASN1_TYPE *type)
{
    const unsigned char *p;
    VOMS_IETF_ATTR      *attr;
    brix_voms_status_t   rc = BRIX_VOMS_OK;
    int                  i, n;

    if (type == NULL || type->type != V_ASN1_SEQUENCE) {
        return BRIX_VOMS_ERR_DECODE;
    }
    p = ASN1_STRING_get0_data(type->value.sequence);
    attr = d2i_VOMS_IETF_ATTR(NULL, &p, ASN1_STRING_length(type->value.sequence));
    if (attr == NULL) {
        return BRIX_VOMS_ERR_DECODE;
    }
    n = attr->policy_authority ? sk_GENERAL_NAME_num(attr->policy_authority) : 0;
    for (i = 0; i < n && e->vo[0] == '\0'; i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(attr->policy_authority, i);

        if (gn->type == GEN_URI) {
            (void) voms_split_policy_uri(e,
                (const char *) ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier),
                (size_t) ASN1_STRING_length(gn->d.uniformResourceIdentifier));
        }
    }
    n = sk_VOMS_IETF_ATTR_VALUE_num(attr->values);
    for (i = 0; i < n && rc == BRIX_VOMS_OK; i++) {
        VOMS_IETF_ATTR_VALUE *v = sk_VOMS_IETF_ATTR_VALUE_value(attr->values, i);

        if (v->type == VOMS_IETF_VALUE_OCTETS) {
            rc = voms_add_fqan(e, v->d.octets);
        } else if (v->type == VOMS_IETF_VALUE_STRING) {
            rc = voms_add_fqan(e, v->d.string);
        }
    }
    VOMS_IETF_ATTR_free(attr);
    return rc;
}

/* Every FQAN attribute of the AC (an AC normally carries exactly one). */
static brix_voms_status_t
voms_read_fqans(brix_voms_entry_t *e, const VOMS_AC_INFO *info)
{
    char txt[80];
    int  i, j, n = sk_X509_ATTRIBUTE_num(info->attributes);

    for (i = 0; i < n; i++) {
        X509_ATTRIBUTE *attr = sk_X509_ATTRIBUTE_value(info->attributes, i);
        int             count;

        if (OBJ_obj2txt(txt, sizeof(txt), X509_ATTRIBUTE_get0_object(attr), 1) <= 0
            || strcmp(txt, BRIX_VOMS_OID_FQAN) != 0)
        {
            continue;
        }
        count = X509_ATTRIBUTE_count(attr);
        for (j = 0; j < count; j++) {
            brix_voms_status_t rc =
                voms_read_ietf_attr(e, X509_ATTRIBUTE_get0_type(attr, j));

            if (rc != BRIX_VOMS_OK) {
                return rc;
            }
        }
    }
    return (e->nfqans > 0) ? BRIX_VOMS_OK : BRIX_VOMS_ERR_ATTRS;
}

/* Generic attributes (OID .11): best effort, an undecodable extension is
 * ignored rather than failing the AC — they carry no authorization. */
static brix_voms_status_t
voms_read_generic(brix_voms_entry_t *e, const VOMS_AC_INFO *info)
{
    VOMS_FULL_ATTRIBUTES *full;
    int                   i, j, total = 0;

    full = voms_ext_attributes(voms_acinfo_extension(info, BRIX_VOMS_OID_ATTRIBUTES));
    if (full == NULL) {
        return BRIX_VOMS_OK;
    }
    for (i = 0; i < sk_VOMS_ATTR_HOLDER_num(full->providers); i++) {
        total += sk_VOMS_GENERIC_ATTR_num(
            sk_VOMS_ATTR_HOLDER_value(full->providers, i)->attributes);
    }
    e->attrs = calloc((size_t) (total > 0 ? total : 1), sizeof(*e->attrs));
    if (e->attrs == NULL) {
        VOMS_FULL_ATTRIBUTES_free(full);
        return BRIX_VOMS_ERR_NOMEM;
    }
    for (i = 0; i < sk_VOMS_ATTR_HOLDER_num(full->providers); i++) {
        VOMS_ATTR_HOLDER *h = sk_VOMS_ATTR_HOLDER_value(full->providers, i);

        for (j = 0; j < sk_VOMS_GENERIC_ATTR_num(h->attributes); j++) {
            VOMS_GENERIC_ATTR *a = sk_VOMS_GENERIC_ATTR_value(h->attributes, j);
            brix_voms_attr_t  *out = &e->attrs[e->nattrs];

            out->name = voms_strdup_asn1(a->name);
            out->value = voms_strdup_asn1(a->value);
            out->qualifier = voms_strdup_asn1(a->qualifier);
            if (out->name == NULL || out->value == NULL || out->qualifier == NULL) {
                VOMS_FULL_ATTRIBUTES_free(full);
                return BRIX_VOMS_ERR_NOMEM;
            }
            e->nattrs++;
        }
    }
    VOMS_FULL_ATTRIBUTES_free(full);
    return BRIX_VOMS_OK;
}

/* Names and times of one AC into its entry. */
static void
voms_read_names(brix_voms_entry_t *e, const VOMS_AC_INFO *info)
{
    const VOMS_ATTCERT_ISSUER *iss = info->issuer;
    X509_NAME                 *name = NULL;

    if (iss->type == VOMS_ISSUER_V2FORM) {
        name = voms_first_dirname(iss->d.v2form->issuer_name);
    } else {
        name = voms_first_dirname(iss->d.v1form);
    }
    brix_voms_dn_oneline(name, e->issuer_dn, sizeof(e->issuer_dn));
    if (info->holder->base_certificate_id != NULL) {
        brix_voms_dn_oneline(
            voms_first_dirname(info->holder->base_certificate_id->issuer),
            e->holder_dn, sizeof(e->holder_dn));
    }
    e->not_before = voms_asn1_time(info->validity->not_before);
    e->not_after = voms_asn1_time(info->validity->not_after);
    e->verdict = BRIX_VOMS_ERR_ARGS;   /* "not verified yet" until brix_voms_verify */
}

static brix_voms_status_t
voms_fill_entry(brix_voms_entry_t *e, VOMS_AC *ac)
{
    brix_voms_status_t rc;

    e->ac = ac;
    voms_read_names(e, ac->acinfo);
    rc = voms_read_fqans(e, ac->acinfo);
    if (rc != BRIX_VOMS_OK) {
        return rc;
    }
    return voms_read_generic(e, ac->acinfo);
}

brix_voms_status_t
brix_voms_decode(const unsigned char *der, int len, brix_voms_result_t **out)
{
    const unsigned char *p = der;
    VOMS_AC_SEQ         *seq;
    brix_voms_result_t  *res;
    int                  i, n;

    *out = NULL;
    if (der == NULL || len <= 0) {
        return BRIX_VOMS_ERR_ARGS;
    }
    seq = d2i_VOMS_AC_SEQ(NULL, &p, len);
    if (seq == NULL || p != der + len) {
        VOMS_AC_SEQ_free(seq);
        return BRIX_VOMS_ERR_DECODE;
    }
    n = sk_VOMS_AC_num(seq->acs);
    if (n <= 0 || n > BRIX_VOMS_MAX_ENTRIES) {
        VOMS_AC_SEQ_free(seq);
        return BRIX_VOMS_ERR_DECODE;
    }
    res = calloc(1, sizeof(*res));
    if (res == NULL
        || (res->entries = calloc((size_t) n, sizeof(*res->entries))) == NULL
        || (res->seqs = calloc(1, sizeof(*res->seqs))) == NULL)
    {
        if (res != NULL) {
            free(res->entries);
        }
        free(res);
        VOMS_AC_SEQ_free(seq);
        return BRIX_VOMS_ERR_NOMEM;
    }
    res->seqs[0] = seq;
    res->nseqs = 1;
    res->n = n;
    for (i = 0; i < n; i++) {
        brix_voms_status_t rc = voms_fill_entry(&res->entries[i], sk_VOMS_AC_value(seq->acs, i));

        if (rc != BRIX_VOMS_OK) {
            brix_voms_result_free(res);
            return rc;
        }
    }
    *out = res;
    return BRIX_VOMS_OK;
}

void
brix_voms_result_free(brix_voms_result_t *res)
{
    int i, j;

    if (res == NULL) {
        return;
    }
    for (i = 0; i < res->n; i++) {
        brix_voms_entry_t *e = &res->entries[i];

        for (j = 0; j < e->nfqans; j++) {
            free(e->fqans[j]);
        }
        free(e->fqans);
        for (j = 0; j < e->nattrs; j++) {
            free(e->attrs[j].name);
            free(e->attrs[j].value);
            free(e->attrs[j].qualifier);
        }
        free(e->attrs);
    }
    free(res->entries);
    for (i = 0; i < res->nseqs; i++) {
        VOMS_AC_SEQ_free(res->seqs[i]);
    }
    free(res->seqs);
    free(res);
}
