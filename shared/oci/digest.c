/* digest.c — OCI content-digest grammar + hash helpers.
 *
 * WHAT: the digest.h contract: strict "<alg>:<hex>" parse/format, constant-
 *       time compare, one-shot and streaming hashing over the registered
 *       algorithms.
 * WHY:  see digest.h — the grammar is the traversal defense and must live in
 *       exactly one TU.
 * HOW:  hand-rolled byte checks (no regex, no alloc) for the grammar; OpenSSL
 *       EVP for the hashing, matching cvmfs/object/object.c's precedent. The
 *       compare accumulates XOR over the full fixed width so timing does not
 *       depend on where the first difference sits, nor on which algorithm the
 *       operands carry.
 */
#include "oci/digest.h"

#include <string.h>

#include <openssl/evp.h>

/* One table, so a name, its hex width and its EVP binding cannot drift apart.
 * Adding an algorithm is adding a row — and the row is what the grammar, the
 * store layout and the verifier all read. */
typedef struct {
    const char    *name;
    size_t         namelen;
    size_t         hexlen;
    size_t         rawlen;
} oci_alg_row_t;

static const oci_alg_row_t oci_algs[] = {
    { "sha256", 6, BRIX_OCI_SHA256_HEXLEN, 32 },
    { "sha512", 6, BRIX_OCI_SHA512_HEXLEN, 64 }
};

#define OCI_ALG_COUNT (sizeof(oci_algs) / sizeof(oci_algs[0]))

/* The header publishes the count so walkers can iterate the on-disk
 * algorithm directories; it must be the table, not a second opinion. */
_Static_assert(OCI_ALG_COUNT == BRIX_OCI_ALG_COUNT,
               "BRIX_OCI_ALG_COUNT is out of step with the algorithm table");

static const oci_alg_row_t *
oci_alg_row(brix_oci_alg_t alg)
{
    return ((size_t) alg < OCI_ALG_COUNT) ? &oci_algs[alg] : NULL;
}

/* EVP binding lives beside the table but not IN it: EVP_sha256() is a
 * function call, not a constant initialiser, so a static table cannot hold
 * it portably. */
static const EVP_MD *
oci_alg_md(brix_oci_alg_t alg)
{
    switch (alg) {
    case BRIX_OCI_ALG_SHA256:
        return EVP_sha256();
    case BRIX_OCI_ALG_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
}

const char *
brix_oci_alg_name(brix_oci_alg_t alg)
{
    const oci_alg_row_t *r = oci_alg_row(alg);

    return (r != NULL) ? r->name : NULL;
}

size_t
brix_oci_alg_hexlen(brix_oci_alg_t alg)
{
    const oci_alg_row_t *r = oci_alg_row(alg);

    return (r != NULL) ? r->hexlen : 0;
}

static int
hex_lower(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Width-implied parse — see digest.h. Shares the hex validation with the
 * full parse by handing it a formatted "<alg>:<hex>", so the two can never
 * disagree about what a valid digit is. */
int
brix_oci_digest_parse_hex(const char *hex, size_t n, brix_oci_digest_t *out)
{
    char   s[BRIX_OCI_DIGEST_STRLEN];
    size_t a;

    if (hex == NULL) {
        return -1;
    }
    for (a = 0; a < OCI_ALG_COUNT; a++) {
        const oci_alg_row_t *r = &oci_algs[a];

        if (n != r->hexlen) {
            continue;
        }
        memcpy(s, r->name, r->namelen);
        s[r->namelen] = ':';
        memcpy(s + r->namelen + 1, hex, n);
        return brix_oci_digest_parse(s, r->namelen + 1 + n, out);
    }
    return -1;
}


/* Strict parse: a registered algorithm name, ':', then exactly that
 * algorithm's width in lowercase hex, and nothing more. */
int
brix_oci_digest_parse(const char *s, size_t n, brix_oci_digest_t *out)
{
    const oci_alg_row_t *r;
    size_t               i, a;

    if (s == NULL || out == NULL) {
        return -1;
    }

    for (a = 0; a < OCI_ALG_COUNT; a++) {
        r = &oci_algs[a];
        if (n != r->namelen + 1 + r->hexlen) {
            continue;
        }
        if (memcmp(s, r->name, r->namelen) != 0 || s[r->namelen] != ':') {
            continue;
        }
        for (i = 0; i < r->hexlen; i++) {
            if (!hex_lower(s[r->namelen + 1 + i])) {
                return -1;
            }
        }
        /* Zero first: the tail past this algorithm's width must be a known
         * value, because the constant-time compare below reads the whole
         * fixed buffer regardless of which algorithm it holds. */
        memset(out, 0, sizeof(*out));
        memcpy(out->hex, s + r->namelen + 1, r->hexlen);
        out->alg = (brix_oci_alg_t) a;
        return 0;
    }
    return -1;
}

int
brix_oci_digest_format(const brix_oci_digest_t *d, char *out, size_t outsz)
{
    const oci_alg_row_t *r;
    size_t               need;

    if (d == NULL || out == NULL) {
        return -1;
    }
    r = oci_alg_row(d->alg);
    if (r == NULL) {
        return -1;
    }
    need = r->namelen + 1 + r->hexlen + 1;
    if (outsz < need) {
        return -1;
    }
    memcpy(out, r->name, r->namelen);
    out[r->namelen] = ':';
    memcpy(out + r->namelen + 1, d->hex, r->hexlen);
    out[r->namelen + 1 + r->hexlen] = '\0';
    return (int) (need - 1);
}

/* XOR-accumulate over the full buffer: the loop's shape never depends on the
 * data or the algorithm, so a mismatch at byte 0 and at byte 127 cost the
 * same. The algorithm difference is folded into the same accumulator rather
 * than short-circuiting on it. */
int
brix_oci_digest_eq(const brix_oci_digest_t *a, const brix_oci_digest_t *b)
{
    unsigned char acc = 0;
    size_t        i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0; i < BRIX_OCI_HEXLEN_MAX; i++) {
        acc |= (unsigned char) (a->hex[i] ^ b->hex[i]);
    }
    acc |= (unsigned char) (a->alg != b->alg);
    return acc == 0;
}

static void
digest_from_raw(const unsigned char *raw, const oci_alg_row_t *r,
                brix_oci_alg_t alg, brix_oci_digest_t *out)
{
    static const char hexc[] = "0123456789abcdef";
    size_t            i;

    memset(out, 0, sizeof(*out));
    for (i = 0; i < r->rawlen; i++) {
        out->hex[i * 2]     = hexc[raw[i] >> 4];
        out->hex[i * 2 + 1] = hexc[raw[i] & 0x0f];
    }
    out->alg = alg;
}

int
brix_oci_digest_hash(brix_oci_alg_t alg, const void *data, size_t len,
                     brix_oci_digest_t *out)
{
    const oci_alg_row_t *r = oci_alg_row(alg);
    const EVP_MD        *md = oci_alg_md(alg);
    unsigned char        raw[EVP_MAX_MD_SIZE];
    unsigned int         rawlen = 0;

    if (out == NULL || r == NULL || md == NULL) {
        return -1;
    }
    if (EVP_Digest(data, len, raw, &rawlen, md, NULL) != 1
        || rawlen != r->rawlen)
    {
        return -1;
    }
    digest_from_raw(raw, r, alg, out);
    return 0;
}

int
brix_oci_hash_init(brix_oci_hash_ctx_t *c, brix_oci_alg_t alg)
{
    const EVP_MD *md_alg = oci_alg_md(alg);
    EVP_MD_CTX   *md;

    if (c == NULL || md_alg == NULL) {
        return -1;
    }
    md = EVP_MD_CTX_new();
    if (md == NULL) {
        return -1;
    }
    if (EVP_DigestInit_ex(md, md_alg, NULL) != 1) {
        EVP_MD_CTX_free(md);
        return -1;
    }
    c->md = md;
    c->live = 1;
    c->alg = alg;
    return 0;
}

int
brix_oci_hash_update(brix_oci_hash_ctx_t *c, const void *data, size_t len)
{
    if (c == NULL || !c->live) {
        return -1;
    }
    if (EVP_DigestUpdate((EVP_MD_CTX *) c->md, data, len) != 1) {
        return -1;
    }
    return 0;
}

int
brix_oci_hash_final(brix_oci_hash_ctx_t *c, brix_oci_digest_t *out)
{
    const oci_alg_row_t *r;
    unsigned char        raw[EVP_MAX_MD_SIZE];
    unsigned int         rawlen = 0;
    int                  rc = -1;

    if (c == NULL || !c->live || out == NULL) {
        return -1;
    }
    r = oci_alg_row(c->alg);
    if (r != NULL
        && EVP_DigestFinal_ex((EVP_MD_CTX *) c->md, raw, &rawlen) == 1
        && rawlen == r->rawlen)
    {
        digest_from_raw(raw, r, c->alg, out);
        rc = 0;
    }
    brix_oci_hash_abort(c);
    return rc;
}

void
brix_oci_hash_abort(brix_oci_hash_ctx_t *c)
{
    if (c == NULL || !c->live) {
        return;
    }
    EVP_MD_CTX_free((EVP_MD_CTX *) c->md);
    c->md = NULL;
    c->live = 0;
}

int
brix_oci_sha256(const void *data, size_t len, brix_oci_digest_t *out)
{
    return brix_oci_digest_hash(BRIX_OCI_ALG_SHA256, data, len, out);
}

int
brix_oci_sha256_init(brix_oci_sha256_ctx_t *c)
{
    return brix_oci_hash_init(c, BRIX_OCI_ALG_SHA256);
}

int
brix_oci_sha256_update(brix_oci_sha256_ctx_t *c, const void *data, size_t len)
{
    return brix_oci_hash_update(c, data, len);
}

int
brix_oci_sha256_final(brix_oci_sha256_ctx_t *c, brix_oci_digest_t *out)
{
    return brix_oci_hash_final(c, out);
}

void
brix_oci_sha256_abort(brix_oci_sha256_ctx_t *c)
{
    brix_oci_hash_abort(c);
}
