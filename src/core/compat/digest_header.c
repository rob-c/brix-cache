/*
 * digest_header.c — RFC-3230 `Digest:` header grammar (see digest_header.h).
 *
 * The token table is the single source of truth for three facts per algorithm:
 * the wire token, the canonical brix name, and whether the value is base64 or
 * hex. It grew out of the WebDAV PUT ingest-digest parser, which now shares it
 * with the sd_http checksum-offload slot rather than keeping a private copy.
 */

#include "digest_header.h"

#include "hex.h"      /* brix_hex_encode — lowercase, NUL-terminated */

/* Decode scratch for a base64 value. Sized by ngx_base64_decoded_length(), NOT
 * by the digest width: that bound is ((len+3)/4)*3, which for a padded sha-512
 * (88 chars) is 66 — three bytes over the 64 the digest actually occupies. A
 * buffer sized at 64 makes every sha-512 fail the pre-decode bound check and
 * read as an unusable value. The true width is still enforced downstream, by
 * the hex output not fitting BRIX_DIGEST_HEX_MAX. */
#define BRIX_DIGEST_RAW_MAX  72

/* `b64` = the value is base64 (md5/sha per RFC 3230 + RFC 1864); otherwise it
 * is lowercase hex (the WLCG/dCache convention for the CRC family). `hexw` is
 * the algorithm's fixed hex width, used to re-pad a value an origin trimmed.
 *
 * Both spellings of each SHA name are listed because origins disagree: RFC 3230
 * registers the hyphenated form, several WLCG endpoints send the bare one. The
 * hyphenated spelling comes first so the reverse lookup that builds a
 * `Want-Digest:` request asks in the registered form. */
static const struct {
    const char *tok;
    size_t      toklen;
    const char *alg;
    int         b64;
    size_t      hexw;
} digest_tokens[] = {
    { "md5",     3, "md5",     1,  32 },
    { "sha-256", 7, "sha256",  1,  64 },
    { "sha256",  6, "sha256",  1,  64 },
    { "sha-512", 7, "sha512",  1, 128 },
    { "sha512",  6, "sha512",  1, 128 },
    { "sha-1",   5, "sha1",    1,  40 },
    { "sha1",    4, "sha1",    1,  40 },
    { "adler32", 7, "adler32", 0,   8 },
    { "crc32c",  6, "crc32c",  0,   8 },
    { "crc32",   5, "crc32",   0,   8 },
};

#define DIGEST_NTOKENS  (sizeof(digest_tokens) / sizeof(digest_tokens[0]))

const char *
brix_digest_wire_token(const char *canon_alg)
{
    size_t i;

    if (canon_alg == NULL) {
        return NULL;
    }
    for (i = 0; i < DIGEST_NTOKENS; i++) {
        if (ngx_strcmp(canon_alg, digest_tokens[i].alg) == 0) {
            return digest_tokens[i].tok;
        }
    }
    return NULL;
}

/*
 * WHAT: Classify one ASCII hexadecimal digit from a checksum header.
 * WHY:  Value decoding keeps output sizing separate from byte grammar.
 * HOW:  Accept decimal digits and either case of the six hex letters.
 */
static int
digest_is_hex(u_char value)
{
    return (value >= '0' && value <= '9') ||
           (value >= 'a' && value <= 'f') ||
           (value >= 'A' && value <= 'F');
}

/*
 * WHAT: Copy a hex-encoded digest value into `out`, lowercased.
 * WHY:  Split from the base64 leg so neither branch carries the other's nesting.
 * HOW:  Validate the WHOLE value before writing a byte of it — a malformed
 *       value must never be reported as a digest, since the caller treats what
 *       it gets as truth, and a rejected value must leave `out` untouched
 *       rather than seeded with a shorter prefix that still looks like hex.
 */
static ngx_int_t
digest_hex_copy(const u_char *val, size_t vlen, char *out, size_t outsz)
{
    size_t i;

    if (vlen + 1 > outsz) {
        return NGX_ERROR;
    }
    for (i = 0; i < vlen; i++) {
        if (!digest_is_hex(val[i])) {
            return NGX_ERROR;
        }
    }
    for (i = 0; i < vlen; i++) {
        out[i] = (char) ngx_tolower(val[i]);
    }
    out[vlen] = '\0';
    return NGX_OK;
}

/*
 * WHAT: Decode a base64 digest value and hex-encode it into `out`.
 * WHY:  RFC 3230 carries md5/sha values in base64; every consumer here compares
 *       hex. HOW: bound the decode against a stack buffer first (no pool on a
 *       driver thread), then ngx_decode_base64 + brix_hex_encode.
 */
static ngx_int_t
digest_b64_hex(const u_char *val, size_t vlen, char *out, size_t outsz)
{
    u_char    raw[BRIX_DIGEST_RAW_MAX];
    ngx_str_t src, dst;

    if (ngx_base64_decoded_length(vlen) > sizeof(raw)) {
        return NGX_ERROR;
    }
    src.data = (u_char *) val;
    src.len  = vlen;
    dst.data = raw;
    if (ngx_decode_base64(&dst, &src) != NGX_OK) {
        return NGX_ERROR;
    }
    if (dst.len == 0 || dst.len * 2 + 1 > outsz) {
        return NGX_ERROR;
    }
    brix_hex_encode(raw, dst.len, out);
    return NGX_OK;
}

ngx_int_t
brix_digest_value_hex(const u_char *val, size_t vlen, int is_b64, char *out,
    size_t outsz)
{
    if (vlen == 0 || outsz == 0) {
        return NGX_ERROR;
    }
    return is_b64 ? digest_b64_hex(val, vlen, out, outsz)
                  : digest_hex_copy(val, vlen, out, outsz);
}

void
brix_digest_hex_pad(const char *canon_alg, char *hex, size_t hex_sz)
{
    size_t i, have, want = 0;

    for (i = 0; i < DIGEST_NTOKENS; i++) {
        if (ngx_strcmp(canon_alg, digest_tokens[i].alg) == 0) {
            want = digest_tokens[i].hexw;
            break;
        }
    }
    have = ngx_strlen(hex);
    if (want == 0 || have >= want || want + 1 > hex_sz) {
        return;
    }
    ngx_memmove(hex + (want - have), hex, have + 1);
    ngx_memset(hex, '0', want - have);
}

/* Where one matched pair's result is delivered. Bundled so the per-pair helper
 * stays readable: `want` NULL means "the first supported algorithm wins". */
typedef struct {
    const char  *want;
    const char **alg_out;
    char        *hex_out;
    size_t       hex_sz;
} digest_sink_t;

/* Strip leading and trailing linear whitespace from a [*s, *s+*len) slice. */
static void
digest_tok_trim(const u_char **s, size_t *len)
{
    const u_char *p = *s;
    size_t        n = *len;

    while (n > 0 && (*p == ' ' || *p == '\t')) { p++; n--; }
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t')) { n--; }
    *s = p;
    *len = n;
}

/*
 * WHAT: Decide one trimmed `token=value` pair. Returns 1 when the pair settles
 *       the scan (*kind then FOUND or BAD), 0 to keep looking.
 * WHY:  An origin may list several digests; only the one the caller asked for
 *       (or, with no request, the first we understand) may end the scan.
 * HOW:  Table match on the token → skip when a specific algorithm was asked for
 *       and this is not it → normalise the value per the table's encoding flag.
 */
static int
digest_pair(const u_char *tok, size_t tlen, const u_char *v, size_t vlen,
    const digest_sink_t *sink, brix_digest_kind_t *kind)
{
    size_t i;

    for (i = 0; i < DIGEST_NTOKENS; i++) {
        if (tlen != digest_tokens[i].toklen
            || ngx_strncasecmp((u_char *) tok,
                   (u_char *) digest_tokens[i].tok, tlen) != 0)
        {
            continue;
        }
        if (sink->want != NULL
            && ngx_strcmp(sink->want, digest_tokens[i].alg) != 0)
        {
            return 0;                  /* a digest, but not the one asked for */
        }
        if (brix_digest_value_hex(v, vlen, digest_tokens[i].b64,
                sink->hex_out, sink->hex_sz) != NGX_OK)
        {
            *kind = BRIX_DIGEST_BAD;
        } else {
            if (sink->alg_out != NULL) { *sink->alg_out = digest_tokens[i].alg; }
            *kind = BRIX_DIGEST_FOUND;
        }
        return 1;
    }
    return 0;
}

brix_digest_kind_t
brix_digest_header_scan(const u_char *val, size_t len, const char *want_canon,
    const char **alg_out, char *hex_out, size_t hex_sz)
{
    digest_sink_t       sink = { want_canon, alg_out, hex_out, hex_sz };
    brix_digest_kind_t  kind = BRIX_DIGEST_NONE;
    const u_char       *p = val, *end = val + len;

    if (val == NULL || hex_out == NULL || hex_sz == 0) {
        return BRIX_DIGEST_NONE;
    }
    while (p < end) {
        const u_char *comma = ngx_strlchr((u_char *) p, (u_char *) end, ',');
        const u_char *iend  = comma ? comma : end;
        const u_char *eq    = ngx_strlchr((u_char *) p, (u_char *) iend, '=');

        if (eq != NULL) {
            const u_char *tok = p, *v = eq + 1;
            size_t        tlen = (size_t) (eq - p);
            size_t        vlen = (size_t) (iend - (eq + 1));

            digest_tok_trim(&tok, &tlen);
            digest_tok_trim(&v, &vlen);
            if (digest_pair(tok, tlen, v, vlen, &sink, &kind)) {
                return kind;
            }
        }
        p = comma ? comma + 1 : end;
    }
    return BRIX_DIGEST_NONE;
}
