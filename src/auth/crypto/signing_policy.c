/*
 * signing_policy.c — Globus EACL signing_policy parser + subject matcher.
 *
 * See signing_policy.h for the contract.  ngx-free: only libc + this header.
 * No globals; every allocation is owned by the returned brix_sp_policy_t and
 * released by brix_sp_free().  Any malformed input causes brix_sp_parse() to
 * fail closed (return NULL) so the caller rejects the corresponding CA.
 */
#include "auth/crypto/signing_policy.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * A single access_id_CA block: the CA DN it names, whether it grants signing
 * rights (pos_rights CA:sign seen and no overriding neg_rights), and the list
 * of cond_subjects globs a signed subject must match.
 */
typedef struct {
    char   *ca_dn;
    int     granted;
    int     denied;   /* neg_rights seen — overrides granted */
    char  **globs;
    size_t  nglobs;
    size_t  cap_globs;
} brix_sp_block_t;

struct brix_sp_policy_s {
    brix_sp_block_t *blocks;
    size_t           nblocks;
    size_t           cap_blocks;
};

/* -- small helpers --------------------------------------------------------- */

static char *
sp_strdup_n(const char *s, size_t n)
{
    char *out = malloc(n + 1);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static int
sp_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

/* Advance past leading whitespace; return pointer to first non-space. */
static const char *
sp_skip_space(const char *p, const char *end)
{
    while (p < end && sp_is_space(*p)) {
        p++;
    }
    return p;
}

/* Length of the whitespace-delimited token starting at p (no quote handling). */
static size_t
sp_token_len(const char *p, const char *end)
{
    const char *q = p;
    while (q < end && !sp_is_space(*q)) {
        q++;
    }
    return (size_t) (q - p);
}

static void
sp_set_err(char *errbuf, size_t errlen, size_t line, const char *fmt, ...)
{
    char detail[192];
    va_list ap;

    if (errbuf == NULL || errlen == 0) {
        return;
    }
    va_start(ap, fmt);
    /* phase74-fp: fmt is always a string literal from this file's call sites
     * (compile-time table of parse-error messages), never wire/user-derived;
     * truncation of the detail buffer is acceptable for an error message. */
    (void) vsnprintf(detail, sizeof(detail), fmt, ap);  // NOLINT(cert-err33-c,clang-diagnostic-format-nonliteral)
    va_end(ap);
    snprintf(errbuf, errlen, "line %zu: %s", line, detail);
}

/* -- glob matcher ---------------------------------------------------------- */

int
brix_sp_glob_match(const char *pat, const char *str)
{
    const char *star = NULL;
    const char *ss   = NULL;

    while (*str) {
        if (*pat == '?'
            || tolower((unsigned char) *pat) == tolower((unsigned char) *str))
        {
            pat++;
            str++;
        } else if (*pat == '*') {
            star = pat++;
            ss   = str;
        } else if (star != NULL) {
            pat = star + 1;
            str = ++ss;
        } else {
            return 0;
        }
    }
    while (*pat == '*') {
        pat++;
    }
    return *pat == '\0';
}

/* -- block/glob accumulation ----------------------------------------------- */

static brix_sp_block_t *
sp_open_block(brix_sp_policy_t *p, char *ca_dn)
{
    if (p->nblocks == p->cap_blocks) {
        size_t ncap = p->cap_blocks ? p->cap_blocks * 2 : 4;
        brix_sp_block_t *nb = realloc(p->blocks, ncap * sizeof(*nb));
        if (nb == NULL) {
            return NULL;
        }
        p->blocks = nb;
        p->cap_blocks = ncap;
    }

    brix_sp_block_t *b = &p->blocks[p->nblocks++];
    memset(b, 0, sizeof(*b));
    b->ca_dn = ca_dn;
    return b;
}

static int
sp_add_glob(brix_sp_block_t *b, const char *s, size_t n)
{
    char *g = sp_strdup_n(s, n);
    if (g == NULL) {
        return -1;
    }
    if (b->nglobs == b->cap_globs) {
        size_t ncap = b->cap_globs ? b->cap_globs * 2 : 4;
        char **ng = realloc(b->globs, ncap * sizeof(*ng));
        if (ng == NULL) {
            free(g);
            return -1;
        }
        b->globs = ng;
        b->cap_globs = ncap;
    }
    b->globs[b->nglobs++] = g;
    return 0;
}

/*
 * Extract the quoted string starting at *pp (first char is ' or ").  On
 * success sets out/outlen to the inner span and advances *pp past the close
 * quote; returns 0.  Returns -1 if there is no opening or matching close quote.
 */
static int
sp_take_quoted(const char **pp, const char *end,
               const char **out, size_t *outlen)
{
    const char *p = *pp;
    char        q;
    const char *inner;

    if (p >= end || (*p != '\'' && *p != '"')) {
        return -1;
    }
    q = *p++;
    inner = p;
    while (p < end && *p != q) {
        p++;
    }
    if (p >= end) {
        return -1;   /* unterminated quote */
    }
    *out = inner;
    *outlen = (size_t) (p - inner);
    *pp = p + 1;
    return 0;
}

/*
 * Parse the cond_subjects value region [p,end): either a single-quoted list
 * of double-quoted globs, a lone double-quoted glob, or a bare token.  Adds
 * each glob to the block.  Returns 0 on success, -1 on allocation failure.
 */
static int
sp_parse_cond_subjects(brix_sp_block_t *b, const char *p, const char *end)
{
    p = sp_skip_space(p, end);

    /* Strip an outer single-quote wrapper if present. */
    if (p < end && *p == '\'') {
        const char *inner;
        size_t      ilen;
        if (sp_take_quoted(&p, end, &inner, &ilen) == 0) {
            p = inner;
            end = inner + ilen;
        }
    }

    /* Collect every double-quoted glob in the region. */
    int found = 0;
    const char *scan = p;
    while (scan < end) {
        if (*scan == '"') {
            const char *g;
            size_t      glen;
            if (sp_take_quoted(&scan, end, &g, &glen) != 0) {
                break;
            }
            if (sp_add_glob(b, g, glen) != 0) {
                return -1;
            }
            found = 1;
        } else {
            scan++;
        }
    }

    if (found) {
        return 0;
    }

    /* No double quotes: treat the trimmed remainder as one bare glob. */
    const char *bstart = sp_skip_space(p, end);
    const char *bend = end;
    while (bend > bstart && sp_is_space(bend[-1])) {
        bend--;
    }
    if (bend > bstart) {
        return sp_add_glob(b, bstart, (size_t) (bend - bstart));
    }
    return 0;   /* empty cond_subjects — block simply grants nothing */
}

/* -- line dispatch --------------------------------------------------------- */

static int
sp_handle_access_id(brix_sp_policy_t *p, const char *rest, const char *end,
                    brix_sp_block_t **cur, size_t line,
                    char *errbuf, size_t errlen)
{
    const char *dn;
    size_t      dnlen;
    char       *ca_dn;

    /* Skip the type token (X509) and reach the quoted DN. */
    while (rest < end && *rest != '\'' && *rest != '"') {
        rest++;
    }
    if (sp_take_quoted(&rest, end, &dn, &dnlen) != 0 || dnlen == 0) {
        sp_set_err(errbuf, errlen, line, "access_id_CA missing quoted DN");
        return -1;
    }
    ca_dn = sp_strdup_n(dn, dnlen);
    if (ca_dn == NULL) {
        sp_set_err(errbuf, errlen, line, "out of memory");
        return -1;
    }
    *cur = sp_open_block(p, ca_dn);
    if (*cur == NULL) {
        free(ca_dn);
        sp_set_err(errbuf, errlen, line, "out of memory");
        return -1;
    }
    return 0;
}

static int
sp_handle_line(brix_sp_policy_t *p, const char *line, size_t len,
               brix_sp_block_t **cur, size_t lineno,
               char *errbuf, size_t errlen)
{
    const char *end = line + len;
    const char *p0  = sp_skip_space(line, end);
    size_t      klen;

    if (p0 >= end || *p0 == '#') {
        return 0;   /* blank or comment */
    }

    klen = sp_token_len(p0, end);
    const char *rest = sp_skip_space(p0 + klen, end);

    if (klen == 12 && strncmp(p0, "access_id_CA", 12) == 0) {
        return sp_handle_access_id(p, rest, end, cur, lineno, errbuf, errlen);
    }

    if (klen == 10 && strncmp(p0, "pos_rights", 10) == 0) {
        if (*cur == NULL) {
            sp_set_err(errbuf, errlen, lineno, "pos_rights before access_id_CA");
            return -1;
        }
        (*cur)->granted = 1;
        return 0;
    }

    if (klen == 10 && strncmp(p0, "neg_rights", 10) == 0) {
        if (*cur == NULL) {
            sp_set_err(errbuf, errlen, lineno, "neg_rights before access_id_CA");
            return -1;
        }
        (*cur)->denied = 1;
        return 0;
    }

    if (klen == 13 && strncmp(p0, "cond_subjects", 13) == 0) {
        if (*cur == NULL) {
            sp_set_err(errbuf, errlen, lineno,
                       "cond_subjects before access_id_CA");
            return -1;
        }
        /* Skip the auth-scope token (globus) then parse the glob region. */
        size_t slen = sp_token_len(rest, end);
        rest = sp_skip_space(rest + slen, end);
        if (sp_parse_cond_subjects(*cur, rest, end) != 0) {
            sp_set_err(errbuf, errlen, lineno, "out of memory");
            return -1;
        }
        return 0;
    }

    sp_set_err(errbuf, errlen, lineno, "unknown directive \"%.*s\"",
               (int) klen, p0);
    return -1;
}

/* -- public API ------------------------------------------------------------ */

brix_sp_policy_t *
brix_sp_parse(const char *buf, size_t len, char *errbuf, size_t errlen)
{
    brix_sp_policy_t *p;
    brix_sp_block_t  *cur = NULL;
    const char       *cursor = buf;
    const char       *end = buf + len;
    size_t            lineno = 0;

    p = calloc(1, sizeof(*p));
    if (p == NULL) {
        sp_set_err(errbuf, errlen, 0, "out of memory");
        return NULL;
    }

    while (cursor < end) {
        const char *nl = memchr(cursor, '\n', (size_t) (end - cursor));
        const char *lend = nl ? nl : end;
        size_t      llen = (size_t) (lend - cursor);

        /* Strip a trailing '\r' so CRLF files parse identically. */
        if (llen > 0 && cursor[llen - 1] == '\r') {
            llen--;
        }
        lineno++;

        if (sp_handle_line(p, cursor, llen, &cur, lineno, errbuf, errlen) != 0) {
            brix_sp_free(p);
            return NULL;
        }

        if (nl == NULL) {
            break;
        }
        cursor = nl + 1;
    }

    return p;
}

void
brix_sp_free(brix_sp_policy_t *p)
{
    if (p == NULL) {
        return;
    }
    for (size_t i = 0; i < p->nblocks; i++) {
        brix_sp_block_t *b = &p->blocks[i];
        for (size_t g = 0; g < b->nglobs; g++) {
            free(b->globs[g]);
        }
        free(b->globs);
        free(b->ca_dn);
    }
    free(p->blocks);
    free(p);
}

int
brix_sp_ca_dn_present(const brix_sp_policy_t *p, const char *ca_dn)
{
    if (p == NULL || ca_dn == NULL) {
        return 0;
    }
    for (size_t i = 0; i < p->nblocks; i++) {
        if (strcasecmp(p->blocks[i].ca_dn, ca_dn) == 0) {
            return 1;
        }
    }
    return 0;
}

int
brix_sp_subject_allowed(const brix_sp_policy_t *p,
                        const char *ca_dn, const char *subject_dn)
{
    if (p == NULL || ca_dn == NULL || subject_dn == NULL) {
        return 0;
    }
    for (size_t i = 0; i < p->nblocks; i++) {
        brix_sp_block_t *b = &p->blocks[i];

        if (strcasecmp(b->ca_dn, ca_dn) != 0) {
            continue;
        }
        if (!b->granted || b->denied) {
            continue;
        }
        for (size_t g = 0; g < b->nglobs; g++) {
            if (brix_sp_glob_match(b->globs[g], subject_dn)) {
                return 1;
            }
        }
    }
    return 0;
}
