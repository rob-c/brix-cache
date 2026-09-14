/*
 * resolv_conf.c — resolv.conf(5) parser (phase-116 W1).
 *
 * WHAT: The implementation behind resolv_conf.h: defaults, a line tokenizer,
 *       keyword handlers for nameserver/search/domain/options, the env
 *       overrides, and a bounded file loader.
 * WHY:  Must behave like the host resolver (glibc) so a hostname that works
 *       for `getent hosts` on the box works the same way inside brix: last
 *       search/domain line wins, options accumulate, unknown tokens are
 *       ignored, and hard limits are silently enforced.
 * HOW:  No allocation — every value lands in the fixed arrays of
 *       brix_resolv_conf_t; the loader reads at most 64 KiB (resolv.conf is a
 *       few lines; a bigger file is not one).  Pure C so the unittest builds it
 *       without nginx.
 */
#include "core/types/tunables.h"
#include "resolv_conf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define RESOLV_READ_MAX   BRIX_DNS_RESOLV_READ_MAX
#define RESOLV_NDOTS_MAX  15
#define RESOLV_TIMEOUT_MAX 30
#define RESOLV_ATTEMPTS_MAX 5


void
brix_resolv_conf_defaults(brix_resolv_conf_t *rc)
{
    memset(rc, 0, sizeof(*rc));
    strcpy(rc->nameservers[0], "127.0.0.1");
    rc->nnameservers = 1;
    rc->ndots    = 1;
    rc->timeout  = 5;
    rc->attempts = 2;
    rc->defaulted = 1;   /* cleared by the loader once a file was read */
}


unsigned
brix_resolv_conf_count_dots(const char *name, size_t len)
{
    unsigned  n = 0;
    size_t    i;

    if (len > 0 && name[len - 1] == '.') {
        len--;
    }
    for (i = 0; i < len; i++) {
        if (name[i] == '.') {
            n++;
        }
    }
    return n;
}


/* Copy a bounded token into a NUL-terminated buffer; 0 when it does not fit. */
static int
resolv_copy_token(char *dst, size_t dstsz, const char *tok, size_t len)
{
    if (len == 0 || len >= dstsz) {
        return 0;
    }
    memcpy(dst, tok, len);
    dst[len] = '\0';
    return 1;
}


/* The digits after "host:": 1..65535 and nothing else. */
static int
resolv_port_ok(const char *p, size_t len)
{
    unsigned  v = 0;
    size_t    i;

    if (len == 0 || len > 5) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return 0;
        }
        v = v * 10 + (unsigned) (p[i] - '0');
    }
    return v >= 1 && v <= BRIX_DNS_PORT_MAX;
}


/* inet_pton() on a bounded host token (zone already stripped). */
static int
resolv_is_literal(const char *host, size_t len, int family)
{
    char           buf[BRIX_RESOLV_NS_LEN];
    unsigned char  addr[16];

    if (len == 0 || len >= sizeof(buf)) {
        return 0;
    }
    memcpy(buf, host, len);
    buf[len] = '\0';
    return inet_pton(family, buf, addr) == 1;
}


/* "[v6]" or "[v6]:port" (zone inside the brackets dropped) -> stored as
 * "v6" or "[v6]:port". */
static int
resolv_bracketed_ns(const char *tok, size_t len, char *dst, size_t dstsz)
{
    const char *close = memchr(tok, ']', len);
    const char *pct;
    size_t      inner, rest;
    int         n;

    if (close == NULL) {
        return 0;
    }
    inner = (size_t) (close - tok - 1);
    pct = memchr(tok + 1, '%', inner);
    if (pct != NULL) {
        inner = (size_t) (pct - (tok + 1));
    }
    if (!resolv_is_literal(tok + 1, inner, AF_INET6)) {
        return 0;
    }
    rest = len - (size_t) (close + 1 - tok);
    if (rest == 0) {
        return resolv_copy_token(dst, dstsz, tok + 1, inner);
    }
    if (close[1] != ':' || !resolv_port_ok(close + 2, rest - 1)) {
        return 0;
    }
    n = snprintf(dst, dstsz, "[%.*s]%.*s", (int) inner, tok + 1,
                 (int) rest, close + 1);
    return n > 0 && (size_t) n < dstsz;
}


/* "v4", "v4:port" or a bare "v6" (zone dropped) -> stored as written. */
static int
resolv_plain_ns(const char *tok, size_t len, char *dst, size_t dstsz)
{
    const char *pct = memchr(tok, '%', len);
    const char *colon, *second;
    size_t      after;

    if (pct != NULL) {
        len = (size_t) (pct - tok);
    }
    colon = memchr(tok, ':', len);
    if (colon == NULL) {
        return resolv_is_literal(tok, len, AF_INET)
               && resolv_copy_token(dst, dstsz, tok, len);
    }
    after = len - (size_t) (colon + 1 - tok);
    second = memchr(colon + 1, ':', after);
    if (second == NULL) {
        return resolv_is_literal(tok, (size_t) (colon - tok), AF_INET)
               && resolv_port_ok(colon + 1, after)
               && resolv_copy_token(dst, dstsz, tok, len);
    }
    return resolv_is_literal(tok, len, AF_INET6)
           && resolv_copy_token(dst, dstsz, tok, len);
}


/* WHAT: nameserver <addr>[:port] — the first nameserver line replaces the
 *       127.0.0.1 default; only address literals are kept (v4, v4:port, v6,
 *       [v6], [v6]:port), an IPv6 zone ("%eth0") is dropped because nginx's
 *       resolver cannot bind a scope id, and ":port" is the brix extension
 *       that lets an unprivileged stub serve the tests.
 * WHY:  glibc ignores a nameserver line it cannot parse as an address.  If
 *       the token were passed through, nginx's `resolver` would look the name
 *       up at configuration time — the blocking startup DNS dependency
 *       phase 116 exists to remove.  A file whose nameserver lines are all
 *       unparseable therefore ends with nnameservers == 0, which the builder
 *       reports and turns into the libc thread-pool fallback. */
static void
resolv_kw_nameserver(brix_resolv_conf_t *rc, const char *tok, size_t len,
    unsigned *seen_ns)
{
    char  *dst;
    int    kept;

    if (!*seen_ns) {
        rc->nnameservers = 0;
        *seen_ns = 1;
    }
    if (rc->nnameservers >= BRIX_RESOLV_MAX_NS) {
        return;
    }
    dst = rc->nameservers[rc->nnameservers];
    kept = (len > 0 && tok[0] == '[')
           ? resolv_bracketed_ns(tok, len, dst, BRIX_RESOLV_NS_LEN)
           : resolv_plain_ns(tok, len, dst, BRIX_RESOLV_NS_LEN);
    if (kept) {
        rc->nnameservers++;
    }
}


/* search/domain: the LAST such line wins (glibc), so reset then append. */
static void
resolv_kw_search(brix_resolv_conf_t *rc, const char *rest, size_t len)
{
    size_t  i = 0;

    rc->nsearch = 0;
    while (i < len && rc->nsearch < BRIX_RESOLV_MAX_SEARCH) {
        size_t  start, tlen;

        while (i < len && (rest[i] == ' ' || rest[i] == '\t')) {
            i++;
        }
        start = i;
        while (i < len && rest[i] != ' ' && rest[i] != '\t') {
            i++;
        }
        tlen = i - start;
        if (tlen > 0 && rest[start] != '.'
            && resolv_copy_token(rc->search[rc->nsearch],
                                 BRIX_RESOLV_DOMAIN_LEN, rest + start, tlen))
        {
            /* a trailing dot on a search domain is dropped (glibc) */
            size_t  n = strlen(rc->search[rc->nsearch]);
            if (rc->search[rc->nsearch][n - 1] == '.') {
                rc->search[rc->nsearch][n - 1] = '\0';
            }
            rc->nsearch++;
        }
    }
}


/* Clamp a numeric "name:N" option into [1, max] (0 -> 1, as glibc does). */
static unsigned
resolv_clamp(unsigned val, unsigned max)
{
    if (val == 0) {
        return 1;
    }
    return val > max ? max : val;
}


/* One "options" token: ndots:N, timeout:N, attempts:N, rotate; anything
 * else (edns0, single-request, ...) is ignored. */
static void
resolv_option(brix_resolv_conf_t *rc, const char *tok, size_t len)
{
    const char *colon = memchr(tok, ':', len);
    size_t      nlen  = colon ? (size_t) (colon - tok) : len;
    unsigned    val   = colon ? (unsigned) strtoul(colon + 1, NULL, 10) : 0;

    if (colon == NULL) {
        if (nlen == 6 && memcmp(tok, "rotate", 6) == 0) {
            rc->rotate = 1;
        }
        return;
    }
    if (nlen == 5 && memcmp(tok, "ndots", 5) == 0) {
        rc->ndots = val > RESOLV_NDOTS_MAX ? RESOLV_NDOTS_MAX : val;
    } else if (nlen == 7 && memcmp(tok, "timeout", 7) == 0) {
        rc->timeout = resolv_clamp(val, RESOLV_TIMEOUT_MAX);
    } else if (nlen == 8 && memcmp(tok, "attempts", 8) == 0) {
        rc->attempts = resolv_clamp(val, RESOLV_ATTEMPTS_MAX);
    }
}


static void
resolv_kw_options(brix_resolv_conf_t *rc, const char *rest, size_t len)
{
    size_t  i = 0;

    while (i < len) {
        size_t  start;

        while (i < len && (rest[i] == ' ' || rest[i] == '\t')) {
            i++;
        }
        start = i;
        while (i < len && rest[i] != ' ' && rest[i] != '\t') {
            i++;
        }
        if (i > start) {
            resolv_option(rc, rest + start, i - start);
        }
    }
}


/* Keyword tokens are matched by (length, text); a table keeps resolv_line a
 * flat walk instead of a chain of memcmp branches. */
typedef enum { RESOLV_KW_NONE, RESOLV_KW_NAMESERVER, RESOLV_KW_SEARCH,
               RESOLV_KW_OPTIONS } resolv_kw_t;

static resolv_kw_t
resolv_keyword(const char *kw, size_t len)
{
    static const struct { const char *name; size_t len; resolv_kw_t kw; } tab[] = {
        { "nameserver", 10, RESOLV_KW_NAMESERVER },
        { "search",      6, RESOLV_KW_SEARCH },
        { "domain",      6, RESOLV_KW_SEARCH },
        { "options",     7, RESOLV_KW_OPTIONS },
    };
    size_t  i;

    for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
        if (tab[i].len == len && memcmp(kw, tab[i].name, len) == 0) {
            return tab[i].kw;
        }
    }
    return RESOLV_KW_NONE;
}


static int
resolv_is_blank(char c)
{
    return c == ' ' || c == '\t';
}


/* Split "  keyword   rest  " into its keyword and its trimmed remainder.
 * Returns 0 when the line carries no keyword or no argument. */
static int
resolv_split_line(const char *line, size_t len, const char **kw, size_t *kw_len,
    const char **rest, size_t *rest_len)
{
    size_t  i = 0, start;

    while (i < len && resolv_is_blank(line[i])) {
        i++;
    }
    start = i;
    while (i < len && !resolv_is_blank(line[i])) {
        i++;
    }
    *kw = line + start;
    *kw_len = i - start;
    while (i < len && resolv_is_blank(line[i])) {
        i++;
    }
    *rest = line + i;
    *rest_len = len - i;
    while (*rest_len > 0
           && (resolv_is_blank((*rest)[*rest_len - 1])
               || (*rest)[*rest_len - 1] == '\r'))
    {
        (*rest_len)--;
    }
    return *kw_len != 0 && *rest_len != 0;
}


/* One line of resolv.conf: "keyword arg..." — comments and blank lines were
 * dropped by the caller.  sortlist / lookup / unknown keywords are ignored,
 * as glibc does. */
static void
resolv_line(brix_resolv_conf_t *rc, const char *line, size_t len,
    unsigned *seen_ns)
{
    const char  *kw, *rest;
    size_t       kw_len, rest_len, tlen = 0;

    if (!resolv_split_line(line, len, &kw, &kw_len, &rest, &rest_len)) {
        return;
    }
    switch (resolv_keyword(kw, kw_len)) {
    case RESOLV_KW_NAMESERVER:
        while (tlen < rest_len && !resolv_is_blank(rest[tlen])) {
            tlen++;
        }
        resolv_kw_nameserver(rc, rest, tlen, seen_ns);
        break;
    case RESOLV_KW_SEARCH:
        resolv_kw_search(rc, rest, rest_len);
        break;
    case RESOLV_KW_OPTIONS:
        resolv_kw_options(rc, rest, rest_len);
        break;
    case RESOLV_KW_NONE:
        break;
    }
}


void
brix_resolv_conf_parse_text(brix_resolv_conf_t *rc, const char *text,
    size_t len)
{
    size_t    i = 0;
    unsigned  seen_ns = 0;

    while (i < len) {
        size_t      start = i, llen;
        const char *hash;

        while (i < len && text[i] != '\n') {
            i++;
        }
        llen = i - start;
        if (i < len) {
            i++;                                   /* skip the newline */
        }
        /* comments start with '#' or ';' anywhere on the line */
        hash = memchr(text + start, '#', llen);
        if (hash != NULL) {
            llen = (size_t) (hash - (text + start));
        }
        hash = memchr(text + start, ';', llen);
        if (hash != NULL) {
            llen = (size_t) (hash - (text + start));
        }
        resolv_line(rc, text + start, llen, &seen_ns);
    }
}


void
brix_resolv_conf_apply_env(brix_resolv_conf_t *rc, const char *localdomain,
    const char *res_options)
{
    if (localdomain != NULL && localdomain[0] != '\0') {
        resolv_kw_search(rc, localdomain, strlen(localdomain));
        rc->env_search = 1;
    }
    if (res_options != NULL && res_options[0] != '\0') {
        resolv_kw_options(rc, res_options, strlen(res_options));
    }
}


int
brix_resolv_conf_load(brix_resolv_conf_t *rc, const char *path)
{
    FILE   *fp;
    char   *buf;
    size_t  n;

    brix_resolv_conf_defaults(rc);
    if (path == NULL || path[0] == '\0') {
        path = BRIX_RESOLV_DEFAULT_PATH;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        brix_resolv_conf_apply_env(rc, getenv("LOCALDOMAIN"),
                                   getenv("RES_OPTIONS"));
        return -1;
    }
    buf = malloc(RESOLV_READ_MAX);
    if (buf == NULL) {
        fclose(fp);
        brix_resolv_conf_apply_env(rc, getenv("LOCALDOMAIN"),
                                   getenv("RES_OPTIONS"));
        return -1;
    }
    n = fread(buf, 1, RESOLV_READ_MAX, fp);
    if (n == 0 && ferror(fp)) {
        /* The path opened but holds no readable content — a directory (fopen
         * succeeds, the first read is EISDIR) or an I/O error. That is the
         * operator's own path being unusable, not an empty resolv.conf, so
         * report it like an unopenable file instead of silently keeping the
         * 127.0.0.1 default. A genuinely empty file reads 0 bytes with no
         * error and still defaults, as glibc does.
         */
        fclose(fp);
        free(buf);
        brix_resolv_conf_apply_env(rc, getenv("LOCALDOMAIN"),
                                   getenv("RES_OPTIONS"));
        return -1;
    }
    fclose(fp);

    rc->defaulted = 0;
    brix_resolv_conf_parse_text(rc, buf, n);
    free(buf);
    brix_resolv_conf_apply_env(rc, getenv("LOCALDOMAIN"),
                               getenv("RES_OPTIONS"));
    return 0;
}
