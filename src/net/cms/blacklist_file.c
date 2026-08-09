/*
 * cms/blacklist_file.c — file-driven server blacklist (Phase-89 W6′).
 *
 * See blacklist_file.h for the contract.  Split: pure line parsing and entry
 * matching up top (no I/O), then the stat/read/re-assert poll driver.  The
 * blacklist file is operator host config (like the sss keytab), not managed
 * storage, so it is read with plain stdio below the VFS seam.
 */

#include "blacklist_file.h"
#include "net/manager/registry.h"
#include "auth/protbind/protbind.h"   /* §2.13: XrdOucNList `*` host matching */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>

/* ---- pure helpers ------------------------------------------------------- */

/* blfile_parse_ipv4 — dotted-quad text (len bytes, not NUL-terminated) to a
 * host-byte-order u32.  Returns 0 on success, -1 if not an IPv4 literal. */
static int
blfile_parse_ipv4(const char *s, size_t len, uint32_t *out)
{
    char            buf[INET_ADDRSTRLEN];
    struct in_addr  a;

    if (len == 0 || len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, s, len);
    buf[len] = '\0';
    if (inet_pton(AF_INET, buf, &a) != 1) {
        return -1;
    }
    *out = ntohl(a.s_addr);
    return 0;
}

/* blfile_parse_uint — bounded decimal parse of [s, s+len).  Returns the value
 * or -1 on empty/non-digit/overflow-past-max input. */
static long
blfile_parse_uint(const char *s, size_t len, long max)
{
    long    v = 0;
    size_t  i;

    if (len == 0) {
        return -1;
    }
    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        v = v * 10 + (s[i] - '0');
        if (v > max) {
            return -1;
        }
    }
    return v;
}

/* blfile_parse_cidr — IPv4 CIDR entry text ("a.b.c.d/n", slash points at the
 * '/').  Returns 0 with out filled as a CIDR entry, -1 on malformed input. */
static int
blfile_parse_cidr(const char *line, size_t len, const char *slash,
    brix_cms_blfile_entry_t *out)
{
    uint32_t  net;
    long      v;

    if (blfile_parse_ipv4(line, (size_t) (slash - line), &net) != 0) {
        return -1;
    }
    v = blfile_parse_uint(slash + 1, len - (size_t) (slash - line) - 1, 32);
    if (v < 0) {
        return -1;
    }
    out->is_cidr = 1;
    out->mask    = (v == 0) ? 0 : (uint32_t) (0xffffffffu << (32 - v));
    out->net     = net & out->mask;
    return 0;
}

/* blfile_find_port_colon — locate the port separator in a host[:port] line.
 * Bracketed IPv6 ([::1]:1094) keeps its colons inside the brackets; only a
 * colon AFTER the closing bracket (or in a bracket-less line with exactly one
 * colon) is a port separator.  A bare IPv6 literal (multiple colons, no
 * brackets) is taken whole as the host text.  Returns 0 with *colon set (NULL
 * when there is no port), -1 on a malformed bracketed line. */
static int
blfile_find_port_colon(const char *line, size_t len, const char **colon)
{
    *colon = NULL;
    if (line[0] == '[') {
        const char *rb = memchr(line, ']', len);

        if (rb == NULL) {
            return -1;
        }
        if ((size_t) (rb - line) + 1 < len) {
            if (rb[1] != ':') {
                return -1;
            }
            *colon = rb + 1;
        }
    } else {
        const char *first = memchr(line, ':', len);

        if (first != NULL
            && memchr(first + 1, ':', len - (size_t) (first - line) - 1) == NULL)
        {
            *colon = first;
        }
    }
    return 0;
}

/* blfile_parse_hostspec — the first token of a line: exact host, host:port,
 * IPv4 CIDR, or (§2.13) a `*` wildcard pattern (at most one star, whole-host
 * — a pattern takes no :port suffix, matching stock hostpat rules). */
static int
blfile_parse_hostspec(const char *line, size_t len,
    brix_cms_blfile_entry_t *out)
{
    const char *slash;
    const char *colon;
    const char *star;
    long        v;

    slash = memchr(line, '/', len);
    if (slash != NULL) {
        /* IPv4 CIDR: a.b.c.d/n */
        return blfile_parse_cidr(line, len, slash, out);
    }

    star = memchr(line, '*', len);
    if (star != NULL) {
        /* §2.13: wildcard pattern — exactly one star, no port suffix. */
        if (memchr(star + 1, '*', len - (size_t) (star - line) - 1) != NULL
            || len == 0 || len >= sizeof(out->host))
        {
            return -1;
        }
        memcpy(out->host, line, len);
        out->host[len] = '\0';
        out->is_pattern = 1;
        return 0;
    }

    if (blfile_find_port_colon(line, len, &colon) != 0) {
        return -1;
    }

    if (colon != NULL) {
        v = blfile_parse_uint(colon + 1, len - (size_t) (colon - line) - 1,
                              65535);
        if (v < 1) {
            return -1;
        }
        out->port = (uint16_t) v;
        len = (size_t) (colon - line);
    }

    if (len == 0 || len >= sizeof(out->host)) {
        return -1;
    }
    memcpy(out->host, line, len);
    out->host[len] = '\0';
    return 0;
}

/* blfile_parse_redirect — §2.13: the `redirect <host:port>` action tail.
 * The target must carry an explicit port (kYR_try names a concrete manager
 * endpoint — guessing one would bounce nodes into the void). */
static int
blfile_parse_redirect(const char *tok, size_t len,
    brix_cms_blfile_entry_t *out)
{
    const char *colon;
    long        v;

    if (blfile_find_port_colon(tok, len, &colon) != 0 || colon == NULL) {
        return -1;
    }
    v = blfile_parse_uint(colon + 1, len - (size_t) (colon - tok) - 1, 65535);
    if (v < 1) {
        return -1;
    }
    len = (size_t) (colon - tok);
    if (len == 0 || len >= sizeof(out->redirect_host)) {
        return -1;
    }
    memcpy(out->redirect_host, tok, len);
    out->redirect_host[len] = '\0';
    out->redirect_port = (uint16_t) v;
    out->has_redirect  = 1;
    return 0;
}

int
brix_cms_blfile_parse_line(const char *line, size_t len,
    brix_cms_blfile_entry_t *out)
{
    const char *ws;
    size_t      head_len;

    if (line == NULL || out == NULL || len == 0) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    /* §2.13: split an optional ` redirect <host:port>` action tail off the
     * hostspec head.  Any other interior whitespace stays malformed. */
    ws = memchr(line, ' ', len);
    if (ws == NULL) {
        ws = memchr(line, '\t', len);
    }
    head_len = (ws != NULL) ? (size_t) (ws - line) : len;

    if (ws != NULL) {
        const char *tail = ws;
        const char *tail_end = line + len;
        size_t      kw_len;

        while (tail < tail_end && (*tail == ' ' || *tail == '\t')) {
            tail++;
        }
        kw_len = sizeof("redirect") - 1;
        if ((size_t) (tail_end - tail) <= kw_len + 1
            || memcmp(tail, "redirect", kw_len) != 0
            || (tail[kw_len] != ' ' && tail[kw_len] != '\t'))
        {
            return -1;
        }
        tail += kw_len;
        while (tail < tail_end && (*tail == ' ' || *tail == '\t')) {
            tail++;
        }
        if (tail == tail_end
            || memchr(tail, ' ', (size_t) (tail_end - tail)) != NULL
            || memchr(tail, '\t', (size_t) (tail_end - tail)) != NULL
            || blfile_parse_redirect(tail, (size_t) (tail_end - tail),
                                     out) != 0)
        {
            return -1;
        }
    }

    return blfile_parse_hostspec(line, head_len, out);
}

int
brix_cms_blfile_entry_matches(const brix_cms_blfile_entry_t *e,
    const char *host, uint16_t port)
{
    if (e == NULL || host == NULL) {
        return 0;
    }

    if (e->is_cidr) {
        uint32_t addr;

        if (blfile_parse_ipv4(host, strlen(host), &addr) != 0) {
            return 0;    /* CIDR entries only cover IPv4 hosts */
        }
        return (addr & e->mask) == e->net;
    }

    if (e->is_pattern) {
        /* §2.13: one-`*` wildcard span, XrdOucNList rules — same matcher the
         * protbind host templates use, so the two grammars can never drift. */
        ngx_str_t tpl;

        tpl.data = (u_char *) e->host;
        tpl.len  = strlen(e->host);
        return brix_protbind_host_match(&tpl, host) ? 1 : 0;
    }

    if (strcmp(e->host, host) != 0) {
        return 0;
    }
    return e->port == 0 || e->port == port;
}

/* §2.13 — login-time consult over the loaded entry set (contract in .h). */
const brix_cms_blfile_entry_t *
brix_cms_blfile_find(const brix_cms_blfile_t *bl, const char *host,
    uint16_t port)
{
    ngx_uint_t  i;

    if (bl == NULL) {
        return NULL;
    }
    for (i = 0; i < bl->nentries; i++) {
        if (brix_cms_blfile_entry_matches(&bl->entries[i], host, port)) {
            return &bl->entries[i];
        }
    }
    return NULL;
}

/* ---- poll driver -------------------------------------------------------- */

/* blfile_scan_line — find the '\n'-terminated line at *pos in buf[0..got),
 * trim surrounding whitespace, and advance *pos past the line.  Returns the
 * trimmed bounds in *start / *end (start == end for a blank line). */
static void
blfile_scan_line(const char *buf, size_t got, size_t *pos,
    size_t *start, size_t *end)
{
    size_t  eol = *pos;

    while (eol < got && buf[eol] != '\n') {
        eol++;
    }

    /* Trim surrounding whitespace. */
    *start = *pos;
    *end   = eol;
    while (*start < *end && (buf[*start] == ' ' || buf[*start] == '\t'
                             || buf[*start] == '\r')) {
        (*start)++;
    }
    while (*end > *start && (buf[*end - 1] == ' ' || buf[*end - 1] == '\t'
                             || buf[*end - 1] == '\r')) {
        (*end)--;
    }
    *pos = eol + 1;
}

/* blfile_reload — parse the file at path into bl->entries, skipping comments,
 * blank lines, and (with a warning) malformed lines.  Never fails the poll:
 * an unreadable file simply keeps the previous entry set. */
static void
blfile_reload(brix_cms_blfile_t *bl, const char *path, ngx_log_t *log)
{
    /* vfs-seam-allow: operator blacklist file is host config, not managed storage */
    FILE   *f = fopen(path, "r");
    char    buf[BRIX_CMS_BLFILE_MAX_BYTES];
    size_t  got, pos;

    if (f == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "brix: cms blacklist file \"%s\" unreadable; "
                      "keeping previous %ui entries", path, bl->nentries);
        return;
    }
    got = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[got] = '\0';

    bl->nentries = 0;

    for (pos = 0; pos < got; /* advanced inside */) {
        size_t  start, end;

        /* Scan and trim the next line, then drop blanks and '#' comments. */
        blfile_scan_line(buf, got, &pos, &start, &end);
        if (start == end || buf[start] == '#') {
            continue;
        }

        if (bl->nentries >= BRIX_CMS_BLFILE_MAX_ENTRIES) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: cms blacklist file \"%s\": more than %d "
                          "entries; rest ignored", path,
                          BRIX_CMS_BLFILE_MAX_ENTRIES);
            break;
        }

        if (brix_cms_blfile_parse_line(buf + start, end - start,
                                       &bl->entries[bl->nentries]) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "brix: cms blacklist file \"%s\": skipping "
                          "malformed line \"%*s\"", path,
                          (int) (end - start), buf + start);
            continue;
        }
        bl->nentries++;
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: cms blacklist file \"%s\" loaded: %ui entries",
                  path, bl->nentries);
}

/*
 * blfile_refresh — the shared rate-limited stat/reload half of both polls.
 *
 * WHAT: Applies the poll rate limit, re-reads the file on an mtime change,
 *       and reports (1) whether enforcement should run this call.
 * WHY:  Blacklist and whitelist modes differ only in the enforcement rule;
 *       one refresh keeps the stat cadence and reload behaviour identical.
 * HOW:  Exactly the original poll prologue, factored.
 */
static int
blfile_refresh(brix_cms_blfile_t *bl, const ngx_str_t *path,
    ngx_uint_t force, ngx_log_t *log)
{
    char         pathbuf[1024];
    struct stat  st;

    if (bl == NULL || path == NULL || path->len == 0
        || path->len >= sizeof(pathbuf))
    {
        return 0;
    }
    if (!force && bl->next_poll != 0 && ngx_current_msec < bl->next_poll) {
        return 0;
    }
    bl->next_poll = ngx_current_msec + BRIX_CMS_BLFILE_POLL_MS;

    memcpy(pathbuf, path->data, path->len);
    pathbuf[path->len] = '\0';

    if (stat(pathbuf, &st) != 0) {  /* vfs-seam-allow: operator config file, not managed storage */
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "brix: cms blacklist file \"%s\" stat failed; "
                      "keeping previous %ui entries", pathbuf, bl->nentries);
    } else if (st.st_mtime != bl->mtime) {
        blfile_reload(bl, pathbuf, log);
        bl->mtime = st.st_mtime;
    }

    return bl->nentries > 0;
}

/* blfile_enforce — walk a registry snapshot and blacklist every server whose
 * membership test (`matching` for blacklist mode, non-matching for whitelist
 * mode) says it must not serve.  The snapshot is a by-value copy, so no
 * registry lock is held while we walk (brix_srv_blacklist locks per call).
 * Heap, not stack — 128 snapshot entries are ~80 KB. */
static void
blfile_enforce(const brix_cms_blfile_t *bl, ngx_msec_t blacklist_ms,
    int want_match, ngx_log_t *log)
{
    brix_srv_snapshot_entry_t  *snap;
    ngx_uint_t                  n, s;

    snap = ngx_alloc(sizeof(*snap) * BRIX_SRV_REGISTRY_SLOTS, log);
    if (snap == NULL) {
        return;
    }
    n = brix_srv_snapshot(snap, BRIX_SRV_REGISTRY_SLOTS, ngx_current_msec);
    for (s = 0; s < n; s++) {
        int matched =
            brix_cms_blfile_find(bl, snap[s].host, snap[s].port) != NULL;

        if (matched == want_match) {
            brix_srv_blacklist(snap[s].host, snap[s].port, blacklist_ms);
        }
    }
    ngx_free(snap);
}

void
brix_cms_blfile_poll(brix_cms_blfile_t *bl, const ngx_str_t *path,
    ngx_msec_t blacklist_ms, ngx_uint_t force, ngx_log_t *log)
{
    if (!blfile_refresh(bl, path, force, log)) {
        return;
    }
    blfile_enforce(bl, blacklist_ms, 1 /* matching entries are banned */, log);
}

/* §2.13 — whitelist mode: everyone NOT matching an entry is banned.  An empty
 * or unreadable whitelist enforces nothing (fail-open toward availability —
 * an operator emptying the file must not drain the whole cluster). */
void
brix_cms_wlfile_poll(brix_cms_blfile_t *wl, const ngx_str_t *path,
    ngx_msec_t blacklist_ms, ngx_uint_t force, ngx_log_t *log)
{
    if (!blfile_refresh(wl, path, force, log)) {
        return;
    }
    blfile_enforce(wl, blacklist_ms, 0 /* NON-matching servers are banned */,
                   log);
}
