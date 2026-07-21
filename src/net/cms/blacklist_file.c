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

int
brix_cms_blfile_parse_line(const char *line, size_t len,
    brix_cms_blfile_entry_t *out)
{
    const char *slash;
    const char *colon;
    long        v;

    if (line == NULL || out == NULL || len == 0
        || memchr(line, ' ', len) != NULL || memchr(line, '\t', len) != NULL)
    {
        return -1;    /* interior whitespace: not a host, reject not guess */
    }
    memset(out, 0, sizeof(*out));

    slash = memchr(line, '/', len);
    if (slash != NULL) {
        /* IPv4 CIDR: a.b.c.d/n */
        uint32_t net;

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

    /* host[:port] — bracketed IPv6 ([::1]:1094) keeps its colons inside the
     * brackets; only a colon AFTER the closing bracket (or in a bracket-less
     * line with exactly one colon) is a port separator.  A bare IPv6 literal
     * (multiple colons, no brackets) is taken whole as the host text. */
    colon = NULL;
    if (line[0] == '[') {
        const char *rb = memchr(line, ']', len);

        if (rb == NULL) {
            return -1;
        }
        if ((size_t) (rb - line) + 1 < len) {
            if (rb[1] != ':') {
                return -1;
            }
            colon = rb + 1;
        }
    } else {
        const char *first = memchr(line, ':', len);

        if (first != NULL
            && memchr(first + 1, ':', len - (size_t) (first - line) - 1) == NULL)
        {
            colon = first;
        }
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

    if (strcmp(e->host, host) != 0) {
        return 0;
    }
    return e->port == 0 || e->port == port;
}

/* ---- poll driver -------------------------------------------------------- */

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
        size_t  eol = pos, start, end;

        while (eol < got && buf[eol] != '\n') {
            eol++;
        }

        /* Trim surrounding whitespace, then drop blanks and '#' comments. */
        start = pos;
        end   = eol;
        while (start < end && (buf[start] == ' ' || buf[start] == '\t'
                               || buf[start] == '\r')) {
            start++;
        }
        while (end > start && (buf[end - 1] == ' ' || buf[end - 1] == '\t'
                               || buf[end - 1] == '\r')) {
            end--;
        }
        pos = eol + 1;
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

void
brix_cms_blfile_poll(brix_cms_blfile_t *bl, const ngx_str_t *path,
    ngx_msec_t blacklist_ms, ngx_uint_t force, ngx_log_t *log)
{
    char         pathbuf[1024];
    struct stat  st;
    ngx_uint_t   i, n, s;

    if (bl == NULL || path == NULL || path->len == 0
        || path->len >= sizeof(pathbuf))
    {
        return;
    }
    if (!force && bl->next_poll != 0 && ngx_current_msec < bl->next_poll) {
        return;
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

    if (bl->nentries == 0) {
        return;
    }

    /* Re-assert against every registered server that matches an entry.  The
     * snapshot is a by-value copy, so no registry lock is held while we walk
     * and re-blacklist (brix_srv_blacklist takes the lock per call).  Heap,
     * not stack — 128 snapshot entries are ~80 KB. */
    {
        brix_srv_snapshot_entry_t  *snap;

        snap = ngx_alloc(sizeof(*snap) * BRIX_SRV_REGISTRY_SLOTS, log);
        if (snap == NULL) {
            return;
        }
        n = brix_srv_snapshot(snap, BRIX_SRV_REGISTRY_SLOTS,
                              ngx_current_msec);
        for (s = 0; s < n; s++) {
            for (i = 0; i < bl->nentries; i++) {
                if (brix_cms_blfile_entry_matches(&bl->entries[i],
                                                  snap[s].host, snap[s].port))
                {
                    brix_srv_blacklist(snap[s].host, snap[s].port,
                                         blacklist_ms);
                    break;
                }
            }
        }
        ngx_free(snap);
    }
}
