/*
 * webfile.c — HTTP(S)/WebDAV transport for the FUSE driver (read path).
 *
 * WHAT: A small "web file" layer mirroring the root:// mfile API so the FUSE
 *       driver can mount an http/https/dav/davs endpoint:
 *         - xrdc_web_stat()    : PROPFIND Depth:0  → size/mtime/is-dir (getattr)
 *         - xrdc_web_readdir() : PROPFIND Depth:1  → child entries (readdir)
 *         - xrdc_webfile_open/pread/close : a file opened for read whose pread
 *           issues an HTTP Range GET over a PERSISTENT keep-alive connection, so
 *           sequential FUSE reads do not pay a TCP+TLS handshake each — essential
 *           for a fair root-vs-https performance comparison. Resilient: a dropped
 *           connection is transparently re-established and the read re-issued.
 * WHY:  Lets one FUSE driver serve the same namespace over either the binary
 *       root:// protocol or HTTP(S)/WebDAV, against this server or any standard
 *       WebDAV/XrdHttp server, for an apples-to-apples protocol comparison.
 * HOW:  Metadata uses the generic one-shot xrdc_http_req (PROPFIND); the read hot
 *       path keeps its own socket. PROPFIND XML is parsed namespace-prefix-
 *       agnostically (D:, lp1:, a:, or none) so it works across server vendors.
 *       Auth is anonymous or Bearer-token (Authorization header); TLS verifies
 *       the server chain against ca_dir (https/davs).
 *
 * Clean-room: composes the public http/tls/uri helpers; no libXrdCl.
 */
#include "xrdc.h"
#include "compat/uri.h"
#include "compat/host_format.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>

#define WEB_TIMEOUT_MS   30000
#define WEB_HDR_MAX      16384         /* response header ceiling for a GET */

/* ------------------------------------------------------------------ */
/* PROPFIND XML scraping (namespace-prefix agnostic)                   */
/* ------------------------------------------------------------------ */

/* Value of <[ns:]name> ... </...> within [p,end): returns start + sets *vlen,
 * or NULL. Matches any namespace prefix by keying on "name>" as the open-tag
 * tail and the next "<" as the value terminator. */
static const char *
tag_val(const char *p, const char *end, const char *name, size_t *vlen)
{
    char    needle[64];
    int     nl = snprintf(needle, sizeof(needle), "%s>", name);
    const char *o = p;
    if (nl < 0 || (size_t) nl >= sizeof(needle)) {
        return NULL;
    }
    while ((o = strstr(o, needle)) != NULL && o < end) {
        /* ensure it is a real tag end: preceded by '<' or ':' run */
        const char *v = o + nl;
        const char *ve = memchr(v, '<', (size_t) (end - v));
        if (ve != NULL) {
            *vlen = (size_t) (ve - v);
            return v;
        }
        o = v;
    }
    return NULL;
}

/* True if [p,end) contains a <[ns:]collection .../> element (defined below). */
static int has_collection_element(const char *p, const char *end);

/* Parse the HTTP-date in getlastmodified ("Wed, 21 Jun 2026 14:33:03 GMT") to a
 * unix time; 0 if unparseable. */
static long
parse_http_date(const char *v, size_t n)
{
    char       tmp[64];
    struct tm  tm;
    if (n == 0 || n >= sizeof(tmp)) {
        return 0;
    }
    memcpy(tmp, v, n);
    tmp[n] = '\0';
    memset(&tm, 0, sizeof(tm));
    if (strptime(tmp, "%a, %d %b %Y %H:%M:%S", &tm) == NULL) {
        return 0;
    }
    return (long) timegm(&tm);
}

/* Fill *si from one <response> block [p,end). Returns the decoded href into
 * href/hrefsz (path component only). 0 on success. */
static int
parse_response(const char *p, const char *end, xrdc_statinfo *si,
               char *href, size_t hrefsz)
{
    size_t      vlen = 0;
    const char *v;
    int         is_dir;

    memset(si, 0, sizeof(*si));
    href[0] = '\0';

    v = tag_val(p, end, "href", &vlen);
    if (v == NULL) {
        return -1;
    }
    if (xrootd_http_urldecode((const unsigned char *) v, vlen, href, hrefsz, 0)
        != XROOTD_URLDECODE_OK) {
        return -1;
    }
    /* reduce an absolute-URL href (http://h/p) to its path component */
    if (strstr(href, "://") != NULL) {
        char *sl = strstr(href, "://");
        char *ps = strchr(sl + 3, '/');
        if (ps != NULL) {
            memmove(href, ps, strlen(ps) + 1);
        }
    }

    /* A directory's resourcetype contains a <[ns:]collection/> element. Match the
     * element by its exact local name so neither <D:collection-set/> (DAV ACL on
     * files) nor <lp1:iscollection>0</lp1:iscollection> (XrdHttp, substring
     * "collection>") false-positives a file as a directory. */
    is_dir = has_collection_element(p, end);
    if (is_dir) {
        si->flags |= kXR_isDir;
    }
    v = tag_val(p, end, "getcontentlength", &vlen);
    if (v != NULL) {
        char num[32];
        size_t nn = vlen < sizeof(num) - 1 ? vlen : sizeof(num) - 1;
        memcpy(num, v, nn);
        num[nn] = '\0';
        si->size = strtoll(num, NULL, 10);
    }
    v = tag_val(p, end, "getlastmodified", &vlen);
    if (v != NULL) {
        si->mtime = parse_http_date(v, vlen);
    }
    return 0;
}

/* Response-block splitters (defined below) — tolerate ns prefixes + attributes. */
static const char *next_response_open(const char *p, const char *end);
static const char *next_response_close(const char *p, const char *end);

/* Build the Authorization header (Bearer) or empty. */
static void
web_auth(const char *bearer, char *out, size_t outsz)
{
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(out, outsz, "Authorization: Bearer %s\r\n", bearer);
    } else {
        out[0] = '\0';
    }
}

int
xrdc_web_stat(const xrdc_weburl *u, const char *path, const char *bearer,
              int verify, const char *ca_dir, xrdc_statinfo *si, xrdc_status *st)
{
    char           hdrs[2400];
    char           auth[2200];
    xrdc_http_resp r;
    const char    *rp, *re;
    char           href[XRDC_PATH_MAX];

    web_auth(bearer, auth, sizeof(auth));
    snprintf(hdrs, sizeof(hdrs), "Depth: 0\r\n%s", auth);
    if (xrdc_http_req(u->host, u->port, u->tls, "PROPFIND", path, hdrs, NULL, 0,
                      WEB_TIMEOUT_MS, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status == 404) {
        xrdc_http_resp_free(&r);
        xrdc_status_set(st, kXR_NotFound, 0, "not found");
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", r.status);
        xrdc_http_resp_free(&r);
        return -1;
    }
    /* Bound the first <[ns:]response[ attrs]>...</[ns:]response> block. The open
     * tag may carry attributes (XrdHttp) or not (nginx), so we cannot pair on a
     * bare "response>"; next_response_open/close tolerate both forms. */
    {
        const char *body = r.body ? r.body : "";
        const char *bend = body + (r.body ? r.body_len : 0);
        rp = next_response_open(body, bend);
        if (rp == NULL) {
            xrdc_http_resp_free(&r);
            xrdc_status_set(st, XRDC_EPROTO, 0, "PROPFIND: empty multistatus");
            return -1;
        }
        re = next_response_close(rp, bend);
        if (re == NULL) {
            re = bend;
        }
    }
    if (parse_response(rp, re, si, href, sizeof(href)) != 0) {
        xrdc_http_resp_free(&r);
        xrdc_status_set(st, XRDC_EPROTO, 0, "PROPFIND: unparseable response");
        return -1;
    }
    xrdc_http_resp_free(&r);
    return 0;
}

/* True if c can appear in an XML name (ASCII subset sufficient for ns prefixes). */
static int
xml_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

/* Locate the next opening "<[ns:]response[ attrs...]>" tag in [p,end). Returns a
 * pointer to the first byte of inner content (just past the tag's '>'), or NULL.
 * Tolerant of: a namespace prefix ("D:", "lp1:") AND attributes on the open tag
 * (XrdHttp emits <D:response xmlns:lp1="DAV:" ...>; nginx emits <D:response>). */
static const char *
next_response_open(const char *p, const char *end)
{
    while (p < end) {
        const char *lt = memchr(p, '<', (size_t) (end - p));
        if (lt == NULL) {
            return NULL;
        }
        const char *q = lt + 1;
        if (q < end && *q == '/') {                /* a closing tag — skip */
            p = q + 1;
            continue;
        }
        const char *name = q, *s = q;
        while (s < end && xml_name_char(*s)) {
            s++;
        }
        if (s < end && *s == ':') {                /* strip "ns:" prefix */
            name = s + 1;
        }
        if ((size_t) (end - name) >= 8 && strncmp(name, "response", 8) == 0) {
            const char *a = name + 8;
            if (a < end && (*a == '>' || *a == ' ' || *a == '\t'
                            || *a == '\r' || *a == '\n' || *a == '/')) {
                const char *gt = memchr(a, '>', (size_t) (end - a));
                return gt != NULL ? gt + 1 : NULL;
            }
        }
        p = lt + 1;
    }
    return NULL;
}

/* Locate the next closing "</[ns:]response>" tag in [p,end). Returns a pointer to
 * its '<' (so [content,close) bounds the element body), or NULL. */
static const char *
next_response_close(const char *p, const char *end)
{
    while (p + 2 <= end) {
        const char *lt = memmem(p, (size_t) (end - p), "</", 2);
        if (lt == NULL) {
            return NULL;
        }
        const char *name = lt + 2, *s = name;
        while (s < end && xml_name_char(*s)) {
            s++;
        }
        if (s < end && *s == ':') {
            name = s + 1;
        }
        if ((size_t) (end - name) >= 9 && strncmp(name, "response>", 9) == 0) {
            return lt;
        }
        p = lt + 2;
    }
    return NULL;
}

/* True if [p,end) contains an element whose LOCAL name is exactly "collection"
 * (i.e. <collection.../> or <ns:collection.../>). Keys on the element local name
 * so it rejects <D:collection-set/> (local name "collection-set") and the value
 * tag <lp1:iscollection> (local name "iscollection") — both of which would fool a
 * naive substring search and mislabel a FILE as a directory. */
static int
has_collection_element(const char *p, const char *end)
{
    while (p < end) {
        const char *lt = memchr(p, '<', (size_t) (end - p));
        if (lt == NULL) {
            return 0;
        }
        const char *n = lt + 1;
        if (n < end && (*n == '/' || *n == '?' || *n == '!')) {
            p = n + 1;                              /* closing / PI / comment */
            continue;
        }
        const char *name = n, *s = n;
        while (s < end && xml_name_char(*s)) {
            s++;
        }
        if (s < end && *s == ':') {                /* skip ns prefix, re-scan name */
            name = s + 1;
            s = name;
            while (s < end && xml_name_char(*s)) {
                s++;
            }
        }
        if ((size_t) (s - name) == 10 && strncmp(name, "collection", 10) == 0
            && s < end && (*s == '/' || *s == '>' || *s == ' '
                           || *s == '\t' || *s == '\r' || *s == '\n')) {
            return 1;
        }
        p = lt + 1;
    }
    return 0;
}

/* basename of a path, with any trailing '/' ignored; "" for "/" or empty. */
static void
path_basename(const char *path, char *out, size_t outsz)
{
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        len--;
    }
    size_t i = len;
    while (i > 0 && path[i - 1] != '/') {
        i--;
    }
    size_t bn = len - i;
    if (bn >= outsz) {
        bn = outsz - 1;
    }
    memcpy(out, path + i, bn);
    out[bn] = '\0';
}

int
xrdc_web_readdir(const xrdc_weburl *u, const char *path, const char *bearer,
                 int verify, const char *ca_dir, xrdc_dirent **ents_out,
                 size_t *n_out, xrdc_status *st)
{
    char           hdrs[2400];
    char           auth[2200];
    xrdc_http_resp r;
    const char    *p;
    xrdc_dirent   *ents = NULL;
    size_t         n = 0, cap = 0;
    char           self[XRDC_PATH_MAX];

    *ents_out = NULL;
    *n_out = 0;
    web_auth(bearer, auth, sizeof(auth));
    snprintf(hdrs, sizeof(hdrs), "Depth: 1\r\n%s", auth);
    if (xrdc_http_req(u->host, u->port, u->tls, "PROPFIND", path, hdrs, NULL, 0,
                      WEB_TIMEOUT_MS, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", r.status);
        xrdc_http_resp_free(&r);
        return -1;
    }
    /* the self-entry basename to skip (the directory itself) */
    path_basename(path, self, sizeof(self));

    p = r.body ? r.body : "";
    {
    const char *bend = p + (r.body ? r.body_len : 0);
    while ((p = next_response_open(p, bend)) != NULL) {
        const char   *open = p;                      /* content after the open tag */
        const char   *end = next_response_close(open, bend);   /* the close tag */
        xrdc_statinfo si;
        char          href[XRDC_PATH_MAX], name[XRDC_NAME_MAX];
        if (end == NULL) {
            break;
        }
        if (parse_response(open, end, &si, href, sizeof(href)) == 0 && href[0]) {
            path_basename(href, name, sizeof(name));
            if (name[0] != '\0' && strcmp(name, self) != 0) {
                if (n == cap) {
                    size_t nc = cap ? cap * 2 : 32;
                    xrdc_dirent *ne = realloc(ents, nc * sizeof(*ne));
                    if (ne == NULL) {
                        free(ents);
                        xrdc_http_resp_free(&r);
                        xrdc_status_set(st, XRDC_EPROTO, 0, "readdir: out of memory");
                        return -1;
                    }
                    ents = ne;
                    cap = nc;
                }
                memset(&ents[n], 0, sizeof(ents[n]));
                snprintf(ents[n].name, sizeof(ents[n].name), "%s", name);
                ents[n].have_stat = 1;
                ents[n].st = si;
                n++;
            }
        }
        p = end + 2;                                 /* past the "</" of the close */
    }
    }
    xrdc_http_resp_free(&r);
    *ents_out = ents;
    *n_out = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Persistent-connection ranged read (the FUSE read hot path)         */
/* ------------------------------------------------------------------ */

struct xrdc_webfile {
    char     host[256];
    int      port;
    int      tls;
    int      verify;
    char     ca_dir[512];
    char     hostport[300];        /* Host: header value (IPv6-bracketed) */
    char     path[XRDC_PATH_MAX];
    char     auth[2200];           /* "Authorization: Bearer ...\r\n" or "" */
    int      timeout_ms;
    int64_t  size;
    /* persistent transport */
    xrdc_io  io;
    void    *tls_ctx;
    int      connected;
};

static void
web_disconnect(xrdc_webfile *wf)
{
    if (!wf->connected) {
        return;
    }
    if (wf->tls) {
        xrdc_tls_client_free(&wf->io, wf->tls_ctx);
        wf->tls_ctx = NULL;
    }
    if (wf->io.fd >= 0) {
        close(wf->io.fd);
    }
    wf->io.fd = -1;
    wf->connected = 0;
}

static int
web_connect(xrdc_webfile *wf, xrdc_status *st)
{
    memset(&wf->io, 0, sizeof(wf->io));
    wf->io.fd = xrdc_tcp_connect(wf->host, wf->port, wf->timeout_ms, st);
    if (wf->io.fd < 0) {
        return -1;
    }
    wf->io.timeout_ms = wf->timeout_ms;
    if (wf->tls && xrdc_tls_client(&wf->io, wf->host, wf->verify, wf->verify,
                                   wf->ca_dir[0] ? wf->ca_dir : NULL,
                                   &wf->tls_ctx, st) != 0) {
        close(wf->io.fd);
        wf->io.fd = -1;
        return -1;
    }
    wf->connected = 1;
    return 0;
}

/* Read up to n bytes (branches on TLS). >0 bytes, 0 EOF, -1 error. */
static ssize_t
web_read_some(xrdc_webfile *wf, void *buf, size_t n, xrdc_status *st)
{
    if (wf->io.ssl != NULL) {
        size_t got = 0;
        if (xrdc_tls_read_some(&wf->io, buf, n, &got, st) != 0) {
            return -1;
        }
        return (ssize_t) got;
    }
    struct pollfd pfd;
    ssize_t       r;
    int           pr;
    pfd.fd = wf->io.fd; pfd.events = POLLIN; pfd.revents = 0;
    do { pr = poll(&pfd, 1, wf->io.timeout_ms); } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
        xrdc_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno, "web read");
        return -1;
    }
    do { r = read(wf->io.fd, buf, n); } while (r < 0 && errno == EINTR);
    if (r < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno, "web read: %s", strerror(errno));
        return -1;
    }
    return r;
}

/* Case-insensitive header value lookup in a NUL-terminated header block. */
static long long
hdr_clen(const char *hdrs)
{
    const char *p = hdrs;
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            return strtoll(p + 15, NULL, 10);
        }
    }
    if (strncasecmp(hdrs, "Content-Length:", 15) == 0) {
        return strtoll(hdrs + 15, NULL, 10);
    }
    return -1;
}

/* One ranged GET over the (already-connected) persistent socket. Fills up to len
 * bytes at off into buf; returns bytes read (0 = EOF/416), or -1 (st set). On any
 * transport/protocol fault returns -1 AND disconnects so the caller can retry. */
static ssize_t
web_get_range(xrdc_webfile *wf, int64_t off, void *buf, size_t len,
              xrdc_status *st)
{
    char    req[3200];
    char    hbuf[WEB_HDR_MAX + 1];
    size_t  hlen = 0;
    char   *eoh = NULL;
    int     status = 0;
    long long clen;
    int     rn = snprintf(req, sizeof(req),
                          "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: xrootdfs\r\n"
                          "Accept: */*\r\nConnection: keep-alive\r\n"
                          "Range: bytes=%lld-%lld\r\n%s\r\n",
                          wf->path[0] ? wf->path : "/", wf->hostport,
                          (long long) off, (long long) (off + (int64_t) len - 1),
                          wf->auth);
    if (rn < 0 || (size_t) rn >= sizeof(req)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "web GET: request too long");
        return -1;
    }
    if (xrdc_write_full(&wf->io, req, (size_t) rn, st) != 0) {
        web_disconnect(wf);
        return -1;
    }

    /* Read response headers (up to the CRLFCRLF), keeping any body overflow. */
    for (;;) {
        ssize_t r;
        if (hlen >= WEB_HDR_MAX) {
            web_disconnect(wf);
            xrdc_status_set(st, XRDC_EPROTO, 0, "web GET: header too large");
            return -1;
        }
        r = web_read_some(wf, hbuf + hlen, WEB_HDR_MAX - hlen, st);
        if (r <= 0) {
            web_disconnect(wf);
            if (r == 0) {
                xrdc_status_set(st, XRDC_ESOCK, 0, "web GET: peer closed");
            }
            return -1;
        }
        hlen += (size_t) r;
        hbuf[hlen] = '\0';
        eoh = strstr(hbuf, "\r\n\r\n");
        if (eoh != NULL) {
            break;
        }
    }
    if (strncmp(hbuf, "HTTP/", 5) == 0) {
        const char *sp = strchr(hbuf, ' ');
        status = sp ? atoi(sp + 1) : 0;
    }
    if (status == 416) {                 /* range past EOF → no bytes */
        return 0;
    }
    if (status != 206 && status != 200) {
        web_disconnect(wf);
        if (status == 404) {
            xrdc_status_set(st, kXR_NotFound, 0, "not found");
        } else if (status == 401 || status == 403) {
            xrdc_status_set(st, kXR_NotAuthorized, 0, "HTTP %d", status);
        } else {
            xrdc_status_set(st, XRDC_EPROTO, 0, "web GET: HTTP %d", status);
        }
        return -1;
    }

    *eoh = '\0';
    clen = hdr_clen(hbuf);
    if (clen < 0) {
        /* No Content-Length (e.g. chunked): we cannot keep the socket aligned;
         * bail and let the caller fall back (rare for a ranged GET). */
        web_disconnect(wf);
        xrdc_status_set(st, XRDC_EPROTO, 0, "web GET: no Content-Length");
        return -1;
    }

    /* body bytes already sitting in hbuf after the header terminator */
    {
        char   *bstart = eoh + 4;
        size_t  have = hlen - (size_t) (bstart - hbuf);
        size_t  want = (clen < (long long) len) ? (size_t) clen : len;
        size_t  copied = (have < want) ? have : want;
        size_t  total_body = (size_t) clen;        /* must fully consume */
        size_t  consumed;

        memcpy(buf, bstart, copied);
        consumed = have;                            /* bytes of body read so far */

        /* read the remainder of `want` straight into buf */
        if (copied < want) {
            if (xrdc_read_full(&wf->io, (char *) buf + copied, want - copied, st)
                != 0) {
                web_disconnect(wf);
                return -1;
            }
            consumed += want - copied;
            copied = want;
        }
        /* drain any body beyond what we wanted, to keep the connection aligned
         * for the next keep-alive request (status 200 = server ignored Range) */
        while (consumed < total_body) {
            char    sink[8192];
            size_t  chunk = total_body - consumed;
            if (chunk > sizeof(sink)) {
                chunk = sizeof(sink);
            }
            if (xrdc_read_full(&wf->io, sink, chunk, st) != 0) {
                web_disconnect(wf);
                return -1;
            }
            consumed += chunk;
        }
        if (status == 200) {
            /* Range ignored: keep-alive is fine (we consumed the whole body), but
             * for a large file that is wasteful — leave the connection up; the
             * caller still got the right bytes for this offset. */
        }
        return (ssize_t) want;
    }
}

xrdc_webfile *
xrdc_webfile_open(const xrdc_weburl *u, const char *path, const char *bearer,
                  int verify, const char *ca_dir, int timeout_ms,
                  xrdc_statinfo *si_out, xrdc_status *st)
{
    xrdc_webfile *wf;
    xrdc_statinfo si;

    /* stat first: confirms existence + gives the size (and feeds getattr). */
    if (xrdc_web_stat(u, path, bearer, verify, ca_dir, &si, st) != 0) {
        return NULL;
    }
    if (si.flags & kXR_isDir) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "is a directory");
        return NULL;
    }
    wf = calloc(1, sizeof(*wf));
    if (wf == NULL) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "out of memory");
        return NULL;
    }
    snprintf(wf->host, sizeof(wf->host), "%s", u->host);
    wf->port = u->port;
    wf->tls = u->tls;
    wf->verify = verify;
    if (ca_dir != NULL) {
        snprintf(wf->ca_dir, sizeof(wf->ca_dir), "%s", ca_dir);
    }
    snprintf(wf->path, sizeof(wf->path), "%s", path);
    web_auth(bearer, wf->auth, sizeof(wf->auth));
    xrootd_format_host_port(u->host, (uint16_t) u->port, wf->hostport,
                            sizeof(wf->hostport));
    wf->timeout_ms = timeout_ms > 0 ? timeout_ms : WEB_TIMEOUT_MS;
    wf->size = si.size;
    wf->io.fd = -1;
    if (si_out != NULL) {
        *si_out = si;
    }
    return wf;
}

int64_t
xrdc_webfile_size(const xrdc_webfile *wf)
{
    return wf->size;
}

ssize_t
xrdc_webfile_pread(xrdc_webfile *wf, int64_t off, void *buf, size_t len,
                   xrdc_status *st)
{
    int attempt;
    if (off >= wf->size) {
        return 0;                                  /* past EOF */
    }
    if ((int64_t) len > wf->size - off) {
        len = (size_t) (wf->size - off);           /* clamp tail read */
    }
    if (len == 0) {
        return 0;
    }
    /* one transparent reconnect: a keep-alive socket may have been dropped by an
     * idle timeout or a flaky link between reads. */
    for (attempt = 0; attempt < 2; attempt++) {
        ssize_t r;
        if (!wf->connected && web_connect(wf, st) != 0) {
            xrdc_backoff_sleep_fast((unsigned) attempt);
            continue;
        }
        r = web_get_range(wf, off, buf, len, st);
        if (r >= 0) {
            return r;
        }
        if (!xrdc_status_retryable(st)) {
            return -1;                             /* fatal (404/403/…) */
        }
        xrdc_backoff_sleep_fast((unsigned) attempt);
    }
    return -1;
}

void
xrdc_webfile_close(xrdc_webfile *wf, xrdc_status *st)
{
    (void) st;
    if (wf == NULL) {
        return;
    }
    web_disconnect(wf);
    free(wf);
}
