/*
 * webfile.c - (kept) routing + shared helpers
 * Phase-38 split of webfile.c; behavior-identical.
 */
#include "webfile_internal.h"
#include "web_ka.h"
#include "net/cpool.h"
#include "posix/fuse_ops.h"   /* brix_fuse_conn_healthy for the pooled wrappers */

const char *
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

/* Parse the HTTP-date in getlastmodified ("Wed, 21 Jun 2026 14:33:03 GMT") to a
 * unix time; 0 if unparseable. */
long
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
int
parse_response(const char *p, const char *end, brix_statinfo *si,
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
    if (brix_http_urldecode((const unsigned char *) v, vlen, href, hrefsz, 0)
        != BRIX_URLDECODE_OK) {
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

/* Build the Authorization header (Bearer) or empty. */
void
web_auth(const char *bearer, char *out, size_t outsz)
{
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(out, outsz, "Authorization: Bearer %s\r\n", bearer);
    } else {
        out[0] = '\0';
    }
}


/* Parse one PROPFIND (Depth 0) multistatus body into *si. Shared by the
 * stateless brix_web_stat and the pooled brix_web_stat_pooled — they differ only
 * in transport. The open tag may carry attributes (XrdHttp) or not (nginx), so
 * we cannot pair on a bare "response>"; next_response_open/close tolerate both. */
int
webdav_parse_single(const char *body, size_t blen, brix_statinfo *si,
                    brix_status *st)
{
    const char *b   = body ? body : "";
    const char *end = b + blen;
    const char *rp  = next_response_open(b, end);
    const char *re;
    char        href[XRDC_PATH_MAX];

    if (rp == NULL) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND: empty multistatus");
        return -1;
    }
    re = next_response_close(rp, end);
    if (re == NULL) {
        re = end;
    }
    if (parse_response(rp, re, si, href, sizeof(href)) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND: unparseable response");
        return -1;
    }
    return 0;
}

int
brix_web_stat(const brix_weburl *u, const char *path, const char *bearer,
              int verify, const char *ca_dir, brix_statinfo *si, brix_status *st)
{
    char           hdrs[2400];
    char           auth[2200];
    brix_http_resp r;
    int            rc;

    web_auth(bearer, auth, sizeof(auth));
    snprintf(hdrs, sizeof(hdrs), "Depth: 0\r\n%s", auth);
    if (brix_http_req(u->host, u->port, u->tls, "PROPFIND", path, hdrs, NULL, 0,
                      WEB_TIMEOUT_MS, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status == 404) {
        brix_http_resp_free(&r);
        brix_status_set(st, kXR_NotFound, 0, "not found");
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", r.status);
        brix_http_resp_free(&r);
        return -1;
    }
    rc = webdav_parse_single(r.body, r.body ? r.body_len : 0, si, st);
    brix_http_resp_free(&r);
    return rc;
}

/* Pooled keep-alive stat (Depth 0): checkout → propfind → parse → checkin. The
 * health predicate keeps the socket on a protocol result (404/403) and drops it
 * on a transport/proto sever (ESOCK/EPROTO), same as the read/root paths. */
int
brix_web_stat_pooled(brix_cpool *pool, const char *path, brix_statinfo *si,
                     brix_status *st)
{
    char         *body = NULL;
    size_t        blen = 0;
    brix_webmeta *m = brix_cpool_checkout(pool, st);
    int           rc;

    if (m == NULL) {
        return -1;
    }
    rc = brix_webmeta_propfind(m, path, 0, &body, &blen, st);
    if (rc == 0) {
        rc = webdav_parse_single(body, blen, si, st);
    }
    free(body);
    brix_cpool_checkin(pool, m, rc == 0 ? 1 : brix_fuse_conn_healthy(st));
    return rc;
}


/* True if c can appear in an XML name (ASCII subset sufficient for ns prefixes). */
int
xml_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}


/* ---- Delimit an element's local (namespace-stripped) name ----
 *
 * WHAT: Given q pointing at the first byte after a tag's '<' (a non-closing
 * tag), scans the element name within [q,end), strips an optional single "ns:"
 * prefix, sets *name to the local-name start, and returns a pointer just past
 * the local name (its first non-name byte, or end).
 *
 * WHY: Both response-block scanning and collection detection must key on an
 * element's LOCAL name so that neither a namespace prefix ("D:", "lp1:") nor a
 * differing prefix changes the match. Centralising the prefix-strip + name-scan
 * keeps that rule in one place and drops the branch weight of the callers.
 *
 * HOW:
 *   1. Advance s over the leading name run (xml_name_char bytes).
 *   2. If s stops on ':', treat what preceded as an "ns:" prefix: move name past
 *      the colon and re-scan the local name run from there.
 *   3. Otherwise the whole run is the local name (name stays at q).
 *   4. Publish the local-name start via *name and return the scan cursor s.
 */
static const char *
xml_local_name(const char *q, const char *end, const char **name)
{
    const char *s = q;
    while (s < end && xml_name_char(*s)) {
        s++;
    }
    if (s < end && *s == ':') {                    /* strip "ns:" prefix */
        const char *local = s + 1;
        s = local;
        while (s < end && xml_name_char(*s)) {
            s++;
        }
        *name = local;
        return s;
    }
    *name = q;
    return s;
}


/* ---- True if c terminates an XML element name ----
 *
 * WHAT: Returns non-zero when c is a byte that can legally follow an element's
 * name in an open tag: '/', '>', or ASCII whitespace (space, tab, CR, LF).
 *
 * WHY: Matching a name only up to its declared length can false-positive on a
 * longer name that shares the prefix (e.g. "collection" vs "collection-set").
 * Requiring a real name-boundary byte after the match rejects that; folding the
 * six-way character test into one predicate keeps each caller's branch count low.
 *
 * HOW: Compare c against the fixed boundary set and return the disjunction.
 */
static int
xml_name_boundary(char c)
{
    return c == '/' || c == '>' || c == ' '
        || c == '\t' || c == '\r' || c == '\n';
}


/* Locate the next opening "<[ns:]response[ attrs...]>" tag in [p,end). Returns a
 * pointer to the first byte of inner content (just past the tag's '>'), or NULL.
 * Tolerant of: a namespace prefix ("D:", "lp1:") AND attributes on the open tag
 * (XrdHttp emits <D:response xmlns:lp1="DAV:" ...>; nginx emits <D:response>). */
const char *
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
        const char *name;
        (void) xml_local_name(q, end, &name);      /* strip any "ns:" prefix */
        if ((size_t) (end - name) >= 8 && strncmp(name, "response", 8) == 0) {
            const char *a = name + 8;
            if (a < end && xml_name_boundary(*a)) {
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
const char *
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
int
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
        const char *name;
        const char *s = xml_local_name(n, end, &name);   /* skip ns prefix */
        if ((size_t) (s - name) == 10 && strncmp(name, "collection", 10) == 0
            && s < end && xml_name_boundary(*s)) {
            return 1;
        }
        p = lt + 1;
    }
    return 0;
}


/* basename of a path, with any trailing '/' ignored; "" for "/" or empty. */
void
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


/* Parse a PROPFIND (Depth 1) multistatus body into a brix_dirent array, skipping
 * the self entry `self` (the directory's own basename). Shared by the stateless
 * brix_web_readdir and the pooled brix_web_readdir_pooled. */
int
webdav_parse_multi(const char *body, size_t blen, const char *self,
                   brix_dirent **ents_out, size_t *n_out, brix_status *st)
{
    const char  *p   = body ? body : "";
    const char  *end = p + blen;
    brix_dirent *ents = NULL;
    size_t       n = 0, cap = 0;

    *ents_out = NULL;
    *n_out = 0;
    while ((p = next_response_open(p, end)) != NULL) {
        const char   *open = p;                      /* content after the open tag */
        const char   *close = next_response_close(open, end);
        brix_statinfo si;
        char          href[XRDC_PATH_MAX], name[XRDC_NAME_MAX];
        if (close == NULL) {
            break;
        }
        if (parse_response(open, close, &si, href, sizeof(href)) == 0 && href[0]) {
            path_basename(href, name, sizeof(name));
            if (name[0] != '\0' && strcmp(name, self) != 0) {
                if (n == cap) {
                    size_t nc = cap ? cap * 2 : 32;
                    brix_dirent *ne = realloc(ents, nc * sizeof(*ne));
                    if (ne == NULL) {
                        free(ents);
                        brix_status_set(st, XRDC_EPROTO, 0, "readdir: out of memory");
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
        p = close + 2;                               /* past the "</" of the close */
    }
    *ents_out = ents;
    *n_out = n;
    return 0;
}

int
brix_web_readdir(const brix_weburl *u, const char *path, const char *bearer,
                 int verify, const char *ca_dir, brix_dirent **ents_out,
                 size_t *n_out, brix_status *st)
{
    char           hdrs[2400];
    char           auth[2200];
    brix_http_resp r;
    char           self[XRDC_PATH_MAX];
    int            rc;

    *ents_out = NULL;
    *n_out = 0;
    web_auth(bearer, auth, sizeof(auth));
    snprintf(hdrs, sizeof(hdrs), "Depth: 1\r\n%s", auth);
    if (brix_http_req(u->host, u->port, u->tls, "PROPFIND", path, hdrs, NULL, 0,
                      WEB_TIMEOUT_MS, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND HTTP %d", r.status);
        brix_http_resp_free(&r);
        return -1;
    }
    path_basename(path, self, sizeof(self));    /* the self-entry basename to skip */
    rc = webdav_parse_multi(r.body, r.body ? r.body_len : 0, self,
                            ents_out, n_out, st);
    brix_http_resp_free(&r);
    return rc;
}

/* Pooled keep-alive readdir (Depth 1). Same idiom as brix_web_stat_pooled. */
int
brix_web_readdir_pooled(brix_cpool *pool, const char *path,
                        brix_dirent **ents_out, size_t *n_out, brix_status *st)
{
    char         *body = NULL;
    size_t        blen = 0;
    char          self[XRDC_PATH_MAX];
    brix_webmeta *m = brix_cpool_checkout(pool, st);
    int           rc;

    *ents_out = NULL;
    *n_out = 0;
    if (m == NULL) {
        return -1;
    }
    rc = brix_webmeta_propfind(m, path, 1, &body, &blen, st);
    if (rc == 0) {
        path_basename(path, self, sizeof(self));
        rc = webdav_parse_multi(body, blen, self, ents_out, n_out, st);
    }
    free(body);
    brix_cpool_checkin(pool, m, rc == 0 ? 1 : brix_fuse_conn_healthy(st));
    return rc;
}
