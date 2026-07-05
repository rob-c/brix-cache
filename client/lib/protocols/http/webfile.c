/*
 * webfile.c - (kept) routing + shared helpers
 * Phase-38 split of webfile.c; behavior-identical.
 */
#include "webfile_internal.h"

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


int
brix_web_stat(const brix_weburl *u, const char *path, const char *bearer,
              int verify, const char *ca_dir, brix_statinfo *si, brix_status *st)
{
    char           hdrs[2400];
    char           auth[2200];
    brix_http_resp r;
    const char    *rp, *re;
    char           href[XRDC_PATH_MAX];

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
    /* Bound the first <[ns:]response[ attrs]>...</[ns:]response> block. The open
     * tag may carry attributes (XrdHttp) or not (nginx), so we cannot pair on a
     * bare "response>"; next_response_open/close tolerate both forms. */
    {
        const char *body = r.body ? r.body : "";
        const char *bend = body + (r.body ? r.body_len : 0);
        rp = next_response_open(body, bend);
        if (rp == NULL) {
            brix_http_resp_free(&r);
            brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND: empty multistatus");
            return -1;
        }
        re = next_response_close(rp, bend);
        if (re == NULL) {
            re = bend;
        }
    }
    if (parse_response(rp, re, si, href, sizeof(href)) != 0) {
        brix_http_resp_free(&r);
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND: unparseable response");
        return -1;
    }
    brix_http_resp_free(&r);
    return 0;
}


/* True if c can appear in an XML name (ASCII subset sufficient for ns prefixes). */
int
xml_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
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


int
brix_web_readdir(const brix_weburl *u, const char *path, const char *bearer,
                 int verify, const char *ca_dir, brix_dirent **ents_out,
                 size_t *n_out, brix_status *st)
{
    char           hdrs[2400];
    char           auth[2200];
    brix_http_resp r;
    const char    *p;
    brix_dirent   *ents = NULL;
    size_t         n = 0, cap = 0;
    char           self[XRDC_PATH_MAX];

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
    /* the self-entry basename to skip (the directory itself) */
    path_basename(path, self, sizeof(self));

    p = r.body ? r.body : "";
    {
    const char *bend = p + (r.body ? r.body_len : 0);
    while ((p = next_response_open(p, bend)) != NULL) {
        const char   *open = p;                      /* content after the open tag */
        const char   *end = next_response_close(open, bend);   /* the close tag */
        brix_statinfo si;
        char          href[XRDC_PATH_MAX], name[XRDC_NAME_MAX];
        if (end == NULL) {
            break;
        }
        if (parse_response(open, end, &si, href, sizeof(href)) == 0 && href[0]) {
            path_basename(href, name, sizeof(name));
            if (name[0] != '\0' && strcmp(name, self) != 0) {
                if (n == cap) {
                    size_t nc = cap ? cap * 2 : 32;
                    brix_dirent *ne = realloc(ents, nc * sizeof(*ne));
                    if (ne == NULL) {
                        free(ents);
                        brix_http_resp_free(&r);
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
        p = end + 2;                                 /* past the "</" of the close */
    }
    }
    brix_http_resp_free(&r);
    *ents_out = ents;
    *n_out = n;
    return 0;
}
