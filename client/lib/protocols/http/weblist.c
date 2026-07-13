/*
 * weblist.c — list the files under a WebDAV collection (for recursive web copy).
 *
 * WHAT: brix_webdav_list() issues one PROPFIND Depth: infinity against a davs/http
 *       collection and returns the absolute server paths of every FILE beneath it
 *       (collections themselves are skipped — subdirs are recreated locally from the
 *       file paths).
 * WHY:  The XRootD/WebDAV wire has no "give me the tree" transfer op, so `xrdcp -r`
 *       over davs:// must enumerate the collection itself and copy each file. Keeping
 *       the enumeration here (a new file) leaves the copy engine untouched.
 * HOW:  PROPFIND over the existing HTTP client; scan the multistatus body for each
 *       <D:response> block, take its <D:href> and treat it as a file unless the block
 *       carries <D:collection/>. hrefs are percent-decoded; an absolute-URL href is
 *       reduced to its path. Bounded entry count.
 *
 * Clean-room: parses the documented WebDAV multistatus shape this module emits
 * (src/protocols/webdav/propfind.c), not any client library.
 */
#include "brix.h"
#include "core/compat/uri.h"          /* shared RFC-3986 percent-decoder (libxrdproto) */
#include "core/compat/host_format.h"  /* brix_format_host_port (IPv6-bracketed Host) */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define XRDC_WEBLIST_MAX     200000   /* hard cap on files returned */
#define XRDC_WEBLIST_TIMEOUT 60000

/* Page-invariant inputs for one ListObjectsV2 listing.
 *
 * WHAT: Holds everything that stays constant across the paginated GETs — bucket
 *       name, pre-encoded prefix, SigV4 signing host + credentials + region — so the
 *       per-page request builder takes one context pointer instead of a long arg list.
 * WHY:  brix_s3_list's extern signature is frozen (declared in brix_net.h); the
 *       consolidation is confined to this file's static page machinery.
 * HOW:  Populated once in brix_s3_list, then passed by const pointer to
 *       s3_list_build_request for each page.
 */
typedef struct {
    char        bucket[256];
    char        encp[XRDC_PATH_MAX * 3];   /* pre-encoded object prefix */
    char        hostport[300];             /* bracketed Host, byte-matching the wire */
    int         have_prefix;
    const char *ak;
    const char *sk;
    const char *region;
} s3_list_req_t;

/* Growable string-vector accumulator shared by the page/block scanners.
 *
 * WHAT: Bundles the (array, count, capacity) triple that push() grows so the
 *       scanners pass one accumulator pointer instead of three out-params.
 * WHY:  Both the S3 key scan and the WebDAV block scan feed the same array; a single
 *       struct keeps every helper under the 5-parameter gate.
 * HOW:  Zero-initialised by the public entry, threaded by pointer into every scanner,
 *       and its arr/n handed to brix_strv_free on error and to *keys / *paths on success.
 */
typedef struct {
    char  **arr;
    size_t  n;
    size_t  cap;
} weblist_acc_t;

/* Caller-owned output buffers for one built request (path + signed headers).
 *
 * WHAT: Carries the destination path and header buffers (with their sizes) for
 *       s3_list_build_request, so it stays within the parameter gate.
 * WHY:  brix_s3_list's signature is frozen; the buffer plumbing is confined here.
 * HOW:  Points at the paging loop's stack buffers; filled per page then consumed by
 *       brix_http_req.
 */
typedef struct {
    char  *path;
    size_t pathsz;
    char  *hdrs;
    size_t hdrssz;
} s3_list_out_t;

/* Append a strdup'd copy of s to the accumulator's growable array. 0 / -1. */
static int
push(weblist_acc_t *acc, const char *s)
{
    if (acc->n == acc->cap) {
        size_t  nc = acc->cap ? acc->cap * 2 : 64;
        char  **na = (char **) realloc(acc->arr, nc * sizeof(char *));
        if (na == NULL) { return -1; }
        acc->arr = na;
        acc->cap = nc;
    }
    acc->arr[acc->n] = strdup(s);
    if (acc->arr[acc->n] == NULL) { return -1; }
    acc->n++;
    return 0;
}

void
brix_strv_free(char **arr, size_t n)
{
    size_t i;
    if (arr == NULL) { return; }
    for (i = 0; i < n; i++) { free(arr[i]); }
    free(arr);
}

/* Copy the text between <tag> and </tag> (first occurrence at/after *p) into out;
 * advances *p past the close tag (even on truncation, so a scan loop can continue
 * past an over-long value). Returns 1 if found and it fit, 0 if not found, -1 if
 * found but too long for out (out holds the truncated prefix). Callers that must
 * not act on a partial value (e.g. a continuation token) treat -1 as a hard error. */
static int
xml_tag(const char **p, const char *otag, const char *ctag, char *out, size_t osz)
{
    const char *s = strstr(*p, otag);
    const char *e;
    size_t      n;
    int         truncated = 0;
    if (s == NULL) { return 0; }
    s += strlen(otag);
    e = strstr(s, ctag);
    if (e == NULL) { return 0; }
    n = (size_t) (e - s);
    if (n >= osz) { n = osz - 1; truncated = 1; }
    memcpy(out, s, n);
    out[n] = '\0';
    *p = e + strlen(ctag);
    return truncated ? -1 : 1;
}

/* Build the SORTED, RFC-3986-encoded ListObjectsV2 canonical query string into out
 * (params: continuation-token < list-type < prefix). encp = pre-encoded prefix.
 * Every append is length-checked. 0 on success, -1 if it would not fit. */
static int
s3_canon_qs(const char *token, const char *encp, int have_prefix,
            char *out, size_t outsz)
{
    char   enctok[8192];
    size_t qn = 0;
    int    w;

    if (token[0] != '\0') {
        if (brix_http_urlencode((const unsigned char *) token, strlen(token),
                                  enctok, sizeof(enctok), "") < 0) {
            return -1;
        }
        w = snprintf(out + qn, outsz - qn, "continuation-token=%s&", enctok);
        if (w < 0 || (size_t) w >= outsz - qn) { return -1; }
        qn += (size_t) w;
    }
    w = snprintf(out + qn, outsz - qn, "list-type=2");
    if (w < 0 || (size_t) w >= outsz - qn) { return -1; }
    qn += (size_t) w;
    if (have_prefix) {
        w = snprintf(out + qn, outsz - qn, "&prefix=%s", encp);
        if (w < 0 || (size_t) w >= outsz - qn) { return -1; }
        qn += (size_t) w;
    }
    return 0;
}

/* ---- Split an s3:// list path into bucket + object-prefix ----
 *
 * WHAT: Parses u->path ("/bucket[/prefix...]") into bucket[] and prefix[]. Returns
 *       0 on success, -1 (with *st set to XRDC_EUSAGE) if the path is not rooted or
 *       the bucket segment does not fit bucket[].
 * WHY:  ListObjectsV2 addresses a bucket in the path and the object prefix in the
 *       query string, so the two components must be separated before signing.
 * HOW:  1. Require a leading '/'. 2. Find the first '/' after it: absent → the whole
 *       tail is the bucket and prefix is empty; present → copy the bucket segment
 *       (length-checked into req->bucket) and take everything after it as the prefix.
 */
static int
s3_list_split_path(const brix_weburl *u, s3_list_req_t *req,
                   char *prefix, size_t prefixsz, brix_status *st)
{
    const char *bsl;

    if (u->path[0] != '/') {
        brix_status_set(st, XRDC_EUSAGE, 0, "s3 list: bad path");
        return -1;
    }
    bsl = strchr(u->path + 1, '/');
    if (bsl == NULL) {
        snprintf(req->bucket, sizeof(req->bucket), "%s", u->path + 1);
        prefix[0] = '\0';
        return 0;
    }
    {
        size_t bl = (size_t) (bsl - (u->path + 1));
        if (bl >= sizeof(req->bucket)) {
            brix_status_set(st, XRDC_EUSAGE, 0, "s3: bucket too long");
            return -1;
        }
        memcpy(req->bucket, u->path + 1, bl);
        req->bucket[bl] = '\0';
    }
    snprintf(prefix, prefixsz, "%s", bsl + 1);
    return 0;
}

/* ---- Build + sign the request path for one ListObjectsV2 page ----
 *
 * WHAT: Renders the canonical URI ("/bucket") and query string (from the current
 *       continuation token) into path[], and, when credentials are supplied, the
 *       SigV4 Authorization headers into hdrs[]. Returns 0, or -1 (with *st set) on
 *       overflow (XRDC_EUSAGE) or a signing failure (XRDC_EAUTH).
 * WHY:  Each page is a distinct signed GET; isolating the per-page URL/signature
 *       assembly keeps the paging loop to control flow only.
 * HOW:  1. Assemble canon_uri "/bucket". 2. Build the sorted canonical query string
 *       (token < list-type < prefix). 3. Compose "uri?qs" into path[]. 4. If ak/sk
 *       are both non-empty, sign the GET over the same bracketed host used on the
 *       wire and emit the Authorization headers; otherwise leave hdrs empty.
 */
static int
s3_list_build_request(const s3_list_req_t *req, const char *token,
                      const s3_list_out_t *out, brix_status *st)
{
    char canon_uri[300], canon_qs[XRDC_PATH_MAX * 4];

    snprintf(canon_uri, sizeof(canon_uri), "/%s", req->bucket);
    if (s3_canon_qs(token, req->encp, req->have_prefix, canon_qs, sizeof(canon_qs)) != 0
        || (size_t) snprintf(out->path, out->pathsz, "%s?%s", canon_uri, canon_qs)
               >= out->pathsz) {
        brix_status_set(st, XRDC_EUSAGE, 0, "s3 list: prefix/continuation too long");
        return -1;
    }
    out->hdrs[0] = '\0';
    if (req->ak != NULL && req->sk != NULL && req->ak[0] != '\0' && req->sk[0] != '\0') {
        if (brix_s3_sign_v4_q("GET", req->hostport, canon_uri, canon_qs, req->ak,
                              req->sk, req->region, "UNSIGNED-PAYLOAD",
                              out->hdrs, out->hdrssz) != 0) {
            brix_status_set(st, XRDC_EAUTH, 0, "s3 list: failed to sign request");
            return -1;
        }
    }
    return 0;
}

/* ---- Append every <Key> in one ListObjectsV2 page body to the result array ----
 *
 * WHAT: Scans r->body for <Key>...</Key> elements and pushes each onto *arr / *n / *cap
 *       until the tag stream ends or XRDC_WEBLIST_MAX is reached. Returns 0, or -1
 *       (with *st set to XRDC_EPROTO) on an over-long key or an allocation failure.
 * WHY:  Object keys are the payload of the listing; keeping the scan separate frees
 *       the pager from the per-key error handling.
 * HOW:  1. Loop xml_tag over the body. 2. Stop cleanly at end-of-tags or the cap.
 *       3. A truncated key (kr < 0) is fatal — a clipped key yields a wrong URL.
 *       4. push() each key; propagate an OOM as a hard error.
 */
static int
s3_list_scan_keys(const brix_http_resp *r, weblist_acc_t *acc, brix_status *st)
{
    const char *p = r->body ? r->body : "";

    for (;;) {
        char key[XRDC_PATH_MAX];
        int  kr = xml_tag(&p, "<Key>", "</Key>", key, sizeof(key));
        if (kr == 0 || acc->n >= XRDC_WEBLIST_MAX) {
            break;
        }
        if (kr < 0) {
            /* A key longer than our buffer would yield a wrong download URL —
             * fail loudly rather than silently dropping or mangling it. */
            brix_status_set(st, XRDC_EPROTO, 0,
                            "s3 list: object key exceeds %zu bytes", sizeof(key));
            return -1;
        }
        if (push(acc, key) != 0) {
            brix_status_set(st, XRDC_EPROTO, 0, "s3 list: out of memory");
            return -1;
        }
    }
    return 0;
}

/* ---- Extract the continuation token for the next ListObjectsV2 page ----
 *
 * WHAT: Reads IsTruncated / NextContinuationToken from r->body into token[] and sets
 *       *more to 1 when another page follows. Returns 0, or -1 (with *st set to
 *       XRDC_EPROTO) if the token is present but longer than token[].
 * WHY:  Pagination correctness hinges on carrying the full token forward; a clipped
 *       token would silently corrupt the listing, so truncation must be fatal.
 * HOW:  1. Reset token to empty and *more to 0. 2. Only when IsTruncated == "true"
 *       read NextContinuationToken. 3. A truncated token is a hard error; otherwise
 *       *more reflects whether a token was found.
 */
static int
s3_list_next_token(const brix_http_resp *r, char *token, size_t tokensz,
                   int *more, brix_status *st)
{
    const char *tp = r->body ? r->body : "";
    char        trunc[8];

    token[0] = '\0';
    *more = 0;
    if (xml_tag(&tp, "<IsTruncated>", "</IsTruncated>", trunc, sizeof(trunc)) == 1
        && strcmp(trunc, "true") == 0) {
        const char *np = r->body;
        int         tr = xml_tag(&np, "<NextContinuationToken>",
                                 "</NextContinuationToken>", token, tokensz);
        if (tr < 0) {
            /* token truncated → continuing would corrupt the listing */
            brix_status_set(st, XRDC_EPROTO, 0,
                            "s3 list: continuation token too long");
            return -1;
        }
        *more = (tr == 1);
    }
    return 0;
}

int
brix_s3_list(const brix_weburl *u, const char *ak, const char *sk,
             const char *region, int verify, const char *ca_dir,
             char ***keys, size_t *n_out, brix_status *st)
{
    s3_list_req_t req;
    weblist_acc_t acc = { NULL, 0, 0 };
    char          prefix[XRDC_PATH_MAX];
    /* The server's NextContinuationToken is the b64url of the last returned key
     * (keys up to S3_MAX_KEY=4096 → token up to ~5.5 KB), so this MUST be large
     * enough or pagination silently corrupts. */
    char          token[8192];
    int           rounds = 0;

    memset(&req, 0, sizeof(req));
    *keys = NULL;
    *n_out = 0;
    if (region == NULL || region[0] == '\0') { region = "us-east-1"; }
    req.ak = ak;
    req.sk = sk;
    req.region = region;
    /* u->path = "/bucket[/prefix...]" → split bucket vs prefix. */
    if (s3_list_split_path(u, &req, prefix, sizeof(prefix), st) != 0) {
        return -1;
    }
    /* The SigV4 signed host MUST match the wire Host header byte-for-byte; that
     * header is built bracketed for IPv6 literals ([::1]:9000), so sign the same. */
    brix_format_host_port(u->host, (uint16_t) u->port, req.hostport, sizeof(req.hostport));
    if (brix_http_urlencode((const unsigned char *) prefix, strlen(prefix),
                              req.encp, sizeof(req.encp), "") < 0) {
        brix_status_set(st, XRDC_EUSAGE, 0, "s3: prefix too long");
        return -1;
    }
    req.have_prefix = (prefix[0] != '\0');
    token[0] = '\0';

    do {
        char           path[XRDC_PATH_MAX * 5];
        char           hdrs[2048];
        s3_list_out_t  out = { path, sizeof(path), hdrs, sizeof(hdrs) };
        brix_http_resp r;
        int            more = 0;

        if (++rounds > 100000) {
            brix_strv_free(acc.arr, acc.n);
            brix_status_set(st, XRDC_EPROTO, 0, "s3 list: too many pages");
            return -1;
        }
        if (s3_list_build_request(&req, token, &out, st) != 0) {
            brix_strv_free(acc.arr, acc.n);
            return -1;
        }
        if (brix_http_req(u->host, u->port, u->tls, "GET", path, hdrs[0] ? hdrs : NULL,
                          NULL, 0, XRDC_WEBLIST_TIMEOUT, verify, ca_dir, &r, st) != 0) {
            brix_strv_free(acc.arr, acc.n);
            return -1;
        }
        if (r.status != 200) {
            brix_status_set(st, XRDC_EPROTO, 0, "s3 ListObjectsV2 returned HTTP %d", r.status);
            brix_http_resp_free(&r);
            brix_strv_free(acc.arr, acc.n);
            return -1;
        }
        if (s3_list_scan_keys(&r, &acc, st) != 0
            || s3_list_next_token(&r, token, sizeof(token), &more, st) != 0) {
            brix_http_resp_free(&r);
            brix_strv_free(acc.arr, acc.n);
            return -1;
        }
        brix_http_resp_free(&r);
        if (!more) { break; }
    } while (1);

    *keys = acc.arr;
    *n_out = acc.n;
    return 0;
}

int
brix_webdav_mkcol(const brix_weburl *u, const char *path, const char *bearer,
                  int verify, const char *ca_dir, brix_status *st)
{
    char           headers[8192];
    brix_http_resp r;
    int            ok;

    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(headers, sizeof(headers), "Authorization: Bearer %s\r\n", bearer);
    } else {
        headers[0] = '\0';
    }
    if (brix_http_req(u->host, u->port, u->tls, "MKCOL", path,
                      headers[0] ? headers : NULL, NULL, 0, XRDC_WEBLIST_TIMEOUT,
                      verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    /* 201 = created; 200 = ok; 405 (Method Not Allowed) / 301 = the collection
     * already exists → idempotent success. Anything else is a real failure. */
    ok = (r.status == 201 || r.status == 200 || r.status == 405 || r.status == 301);
    if (!ok) {
        brix_status_set(st, XRDC_EPROTO, 0, "MKCOL returned HTTP %d", r.status);
    }
    brix_http_resp_free(&r);
    return ok ? 0 : -1;
}

/* ---- Build the PROPFIND request headers for a Depth: infinity listing ----
 *
 * WHAT: Writes "Depth: infinity" plus an optional bearer Authorization line into
 *       headers[].
 * WHY:  The listing walks the whole collection (Depth: infinity) and may need a
 *       token; isolating the header build keeps the caller free of the auth branch.
 * HOW:  1. With a non-empty bearer, emit both the Depth and Authorization lines.
 *       2. Otherwise emit only the Depth line.
 */
static void
webdav_list_build_headers(const char *bearer, char *headers, size_t headerssz)
{
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(headers, headerssz,
                 "Depth: infinity\r\nAuthorization: Bearer %s\r\n", bearer);
    } else {
        snprintf(headers, headerssz, "Depth: infinity\r\n");
    }
}

/* ---- Append the file path of one <D:response> block, if it is a file ----
 *
 * WHAT: Given a single multistatus response block [p, end), extracts its <D:href>,
 *       skips it when the block carries <D:collection/>, and otherwise pushes the
 *       percent-decoded path onto *arr / *n / *cap. Returns 0 (including for skipped
 *       collections and hrefless/malformed blocks), or -1 (with *st set to
 *       XRDC_EPROTO) on an allocation failure.
 * WHY:  The response scan reduces to "per block, emit its file"; pulling the block
 *       logic out keeps the scan loop to control flow only.
 * HOW:  1. Locate <D:href>..</D:href> inside the block; absent → nothing to emit.
 *       2. If the block also holds <D:collection>, it is a directory → skip. 3. Else
 *       percent-decode the href (flags=0 keeps a literal '+'), reduce an absolute-URL
 *       href to its path component, and push it.
 */
static int
webdav_list_emit_block(const char *p, const char *end, weblist_acc_t *acc,
                       brix_status *st)
{
    const char *h = strstr(p, "<D:href>");
    const char *he;
    const char *col;
    char        href[XRDC_PATH_MAX];
    const char *path = href;

    if (h == NULL || h >= end) {
        return 0;
    }
    h += 8;
    he = strstr(h, "</D:href>");
    if (he == NULL || he >= end) {
        return 0;
    }
    col = strstr(p, "<D:collection");
    if (col != NULL && col < end) {
        return 0;   /* directory — subdirs are recreated from the file paths */
    }
    /* flags=0: keep a literal '+' (it is a real path byte in an href, not a
     * form-encoded space). */
    if (brix_http_urldecode((const unsigned char *) h, (size_t) (he - h),
                            href, sizeof(href), 0) != BRIX_URLDECODE_OK) {
        href[0] = '\0';   /* overflow/malformed → skip content */
    }
    /* reduce an absolute-URL href to its path component */
    if (strstr(href, "://") != NULL) {
        char *sl = strstr(href, "://");
        char *ps = strchr(sl + 3, '/');
        path = ps ? ps : "/";
    }
    if (push(acc, path) != 0) {
        brix_status_set(st, XRDC_EPROTO, 0, "webdav list: out of memory");
        return -1;
    }
    return 0;
}

/* ---- Scan a PROPFIND multistatus body, collecting every file path ----
 *
 * WHAT: Walks each <D:response>..</D:response> block in body and appends the file
 *       paths onto *arr / *n / *cap, up to XRDC_WEBLIST_MAX. Returns 0, or -1 (with *st
 *       set) on an allocation failure inside a block.
 * WHY:  Separates the block-boundary iteration from the per-block extraction so the
 *       public entry stays a thin request/dispatch shell.
 * HOW:  1. Find each "<D:response" and its closing "</D:response>"; stop at an
 *       unterminated block or the entry cap. 2. Hand the block to
 *       webdav_list_emit_block. 3. Advance past the close tag.
 */
static int
webdav_list_scan_body(const char *body, weblist_acc_t *acc, brix_status *st)
{
    const char *p = body ? body : "";

    while ((p = strstr(p, "<D:response")) != NULL && acc->n < XRDC_WEBLIST_MAX) {
        const char *end = strstr(p, "</D:response>");
        if (end == NULL) {
            break;
        }
        if (webdav_list_emit_block(p, end, acc, st) != 0) {
            return -1;
        }
        p = end + 12;
    }
    return 0;
}

int
brix_webdav_list(const brix_weburl *u, const char *bearer, int verify,
                 const char *ca_dir, char ***paths, size_t *n_out, brix_status *st)
{
    char           headers[8192];
    brix_http_resp r;
    weblist_acc_t  acc = { NULL, 0, 0 };

    *paths = NULL;
    *n_out = 0;
    if (u->is_s3) {
        brix_status_set(st, XRDC_EUSAGE, 0, "recursive copy: s3:// listing not supported yet");
        return -1;
    }
    webdav_list_build_headers(bearer, headers, sizeof(headers));
    if (brix_http_req(u->host, u->port, u->tls, "PROPFIND", u->path, headers,
                      NULL, 0, XRDC_WEBLIST_TIMEOUT, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        brix_status_set(st, XRDC_EPROTO, 0, "PROPFIND returned HTTP %d", r.status);
        brix_http_resp_free(&r);
        return -1;
    }

    if (webdav_list_scan_body(r.body, &acc, st) != 0) {
        brix_strv_free(acc.arr, acc.n);
        brix_http_resp_free(&r);
        return -1;
    }
    brix_http_resp_free(&r);
    *paths = acc.arr;
    *n_out = acc.n;
    return 0;
}
