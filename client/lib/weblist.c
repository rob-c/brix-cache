/*
 * weblist.c — list the files under a WebDAV collection (for recursive web copy).
 *
 * WHAT: xrdc_webdav_list() issues one PROPFIND Depth: infinity against a davs/http
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
#include "xrdc.h"
#include "core/compat/uri.h"          /* shared RFC-3986 percent-decoder (libxrdproto) */
#include "core/compat/host_format.h"  /* xrootd_format_host_port (IPv6-bracketed Host) */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define XRDC_WEBLIST_MAX     200000   /* hard cap on files returned */
#define XRDC_WEBLIST_TIMEOUT 60000

/* Append a strdup'd copy of [s,s+len) to a growable array. 0 / -1. */
static int
push(char ***arr, size_t *n, size_t *cap, const char *s)
{
    if (*n == *cap) {
        size_t  nc = *cap ? *cap * 2 : 64;
        char  **na = (char **) realloc(*arr, nc * sizeof(char *));
        if (na == NULL) { return -1; }
        *arr = na;
        *cap = nc;
    }
    (*arr)[*n] = strdup(s);
    if ((*arr)[*n] == NULL) { return -1; }
    (*n)++;
    return 0;
}

void
xrdc_strv_free(char **arr, size_t n)
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
        if (xrootd_http_urlencode((const unsigned char *) token, strlen(token),
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

int
xrdc_s3_list(const xrdc_weburl *u, const char *ak, const char *sk,
             const char *region, int verify, const char *ca_dir,
             char ***keys, size_t *n_out, xrdc_status *st)
{
    char        bucket[256], prefix[XRDC_PATH_MAX], encp[XRDC_PATH_MAX * 3];
    char        hostport[300];
    char      **arr = NULL;
    size_t      n = 0, cap = 0;
    const char *bsl;
    /* The server's NextContinuationToken is the b64url of the last returned key
     * (keys up to S3_MAX_KEY=4096 → token up to ~5.5 KB), so this MUST be large
     * enough or pagination silently corrupts. */
    char        token[8192];
    int         rounds = 0;

    *keys = NULL;
    *n_out = 0;
    if (region == NULL || region[0] == '\0') { region = "us-east-1"; }
    /* u->path = "/bucket[/prefix...]" → split bucket vs prefix. */
    if (u->path[0] != '/') {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 list: bad path");
        return -1;
    }
    bsl = strchr(u->path + 1, '/');
    if (bsl == NULL) {
        snprintf(bucket, sizeof(bucket), "%s", u->path + 1);
        prefix[0] = '\0';
    } else {
        size_t bl = (size_t) (bsl - (u->path + 1));
        if (bl >= sizeof(bucket)) { xrdc_status_set(st, XRDC_EUSAGE, 0, "s3: bucket too long"); return -1; }
        memcpy(bucket, u->path + 1, bl);
        bucket[bl] = '\0';
        snprintf(prefix, sizeof(prefix), "%s", bsl + 1);
    }
    /* The SigV4 signed host MUST match the wire Host header byte-for-byte; that
     * header is built bracketed for IPv6 literals ([::1]:9000), so sign the same. */
    xrootd_format_host_port(u->host, (uint16_t) u->port, hostport, sizeof(hostport));
    if (xrootd_http_urlencode((const unsigned char *) prefix, strlen(prefix),
                              encp, sizeof(encp), "") < 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "s3: prefix too long");
        return -1;
    }
    token[0] = '\0';

    do {
        char           canon_uri[300], canon_qs[XRDC_PATH_MAX * 4], path[XRDC_PATH_MAX * 5];
        char           hdrs[2048];
        xrdc_http_resp r;
        const char    *p;
        char           trunc[8];
        int            more = 0;

        if (++rounds > 100000) {
            xrdc_strv_free(arr, n);
            xrdc_status_set(st, XRDC_EPROTO, 0, "s3 list: too many pages");
            return -1;
        }
        snprintf(canon_uri, sizeof(canon_uri), "/%s", bucket);
        if (s3_canon_qs(token, encp, prefix[0] != '\0', canon_qs, sizeof(canon_qs)) != 0
            || (size_t) snprintf(path, sizeof(path), "%s?%s", canon_uri, canon_qs)
                   >= sizeof(path)) {
            xrdc_strv_free(arr, n);
            xrdc_status_set(st, XRDC_EUSAGE, 0, "s3 list: prefix/continuation too long");
            return -1;
        }

        hdrs[0] = '\0';
        if (ak != NULL && sk != NULL && ak[0] != '\0' && sk[0] != '\0') {
            if (xrdc_s3_sign_v4_q("GET", hostport, canon_uri, canon_qs, ak, sk,
                                  region, "UNSIGNED-PAYLOAD", hdrs, sizeof(hdrs)) != 0) {
                xrdc_strv_free(arr, n);
                xrdc_status_set(st, XRDC_EAUTH, 0, "s3 list: failed to sign request");
                return -1;
            }
        }
        if (xrdc_http_req(u->host, u->port, u->tls, "GET", path, hdrs[0] ? hdrs : NULL,
                          NULL, 0, XRDC_WEBLIST_TIMEOUT, verify, ca_dir, &r, st) != 0) {
            xrdc_strv_free(arr, n);
            return -1;
        }
        if (r.status != 200) {
            xrdc_status_set(st, XRDC_EPROTO, 0, "s3 ListObjectsV2 returned HTTP %d", r.status);
            xrdc_http_resp_free(&r);
            xrdc_strv_free(arr, n);
            return -1;
        }
        p = r.body ? r.body : "";
        for (;;) {
            char key[XRDC_PATH_MAX];
            int  kr = xml_tag(&p, "<Key>", "</Key>", key, sizeof(key));
            if (kr == 0 || n >= XRDC_WEBLIST_MAX) {
                break;
            }
            if (kr < 0) {
                /* A key longer than our buffer would yield a wrong download URL —
                 * fail loudly rather than silently dropping or mangling it. */
                xrdc_http_resp_free(&r);
                xrdc_strv_free(arr, n);
                xrdc_status_set(st, XRDC_EPROTO, 0,
                                "s3 list: object key exceeds %zu bytes", sizeof(key));
                return -1;
            }
            if (push(&arr, &n, &cap, key) != 0) {
                xrdc_http_resp_free(&r);
                xrdc_strv_free(arr, n);
                xrdc_status_set(st, XRDC_EPROTO, 0, "s3 list: out of memory");
                return -1;
            }
        }
        /* pagination: IsTruncated + NextContinuationToken */
        token[0] = '\0';
        {
            const char *tp = r.body ? r.body : "";
            if (xml_tag(&tp, "<IsTruncated>", "</IsTruncated>", trunc, sizeof(trunc)) == 1
                && strcmp(trunc, "true") == 0) {
                const char *np = r.body;
                int         tr = xml_tag(&np, "<NextContinuationToken>",
                                         "</NextContinuationToken>", token, sizeof(token));
                if (tr < 0) {
                    /* token truncated → continuing would corrupt the listing */
                    xrdc_http_resp_free(&r);
                    xrdc_strv_free(arr, n);
                    xrdc_status_set(st, XRDC_EPROTO, 0,
                                    "s3 list: continuation token too long");
                    return -1;
                }
                more = (tr == 1);
            }
        }
        xrdc_http_resp_free(&r);
        if (!more) { break; }
    } while (1);

    *keys = arr;
    *n_out = n;
    return 0;
}

int
xrdc_webdav_mkcol(const xrdc_weburl *u, const char *path, const char *bearer,
                  int verify, const char *ca_dir, xrdc_status *st)
{
    char           headers[8192];
    xrdc_http_resp r;
    int            ok;

    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(headers, sizeof(headers), "Authorization: Bearer %s\r\n", bearer);
    } else {
        headers[0] = '\0';
    }
    if (xrdc_http_req(u->host, u->port, u->tls, "MKCOL", path,
                      headers[0] ? headers : NULL, NULL, 0, XRDC_WEBLIST_TIMEOUT,
                      verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    /* 201 = created; 200 = ok; 405 (Method Not Allowed) / 301 = the collection
     * already exists → idempotent success. Anything else is a real failure. */
    ok = (r.status == 201 || r.status == 200 || r.status == 405 || r.status == 301);
    if (!ok) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "MKCOL returned HTTP %d", r.status);
    }
    xrdc_http_resp_free(&r);
    return ok ? 0 : -1;
}

int
xrdc_webdav_list(const xrdc_weburl *u, const char *bearer, int verify,
                 const char *ca_dir, char ***paths, size_t *n_out, xrdc_status *st)
{
    char           headers[8192];
    xrdc_http_resp r;
    char         **arr = NULL;
    size_t         n = 0, cap = 0;
    const char    *p;
    int            rc = -1;

    *paths = NULL;
    *n_out = 0;
    if (u->is_s3) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "recursive copy: s3:// listing not supported yet");
        return -1;
    }
    if (bearer != NULL && bearer[0] != '\0') {
        snprintf(headers, sizeof(headers),
                 "Depth: infinity\r\nAuthorization: Bearer %s\r\n", bearer);
    } else {
        snprintf(headers, sizeof(headers), "Depth: infinity\r\n");
    }
    if (xrdc_http_req(u->host, u->port, u->tls, "PROPFIND", u->path, headers,
                      NULL, 0, XRDC_WEBLIST_TIMEOUT, verify, ca_dir, &r, st) != 0) {
        return -1;
    }
    if (r.status != 207 && r.status != 200) {
        xrdc_status_set(st, XRDC_EPROTO, 0, "PROPFIND returned HTTP %d", r.status);
        xrdc_http_resp_free(&r);
        return -1;
    }

    p = r.body ? r.body : "";
    while ((p = strstr(p, "<D:response")) != NULL && n < XRDC_WEBLIST_MAX) {
        const char *end = strstr(p, "</D:response>");
        const char *h, *he;
        int         is_dir;
        if (end == NULL) {
            break;
        }
        h = strstr(p, "<D:href>");
        if (h != NULL && h < end) {
            h += 8;
            he = strstr(h, "</D:href>");
            if (he != NULL && he < end) {
                const char *col = strstr(p, "<D:collection");
                is_dir = (col != NULL && col < end);
                if (!is_dir) {
                    char        href[XRDC_PATH_MAX];
                    const char *path = href;
                    /* flags=0: keep a literal '+' (it is a real path byte in an
                     * href, not a form-encoded space). */
                    if (xrootd_http_urldecode((const unsigned char *) h,
                                              (size_t) (he - h), href,
                                              sizeof(href), 0)
                        != XROOTD_URLDECODE_OK) {
                        href[0] = '\0';   /* overflow/malformed → skip content */
                    }
                    /* reduce an absolute-URL href to its path component */
                    if (strstr(href, "://") != NULL) {
                        char *sl = strstr(href, "://");
                        char *ps = strchr(sl + 3, '/');
                        path = ps ? ps : "/";
                    }
                    if (push(&arr, &n, &cap, path) != 0) {
                        xrdc_strv_free(arr, n);
                        xrdc_http_resp_free(&r);
                        xrdc_status_set(st, XRDC_EPROTO, 0, "webdav list: out of memory");
                        return -1;
                    }
                }
            }
        }
        p = end + 12;
    }
    xrdc_http_resp_free(&r);
    *paths = arr;
    *n_out = n;
    rc = 0;
    return rc;
}
