/* _weblist_part2.c — fragment 2 of weblist.c (auto-split).
 * Do not compile directly; it is #included by weblist.c. */
#ifndef _WEBLIST_PART2_C_INC
#define _WEBLIST_PART2_C_INC
#ifndef __WEBLIST_C_COMPILED__
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

#endif /* __WEBLIST_C_COMPILED__ */

/* ---- DELETE a WebDAV resource (file or empty collection) ----
 *
 * WHAT: Issues one WebDAV DELETE for `path` on endpoint `u`. Returns 0 on
 *       success (200/202/204), -1 with *st set otherwise — 404/410 mapped to
 *       XRDC_ENOENT, 401/403 to XRDC_EAUTH. bearer NULL ⇒ anonymous;
 *       client_cert is the X.509 proxy PEM for mutual TLS (or NULL).
 *
 * WHY:  gives `xrdfs rm`/`rmdir` a WebDAV transport so write-metadata verbs work
 *       over http/https/dav/davs, not only root://. DELETE is NOT made idempotent
 *       on 404 (unlike MKCOL): removing a non-existent path is a real error the
 *       user should see, matching the binary protocol's kXR_NotFound.
 *
 * HOW:  1. Build the optional bearer header.
 *       2. brix_http_req(..., "DELETE", ...).
 *       3. Accept 200/202/204; otherwise set a mapped status and fail.
 */
int
brix_webdav_delete(const brix_weburl *u, const char *path, const char *bearer,
                   int verify, const char *ca_dir, const char *client_cert,
                   brix_status *st)
{
    char           headers[8192];
    brix_http_resp r;
    int            ok;

    webdav_bearer_header(bearer, headers, sizeof(headers));
    if (brix_http_req(u->host, u->port, u->tls, "DELETE", path,
                      headers[0] ? headers : NULL, NULL, 0, XRDC_WEBLIST_TIMEOUT,
                      verify, ca_dir, client_cert, &r, st) != 0) {
        return -1;
    }
    ok = (r.status == 200 || r.status == 202 || r.status == 204);
    if (!ok) {
        brix_status_set(st, webdav_status_to_xrdc(r.status), 0,
                        "DELETE returned HTTP %d", r.status);
    }
    brix_http_resp_free(&r);
    return ok ? 0 : -1;
}


/* ---- MOVE (rename) a WebDAV resource ----
 *
 * WHAT: Issues one WebDAV MOVE of `path` to `dest_abs` (an absolute-URL
 *       Destination) on endpoint `u`, with "Overwrite: T". Returns 0 on success
 *       (200/201/204), -1 with *st set otherwise (mapped like DELETE).
 *
 * WHY:  backs `xrdfs mv` over WebDAV. The MOVE Destination MUST be an absolute
 *       URI per RFC 4918; the caller supplies "<scheme>://host:port/newpath" so
 *       this helper does not need to know the endpoint's external scheme.
 *
 * HOW:  1. Compose the "Destination: …\r\nOverwrite: T\r\n" block, appending the
 *          optional bearer line.
 *       2. brix_http_req(..., "MOVE", path, headers, ...).
 *       3. Accept 200/201/204; otherwise set a mapped status and fail.
 */
int
brix_webdav_move(const brix_weburl *u, const char *path, const char *dest_abs,
                 const char *bearer, int verify, const char *ca_dir,
                 const char *client_cert, brix_status *st)
{
    char           headers[8192];
    char           bearer_hdr[8192];
    brix_http_resp r;
    int            ok;

    webdav_bearer_header(bearer, bearer_hdr, sizeof(bearer_hdr));
    snprintf(headers, sizeof(headers),
             "Destination: %s\r\nOverwrite: T\r\n%s", dest_abs, bearer_hdr);
    if (brix_http_req(u->host, u->port, u->tls, "MOVE", path,
                      headers, NULL, 0, XRDC_WEBLIST_TIMEOUT,
                      verify, ca_dir, client_cert, &r, st) != 0) {
        return -1;
    }
    ok = (r.status == 200 || r.status == 201 || r.status == 204);
    if (!ok) {
        brix_status_set(st, webdav_status_to_xrdc(r.status), 0,
                        "MOVE returned HTTP %d", r.status);
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
                 const char *ca_dir, const char *client_cert,
                 char ***paths, size_t *n_out, brix_status *st)
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
                      NULL, 0, XRDC_WEBLIST_TIMEOUT, verify, ca_dir, client_cert, &r, st) != 0) {
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
#endif /* _WEBLIST_PART2_C_INC */
