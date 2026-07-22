/*
 * search.c - Basic WebDAV SEARCH support (RFC 5323).
 *
 * Implements DAV:basicsearch over the request URI scope.  The supported query
 * subset is intentionally conservative: no WHERE clause means "match all";
 * a DAV:contains/DAV:literal clause filters by displayname substring.
 */

#include "search_internal.h"   /* webdav_search_query_t + webdav_search_parse */
#include "auth/impersonate/lifecycle.h"
#include "fs/path/path.h"
#include "fs/vfs/vfs.h"   /* confined walk via vfs_opendir_quiet/readdir_kind/probe */
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */
#include "core/compat/fs_walk.h"
#include "core/http/http_body.h"
#include "core/http/http_xml.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Shared state threaded through the (recursive) directory walk.  Collapsing the
 * request, the multistatus chain endpoints, the entry counter and the query into
 * one file-local struct keeps webdav_search_walk (and its extracted stage
 * helpers) at ≤5 params while passing state explicitly — only `dir_path` and
 * `base_href` vary per recursion level and stay as call arguments.
 */
typedef struct {
    ngx_http_request_t          *r;
    ngx_chain_t                **head;
    ngx_chain_t                **tail;
    ngx_uint_t                  *count;
    const webdav_search_query_t *q;
} webdav_search_walk_ctx_t;

/*
 * Predicate: does this href satisfy the query?  An empty literal matches
 * everything; otherwise the literal must appear as a substring of the last path
 * segment (displayname), matching the conservative DAV:contains semantics.
 */
static ngx_flag_t
webdav_search_matches(const char *href, const webdav_search_query_t *q)
{
    const char *name;

    if (q->literal[0] == '\0') {
        return 1;   /* no WHERE clause → match all */
    }

    /* Reduce href to its final segment (the displayname). */
    name = href + strlen(href);
    while (name > href && *(name - 1) != '/') {
        name--;
    }

    return strstr(name, q->literal) != NULL;
}

/*
 * Append one <D:response> for `href` to the multistatus chain, but only if it
 * matches the query (non-matches return NGX_OK without emitting anything).
 * The href is XML-escaped before interpolation.
 */
static ngx_int_t
webdav_search_append_response(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, const char *href, const webdav_search_query_t *q)
{
    char *safe_href;

    if (!webdav_search_matches(href, q)) {
        return NGX_OK;
    }

    safe_href = webdav_escape_xml_text(r->pool, href);
    if (safe_href == NULL) {
        return NGX_ERROR;
    }

    return brix_http_chain_appendf(r->pool, head, tail,
            "<D:response><D:href>%s</D:href>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:response>",
            safe_href) == NULL
           ? NGX_ERROR : NGX_OK;
}

static ngx_int_t
webdav_search_walk(webdav_search_walk_ctx_t *w, const char *dir_path,
    const char *base_href);

/*
 * WHAT: Test whether a directory listing entry should be skipped entirely.
 * WHY:  SEARCH never surfaces dotfiles or the internal sidecar/upload-temp
 *       namespace, and readdir already elides "."/".." — factoring the filter
 *       out keeps the walk loop focused on emitting matches.
 * HOW:  Returns 1 (skip) for a leading '.' or a reserved internal name, else 0.
 */
static int
webdav_search_entry_skip(const char *dname)
{
    if (dname[0] == '.') {
        return 1;   /* skip hidden files (search never lists dotfiles) */
    }
    if (brix_is_internal_name(dname)) {
        return 1;   /* hide internal sidecars / upload temps (not dotfiles) */
    }
    return 0;
}

/*
 * WHAT: Compose the child href = base_href + dname with exactly one separating
 *       '/', into the caller-provided buffer.
 * WHY:  base_href may or may not already end in '/'; the walk must never emit a
 *       double slash or a truncated href, and both truncation branches share the
 *       same "skip this entry" outcome.
 * HOW:  Picks the join format from base_href's trailing byte; returns NGX_OK on
 *       success or NGX_DECLINED when the formatted result would be truncated (a
 *       caller sentinel to skip the entry — no bytes are emitted).
 */
static ngx_int_t
webdav_search_child_href(const char *base_href, const char *dname,
    char *child_href, size_t child_href_size)
{
    size_t blen = strlen(base_href);
    int    n;

    if (blen == 0 || base_href[blen - 1] != '/') {
        n = snprintf(child_href, child_href_size, "%s/%s", base_href, dname);
    } else {
        n = snprintf(child_href, child_href_size, "%s%s", base_href, dname);
    }

    return (size_t) n >= child_href_size ? NGX_DECLINED : NGX_OK;
}

/*
 * WHAT: Decide whether a listing entry is a directory to recurse into.
 * WHY:  d_type answers directly on most filesystems; only a DT_UNKNOWN result
 *       needs a fallback, and that fallback must be a confined *no-follow* probe
 *       so a trailing symlink is never followed into recursion.
 * HOW:  Returns 1 for BRIX_VFS_DT_DIR; for BRIX_VFS_DT_UNKNOWN runs a confined
 *       no-follow VFS probe of child_path; else 0.
 */
static int
webdav_search_entry_is_dir(webdav_search_walk_ctx_t *w,
    const char *root_canon, brix_vfs_dirent_kind_t dkind,
    const char *child_path)
{
    brix_vfs_ctx_t  pctx;
    brix_vfs_stat_t vst;

    if (dkind == BRIX_VFS_DT_DIR) {
        return 1;
    }
    if (dkind != BRIX_VFS_DT_UNKNOWN) {
        return 0;
    }

    brix_vfs_ctx_init(&pctx, w->r->pool, w->r->connection->log,
        BRIX_PROTO_WEBDAV, root_canon, NULL, 0, 0, NULL, child_path);
    return brix_vfs_probe(&pctx, 1 /* no-follow */, &vst) == NGX_OK
           && vst.is_directory;
}

/*
 * WHAT: Process one already-composed child (append its response, then recurse
 *       into it when the scope is depth-infinity and it is a directory).
 * WHY:  Isolating per-entry emission + descent from the enumeration loop keeps
 *       both the loop and this stage single-purpose and below the complexity cap.
 * HOW:  Appends the child response (NGX_ERROR propagates to the caller to abort
 *       the walk); bumps the shared counter; for a depth==infinity directory,
 *       builds the sub_href (skipping on truncation) and recurses.  Returns
 *       NGX_OK on success or NGX_ERROR on an unrecoverable append/recursion
 *       failure.
 */
static ngx_int_t
webdav_search_visit_child(webdav_search_walk_ctx_t *w, const char *root_canon,
    brix_vfs_dirent_kind_t dkind, const char *child_path,
    const char *child_href)
{
    if (webdav_search_append_response(w->r, w->head, w->tail, child_href, w->q)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    (*w->count)++;

    if (w->q->depth == -1
        && webdav_search_entry_is_dir(w, root_canon, dkind, child_path))
    {
        char sub_href[WEBDAV_MAX_PATH + 3];

        if ((size_t) snprintf(sub_href, sizeof(sub_href), "%s/", child_href)
                < sizeof(sub_href)
            && webdav_search_walk(w, child_path, sub_href) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Enumerate one open directory, visiting each qualifying child.
 * WHY:  Split from the walk so the open/confine/close lifecycle and the per-entry
 *       loop are separate responsibilities.
 * HOW:  Loops readdir until end/error or the result-set cap; skips filtered and
 *       truncated/un-joinable entries; delegates emission+descent to
 *       webdav_search_visit_child.  Returns NGX_OK to finish the directory or
 *       NGX_ERROR to abort the whole walk.
 */
static ngx_int_t
webdav_search_scan_dir(webdav_search_walk_ctx_t *w, brix_vfs_dir_t *dp,
    const char *root_canon, const char *dir_path, const char *base_href)
{
    for ( ;; ) {
        ngx_str_t                name;
        brix_vfs_dirent_kind_t   dkind;
        const char              *dname;
        char                     child_path[WEBDAV_MAX_PATH];
        char                     child_href[WEBDAV_MAX_PATH + 2];

        if (*w->count >= WEBDAV_SEARCH_MAX_ENTRIES) {
            break;   /* result-set cap reached: stop scanning this dir */
        }

        /* "."/".." are filtered by readdir_kind; the entry KIND comes from d_type
         * (no per-entry stat). A symlink/special is listed but never recursed. */
        if (brix_vfs_readdir_kind(dp, &name, &dkind) != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop */
        }
        dname = (const char *) name.data;

        if (webdav_search_entry_skip(dname)) {
            continue;
        }
        if (brix_fs_join_path(dir_path, dname, child_path,
                                sizeof(child_path)) != NGX_OK)
        {
            continue;
        }
        if (webdav_search_child_href(base_href, dname, child_href,
                                     sizeof(child_href)) != NGX_OK)
        {
            continue;   /* href would truncate: skip this entry */
        }

        if (webdav_search_visit_child(w, root_canon, dkind, child_path,
                                      child_href) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * WHAT: Recursively scan dir_path, appending a response for each matching
 *       descendant.  Recurses only when depth==infinity.
 * WHY:  Entry point for the SEARCH namespace walk; owns the confidentiality gate
 *       and the VFS directory lifecycle while delegating enumeration.
 * HOW:  Applies the Phase-40 mapped-user access gate (skip subtree on denial),
 *       opens the directory NON-metered through the VFS, scans it, and always
 *       closes the handle.  The shared counter caps the result set.  Unreadable
 *       dirs are skipped (NGX_OK); an append/recursion failure returns NGX_ERROR
 *       with the directory closed first.
 */
static ngx_int_t
webdav_search_walk(webdav_search_walk_ctx_t *w, const char *dir_path,
    const char *base_href)
{
    brix_vfs_ctx_t  wctx;
    brix_vfs_dir_t *dp;
    ngx_int_t       rc;
    ngx_http_brix_webdav_loc_conf_t *wdcf =
        ngx_http_get_module_loc_conf(w->r, ngx_http_brix_webdav_module);
    const char     *root_canon = (const char *) wdcf->common.root_canon;

    /*
     * Phase 40 confidentiality gate (mirrors propfind): under impersonation the
     * worker uid may be able to readdir() a directory the *mapped* user cannot.
     * Ask the broker to open it as the mapped user first; on denial skip this
     * subtree silently rather than enumerate it with the worker's credentials.
     * No-op (returns NGX_OK) when impersonation is off.
     */
    if (brix_dirlist_access_ok(w->r->connection->log, wdcf->common.root_canon,
                                 dir_path) != NGX_OK)
    {
        return NGX_OK;   /* mapped user may not list this dir — no leak */
    }

    /* Enumerate through the VFS (broker fdopendir under impersonation), NON-metered:
     * a depth-infinity SEARCH must not emit one OP_DIRLIST per visited subdir (the
     * SEARCH op accounts for the whole walk). */
    brix_vfs_ctx_init(&wctx, w->r->pool, w->r->connection->log,
        BRIX_PROTO_WEBDAV, wdcf->common.root_canon, NULL, 0 /* allow_write */,
        0 /* is_tls */, NULL, dir_path);
    dp = brix_vfs_opendir_quiet(&wctx, NULL);
    if (dp == NULL) {
        return NGX_OK;   /* unreadable subtree: skip silently */
    }

    rc = webdav_search_scan_dir(w, dp, root_canon, dir_path, base_href);

    brix_vfs_closedir(dp, w->r->connection->log);
    return rc;
}

/*
 * WHAT: Build the 207 multistatus body chain for the resolved SEARCH scope.
 * WHY:  Splitting body construction from response finalization keeps each stage
 *       single-purpose; this stage owns the XML framing and the walk fan-out.
 * HOW:  Emits the multistatus prologue, the scope's own <D:response>, then (for
 *       depth 1 / infinity on a directory scope) the matching descendants via
 *       webdav_search_walk, and the closing tag.  The chain endpoints and entry
 *       counter live in the caller-owned walk ctx `w`; the scope href is r->uri
 *       truncated to the buffer, exactly as before.  Returns NGX_OK, or
 *       NGX_HTTP_INTERNAL_SERVER_ERROR on any chain-append / walk failure.
 */
static ngx_int_t
webdav_search_build_body(webdav_search_walk_ctx_t *w, const char *path,
    const struct stat *sb, const webdav_search_query_t *q)
{
    ngx_http_request_t *r = w->r;
    char                href[WEBDAV_MAX_PATH + 2];
    size_t              uri_len;

    if (brix_http_chain_appendf(r->pool, w->head, w->tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uri_len = r->uri.len < sizeof(href) - 1 ? r->uri.len : sizeof(href) - 1;
    ngx_memcpy(href, r->uri.data, uri_len);
    href[uri_len] = '\0';

    if (webdav_search_append_response(r, w->head, w->tail, href, q) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if ((q->depth == 1 || q->depth == -1) && S_ISDIR(sb->st_mode)
        && webdav_search_walk(w, path, href) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (brix_http_chain_appendf(r->pool, w->head, w->tail,
            "</D:multistatus>") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Finalize the 207 multistatus response: mark the chain end, set status /
 *       length / Content-Type, then send headers and the body.
 * WHY:  Isolates the nginx output plumbing from body construction so both stay
 *       below the complexity cap.
 * HOW:  Flags the tail as last buffer, sums the body length, sets the 207 status
 *       and the XML Content-Type header, sends the header (short-circuiting on
 *       error / header_only exactly as before) and streams the chain.  Returns
 *       the ngx_http_send_header / ngx_http_output_filter result or
 *       NGX_HTTP_INTERNAL_SERVER_ERROR on header-list push failure.
 */
static ngx_int_t
webdav_search_finalize(ngx_http_request_t *r, ngx_chain_t *head,
    ngx_chain_t *tail)
{
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    ngx_int_t        rc;

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    r->headers_out.status = 207;
    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, head);
}

/*
 * Execute the SEARCH after the body is available: resolve+stat the scope,
 * parse the query, then build a 207 multistatus listing the scope itself plus
 * any matching children (depth 1) or descendants (infinity).  Returns an HTTP
 * status / NGX_* code.
 */
static ngx_int_t
webdav_search_do(ngx_http_request_t *r)
{
    char                     path[WEBDAV_MAX_PATH];
    struct stat              sb;
    ngx_int_t                rc;
    webdav_search_query_t    q;
    ngx_chain_t             *head = NULL, *tail = NULL;
    ngx_uint_t               count = 0;
    webdav_search_walk_ctx_t w;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_search_parse(r, &q);
    if (rc != NGX_OK) {
        return rc;
    }

    w.r = r;
    w.head = &head;
    w.tail = &tail;
    w.count = &count;
    w.q = &q;

    rc = webdav_search_build_body(&w, path, &sb, &q);
    if (rc != NGX_OK) {
        return rc;
    }

    return webdav_search_finalize(r, head, tail);
}

/*
 * Body-ready callback (async re-entry point): runs the search and finalizes the
 * request, also recording WebDAV metrics for the operation.
 *
 * Phase 40: SEARCH walks the namespace exactly like PROPFIND, so it is read
 * asynchronously and the outer dispatch wrapper has already cleared the
 * impersonation principal by the time this callback fires.  Re-establish it for
 * the (synchronous) walk so the directory stat/opendir and confidentiality
 * checks run as the mapped user — otherwise SEARCH would enumerate as the
 * unprivileged worker and could leak entries the mapped user cannot read.
 * No-op unless map mode is active.
 */
static void
webdav_search_body_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_int_t rc;

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = webdav_search_do(r);
    brix_imp_request_end();

    webdav_metrics_finalize_request(r, rc);
}

/*
 * SEARCH entry point.  The query lives in the request body, so work is deferred
 * to webdav_search_body_handler once the body is read.
 */
ngx_int_t
webdav_handle_search(ngx_http_request_t *r)
{
    return brix_http_read_body(r, webdav_search_body_handler);
}
