/*
 * search.c - Basic WebDAV SEARCH support (RFC 5323).
 *
 * Implements DAV:basicsearch over the request URI scope.  The supported query
 * subset is intentionally conservative: no WHERE clause means "match all";
 * a DAV:contains/DAV:literal clause filters by displayname substring.
 */

#include "webdav.h"
#include "impersonate/lifecycle.h"
#include "path/path.h"
#include "fs/vfs.h"   /* confined walk via vfs_opendir_quiet/readdir_kind/probe */
#include "compat/fs_walk.h"
#include "compat/http_body.h"
#include "compat/http_xml.h"

#include <dirent.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define WEBDAV_SEARCH_BODY_MAX       65536u
#define WEBDAV_SEARCH_MAX_ENTRIES    10000u

typedef struct {
    int   depth;
    char  literal[256];
} webdav_search_query_t;

/* Return the first direct child element of `parent` with the given local name,
 * or NULL.  NULL-safe in `parent` so callers can chain lookups without
 * intermediate NULL checks. */
static xmlNodePtr
webdav_search_find_child(xmlNodePtr parent, const char *name)
{
    xmlNodePtr n;

    for (n = parent != NULL ? parent->children : NULL; n != NULL; n = n->next) {
        if (n->type == XML_ELEMENT_NODE
            && xmlStrcmp(n->name, BAD_CAST name) == 0)
        {
            return n;
        }
    }

    return NULL;
}

/*
 * Depth-first search the subtree for the first DAV:literal element and copy its
 * text content into q->literal (truncated to the fixed buffer).  Stops at the
 * first match: the supported query subset has only one literal term.  q->literal
 * being non-empty is the sentinel that unwinds the recursion early.
 */
static void
webdav_search_find_literal(xmlNodePtr n, webdav_search_query_t *q)
{
    for (; n != NULL; n = n->next) {
        if (n->type == XML_ELEMENT_NODE
            && xmlStrcmp(n->name, BAD_CAST "literal") == 0)
        {
            xmlChar *text = xmlNodeGetContent(n);
            if (text != NULL) {
                ngx_cpystrn((u_char *) q->literal, text, sizeof(q->literal));
                xmlFree(text);
            }
            return;
        }

        webdav_search_find_literal(n->children, q);
        if (q->literal[0] != '\0') {
            return;
        }
    }
}

/*
 * Parse the SEARCH request body into a query descriptor.
 * Expects DAV:searchrequest > DAV:basicsearch; extracts the scope depth
 * (0 / 1 / infinity) and an optional DAV:contains literal.  Returns
 * NGX_HTTP_BAD_REQUEST for a missing/oversized/malformed body, NGX_OK otherwise.
 * The libxml2 parse flags are the same hardened set as PROPFIND (no network,
 * no external entities, no HUGE) to block entity-expansion DoS.
 */
static ngx_int_t
webdav_search_parse(ngx_http_request_t *r, webdav_search_query_t *q)
{
    u_char    *body = NULL;
    size_t     body_len = 0;
    ngx_int_t  rc;
    xmlDocPtr  doc;
    xmlNodePtr root, basic, from, scope, depth, where;
    int        opts = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
    opts |= XML_PARSE_NO_XXE;
#endif

    q->depth = 0;
    q->literal[0] = '\0';

    rc = xrootd_http_body_read_all(r, WEBDAV_SEARCH_BODY_MAX, &body, &body_len);
    if (rc != NGX_OK || body_len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    doc = xmlReadMemory((const char *) body, (int) body_len,
                        "search.xml", NULL, opts);
    if (doc == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    root = xmlDocGetRootElement(doc);
    basic = webdav_search_find_child(root, "basicsearch");
    if (root == NULL || xmlStrcmp(root->name, BAD_CAST "searchrequest") != 0
        || basic == NULL)
    {
        xmlFreeDoc(doc);
        return NGX_HTTP_BAD_REQUEST;
    }

    from = webdav_search_find_child(basic, "from");
    scope = webdav_search_find_child(from, "scope");
    depth = webdav_search_find_child(scope, "depth");
    if (depth != NULL) {
        xmlChar *text = xmlNodeGetContent(depth);
        if (text != NULL) {
            if (xmlStrcmp(text, BAD_CAST "1") == 0) {
                q->depth = 1;
            } else if (xmlStrcmp(text, BAD_CAST "infinity") == 0) {
                q->depth = -1;
            }
            xmlFree(text);
        }
    }

    where = webdav_search_find_child(basic, "where");
    if (where != NULL) {
        webdav_search_find_literal(where->children, q);
    }

    xmlFreeDoc(doc);
    return NGX_OK;
}

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

    return xrootd_http_chain_appendf(r->pool, head, tail,
            "<D:response><D:href>%s</D:href>"
            "<D:status>HTTP/1.1 200 OK</D:status></D:response>",
            safe_href) == NULL
           ? NGX_ERROR : NGX_OK;
}

/*
 * Recursively scan dir_path, appending a response for each matching descendant.
 * `count` is shared across the recursion and capped at WEBDAV_SEARCH_MAX_ENTRIES
 * to bound the result set.  Recurses only when depth==infinity.  Unreadable dirs
 * are skipped; on append error the DIR is closed before returning NGX_ERROR.
 */
static ngx_int_t
webdav_search_walk(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, const char *dir_path, const char *base_href,
    ngx_uint_t *count, const webdav_search_query_t *q)
{
    xrootd_vfs_ctx_t  wctx;
    xrootd_vfs_dir_t *dp;
    ngx_http_xrootd_webdav_loc_conf_t *wdcf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    /*
     * Phase 40 confidentiality gate (mirrors propfind): under impersonation the
     * worker uid may be able to readdir() a directory the *mapped* user cannot.
     * Ask the broker to open it as the mapped user first; on denial skip this
     * subtree silently rather than enumerate it with the worker's credentials.
     * No-op (returns NGX_OK) when impersonation is off.
     */
    if (xrootd_dirlist_access_ok(r->connection->log, wdcf->common.root_canon,
                                 dir_path) != NGX_OK)
    {
        return NGX_OK;   /* mapped user may not list this dir — no leak */
    }

    /* Enumerate through the VFS (broker fdopendir under impersonation), NON-metered:
     * a depth-infinity SEARCH must not emit one OP_DIRLIST per visited subdir (the
     * SEARCH op accounts for the whole walk). */
    xrootd_vfs_ctx_init(&wctx, r->pool, r->connection->log, XROOTD_PROTO_WEBDAV,
        wdcf->common.root_canon, NULL, 0 /* allow_write */, 0 /* is_tls */,
        NULL, dir_path);
    dp = xrootd_vfs_opendir_quiet(&wctx, NULL);
    if (dp == NULL) {
        return NGX_OK;   /* unreadable subtree: skip silently */
    }

    for ( ;; ) {
        ngx_str_t                name;
        xrootd_vfs_dirent_kind_t dkind;
        const char              *dname;
        char        child_path[WEBDAV_MAX_PATH];
        char        child_href[WEBDAV_MAX_PATH + 2];
        size_t      blen;
        int         is_dir;
        ngx_int_t   rrc;

        if (*count >= WEBDAV_SEARCH_MAX_ENTRIES) {
            break;   /* result-set cap reached: stop scanning this dir */
        }

        /* "."/".." are filtered by readdir_kind; the entry KIND comes from d_type
         * (no per-entry stat). A symlink/special is listed but never recursed. */
        rrc = xrootd_vfs_readdir_kind(dp, &name, &dkind);
        if (rrc != NGX_OK) {
            break;   /* NGX_DONE (end) or error → stop */
        }
        dname = (const char *) name.data;

        if (dname[0] == '.') {
            continue;   /* skip hidden files (search never lists dotfiles) */
        }

        if (xrootd_fs_join_path(dir_path, dname, child_path,
                                sizeof(child_path)) != NGX_OK)
        {
            continue;
        }

        /* Compose child href = base_href + name with exactly one separating
         * '/'; skip the entry if the result would be truncated. */
        blen = strlen(base_href);
        if (blen == 0 || base_href[blen - 1] != '/') {
            if ((size_t) snprintf(child_href, sizeof(child_href), "%s/%s",
                                  base_href, dname) >= sizeof(child_href))
            {
                continue;
            }
        } else if ((size_t) snprintf(child_href, sizeof(child_href), "%s%s",
                                     base_href, dname)
                   >= sizeof(child_href))
        {
            continue;
        }

        if (webdav_search_append_response(r, head, tail, child_href, q)
            != NGX_OK)
        {
            xrootd_vfs_closedir(dp, r->connection->log);
            return NGX_ERROR;
        }
        (*count)++;

        /* Recurse only into directories. d_type gives the answer directly; on a
         * DT_UNKNOWN filesystem fall back to a confined no-follow probe (so a
         * trailing symlink is never followed into recursion). */
        is_dir = (dkind == XROOTD_VFS_DT_DIR);
        if (dkind == XROOTD_VFS_DT_UNKNOWN) {
            xrootd_vfs_ctx_t  pctx;
            xrootd_vfs_stat_t vst;

            xrootd_vfs_ctx_init(&pctx, r->pool, r->connection->log,
                XROOTD_PROTO_WEBDAV, wdcf->common.root_canon, NULL, 0, 0, NULL,
                child_path);
            is_dir = (xrootd_vfs_probe(&pctx, 1 /* no-follow */, &vst) == NGX_OK
                      && vst.is_directory);
        }

        if (q->depth == -1 && is_dir) {
            char sub_href[WEBDAV_MAX_PATH + 3];
            if ((size_t) snprintf(sub_href, sizeof(sub_href), "%s/",
                                  child_href) < sizeof(sub_href)
                && webdav_search_walk(r, head, tail, child_path, sub_href,
                                      count, q) != NGX_OK)
            {
                xrootd_vfs_closedir(dp, r->connection->log);
                return NGX_ERROR;
            }
        }
    }

    xrootd_vfs_closedir(dp, r->connection->log);
    return NGX_OK;
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
    char                  path[WEBDAV_MAX_PATH];
    char                  href[WEBDAV_MAX_PATH + 2];
    struct stat           sb;
    ngx_int_t             rc;
    webdav_search_query_t q;
    ngx_chain_t          *head = NULL, *tail = NULL, *lc;
    ngx_uint_t            count = 0;
    off_t                 total_len = 0;
    ngx_table_elt_t      *h;
    size_t                uri_len;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_search_parse(r, &q);
    if (rc != NGX_OK) {
        return rc;
    }

    if (xrootd_http_chain_appendf(r->pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uri_len = r->uri.len < sizeof(href) - 1 ? r->uri.len : sizeof(href) - 1;
    ngx_memcpy(href, r->uri.data, uri_len);
    href[uri_len] = '\0';

    if (webdav_search_append_response(r, &head, &tail, href, &q) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if ((q.depth == 1 || q.depth == -1) && S_ISDIR(sb.st_mode)
        && webdav_search_walk(r, &head, &tail, path, href, &count, &q)
           != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (xrootd_http_chain_appendf(r->pool, &head, &tail,
            "</D:multistatus>") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

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
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    ngx_int_t rc;

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = webdav_search_do(r);
    xrootd_imp_request_end();

    webdav_metrics_finalize_request(r, rc);
}

/*
 * SEARCH entry point.  The query lives in the request body, so work is deferred
 * to webdav_search_body_handler once the body is read.
 */
ngx_int_t
webdav_handle_search(ngx_http_request_t *r)
{
    return xrootd_http_read_body(r, webdav_search_body_handler);
}
