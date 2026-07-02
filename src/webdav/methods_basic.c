/*
 * methods_basic.c - OPTIONS and HEAD handlers.
 *
 * WHAT: Implements HTTP OPTIONS, HEAD, and PROPPATCH responses for WebDAV resources. OPTIONS advertises supported DAV capabilities (version 1+2) and method Allow list derived from write permission configuration. HEAD returns resource metadata without body transfer. PROPPATCH handles dead property requests by draining the body and returning 207 Multi-Status with 200 OK per property — minimal compliance for client compatibility.
 *
 * WHY: HTTP OPTIONS is required for pre-flight CORS validation (webdav_add_cors_headers integration) and DAV capability discovery. RFC 4918 §5.3 requires OPTIONS responses to include Allow header listing enabled methods. HEAD provides lightweight resource metadata access without body transfer overhead — essential for fd-cache optimization in GET operations (avoiding full file read). PROPPATCH dead property handling follows minimal compliance strategy: Cyberduck and rucio clients issue PROPPATCH after PUT treating 501 as hard error, so draining + returning 207 avoids blocking these widely-used WebDAV clients.
 *
 * HOW: OPTIONS handler sets DAV: "1, 2" header, constructs Allow list from conf->common.allow_write (read-only vs write-enabled), pushes MS-Author-Via: "DAV" header for Microsoft client compatibility, sends via ngx_http_send_special with NGX_HTTP_LAST (no body). HEAD handler uses webdav_resolve_stat composition helper for path+stat, sets Content-Length based on file size (0 for directories), last_modified_time, allow_ranges flag (disabled for directories), Content-Type (httpd/unix-directory vs application/octet-stream), and optional ETag via webdav_add_etag. PROPPATCH handler drains request body immediately, escapes URI with webdav_escape_xml_text, generates minimal 207 Multi-Status XML response with empty D:prop element and HTTP/1.1 200 OK status per property.
 */

#include "webdav.h"
#include "fs/vfs.h"   /* confined read-open for the Want-Digest checksum */
#include "impersonate/lifecycle.h"
#include "core/compat/etag.h"
#include "core/compat/http_body.h"
#include "core/compat/http_file_response.h"
#include "core/compat/http_xml.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "core/compat/alloc_guard.h"

#define WEBDAV_PROPPATCH_BODY_MAX 65536u

/*
 * WHAT: Handle HTTP OPTIONS request — advertise DAV capabilities (version 1+2) and method Allow list for this location.
 *
 * WHY: RFC 4918 §5.3 requires OPTIONS responses to include DAV header listing supported versions and Allow header listing enabled methods. CORS pre-flight validation depends on OPTIONS response (webdav_add_cors_headers integration). MS-Author-Via: "DAV" header enables Microsoft Office client compatibility for WebDAV-based document storage workflows.
 *
 * HOW: Set status 200 OK with zero Content-Length, push DAV: "1, 2" header (DAV version 1 and extension), construct Allow list from conf->common.allow_write flag (read-only: OPTIONS+GET+HEAD+PROPFIND; write-enabled: adds PUT+DELETE+MKCOL+MOVE+COPY), push MS-Author-Via: "DAV" for Microsoft client compatibility. Send headers via ngx_http_send_header() then complete with ngx_http_send_special(r, NGX_HTTP_LAST) — no body required for OPTIONS response.
 */
ngx_int_t
webdav_handle_options(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t                   *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "DAV");
    ngx_str_set(&h->value, "1, 2, access-control");

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "DASL");
    ngx_str_set(&h->value, "<DAV:basicsearch>");

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "Allow");
    if (xrootd_http_operation_allow_header(r->pool,
            xrootd_webdav_operations, xrootd_webdav_operations_count,
            XROOTD_WEBDAV_ALLOW_FLAGS(conf),
            &h->value) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "MS-Author-Via");
    ngx_str_set(&h->value, "DAV");

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/*
 * WHAT: Handle HTTP HEAD request — return resource metadata headers without body transfer. Uses webdav_resolve_stat composition helper for path+stat lookup.
 *
 * WHY: HEAD provides lightweight resource metadata access without full file read overhead — essential for fd-cache optimization in GET operations (avoiding expensive stat+open syscall pairs when cache already holds valid fd). Also enables pre-flight content length validation before body transfer decisions. The send_body parameter controls whether to proceed with body generation after header response (used by PROPFIND/PROPPATCH integration paths).
 *
 * HOW: Resolve path + stat via webdav_resolve_stat composition helper, set Content-Length based on file type (0 for directories, st_size for files), last_modified_time from sb.st_mtime, allow_ranges flag (disabled for directories per RFC 7233 §14.1). Set Content-Type (httpd/unix-directory vs application/octet-stream). Add ETag via webdav_add_etag only for non-directories. Send headers via ngx_http_send_header() — if send_body=0 or r->header_only=1, complete with NGX_HTTP_LAST without body transfer; otherwise return NGX_OK allowing downstream body generation.
 */
ngx_int_t
webdav_handle_head(ngx_http_request_t *r, int send_body)
{
    char                               path[WEBDAV_MAX_PATH];
    struct stat                        sb;
    ngx_int_t                          rc;
    ngx_table_elt_t                   *h;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = S_ISDIR(sb.st_mode) ? 0 : sb.st_size;
    r->headers_out.last_modified_time = sb.st_mtime;
    r->allow_ranges = S_ISDIR(sb.st_mode) ? 0 : 1;

    if (S_ISDIR(sb.st_mode)) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Type");
        ngx_str_set(&h->value, "httpd/unix-directory");
    } else {
        ngx_http_set_content_type(r);  /* uses nginx types{} block */
    }

    if (!S_ISDIR(sb.st_mode)) {
        rc = xrootd_http_add_etag_header(r, sb.st_mtime, sb.st_size,
                                         XROOTD_ETAG_WEAK, 1);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    /* Inject Digest: header for Want-Digest: requests (RFC 3230 / XrdClHttp).
     * Opens the file only when a checksum was actually requested, uses xattr
     * cache so repeated HEAD requests for the same file are cheap. */
    if (!S_ISDIR(sb.st_mode)) {
        xrdhttp_req_ctx_t *ctx = xrdhttp_get_ctx(r);
        if (ctx != NULL && ctx->want_cksum[0]) {
            ngx_http_xrootd_webdav_loc_conf_t *conf =
                ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
            ngx_http_xrootd_webdav_req_ctx_t  *wctx =
                ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
            xrootd_vfs_ctx_t   vctx;
            xrootd_vfs_file_t *fh;
            int                vfs_err = 0;
            int                is_tls  = 0;

            /* Open the same way GET does (confined VFS read open) so the Digest
             * reflects exactly the bytes a GET would serve — including an
             * in-export symlink target. Metered + impersonation-aware. */
#if (NGX_HTTP_SSL)
            is_tls = (r->connection->ssl != NULL) ? 1 : 0;
#endif
            xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log,
                XROOTD_PROTO_WEBDAV, conf->common.root_canon,
                conf->cache_root_canon, conf->common.allow_write, is_tls,
                (wctx != NULL) ? wctx->identity : NULL, path);

            fh = xrootd_vfs_open(&vctx, XROOTD_VFS_O_READ, &vfs_err);
            if (fh != NULL) {
                (void) xrdhttp_add_checksum_header(r, xrootd_vfs_file_fd(fh), &sb);
                xrootd_vfs_close(fh, r->connection->log);
            }
        }
    }

    ngx_http_send_header(r);

    if (!send_body || r->header_only) {
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }

    return NGX_OK;
}

/*
 * Re-serialize a client property element into the canonical XML fragment we
 * persist as its dead-property value: "<X:local xmlns:X="ns">text</X:local>"
 * (namespaced) or "<local>text</local>" (no namespace).  Both the namespace URI
 * and the text content are XML-escaped first, so untrusted property data cannot
 * inject markup when it is later spliced into a PROPFIND response.
 * Returns a pool string and its length in *out_len, or NULL on alloc failure.
 */
static char *
webdav_proppatch_serialize_dead_prop(ngx_http_request_t *r, xmlNodePtr prop,
    size_t *out_len)
{
    const char *local;
    const char *ns;
    char       *safe_ns = NULL;
    char       *safe_text;
    char       *xml;
    xmlChar    *text;
    size_t      len;

    local = (const char *) prop->name;
    ns = (prop->ns != NULL && prop->ns->href != NULL)
         ? (const char *) prop->ns->href : "";

    text = xmlNodeGetContent(prop);
    safe_text = webdav_escape_xml_text(r->pool,
                                       text != NULL ? (const char *) text : "");
    if (text != NULL) {
        xmlFree(text);
    }
    if (safe_text == NULL) {
        return NULL;
    }

    if (ns[0] != '\0') {
        safe_ns = webdav_escape_xml_text(r->pool, ns);
        if (safe_ns == NULL) {
            return NULL;
        }

        /* Buffer sizing: the literal scaffolding + the local name twice (open
         * and close tag) + the escaped namespace + escaped text + NUL. */
        len = ngx_strlen("<X: xmlns:X=\"\"></X:>")
              + strlen(local) * 2 + strlen(safe_ns) + strlen(safe_text) + 1;
        XROOTD_PNALLOC_OR_RETURN(xml, r->pool, len, NULL);
        snprintf(xml, len, "<X:%s xmlns:X=\"%s\">%s</X:%s>",
                 local, safe_ns, safe_text, local);

    } else {
        len = ngx_strlen("<></>") + strlen(local) * 2 + strlen(safe_text) + 1;
        XROOTD_PNALLOC_OR_RETURN(xml, r->pool, len, NULL);
        snprintf(xml, len, "<%s>%s</%s>", local, safe_text, local);
    }

    *out_len = strlen(xml);
    return xml;
}

/*
 * Append one <D:propstat> block reporting the per-property outcome: the empty
 * property element (name only, via the dead-prop empty serializer) wrapped with
 * the given HTTP status line.  RFC 4918 §9.2 requires one propstat per property
 * carrying its individual result.
 */
static ngx_int_t
webdav_proppatch_append_propstat(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, const char *ns, const char *local,
    const char *status)
{
    if (xrootd_http_chain_appendf(r->pool, head, tail,
            "<D:propstat><D:prop>") == NULL)
    {
        return NGX_ERROR;
    }

    if (webdav_dead_prop_append_empty(r, ns, local, head, tail) != NGX_OK) {
        return NGX_ERROR;
    }

    if (xrootd_http_chain_appendf(r->pool, head, tail,
            "</D:prop><D:status>%s</D:status></D:propstat>",
            status) == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Apply a PROPPATCH after the body is read: resolve+stat the target, check it
 * is not locked, parse the DAV:propertyupdate document, then walk its set/remove
 * actions applying each to the xattr-backed dead-property store and emitting a
 * per-property 207 multistatus.  Returns the HTTP status / NGX_* code; an empty
 * or unparseable update is 400.
 */
static ngx_int_t
webdav_proppatch_do(ngx_http_request_t *r)
{
    ngx_chain_t     *head = NULL;
    ngx_chain_t     *tail = NULL;
    ngx_pool_t      *pool = r->pool;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    ngx_int_t        rc;
    char            *safe_href;
    char             href_buf[WEBDAV_MAX_PATH + 1];
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    u_char          *body = NULL;
    size_t           body_len = 0;
    xmlDocPtr        doc;
    xmlNodePtr       root, action, prop_container, prop;
    ngx_uint_t       processed = 0;
    size_t           uri_len;
    int              opts = XML_PARSE_NONET | XML_PARSE_NOERROR
                          | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
    opts |= XML_PARSE_NO_XXE;
#endif

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = xrootd_http_body_read_all(r, WEBDAV_PROPPATCH_BODY_MAX,
                                   &body, &body_len);
    if (rc != NGX_OK || body_len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    doc = xmlReadMemory((const char *) body, (int) body_len,
                        "proppatch.xml", NULL, opts);
    if (doc == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    root = xmlDocGetRootElement(doc);
    if (root == NULL
        || xmlStrcmp(root->name, BAD_CAST "propertyupdate") != 0)
    {
        xmlFreeDoc(doc);
        return NGX_HTTP_BAD_REQUEST;
    }

    uri_len = r->uri.len < sizeof(href_buf) - 1
              ? r->uri.len : sizeof(href_buf) - 1;
    ngx_memcpy(href_buf, r->uri.data, uri_len);
    href_buf[uri_len] = '\0';

    safe_href = webdav_escape_xml_text(pool, href_buf);
    if (safe_href == NULL) {
        xmlFreeDoc(doc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (xrootd_http_chain_appendf(pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">"
            "<D:response>"
            "<D:href>%s</D:href>",
            safe_href) == NULL)
    {
        xmlFreeDoc(doc);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Outer loop: each child of <propertyupdate> is a <set> or <remove> action
     * (anything else is ignored). is_set distinguishes the two. */
    for (action = root->children; action != NULL; action = action->next) {
        ngx_flag_t is_set;

        if (action->type != XML_ELEMENT_NODE) {
            continue;
        }

        if (xmlStrcmp(action->name, BAD_CAST "set") == 0) {
            is_set = 1;
        } else if (xmlStrcmp(action->name, BAD_CAST "remove") == 0) {
            is_set = 0;
        } else {
            continue;
        }

        /* Middle loop: locate the single <prop> wrapper inside this action. */
        for (prop_container = action->children; prop_container != NULL;
             prop_container = prop_container->next)
        {
            if (prop_container->type == XML_ELEMENT_NODE
                && xmlStrcmp(prop_container->name, BAD_CAST "prop") == 0)
            {
                break;
            }
        }
        if (prop_container == NULL) {
            continue;   /* malformed action with no <prop>: skip */
        }

        /* Inner loop: apply each property element in this <prop>. */
        for (prop = prop_container->children; prop != NULL; prop = prop->next) {
            const char *local;
            const char *ns;
            const char *status = "HTTP/1.1 200 OK";

            if (prop->type != XML_ELEMENT_NODE) {
                continue;
            }

            local = (const char *) prop->name;
            ns = (prop->ns != NULL && prop->ns->href != NULL)
                 ? (const char *) prop->ns->href : "";

            /* Per-property outcome (default 200): a protected DAV: live property
             * cannot be modified (403); set/remove failures from the xattr store
             * map to 507 Insufficient Storage. Each result is reported in its own
             * propstat regardless, so partial success is expressed precisely. */
            if (strcmp(ns, "DAV:") == 0
                && webdav_dead_prop_is_protected_dav(local))
            {
                status = "HTTP/1.1 403 Forbidden";

            } else if (is_set) {
                char   *xml;
                size_t  xml_len;

                xml = webdav_proppatch_serialize_dead_prop(r, prop, &xml_len);
                if (xml == NULL
                    || webdav_dead_prop_set(r, path, ns, local, xml, xml_len)
                       != NGX_OK)
                {
                    status = "HTTP/1.1 507 Insufficient Storage";
                }

            } else if (webdav_dead_prop_remove(r, path, ns, local) != NGX_OK) {
                status = "HTTP/1.1 507 Insufficient Storage";
            }

            if (webdav_proppatch_append_propstat(r, &head, &tail, ns, local,
                                                 status) != NGX_OK)
            {
                xmlFreeDoc(doc);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            processed++;
        }
    }

    xmlFreeDoc(doc);

    if (processed == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (xrootd_http_chain_appendf(pool, &head, &tail,
            "</D:response></D:multistatus>") == NULL)
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
 * Body-ready callback (async re-entry point): runs the PROPPATCH and finalizes
 * the request with metrics once the request body has been buffered.
 *
 * Phase 40: the PROPPATCH body is read asynchronously, so the dispatch wrapper
 * has already cleared the impersonation principal.  Re-establish it for the
 * duration (mirrors PUT/PROPFIND) so the dead-property xattr is written AS THE
 * MAPPED USER via the broker; without this the worker (svc) attempts setxattr on
 * the user-owned resource and fails EACCES.  No-op unless map mode is active.
 */
static void
webdav_proppatch_body_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    ngx_int_t rc;

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = webdav_proppatch_do(r);
    xrootd_imp_request_end();

    webdav_metrics_finalize_request(r, rc);
}

/*
 * WHAT: Handle WebDAV PROPPATCH request — RFC 4918 §9.2 dead property
 * modification handler. Dead properties are persisted as filesystem xattrs on
 * the resolved resource; protected DAV live properties are rejected per
 * property with a 403 propstat.
 */
ngx_int_t
webdav_handle_proppatch(ngx_http_request_t *r)
{
    return xrootd_http_read_body(r, webdav_proppatch_body_handler);
}
