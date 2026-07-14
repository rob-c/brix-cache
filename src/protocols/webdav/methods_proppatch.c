/*
 * methods_proppatch.c - WebDAV PROPPATCH handler (RFC 4918 §9.2).
 *
 * Dead-property modification on the resolved resource: set/remove actions inside
 * a DAV:propertyupdate document are applied to the xattr-backed dead-property
 * store and a 207 Multi-Status is emitted with one propstat per property.
 * Protected DAV: live properties are rejected 403 per property; store failures
 * map to 507. Split out verbatim from methods_basic.c; the only public entry
 * point is webdav_handle_proppatch (in webdav_methods.h).
 */

#include "webdav.h"
#include "fs/vfs/vfs.h"   /* confined read-open for the Want-Digest checksum */
#include "auth/impersonate/lifecycle.h"
#include "core/http/etag.h"
#include "core/http/http_body.h"
#include "core/http/http_file_response.h"
#include "core/http/http_xml.h"

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
 * WHAT: Invariant state threaded through the PROPPATCH property walk — the
 * request, the resolved+confined target path, and the growing response chain.
 *
 * WHY: These four values are constant for the duration of one PROPPATCH and are
 * needed by every action/property helper. Bundling them keeps the per-property
 * and per-action helpers under the parameter budget without new globals; state
 * is still passed explicitly (one pointer, not a hidden singleton).
 */
typedef struct {
    ngx_http_request_t *r;      /* the PROPPATCH request */
    const char         *path;   /* resolved, confined target path */
    ngx_chain_t        *head;   /* multistatus response chain head */
    ngx_chain_t        *tail;   /* multistatus response chain tail */
} webdav_proppatch_walk_t;

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
        BRIX_PNALLOC_OR_RETURN(xml, r->pool, len, NULL);
        snprintf(xml, len, "<X:%s xmlns:X=\"%s\">%s</X:%s>",
                 local, safe_ns, safe_text, local);

    } else {
        len = ngx_strlen("<></>") + strlen(local) * 2 + strlen(safe_text) + 1;
        BRIX_PNALLOC_OR_RETURN(xml, r->pool, len, NULL);
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
webdav_proppatch_append_propstat(webdav_proppatch_walk_t *w, const char *ns,
    const char *local, const char *status)
{
    if (brix_http_chain_appendf(w->r->pool, &w->head, &w->tail,
            "<D:propstat><D:prop>") == NULL)
    {
        return NGX_ERROR;
    }

    if (webdav_dead_prop_append_empty(w->r, ns, local, &w->head, &w->tail)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (brix_http_chain_appendf(w->r->pool, &w->head, &w->tail,
            "</D:prop><D:status>%s</D:status></D:propstat>",
            status) == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Apply one PROPPATCH property (set or remove) to the xattr-backed
 * dead-property store and return its RFC 4918 §9.2 per-property status line.
 *
 * WHY: The per-property set/remove/protected decision is the innermost logic of
 * the PROPPATCH walk; isolating it as a pure-ish helper keeps the action loop
 * flat and expresses partial success precisely (each property gets its own
 * verdict). No markup is emitted here — the caller wraps the result in propstat.
 *
 * HOW: A protected DAV: live property is rejected 403 and never touched. A set
 * re-serializes the element and writes it; a remove deletes it; either store
 * failure maps to 507 Insufficient Storage. Defaults to "HTTP/1.1 200 OK".
 * Returns a static status-line string (never NULL).
 */
static const char *
webdav_proppatch_prop_status(webdav_proppatch_walk_t *w, xmlNodePtr prop,
    const char *ns, const char *local, ngx_flag_t is_set)
{
    if (strcmp(ns, "DAV:") == 0
        && webdav_dead_prop_is_protected_dav(local))
    {
        return "HTTP/1.1 403 Forbidden";
    }

    if (is_set) {
        char   *xml;
        size_t  xml_len;

        xml = webdav_proppatch_serialize_dead_prop(w->r, prop, &xml_len);
        if (xml == NULL
            || webdav_dead_prop_set(w->r, w->path, ns, local, xml, xml_len)
               != NGX_OK)
        {
            return "HTTP/1.1 507 Insufficient Storage";
        }
        return "HTTP/1.1 200 OK";
    }

    if (webdav_dead_prop_remove(w->r, w->path, ns, local) != NGX_OK) {
        return "HTTP/1.1 507 Insufficient Storage";
    }
    return "HTTP/1.1 200 OK";
}

/*
 * WHAT: Process one <set>/<remove> action node of a DAV:propertyupdate — apply
 * every property inside its <prop> wrapper and append a propstat per property,
 * bumping *processed for each one.
 *
 * WHY: Extracting the middle (<prop> locate) and inner (per-property) loops out
 * of the orchestrator collapses two nesting levels and gives the action a
 * single-responsibility home. Malformed actions with no <prop> are silently
 * skipped (spec-tolerant), matching the pre-refactor behavior.
 *
 * HOW: Locate the single <prop> element child; for each element child of it,
 * compute the property status via webdav_proppatch_prop_status and append its
 * propstat. Returns NGX_OK, or NGX_ERROR if propstat appending fails.
 */
static ngx_int_t
webdav_proppatch_process_action(webdav_proppatch_walk_t *w, xmlNodePtr action,
    ngx_flag_t is_set, ngx_uint_t *processed)
{
    xmlNodePtr prop_container;
    xmlNodePtr prop;

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
        return NGX_OK;   /* malformed action with no <prop>: skip */
    }

    /* Inner loop: apply each property element in this <prop>. */
    for (prop = prop_container->children; prop != NULL; prop = prop->next) {
        const char *local;
        const char *ns;
        const char *status;

        if (prop->type != XML_ELEMENT_NODE) {
            continue;
        }

        local = (const char *) prop->name;
        ns = (prop->ns != NULL && prop->ns->href != NULL)
             ? (const char *) prop->ns->href : "";

        status = webdav_proppatch_prop_status(w, prop, ns, local, is_set);

        if (webdav_proppatch_append_propstat(w, ns, local, status) != NGX_OK) {
            return NGX_ERROR;
        }

        (*processed)++;
    }

    return NGX_OK;
}

/*
 * WHAT: Emit the opening bytes of the 207 multistatus document for a PROPPATCH
 * on this request URI: the XML prolog, <D:multistatus>, and the <D:href>.
 *
 * WHY: Href escaping and the fixed preamble are a self-contained concern; pulling
 * them out keeps the orchestrator focused on the action walk. The href is
 * XML-escaped so an untrusted URI cannot inject markup into the response.
 *
 * HOW: Null-terminate the URI into a bounded buffer, XML-escape it, and append
 * the preamble chain fragment. Returns NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR
 * on escape/allocation failure.
 */
static ngx_int_t
webdav_proppatch_start_multistatus(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail)
{
    char   href_buf[WEBDAV_MAX_PATH + 1];
    char  *safe_href;
    size_t uri_len;

    uri_len = r->uri.len < sizeof(href_buf) - 1
              ? r->uri.len : sizeof(href_buf) - 1;
    ngx_memcpy(href_buf, r->uri.data, uri_len);
    href_buf[uri_len] = '\0';

    safe_href = webdav_escape_xml_text(r->pool, href_buf);
    if (safe_href == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (brix_http_chain_appendf(r->pool, head, tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">"
            "<D:response>"
            "<D:href>%s</D:href>",
            safe_href) == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

/*
 * WHAT: Close the multistatus document, set the 207 status and Content-Type
 * headers, and send the buffered response chain.
 *
 * WHY: The response-finalize edge (closing markup, length tally, header push,
 * output filter) is one concern separate from the property walk; isolating it
 * keeps the side effects at the orchestrator's tail in one place.
 *
 * HOW: Append the closing elements, mark the last buffer, sum the body length,
 * set status 207 + application/xml Content-Type, send headers, then flush the
 * chain via ngx_http_output_filter. Returns the HTTP status / NGX_* code.
 */
static ngx_int_t
webdav_proppatch_finish_multistatus(ngx_http_request_t *r, ngx_chain_t *head,
    ngx_chain_t *tail)
{
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    off_t            total_len = 0;
    ngx_int_t        rc;

    if (brix_http_chain_appendf(r->pool, &head, &tail,
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
 * WHAT: Parse the PROPPATCH request body into a validated DAV:propertyupdate
 * document root, or map the failure to an HTTP status.
 *
 * WHY: Body read + XXE-safe XML parse + root-element validation are a single
 * input-handling concern with several early-out error codes; separating them
 * keeps the orchestrator's happy path linear. On success the caller owns *doc
 * and must xmlFreeDoc it.
 *
 * HOW: Read up to WEBDAV_PROPPATCH_BODY_MAX bytes (empty body → 400), parse with
 * network/entity-expansion disabled, and require a <propertyupdate> root.
 * Returns NGX_OK with *doc and *root set, else NGX_HTTP_BAD_REQUEST.
 */
static ngx_int_t
webdav_proppatch_parse_body(ngx_http_request_t *r, xmlDocPtr *doc,
    xmlNodePtr *root)
{
    u_char *body = NULL;
    size_t  body_len = 0;
    ngx_int_t rc;
    int     opts = XML_PARSE_NONET | XML_PARSE_NOERROR
                 | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
    opts |= XML_PARSE_NO_XXE;
#endif

    rc = brix_http_body_read_all(r, WEBDAV_PROPPATCH_BODY_MAX,
                                   &body, &body_len);
    if (rc != NGX_OK || body_len == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    *doc = xmlReadMemory((const char *) body, (int) body_len,
                         "proppatch.xml", NULL, opts);
    if (*doc == NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    *root = xmlDocGetRootElement(*doc);
    if (*root == NULL
        || xmlStrcmp((*root)->name, BAD_CAST "propertyupdate") != 0)
    {
        xmlFreeDoc(*doc);
        *doc = NULL;
        return NGX_HTTP_BAD_REQUEST;
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
    webdav_proppatch_walk_t  walk = { r, NULL, NULL, NULL };
    ngx_int_t        rc;
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    xmlDocPtr        doc = NULL;
    xmlNodePtr       root = NULL;
    xmlNodePtr       action;
    ngx_uint_t       processed = 0;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }
    walk.path = path;

    rc = webdav_check_locks(r, path, 1);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_proppatch_parse_body(r, &doc, &root);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_proppatch_start_multistatus(r, &walk.head, &walk.tail);
    if (rc != NGX_OK) {
        xmlFreeDoc(doc);
        return rc;
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

        if (webdav_proppatch_process_action(&walk, action, is_set,
                                            &processed) != NGX_OK)
        {
            xmlFreeDoc(doc);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    xmlFreeDoc(doc);

    if (processed == 0) {
        return NGX_HTTP_BAD_REQUEST;
    }

    return webdav_proppatch_finish_multistatus(r, walk.head, walk.tail);
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
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_int_t rc;

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = webdav_proppatch_do(r);
    brix_imp_request_end();

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
    return brix_http_read_body(r, webdav_proppatch_body_handler);
}
