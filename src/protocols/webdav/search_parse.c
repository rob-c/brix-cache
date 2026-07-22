/*
 * search_parse.c - SEARCH request-body query parsing (RFC 5323 DAV:basicsearch).
 *
 * Split from search.c: owns the XML parse of the SEARCH request body into a
 * webdav_search_query_t (scope depth + optional DAV:contains literal).  The
 * libxml2 parse flags are the same hardened set as PROPFIND (no network, no
 * external entities, no HUGE) to block entity-expansion DoS.
 */

#include "search_internal.h"

#include "core/http/http_body.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <string.h>

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
ngx_int_t
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

    rc = brix_http_body_read_all(r, WEBDAV_SEARCH_BODY_MAX, &body, &body_len);
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
