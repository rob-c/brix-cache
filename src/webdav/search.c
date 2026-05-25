/*
 * search.c - Basic WebDAV SEARCH support (RFC 5323).
 *
 * Implements DAV:basicsearch over the request URI scope.  The supported query
 * subset is intentionally conservative: no WHERE clause means "match all";
 * a DAV:contains/DAV:literal clause filters by displayname substring.
 */

#include "webdav.h"
#include "../compat/fs_walk.h"
#include "../compat/http_body.h"
#include "../compat/http_xml.h"

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

static ngx_flag_t
webdav_search_matches(const char *href, const webdav_search_query_t *q)
{
    const char *name;

    if (q->literal[0] == '\0') {
        return 1;
    }

    name = href + strlen(href);
    while (name > href && *(name - 1) != '/') {
        name--;
    }

    return strstr(name, q->literal) != NULL;
}

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

static ngx_int_t
webdav_search_walk(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, const char *dir_path, const char *base_href,
    ngx_uint_t *count, const webdav_search_query_t *q)
{
    DIR           *dp;
    struct dirent *de;

    dp = opendir(dir_path);
    if (dp == NULL) {
        return NGX_OK;
    }

    while ((de = readdir(dp)) != NULL) {
        char        child_path[WEBDAV_MAX_PATH];
        char        child_href[WEBDAV_MAX_PATH + 2];
        struct stat csb;
        size_t      blen;

        if (xrootd_fs_is_dot_entry(de->d_name) || de->d_name[0] == '.') {
            continue;
        }

        if (*count >= WEBDAV_SEARCH_MAX_ENTRIES) {
            break;
        }

        if (xrootd_fs_join_path(dir_path, de->d_name, child_path,
                                sizeof(child_path)) != NGX_OK
            || stat(child_path, &csb) != 0)
        {
            continue;
        }

        blen = strlen(base_href);
        if (blen == 0 || base_href[blen - 1] != '/') {
            if ((size_t) snprintf(child_href, sizeof(child_href), "%s/%s",
                                  base_href, de->d_name) >= sizeof(child_href))
            {
                continue;
            }
        } else if ((size_t) snprintf(child_href, sizeof(child_href), "%s%s",
                                     base_href, de->d_name)
                   >= sizeof(child_href))
        {
            continue;
        }

        if (webdav_search_append_response(r, head, tail, child_href, q)
            != NGX_OK)
        {
            closedir(dp);
            return NGX_ERROR;
        }
        (*count)++;

        if (q->depth == -1 && S_ISDIR(csb.st_mode)) {
            char sub_href[WEBDAV_MAX_PATH + 3];
            if ((size_t) snprintf(sub_href, sizeof(sub_href), "%s/",
                                  child_href) < sizeof(sub_href)
                && webdav_search_walk(r, head, tail, child_path, sub_href,
                                      count, q) != NGX_OK)
            {
                closedir(dp);
                return NGX_ERROR;
            }
        }
    }

    closedir(dp);
    return NGX_OK;
}

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

static void
webdav_search_body_handler(ngx_http_request_t *r)
{
    webdav_metrics_finalize_request(r, webdav_search_do(r));
}

ngx_int_t
webdav_handle_search(ngx_http_request_t *r)
{
    return xrootd_http_read_body(r, webdav_search_body_handler);
}
