/*
 * propfind.c - WebDAV PROPFIND and Multi-Status XML generation.
 *
 * Implements RFC 4918 §9.1 PROPFIND: supports all three request types:
 *   allprop   — return all known properties with values (default when no body)
 *   propname  — return property names only, no values (RFC 4918 §9.1.5)
 *   prop      — return specific named properties; unknown ones in 404 propstat
 *
 * Request body is parsed with libxml2 when XROOTD_HAVE_LIBXML2 is defined.
 * Without libxml2, all requests are treated as allprop.
 *
 * Body reading uses ngx_http_read_client_request_body with a callback so
 * small and large bodies are handled correctly.
 */

#include "webdav.h"
#include "../compat/etag.h"
#include "../compat/fs_walk.h"
#include "../compat/fs_usage.h"
#include "../compat/http_body.h"
#include "../compat/http_xml.h"
#include "../compat/time.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* -------------------------------------------------------------------------
 * PROPFIND request representation
 * ---------------------------------------------------------------------- */

typedef enum {
    PROPFIND_ALLPROP  = 0,   /* return all properties with values */
    PROPFIND_PROPNAME = 1,   /* return property names only, no values */
    PROPFIND_PROP     = 2,   /* return specific named properties */
} propfind_type_t;

/* Bitmask of known DAV: properties this server supports. */
#define PF_RESOURCETYPE        (1u <<  0)
#define PF_CONTENTLENGTH       (1u <<  1)
#define PF_LASTMODIFIED        (1u <<  2)
#define PF_ETAG                (1u <<  3)
#define PF_CREATIONDATE        (1u <<  4)
#define PF_DISPLAYNAME         (1u <<  5)
#define PF_QUOTA_AVAILABLE     (1u <<  6)
#define PF_QUOTA_USED          (1u <<  7)
#define PF_SUPPORTED_REPORT    (1u <<  8)
#define PF_SUPPORTEDLOCK       (1u <<  9)
#define PF_LOCKDISCOVERY       (1u << 10)
#define PF_CONTENTTYPE         (1u << 11)
#define PF_OWNER               (1u << 12)
#define PF_GROUP               (1u << 13)
#define PF_CURRENT_PRIVILEGE   (1u << 14)
#define PF_SUPPORTED_PRIVILEGE (1u << 15)
#define PF_ACL                 (1u << 16)
#define PF_ACL_RESTRICTIONS    (1u << 17)
#define PF_PRINCIPAL_SET       (1u << 18)
#define PF_ALL                 ((1u << 19) - 1)

/* Maximum number of unrecognised properties tracked for 404 propstat. */
#define PF_UNKNOWN_MAX     16
#define PF_UNKNOWN_XML_MAX 288   /* <ns0:localname xmlns:ns0="uri"/> */

/* Maximum PROPFIND body size we will parse (larger bodies → allprop). */
#define PROPFIND_BODY_MAX  65536u

typedef struct {
    char             ns[128];
    char             local[128];
    char             xml[PF_UNKNOWN_XML_MAX];
} propfind_unknown_t;

typedef struct {
    propfind_type_t  type;
    unsigned         prop_mask;                        /* PROP: which properties wanted */
    ngx_uint_t       unknown_count;
    propfind_unknown_t unknown[PF_UNKNOWN_MAX];
} propfind_req_t;

/* -------------------------------------------------------------------------
 * PROPFIND request body parsing
 * ---------------------------------------------------------------------- */

/*
 * Map a DAV: property local name to its bitmask entry.
 * Returns 0 for unrecognised names.
 */
static unsigned
propfind_name_to_bit(const char *name)
{
    static const struct { const char *name; unsigned bit; } known[] = {
        { "resourcetype",          PF_RESOURCETYPE     },
        { "getcontentlength",      PF_CONTENTLENGTH    },
        { "getlastmodified",       PF_LASTMODIFIED     },
        { "getetag",               PF_ETAG             },
        { "creationdate",          PF_CREATIONDATE     },
        { "displayname",           PF_DISPLAYNAME      },
        { "quota-available-bytes", PF_QUOTA_AVAILABLE  },
        { "quota-used-bytes",      PF_QUOTA_USED       },
        { "supported-report-set",  PF_SUPPORTED_REPORT },
        { "supportedlock",         PF_SUPPORTEDLOCK    },
        { "lockdiscovery",         PF_LOCKDISCOVERY    },
        { "getcontenttype",        PF_CONTENTTYPE      },
        { "owner",                 PF_OWNER            },
        { "group",                 PF_GROUP            },
        { "current-user-privilege-set", PF_CURRENT_PRIVILEGE },
        { "supported-privilege-set", PF_SUPPORTED_PRIVILEGE },
        { "acl",                   PF_ACL              },
        { "acl-restrictions",      PF_ACL_RESTRICTIONS },
        { "principal-collection-set", PF_PRINCIPAL_SET },
    };
    size_t i;

    for (i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (strcmp(name, known[i].name) == 0) {
            return known[i].bit;
        }
    }
    return 0;
}

/*
 * Assemble the request body from r->request_body->bufs into a contiguous
 * pool-allocated buffer.  Returns NULL (and sets *len to 0) if the body is
 * absent, empty, or exceeds PROPFIND_BODY_MAX bytes.
 */
static const char *
propfind_assemble_body(ngx_http_request_t *r, size_t *len)
{
    u_char    *buf;
    ngx_int_t  rc;

    *len = 0;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NULL;
    }

    rc = xrootd_http_body_read_all(r, PROPFIND_BODY_MAX, &buf, len);
    if (rc != NGX_OK || *len == 0) {
        return NULL;
    }

    return (const char *) buf;
}

/*
 * Parse a PROPFIND request body into req.
 * Initialises req to ALLPROP on entry so any early return is safe.
 */
static void
propfind_parse_request(ngx_http_request_t *r, propfind_req_t *req)
{
    const char *body;
    size_t      body_len;

    req->type          = PROPFIND_ALLPROP;
    req->prop_mask     = 0;
    req->unknown_count = 0;

    body = propfind_assemble_body(r, &body_len);
    if (body == NULL) {
        return;   /* no body → allprop per RFC 4918 §9.1 */
    }

    {
        xmlDocPtr  doc;
        xmlNodePtr root, child, prop;
        int        opts = XML_PARSE_NONET | XML_PARSE_NOERROR
                        | XML_PARSE_NOWARNING;
#if defined(XML_PARSE_NO_XXE)
        opts |= XML_PARSE_NO_XXE;
#endif

        doc = xmlReadMemory(body, (int) body_len, "propfind.xml", NULL, opts);
        if (doc == NULL) {
            return;
        }

        root = xmlDocGetRootElement(doc);
        if (root == NULL
            || xmlStrcmp(root->name, BAD_CAST "propfind") != 0)
        {
            xmlFreeDoc(doc);
            return;
        }

        for (child = root->children; child != NULL; child = child->next) {
            if (child->type != XML_ELEMENT_NODE) {
                continue;
            }

            if (xmlStrcmp(child->name, BAD_CAST "allprop") == 0) {
                req->type = PROPFIND_ALLPROP;
                break;
            }

            if (xmlStrcmp(child->name, BAD_CAST "propname") == 0) {
                req->type = PROPFIND_PROPNAME;
                break;
            }

            if (xmlStrcmp(child->name, BAD_CAST "prop") == 0) {
                req->type = PROPFIND_PROP;

                for (prop = child->children; prop != NULL;
                     prop = prop->next)
                {
                    const char *local;
                    unsigned    bit;

                    if (prop->type != XML_ELEMENT_NODE) {
                        continue;
                    }

                    local = (const char *) prop->name;
                    bit   = propfind_name_to_bit(local);

                    if (bit) {
                        req->prop_mask |= bit;
                        continue;
                    }

                    /* Unrecognised property — store XML empty-element for
                     * the 404 propstat block. */
                    if (req->unknown_count < PF_UNKNOWN_MAX) {
                        ngx_uint_t idx = req->unknown_count;
                        const char *ns_href = "";

                        if (prop->ns != NULL && prop->ns->href != NULL) {
                            ns_href = (const char *) prop->ns->href;
                        }

                        snprintf(req->unknown[idx].ns,
                                 sizeof(req->unknown[idx].ns),
                                 "%s",
                                 ns_href);
                        snprintf(req->unknown[idx].local,
                                 sizeof(req->unknown[idx].local),
                                 "%s",
                                 local);

                        if (prop->ns != NULL
                            && xmlStrcmp(prop->ns->href, BAD_CAST "DAV:") != 0)
                        {
                            char *safe_ns = webdav_escape_xml_text(r->pool,
                                                                   ns_href);
                            if (safe_ns == NULL) {
                                safe_ns = "";
                            }
                            /* Non-DAV: namespace — include xmlns declaration. */
                            snprintf(req->unknown[idx].xml,
                                     PF_UNKNOWN_XML_MAX,
                                     "<ns%u:%s xmlns:ns%u=\"%s\"/>",
                                     (unsigned) idx, local,
                                     (unsigned) idx,
                                     safe_ns);
                        } else {
                            snprintf(req->unknown[idx].xml,
                                     PF_UNKNOWN_XML_MAX,
                                     "<D:%s/>", local);
                        }
                        req->unknown_count++;
                    }
                }
                break;
            }
        }

        xmlFreeDoc(doc);
    }
}

/* -------------------------------------------------------------------------
 * Per-resource D:response generation
 * ---------------------------------------------------------------------- */

static ngx_int_t
propfind_append_acl_properties(ngx_http_request_t *r, ngx_chain_t **head,
    ngx_chain_t **tail, unsigned mask)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_http_xrootd_webdav_req_ctx_t  *ctx;
    ngx_pool_t                        *pool = r->pool;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);

    if (mask & PF_OWNER) {
        const char *owner = (ctx != NULL && ctx->dn[0] != '\0')
                            ? ctx->dn : "anonymous";
        char *safe_owner = webdav_escape_xml_text(pool, owner);
        if (safe_owner == NULL
            || xrootd_http_chain_appendf(pool, head, tail,
                "<D:owner><D:href>%s</D:href></D:owner>",
                safe_owner) == NULL)
        {
            return NGX_ERROR;
        }
    }

    if ((mask & PF_GROUP)
        && xrootd_http_chain_appendf(pool, head, tail, "<D:group/>") == NULL)
    {
        return NGX_ERROR;
    }

    if (mask & PF_CURRENT_PRIVILEGE) {
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:current-user-privilege-set>"
                "<D:privilege><D:read/></D:privilege>") == NULL)
        {
            return NGX_ERROR;
        }

        if (conf->common.allow_write
            && xrootd_http_chain_appendf(pool, head, tail,
                "<D:privilege><D:write/></D:privilege>"
                "<D:privilege><D:write-content/></D:privilege>"
                "<D:privilege><D:write-properties/></D:privilege>"
                "<D:privilege><D:bind/></D:privilege>"
                "<D:privilege><D:unbind/></D:privilege>") == NULL)
        {
            return NGX_ERROR;
        }

        if (xrootd_http_chain_appendf(pool, head, tail,
                "</D:current-user-privilege-set>") == NULL)
        {
            return NGX_ERROR;
        }
    }

    if ((mask & PF_SUPPORTED_PRIVILEGE)
        && xrootd_http_chain_appendf(pool, head, tail,
            "<D:supported-privilege-set>"
            "<D:supported-privilege>"
            "<D:privilege><D:all/></D:privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:read/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:write/></D:privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:write-content/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:write-properties/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:bind/></D:privilege>"
            "</D:supported-privilege>"
            "<D:supported-privilege>"
            "<D:privilege><D:unbind/></D:privilege>"
            "</D:supported-privilege>"
            "</D:supported-privilege>"
            "</D:supported-privilege>"
            "</D:supported-privilege-set>") == NULL)
    {
        return NGX_ERROR;
    }

    if (mask & PF_ACL) {
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:acl><D:ace><D:principal><D:all/></D:principal>"
                "<D:grant><D:privilege><D:read/></D:privilege>") == NULL)
        {
            return NGX_ERROR;
        }

        if (conf->common.allow_write
            && xrootd_http_chain_appendf(pool, head, tail,
                "<D:privilege><D:write/></D:privilege>") == NULL)
        {
            return NGX_ERROR;
        }

        if (xrootd_http_chain_appendf(pool, head, tail,
                "</D:grant><D:protected/></D:ace></D:acl>") == NULL)
        {
            return NGX_ERROR;
        }
    }

    if ((mask & PF_ACL_RESTRICTIONS)
        && xrootd_http_chain_appendf(pool, head, tail,
            "<D:acl-restrictions><D:grant-only/><D:no-invert/>"
            "</D:acl-restrictions>") == NULL)
    {
        return NGX_ERROR;
    }

    if ((mask & PF_PRINCIPAL_SET)
        && xrootd_http_chain_appendf(pool, head, tail,
            "<D:principal-collection-set/>") == NULL)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Emit a D:response XML element for one resource.
 *
 * Behaviour depends on req->type:
 *   ALLPROP   — all known properties with values
 *   PROPNAME  — all property names as empty elements, no values, no
 *               expensive calls (skips statvfs and lock scan)
 *   PROP      — only req->prop_mask properties in 200 propstat; any
 *               unrecognised property in req->unknown[] in 404 propstat
 */
static ngx_int_t
propfind_entry(ngx_http_request_t *r, ngx_chain_t **head, ngx_chain_t **tail,
               const char *href, const char *path, struct stat *sb,
               const propfind_req_t *req)
{
    char        date_buf[30];
    char       *safe_href;
    ngx_pool_t *pool  = r->pool;
    unsigned    mask  = (req->type == PROPFIND_PROP) ? req->prop_mask : PF_ALL;
    ngx_flag_t  unknown_found[PF_UNKNOWN_MAX];
    ngx_uint_t  i;

    *ngx_http_time((u_char *) date_buf, sb->st_mtime) = '\0';
    ngx_memzero(unknown_found, sizeof(unknown_found));

    safe_href = webdav_escape_xml_text(pool, href);
    if (safe_href == NULL) {
        return NGX_ERROR;
    }

    if (xrootd_http_chain_appendf(pool, head, tail,
            "<D:response>"
            "<D:href>%s</D:href>"
            "<D:propstat>"
            "<D:prop>", safe_href) == NULL)
    {
        return NGX_ERROR;
    }

    /* ---- PROPNAME: emit all names as empty elements, then close. ---- */
    if (req->type == PROPFIND_PROPNAME) {
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:resourcetype/>"
                "<D:getcontentlength/>"
                "<D:getlastmodified/>"
                "<D:getetag/>"
                "<D:creationdate/>"
                "<D:displayname/>"
                "<D:quota-available-bytes/>"
                "<D:quota-used-bytes/>"
                "<D:supported-report-set/>"
                "<D:supportedlock/>"
                "<D:lockdiscovery/>"
                "<D:getcontenttype/>"
                "<D:owner/>"
                "<D:group/>"
                "<D:current-user-privilege-set/>"
                "<D:supported-privilege-set/>"
                "<D:acl/>"
                "<D:acl-restrictions/>"
                "<D:principal-collection-set/>") == NULL
            || webdav_dead_props_append_all(r, path, head, tail, 1)
               != NGX_OK
            || xrootd_http_chain_appendf(pool, head, tail,
                "</D:prop>"
                "<D:status>HTTP/1.1 200 OK</D:status>"
                "</D:propstat>"
                "</D:response>") == NULL)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    /* ---- ALLPROP / PROP: emit property values filtered by mask. ---- */

    if (mask & PF_RESOURCETYPE) {
        if (S_ISDIR(sb->st_mode)) {
            if (xrootd_http_chain_appendf(pool, head, tail,
                    "<D:resourcetype>"
                    "<D:collection/>"
                    "</D:resourcetype>") == NULL)
                return NGX_ERROR;
        } else if (xrootd_http_chain_appendf(pool, head, tail,
                       "<D:resourcetype/>") == NULL) {
            return NGX_ERROR;
        }
    }

    if (mask & PF_CONTENTLENGTH) {
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:getcontentlength>%lld</D:getcontentlength>",
                S_ISDIR(sb->st_mode) ? 0LL : (long long) sb->st_size) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_LASTMODIFIED) {
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:getlastmodified>%s</D:getlastmodified>",
                date_buf) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_ETAG) {
        char etag_buf[64];
        xrootd_http_etag_str(etag_buf, sizeof(etag_buf), sb->st_mtime,
                             sb->st_size, XROOTD_ETAG_WEAK);
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:getetag>%s</D:getetag>", etag_buf) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_CREATIONDATE) {
        char cdate_buf[32];

        xrootd_format_iso8601(sb->st_ctime, cdate_buf, sizeof(cdate_buf));
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:creationdate>%s</D:creationdate>", cdate_buf) == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_DISPLAYNAME) {
        const char *name = href + strlen(href);
        char       *safe_name;

        while (name > href && *(name - 1) != '/') {
            name--;
        }
        safe_name = webdav_escape_xml_text(pool, name);
        if (safe_name != NULL
            && xrootd_http_chain_appendf(pool, head, tail,
                   "<D:displayname>%s</D:displayname>", safe_name) == NULL)
        {
            return NGX_ERROR;
        }
    }

    if (mask & (PF_QUOTA_AVAILABLE | PF_QUOTA_USED)) {
        xrootd_fs_usage_t fsu;
        if (xrootd_fs_usage_stat(path, &fsu) == NGX_OK) {
            if ((mask & PF_QUOTA_AVAILABLE)
                && xrootd_http_chain_appendf(pool, head, tail,
                       "<D:quota-available-bytes>"
                       "%llu"
                       "</D:quota-available-bytes>",
                       (unsigned long long) fsu.available_bytes) == NULL)
                return NGX_ERROR;
            if ((mask & PF_QUOTA_USED)
                && xrootd_http_chain_appendf(pool, head, tail,
                       "<D:quota-used-bytes>"
                       "%llu"
                       "</D:quota-used-bytes>",
                       (unsigned long long) fsu.used_bytes) == NULL)
                return NGX_ERROR;
        }
    }

    if (mask & PF_SUPPORTED_REPORT) {
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:supported-report-set/>") == NULL)
            return NGX_ERROR;
    }

    if (mask & PF_SUPPORTEDLOCK) {
        (void) webdav_lock_append_supported(r, head, tail);
    }

    if (mask & PF_LOCKDISCOVERY) {
        (void) webdav_lock_append_discovery(r, path, head, tail);
    }

    if (mask & PF_CONTENTTYPE) {
        const char *ct = S_ISDIR(sb->st_mode)
                         ? "httpd/unix-directory"
                         : "application/octet-stream";
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:getcontenttype>%s</D:getcontenttype>", ct) == NULL)
            return NGX_ERROR;
    }

    if (propfind_append_acl_properties(r, head, tail, mask) != NGX_OK) {
        return NGX_ERROR;
    }

    if (req->type == PROPFIND_ALLPROP) {
        if (webdav_dead_props_append_all(r, path, head, tail, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    } else if (req->type == PROPFIND_PROP) {
        for (i = 0; i < req->unknown_count; i++) {
            if (strcmp(req->unknown[i].ns, "DAV:") != 0) {
                if (webdav_dead_prop_append_value(r, path,
                        req->unknown[i].ns, req->unknown[i].local,
                        head, tail, &unknown_found[i]) != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
        }
    }

    if (xrootd_http_chain_appendf(pool, head, tail,
            "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>") == NULL)
        return NGX_ERROR;

    /* For explicit PROP requests: emit 404 propstat for unknown properties. */
    if (req->type == PROPFIND_PROP && req->unknown_count > 0) {
        ngx_flag_t any_missing = 0;

        for (i = 0; i < req->unknown_count; i++) {
            if (!unknown_found[i]) {
                any_missing = 1;
                break;
            }
        }

        if (!any_missing) {
            goto close_response;
        }

        if (xrootd_http_chain_appendf(pool, head, tail,
                "<D:propstat><D:prop>") == NULL)
            return NGX_ERROR;

        for (i = 0; i < req->unknown_count; i++) {
            if (unknown_found[i]) {
                continue;
            }
            if (xrootd_http_chain_appendf(pool, head, tail,
                    "%s", req->unknown[i].xml) == NULL)
                return NGX_ERROR;
        }

        if (xrootd_http_chain_appendf(pool, head, tail,
                "</D:prop>"
                "<D:status>HTTP/1.1 404 Not Found</D:status>"
                "</D:propstat>") == NULL)
            return NGX_ERROR;
    }

close_response:
    if (xrootd_http_chain_appendf(pool, head, tail, "</D:response>") == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Depth header parsing
 * ---------------------------------------------------------------------- */

static int
propfind_parse_depth(ngx_http_request_t *r)
{
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *hdr  = part->elts;
    ngx_uint_t       i;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            if (hdr[i].key.len != 5
                || ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) "Depth", 5) != 0)
            {
                continue;
            }

            if (hdr[i].value.len == 1 && hdr[i].value.data[0] == '1') {
                return 1;
            }
            if (hdr[i].value.len == 8
                && ngx_strncasecmp(hdr[i].value.data,
                                   (u_char *) "infinity", 8) == 0)
            {
                return -1;
            }
            return 0;
        }

        if (part->next == NULL) {
            break;
        }
        part = part->next;
        hdr  = part->elts;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * Depth: infinity recursive walk
 * ---------------------------------------------------------------------- */

#define PROPFIND_INFINITY_MAX_ENTRIES  10000

static ngx_int_t
propfind_walk(ngx_http_request_t *r,
              ngx_chain_t **head, ngx_chain_t **tail,
              const char *dir_path, const char *base_href,
              ngx_uint_t *entry_count, ngx_uint_t max_entries,
              const propfind_req_t *req)
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

        if (xrootd_fs_is_dot_entry(de->d_name) || de->d_name[0] == '.') {
            continue;
        }

        if (*entry_count >= max_entries) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd: PROPFIND Depth:infinity capped at %ui entries "
                          "for \"%s\"", max_entries, dir_path);
            break;
        }

        if (xrootd_fs_join_path(dir_path, de->d_name, child_path,
                                sizeof(child_path)) != NGX_OK)
        {
            continue;
        }

        if (stat(child_path, &csb) != 0) {
            continue;
        }

        {
            size_t blen = strlen(base_href);
            if (blen == 0 || base_href[blen - 1] != '/') {
                if ((size_t) snprintf(child_href, sizeof(child_href),
                                      "%s/%s", base_href, de->d_name)
                    >= sizeof(child_href))
                    continue;
            } else if ((size_t) snprintf(child_href, sizeof(child_href),
                                         "%s%s", base_href, de->d_name)
                       >= sizeof(child_href))
            {
                continue;
            }
        }

        if (propfind_entry(r, head, tail, child_href, child_path, &csb, req)
            != NGX_OK)
        {
            closedir(dp);
            return NGX_ERROR;
        }
        (*entry_count)++;

        if (S_ISDIR(csb.st_mode) && *entry_count < max_entries) {
            char subdir_href[WEBDAV_MAX_PATH + 3];
            if ((size_t) snprintf(subdir_href, sizeof(subdir_href),
                                  "%s/", child_href)
                < sizeof(subdir_href))
            {
                if (propfind_walk(r, head, tail, child_path, subdir_href,
                                  entry_count, max_entries, req) != NGX_OK)
                {
                    closedir(dp);
                    return NGX_ERROR;
                }
            }
        }
    }

    closedir(dp);
    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Core PROPFIND logic (called from body-ready callback)
 * ---------------------------------------------------------------------- */

static ngx_int_t
propfind_do(ngx_http_request_t *r)
{
    char             path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    int              depth;
    ngx_chain_t     *head = NULL;
    ngx_chain_t     *tail = NULL;
    off_t            total_len = 0;
    ngx_chain_t     *lc;
    ngx_table_elt_t *h;
    ngx_uint_t       entry_count = 0;
    propfind_req_t   req;

    rc = webdav_resolve_stat(r, path, sizeof(path), &sb);
    if (rc != NGX_OK) {
        return rc;
    }

    propfind_parse_request(r, &req);

    depth = propfind_parse_depth(r);
    {
        ngx_uint_t depth_slot = (depth == 0)  ? XROOTD_WEBDAV_PROPFIND_DEPTH_0
                              : (depth == 1)  ? XROOTD_WEBDAV_PROPFIND_DEPTH_1
                              :                 XROOTD_WEBDAV_PROPFIND_DEPTH_INF;
        XROOTD_WEBDAV_METRIC_INC(propfind_depth_total[depth_slot]);
    }

    if (xrootd_http_chain_appendf(r->pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    {
        char   href[WEBDAV_MAX_PATH + 2];
        size_t uri_len = r->uri.len;

        if (uri_len >= sizeof(href) - 1) {
            uri_len = sizeof(href) - 2;
        }
        ngx_memcpy(href, r->uri.data, uri_len);
        href[uri_len] = '\0';

        if (propfind_entry(r, &head, &tail, href, path, &sb, &req) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        entry_count++;
    }

    if ((depth == 1 || depth == -1) && S_ISDIR(sb.st_mode)) {
        DIR *dp = opendir(path);

        if (dp != NULL) {
            struct dirent *de;

            while ((de = readdir(dp)) != NULL) {
                char        child_path[WEBDAV_MAX_PATH];
                struct stat csb;
                char        href[WEBDAV_MAX_PATH + 2];
                const char *base;
                size_t      blen;

                if (xrootd_fs_is_dot_entry(de->d_name)
                    || de->d_name[0] == '.')
                {
                    continue;
                }

                if (xrootd_fs_join_path(path, de->d_name, child_path,
                                        sizeof(child_path)) != NGX_OK)
                {
                    continue;
                }

                if (stat(child_path, &csb) != 0) {
                    continue;
                }

                base = (const char *) r->uri.data;
                blen = r->uri.len;
                if (blen == 0 || base[blen - 1] != '/') {
                    if ((size_t) snprintf(href, sizeof(href), "%.*s/%s",
                                          (int) blen, base, de->d_name)
                        >= sizeof(href))
                    {
                        continue;
                    }
                } else if ((size_t) snprintf(href, sizeof(href), "%.*s%s",
                                             (int) blen, base, de->d_name)
                           >= sizeof(href))
                {
                    continue;
                }

                if (propfind_entry(r, &head, &tail, href, child_path,
                                   &csb, &req) != NGX_OK)
                {
                    closedir(dp);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                entry_count++;

                if (depth == -1 && S_ISDIR(csb.st_mode)) {
                    char subdir_href[WEBDAV_MAX_PATH + 3];
                    if ((size_t) snprintf(subdir_href, sizeof(subdir_href),
                                          "%s/", href)
                        < sizeof(subdir_href))
                    {
                        if (propfind_walk(r, &head, &tail,
                                          child_path, subdir_href,
                                          &entry_count,
                                          PROPFIND_INFINITY_MAX_ENTRIES,
                                          &req) != NGX_OK)
                        {
                            closedir(dp);
                            return NGX_HTTP_INTERNAL_SERVER_ERROR;
                        }
                    }
                }
            }
            closedir(dp);
        }
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

    XROOTD_WEBDAV_METRIC_ADD(propfind_entries_total, entry_count);

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

    XROOTD_WEBDAV_METRIC_ADD(bytes_tx_total, (size_t) total_len);
    if (r->connection && r->connection->sockaddr
        && r->connection->sockaddr->sa_family == AF_INET6) {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv6_total, (size_t) total_len);
    } else {
        XROOTD_WEBDAV_METRIC_ADD(bytes_tx_ipv4_total, (size_t) total_len);
    }

    return ngx_http_output_filter(r, head);
}

/* -------------------------------------------------------------------------
 * Public entry point
 * ---------------------------------------------------------------------- */

static void
propfind_body_handler(ngx_http_request_t *r)
{
    ngx_http_finalize_request(r, propfind_do(r));
}

ngx_int_t
webdav_handle_propfind(ngx_http_request_t *r)
{
    return xrootd_http_read_body(r, propfind_body_handler);
}
