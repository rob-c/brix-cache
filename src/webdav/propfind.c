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
#include "../frm/frm.h"
#include "../path/path.h"
#include "../impersonate/lifecycle.h"
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
/* xrd:locality (phase-35 tape residency) is DELIBERATELY excluded from PF_ALL:
 * it must be probed (stat+getxattr per file) only when a client names it
 * explicitly, so ordinary allprop PROPFINDs (incl. Depth: infinity sweeps) cost
 * nothing extra. */
#define PF_LOCALITY            (1u << 19)

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
        { "locality",              PF_LOCALITY         },
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
        /*
         * W8/G1 — entity-expansion DoS guard.  These flags are deliberately
         * the SAFE set: XML_PARSE_NONET blocks network entity fetches and
         * XML_PARSE_NO_XXE (where available) blocks external entity loading.
         * Critically we do NOT set XML_PARSE_HUGE, so libxml2 keeps its default
         * caps on entity-expansion depth/amplification (the "billion laughs"
         * defense).  Do not add XML_PARSE_HUGE here without a separate explicit
         * size/време bound — it removes those caps and re-opens the DoS.
         */
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
                     * the 404 propstat block.  Capture is silently capped at
                     * PF_UNKNOWN_MAX: a request naming thousands of bogus props
                     * must not grow the fixed-size propfind_req_t.  We pre-build
                     * the exact reflected-XML element now (escaped) so the
                     * response writer only needs to splice the stored string. */
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

/*
 * Append the RFC 3744 ACL-related DAV: properties selected by `mask`.
 * These are synthesized from the request's authenticated identity and the
 * location's allow_write flag rather than from a real ACL store: owner is the
 * client DN (or "anonymous"), and the privilege/ACL sets advertise read plus
 * (only when writes are enabled) the write family.  Each clause is gated on its
 * own mask bit so PROP requests get exactly the properties they asked for.
 */
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
    /* For an explicit PROP request only the requested bits are emitted; ALLPROP
     * (and PROPNAME, handled separately below) emits the full PF_ALL set. */
    unsigned    mask  = (req->type == PROPFIND_PROP) ? req->prop_mask : PF_ALL;
    /* Tracks which of the request's unknown props were actually resolved as
     * dead properties, so the rest can be reported in the 404 propstat. */
    ngx_flag_t  unknown_found[PF_UNKNOWN_MAX];
    ngx_uint_t  i;

    /* ngx_http_time writes an RFC 1123 date with no NUL; terminate it here. */
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
                "<D:principal-collection-set/>"
                "<xrd:locality/>") == NULL
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

        /* Display name is the last path segment: scan back from end of href to
         * the byte after the final '/'. */
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

    /*
     * RFC 4331 quota properties describe a COLLECTION's storage quota, not a
     * file's.  Emitting them on a regular file is non-conformant and actively
     * breaks clients: gfal2/davix maps <D:quota-used-bytes> onto st_size, so a
     * file's reported size becomes the filesystem's used bytes (~TB) instead of
     * getcontentlength.  Stock XrdHttp never emits quota per-file.  Gate to
     * directories so files carry only getcontentlength as their size.
     */
    if ((mask & (PF_QUOTA_AVAILABLE | PF_QUOTA_USED)) && S_ISDIR(sb->st_mode)) {
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
        /* Lock helpers are best-effort here: a failure to emit the optional
         * supportedlock/lockdiscovery block must not abort the whole response. */
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

    /*
     * xrd:locality — tape residency (phase-35). Probed (stat+getxattr) only when
     * the client explicitly names the prop (PF_LOCALITY is not in PF_ALL), and
     * only for regular files. Absent xattr ⇒ ONLINE, so a plain disk export needs
     * no migration. Values follow the WLCG locality vocabulary.
     */
    if ((mask & PF_LOCALITY) && !S_ISDIR(sb->st_mode)) {
        frm_residency_t res;
        const char     *loc = "ONLINE";

        if (frm_residency_probe(r->connection->log, path, &res) == NGX_OK) {
            switch (res.state) {
            case FRM_RES_ONLINE:
                loc = res.backend_exists ? "ONLINE_AND_NEARLINE" : "ONLINE";
                break;
            case FRM_RES_NEARLINE:
            case FRM_RES_OFFLINE:
                loc = "NEARLINE";
                break;
            case FRM_RES_LOST:
                loc = "LOST";
                break;
            default:
                loc = "ONLINE";
                break;
            }
        }
        if (xrootd_http_chain_appendf(pool, head, tail,
                "<xrd:locality>%s</xrd:locality>", loc) == NULL)
            return NGX_ERROR;
    }

    if (propfind_append_acl_properties(r, head, tail, mask) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Dead (client-defined) properties: ALLPROP dumps them all; an explicit
     * PROP request instead tries to resolve each unrecognised name against the
     * dead-property store, recording hits in unknown_found[] so the misses can
     * go into a 404 propstat afterwards.  DAV:-namespace unknowns are never
     * looked up here — a DAV: name we don't know is genuinely unsupported. */
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

    /* For explicit PROP requests: emit 404 propstat for unknown properties.
     * Skip the whole block if every named unknown turned out to exist as a dead
     * property (all resolved above) — emitting an empty 404 propstat is invalid. */
    if (req->type == PROPFIND_PROP && req->unknown_count > 0) {
        ngx_flag_t any_missing = 0;

        for (i = 0; i < req->unknown_count; i++) {
            if (!unknown_found[i]) {
                any_missing = 1;
                break;
            }
        }

        /* Emit the 404 propstat only when at least one named property is
         * genuinely missing — an empty 404 propstat would be invalid, so when
         * nothing is missing we skip straight to closing the response. */
        if (any_missing) {
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
    }

    if (xrootd_http_chain_appendf(pool, head, tail, "</D:response>") == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* -------------------------------------------------------------------------
 * Depth header parsing
 * ---------------------------------------------------------------------- */

/*
 * Parse the Depth request header into an internal code:
 *   0  -> "0" or absent (target only)
 *   1  -> "1" (target + immediate children)
 *  -1  -> "infinity" (full recursive walk)
 * Any unrecognised value defaults to 0, the safe/cheapest behaviour.
 */
static int
propfind_parse_depth(ngx_http_request_t *r)
{
    ngx_str_t val = xrootd_http_get_header(r, "Depth");
    if (val.len == 0) return 0;
    if (val.len == 1 && val.data[0] == '1') return 1;
    if (val.len == 8 && ngx_strncasecmp(val.data, (u_char *) "infinity", 8) == 0) return -1;
    return 0;
}

/* -------------------------------------------------------------------------
 * Depth: infinity recursive walk
 * ---------------------------------------------------------------------- */

/* Hard ceiling on entries emitted for a Depth: infinity PROPFIND so a deep or
 * wide tree cannot generate an unbounded response / runaway recursion. */
#define PROPFIND_INFINITY_MAX_ENTRIES  10000

/*
 * Recursively emit D:response elements for every descendant of dir_path
 * (Depth: infinity).  entry_count is shared across the whole walk and checked
 * against max_entries before each entry; once the cap is hit the walk stops and
 * logs a warning (the response is still well-formed, just truncated).  An
 * unreadable directory is skipped, not fatal.  On any propfind_entry error the
 * open DIR is closed before returning NGX_ERROR (no fd leak on the error path).
 */
static ngx_int_t
propfind_walk(ngx_http_request_t *r,
              ngx_chain_t **head, ngx_chain_t **tail,
              const char *dir_path, const char *base_href,
              ngx_uint_t *entry_count, ngx_uint_t max_entries,
              const propfind_req_t *req)
{
    DIR           *dp;
    struct dirent *de;
    ngx_http_xrootd_webdav_loc_conf_t *wdcf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    const char    *root_canon = wdcf->common.root_canon;

    /*
     * Impersonation: before exposing the entries, verify the MAPPED user may
     * actually READ this directory (the broker opens it O_RDONLY as that user) —
     * otherwise a user would be shown the contents of a directory the worker can
     * read but they cannot.  When impersonation is off this is a no-op.  A denied
     * dir is treated exactly like an unreadable subtree: skipped, request not failed.
     */
    if (xrootd_dirlist_access_ok(r->connection->log, root_canon, dir_path)
        != NGX_OK)
    {
        return NGX_OK;
    }

    /* Enumerate AS THE MAPPED USER under impersonation (broker fdopendir) so a
     * 0700 user-owned / 0770 group-restricted dir the unprivileged worker cannot
     * itself open is still listable by its legitimate owner/group-member. */
    dp = xrootd_opendir_confined_canon(r->connection->log, root_canon, dir_path);
    if (dp == NULL) {
        return NGX_OK;   /* unreadable subtree: skip, do not fail the request */
    }

    while ((de = readdir(dp)) != NULL) {
        char        child_path[WEBDAV_MAX_PATH];
        char        child_href[WEBDAV_MAX_PATH + 2];
        struct stat csb;

        /* Skip "."/".." and any dotfile (hidden entries are not listed). */
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

        /* lstat (not stat): do not follow a symlink during the walk — a symlink in
         * the export pointing outside it must not be recursed into (it would
         * enumerate the target tree, e.g. /etc).  Under impersonation the dirlist
         * gate already blocks this via RESOLVE_BENEATH; lstat hardens the
         * non-impersonated path too.  A symlink is S_ISLNK -> not S_ISDIR -> listed
         * as a plain resource, never recursed. */
        if (xrootd_lstat_confined_canon(r->connection->log,
                root_canon, child_path, &csb, 1) != 0) {
            continue;
        }

        /* Build child href = base_href + name, inserting a single '/' only if
         * base_href is not already slash-terminated.  snprintf returns the
         * would-be length; >= buffer size means it was truncated, so skip the
         * entry rather than emit a corrupted href. */
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

        /* Recurse into subdirectories (with a trailing-slash href). Re-check
         * the cap first so a balanced tree cannot blow past max_entries via
         * nested calls before the per-entry check fires. */
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

/*
 * Build and send the complete 207 Multi-Status response.
 * Runs after the request body has been read (see propfind_body_handler), so it
 * may resolve/stat the target and parse the body synchronously.  Assembles the
 * XML as an ngx_chain_t, sums the body length for Content-Length, marks the last
 * buffer, then sends headers + body.  Returns an HTTP status / NGX_* code.
 */
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
            "<D:multistatus xmlns:D=\"DAV:\""
            " xmlns:xrd=\"http://xrootd.org/2010/ns/dav\">") == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* First D:response is always the request target itself (Depth 0/1/inf). */
    {
        char   href[WEBDAV_MAX_PATH + 2];
        size_t uri_len = r->uri.len;

        /* r->uri is not NUL-terminated; copy a bounded, terminated href. */
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

    /* Depth 1 or infinity on a collection: emit each immediate child. For
     * infinity we additionally recurse into each child directory via
     * propfind_walk (the top level is unrolled here so the shared entry_count
     * cap is threaded through). */
    if ((depth == 1 || depth == -1) && S_ISDIR(sb.st_mode)) {
        ngx_http_xrootd_webdav_loc_conf_t *wdcf =
            ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
        DIR *dp;

        /* Impersonation: only list children the MAPPED user may read (the broker
         * opens the dir O_RDONLY as that user); a worker-side readdir would
         * otherwise leak entries the user has no UNIX permission to see.  No-op
         * when impersonation is off. */
        if (xrootd_dirlist_access_ok(r->connection->log,
                                     wdcf->common.root_canon, path) != NGX_OK)
        {
            dp = NULL;
        } else {
            dp = xrootd_opendir_confined_canon(r->connection->log,
                                               wdcf->common.root_canon, path);
        }

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

                if (xrootd_lstat_confined_canon(r->connection->log,
                        wdcf->common.root_canon, child_path, &csb, 1) != 0) {
                    continue;   /* do not follow symlinks */
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

    /* Mark end-of-response on the final buffer so the output filter flushes. */
    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    /* Content-Length = sum of all buffer payloads in the chain. */
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

/*
 * Body-ready callback: nginx invokes this once the (possibly chunked) request
 * body is fully buffered.  It runs propfind_do and finalizes the request with
 * its return code — this is the async re-entry point after webdav_handle_propfind
 * returned NGX_DONE to the request pipeline.
 *
 * Phase 40: the PROPFIND body is read asynchronously, so the outer dispatch
 * wrapper (webdav_dispatch.c) has already cleared the impersonation principal by
 * the time this callback runs.  Re-establish it for the duration of the listing
 * exactly as webdav_handle_put_body does — without it the directory-stat/opendir
 * and the xrootd_dirlist_access_ok confidentiality check run as the unprivileged
 * worker instead of the mapped user, which would both mis-own metadata and leak
 * entries of a directory the mapped user cannot read.  No-op unless map mode.
 */
static void
propfind_body_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    ngx_int_t rc;

    xrootd_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = propfind_do(r);
    xrootd_imp_request_end();

    ngx_http_finalize_request(r, rc);
}

/*
 * PROPFIND entry point.  Defers all work until the request body is read, since
 * the body selects allprop/propname/prop.  xrootd_http_read_body arranges for
 * propfind_body_handler to run and typically returns NGX_DONE.
 */
ngx_int_t
webdav_handle_propfind(ngx_http_request_t *r)
{
    return xrootd_http_read_body(r, propfind_body_handler);
}
