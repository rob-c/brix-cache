/*
 * propfind.c - (kept) routing + shared helpers
 * Phase-38 split of propfind.c; behavior-identical.
 */
#include "propfind_internal.h"

unsigned
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
const char *
propfind_assemble_body(ngx_http_request_t *r, size_t *len)
{
    u_char    *buf;
    ngx_int_t  rc;

    *len = 0;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NULL;
    }

    rc = brix_http_body_read_all(r, PROPFIND_BODY_MAX, &buf, len);
    if (rc != NGX_OK || *len == 0) {
        return NULL;
    }

    return (const char *) buf;
}


/*
 * WHAT: Parse a PROPFIND request body (XML) into a libxml2 document.
 * WHY:  Centralises the entity-expansion DoS guard so every parse of an
 *       attacker-supplied body uses the identical SAFE libxml2 option set.
 * HOW:  xmlReadMemory with the SAFE flags below; returns NULL on parse
 *       failure (the caller then defaults to allprop).  W8/G1 — these flags
 *       are deliberately the SAFE set: XML_PARSE_NONET blocks network entity
 *       fetches and XML_PARSE_NO_XXE (where available) blocks external entity
 *       loading.  Critically we do NOT set XML_PARSE_HUGE, so libxml2 keeps
 *       its default caps on entity-expansion depth/amplification (the "billion
 *       laughs" defense).  Do not add XML_PARSE_HUGE here without a separate
 *       explicit size/време bound — it removes those caps and re-opens the DoS.
 */
static xmlDocPtr
propfind_read_doc(const char *body, size_t body_len)
{
    int opts = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;

#if defined(XML_PARSE_NO_XXE)
    opts |= XML_PARSE_NO_XXE;
#endif

    return xmlReadMemory(body, (int) body_len, "propfind.xml", NULL, opts);
}


/*
 * WHAT: Record one unrecognised <prop> child as a pre-built reflected-XML
 *       empty-element for the 404 propstat block.
 * WHY:  The response writer must echo unknown properties verbatim (name +
 *       namespace) but the fixed-size propfind_req_t cannot grow without bound
 *       — a request naming thousands of bogus props must not exhaust memory.
 * HOW:  Silently cap capture at PF_UNKNOWN_MAX; store the raw namespace/local
 *       for bookkeeping, then pre-render the exact escaped XML element now so
 *       the writer only splices the stored string.  DAV:-namespace props use
 *       the <D:name/> short form; any other namespace gets an inline xmlns
 *       declaration with the namespace href XML-escaped.
 */
static void
propfind_capture_unknown(ngx_http_request_t *r, propfind_req_t *req,
    xmlNodePtr prop)
{
    ngx_uint_t  idx;
    const char *local   = (const char *) prop->name;
    const char *ns_href = "";

    if (req->unknown_count >= PF_UNKNOWN_MAX) {
        return;
    }

    idx = req->unknown_count;

    if (prop->ns != NULL && prop->ns->href != NULL) {
        ns_href = (const char *) prop->ns->href;
    }

    snprintf(req->unknown[idx].ns, sizeof(req->unknown[idx].ns), "%s", ns_href);
    snprintf(req->unknown[idx].local, sizeof(req->unknown[idx].local),
             "%s", local);

    if (prop->ns != NULL
        && xmlStrcmp(prop->ns->href, BAD_CAST "DAV:") != 0)
    {
        char *safe_ns = webdav_escape_xml_text(r->pool, ns_href);
        if (safe_ns == NULL) {
            safe_ns = "";
        }
        /* Non-DAV: namespace — include xmlns declaration. */
        snprintf(req->unknown[idx].xml, PF_UNKNOWN_XML_MAX,
                 "<ns%u:%s xmlns:ns%u=\"%s\"/>",
                 (unsigned) idx, local, (unsigned) idx, safe_ns);
    } else {
        snprintf(req->unknown[idx].xml, PF_UNKNOWN_XML_MAX, "<D:%s/>", local);
    }

    req->unknown_count++;
}


/*
 * WHAT: Collect the named properties of a <prop> element into req.
 * WHY:  A PROPFIND <prop> selects an explicit property set; each child either
 *       maps to a known bit or must be reflected back as an unknown.
 * HOW:  Iterate element children — known names OR their bit into prop_mask,
 *       everything else is handed to propfind_capture_unknown.  Non-element
 *       nodes (text/whitespace) are skipped.
 */
static void
propfind_collect_props(ngx_http_request_t *r, propfind_req_t *req,
    xmlNodePtr child)
{
    xmlNodePtr prop;

    for (prop = child->children; prop != NULL; prop = prop->next) {
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

        propfind_capture_unknown(r, req, prop);
    }
}


/*
 * WHAT: Interpret the children of the <propfind> root element, setting the
 *       request type (allprop / propname / prop) and, for <prop>, its set.
 * WHY:  RFC 4918 §9.1 — exactly one of allprop/propname/prop selects the
 *       listing mode; the first recognised child wins.
 * HOW:  Scan element children; stop at the first allprop/propname/prop.  For
 *       <prop>, delegate the property set to propfind_collect_props.
 */
static void
propfind_walk_root(ngx_http_request_t *r, propfind_req_t *req, xmlNodePtr root)
{
    xmlNodePtr child;

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
            propfind_collect_props(r, req, child);
            break;
        }
    }
}


/*
 * Parse a PROPFIND request body into req.
 * Initialises req to ALLPROP on entry so any early return is safe.
 */
void
propfind_parse_request(ngx_http_request_t *r, propfind_req_t *req)
{
    const char *body;
    size_t      body_len;
    xmlDocPtr   doc;
    xmlNodePtr  root;

    req->type          = PROPFIND_ALLPROP;
    req->prop_mask     = 0;
    req->unknown_count = 0;

    body = propfind_assemble_body(r, &body_len);
    if (body == NULL) {
        return;   /* no body → allprop per RFC 4918 §9.1 */
    }

    doc = propfind_read_doc(body, body_len);
    if (doc == NULL) {
        return;
    }

    root = xmlDocGetRootElement(doc);
    if (root == NULL || xmlStrcmp(root->name, BAD_CAST "propfind") != 0) {
        xmlFreeDoc(doc);
        return;
    }

    propfind_walk_root(r, req, root);

    xmlFreeDoc(doc);
}


/*
 * Depth header parsing
 * */

/*
 * Parse the Depth request header into an internal code:
 *   0  -> "0" or absent (target only)
 *   1  -> "1" (target + immediate children)
 *  -1  -> "infinity" (full recursive walk)
 * Any unrecognised value defaults to 0, the safe/cheapest behaviour.
 */
int
propfind_parse_depth(ngx_http_request_t *r)
{
    ngx_str_t val = brix_http_get_header(r, "Depth");
    if (val.len == 0) return 0;
    if (val.len == 1 && val.data[0] == '1') return 1;
    if (val.len == 8 && ngx_strncasecmp(val.data, (u_char *) "infinity", 8) == 0) return -1;
    return 0;
}


/*
 * Public entry point
 * */

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
 * and the brix_dirlist_access_ok confidentiality check run as the unprivileged
 * worker instead of the mapped user, which would both mis-own metadata and leak
 * entries of a directory the mapped user cannot read.  No-op unless map mode.
 */
void
propfind_body_handler(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *rx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    ngx_int_t rc;

    brix_imp_request_begin(rx != NULL ? rx->identity : NULL);
    rc = propfind_do(r);
    brix_imp_request_end();

    ngx_http_finalize_request(r, rc);
}


/*
 * PROPFIND entry point.  Defers all work until the request body is read, since
 * the body selects allprop/propname/prop.  brix_http_read_body arranges for
 * propfind_body_handler to run and typically returns NGX_DONE.
 */
ngx_int_t
webdav_handle_propfind(ngx_http_request_t *r)
{
    return brix_http_read_body(r, propfind_body_handler);
}
