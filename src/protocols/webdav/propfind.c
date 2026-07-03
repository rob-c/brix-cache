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
 * Parse a PROPFIND request body into req.
 * Initialises req to ALLPROP on entry so any early return is safe.
 */
void
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
