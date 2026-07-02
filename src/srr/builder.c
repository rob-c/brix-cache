/*
 * builder.c — assemble the WLCG SRR "storageservice" JSON document.
 *
 * WHAT: ngx_http_xrootd_srr_build_json() constructs the Storage Resource
 *   Reporting document (schema v4.x) with jansson and serialises it into a
 *   request-pool buffer.  Per-share total/used bytes come from statvfs(2) via
 *   the shared xrootd_fs_usage_stat() helper; identity, share, and endpoint
 *   metadata come from the location config.
 *
 * WHY: WLCG storage accounting (CRIC harvester, DIRAC occupancy plugins) reads
 *   exactly this document over HTTP.  The schema's REQUIRED fields are emitted
 *   unconditionally so the output always validates:
 *     storageservice            → implementation, implementationversion,
 *                                 storageendpoints[], storageshares[]
 *     storagecapacity.online    → totalsize, usedsize
 *     storageendpoints[] item   → name, endpointurl, interfacetype,
 *                                 assignedshares[]
 *     storageshares[] item      → timestamp, totalsize, usedsize, vos[]
 *
 * HOW: jansson json_object()/json_array() tree → two-pass json_dumpb() (NULL
 *   buffer sizes the payload, then dump for real), same idiom as
 *   src/dashboard/api.c.  All config strings are ngx_str_t (NOT NUL-terminated),
 *   so json_stringn(data, len) is used throughout.
 *
 *   Ownership/robustness: storageservice (svc) is attached under root
 *   immediately, and every container is attached to the tree right after it is
 *   allocated.  That makes a single json_decref(root) free the whole (partial)
 *   tree, so ANY allocation failure bails with that one cleanup and returns
 *   NGX_ERROR (→ HTTP 500).  A partial-but-200 document — which a harvester
 *   would ingest as authoritative — can therefore never be emitted.
 */

#include "srr.h"
#include "compat/fs_usage.h"

#include <jansson.h>
#include <stdint.h>
#include <time.h>

/* json_stringn from an ngx_str_t (handles the not-NUL-terminated wire form). */
#define SRR_JSTR(s)  json_stringn((const char *) (s).data, (s).len)


/* Clamp an unsigned byte count into the non-negative json_int_t (int64) range.
 * WLCG totalsize/usedsize are non-negative; a filesystem (or accumulated sum)
 * at/over 2^63 bytes would otherwise wrap to a negative JSON integer that
 * harvesters silently ingest. */
static json_int_t
srr_clamp_size(uint64_t v)
{
    return (v > (uint64_t) INT64_MAX) ? (json_int_t) INT64_MAX : (json_int_t) v;
}


/*
 * Split a comma-separated VO list ("atlas, cms") into a JSON string array.
 * Surrounding whitespace per element is trimmed; empty elements are skipped.
 * An empty/NULL list still yields an empty array — vos is a REQUIRED SRR field,
 * so the property must always be present (possibly []).  Returns NULL only if
 * the array allocation itself fails (caller treats that as fatal).
 */
static json_t *
srr_vos_array(const ngx_str_t *vos)
{
    json_t *arr = json_array();
    u_char *p, *end, *comma, *tokend;

    if (arr == NULL) {
        return NULL;
    }
    if (vos == NULL || vos->len == 0) {
        return arr;
    }

    p   = vos->data;
    end = vos->data + vos->len;

    while (p < end) {
        size_t toklen;

        comma  = ngx_strlchr(p, end, ',');
        tokend = comma ? comma : end;

        while (p < tokend && (*p == ' ' || *p == '\t')) {
            p++;
        }
        toklen = (size_t) (tokend - p);
        while (toklen > 0 && (p[toklen - 1] == ' ' || p[toklen - 1] == '\t')) {
            toklen--;
        }
        if (toklen > 0) {
            json_array_append_new(arr, json_stringn((const char *) p, toklen));
        }

        p = comma ? comma + 1 : end;
    }

    return arr;
}


/* JSON array of every configured share name (for endpoints' assignedshares). */
static json_t *
srr_share_names(ngx_http_xrootd_srr_loc_conf_t *lcf)
{
    json_t             *arr = json_array();
    xrootd_srr_share_t *sh;
    ngx_uint_t          i;

    if (arr == NULL) {
        return NULL;
    }
    if (lcf->shares == NULL) {
        return arr;
    }
    sh = lcf->shares->elts;
    for (i = 0; i < lcf->shares->nelts; i++) {
        json_array_append_new(arr, SRR_JSTR(sh[i].name));
    }
    return arr;
}


/* JSON array of every configured endpoint name (for shares' assignedendpoints). */
static json_t *
srr_endpoint_names(ngx_http_xrootd_srr_loc_conf_t *lcf)
{
    json_t                *arr = json_array();
    xrootd_srr_endpoint_t *ep;
    ngx_uint_t             i;

    if (arr == NULL) {
        return NULL;
    }
    if (lcf->endpoints == NULL) {
        return arr;
    }
    ep = lcf->endpoints->elts;
    for (i = 0; i < lcf->endpoints->nelts; i++) {
        json_array_append_new(arr, SRR_JSTR(ep[i].name));
    }
    return arr;
}


ngx_int_t
ngx_http_xrootd_srr_build_json(ngx_http_request_t *r,
    ngx_http_xrootd_srr_loc_conf_t *lcf, u_char **out, size_t *len)
{
    json_t     *root, *svc, *shares, *eps, *cap, *online, *node;
    uint64_t    cap_total = 0, cap_used = 0;
    time_t      now = time(NULL);
    ngx_uint_t  i;
    size_t      needed;
    u_char     *buf;

    root = json_object();
    svc  = json_object();
    if (root == NULL || svc == NULL) {
        if (root) { json_decref(root); }
        if (svc)  { json_decref(svc); }
        return NGX_ERROR;
    }
    /* Attach svc under root NOW: from here a single json_decref(root) frees the
     * whole tree, so every later failure path is just "json_decref(root);
     * return NGX_ERROR;" and no partial document can be serialised. */
    json_object_set_new(root, "storageservice", svc);

    /* storageservice identity */    if (lcf->name.len) {
        json_object_set_new(svc, "name", SRR_JSTR(lcf->name));
    }
    if (lcf->id.len) {
        json_object_set_new(svc, "id", SRR_JSTR(lcf->id));
    } else if (lcf->name.len) {
        json_object_set_new(svc, "id", SRR_JSTR(lcf->name));
    }
    json_object_set_new(svc, "servicetype", json_string("disk"));
    json_object_set_new(svc, "implementation", json_string("nginx-xrootd"));
    json_object_set_new(svc, "implementationversion",
        lcf->version.len ? SRR_JSTR(lcf->version) : json_string("1.0"));
    json_object_set_new(svc, "qualitylevel",
        lcf->quality.len ? SRR_JSTR(lcf->quality) : json_string("production"));
    json_object_set_new(svc, "latestupdate", json_integer((json_int_t) now));

    /* storageshares[] (attached empty, then populated) */    shares = json_array();
    if (shares == NULL) {
        json_decref(root);
        return NGX_ERROR;
    }
    json_object_set_new(svc, "storageshares", shares);

    if (lcf->shares != NULL) {
        xrootd_srr_share_t *sh = lcf->shares->elts;

        for (i = 0; i < lcf->shares->nelts; i++) {
            xrootd_fs_usage_t  usage;
            uint64_t           total = 0, used = 0;
            json_t            *share, *patharr;
            u_char            *pathz;

            /* statvfs(2) needs a NUL-terminated path; the configured path is an
             * operator-controlled string (not request input), so a direct stat
             * is safe — no confinement resolver needed here. */
            pathz = ngx_pnalloc(r->pool, sh[i].path.len + 1);
            if (pathz == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            ngx_memcpy(pathz, sh[i].path.data, sh[i].path.len);
            pathz[sh[i].path.len] = '\0';

            if (xrootd_fs_usage_stat((const char *) pathz, &usage) == NGX_OK) {
                total = usage.total_bytes;
                used  = usage.used_bytes;
            } else {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
                    "srr: statvfs failed for share \"%V\" path \"%V\" "
                    "(reporting 0 bytes)", &sh[i].name, &sh[i].path);
            }
            /* Saturating accumulate — guards the (astronomical) 2^64 wrap. */
            cap_total += total;
            if (cap_total < total) { cap_total = UINT64_MAX; }
            cap_used += used;
            if (cap_used < used) { cap_used = UINT64_MAX; }

            share = json_object();
            if (share == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            json_array_append_new(shares, share);

            json_object_set_new(share, "name", SRR_JSTR(sh[i].name));
            json_object_set_new(share, "timestamp", json_integer((json_int_t) now));
            json_object_set_new(share, "totalsize",
                                json_integer(srr_clamp_size(total)));
            json_object_set_new(share, "usedsize",
                                json_integer(srr_clamp_size(used)));

            patharr = json_array();
            if (patharr == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            json_object_set_new(share, "path", patharr);
            json_array_append_new(patharr, SRR_JSTR(sh[i].path));

            node = srr_vos_array(&sh[i].vos);
            if (node == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            json_object_set_new(share, "vos", node);

            node = srr_endpoint_names(lcf);
            if (node == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            json_object_set_new(share, "assignedendpoints", node);
        }
    }

    /* storagecapacity.online (site-wide sum of the shares) */    cap    = json_object();
    online = json_object();
    if (cap == NULL || online == NULL) {
        if (cap)    { json_decref(cap); }      /* disjoint: not yet attached */
        if (online) { json_decref(online); }
        json_decref(root);
        return NGX_ERROR;
    }
    json_object_set_new(online, "totalsize", json_integer(srr_clamp_size(cap_total)));
    json_object_set_new(online, "usedsize", json_integer(srr_clamp_size(cap_used)));
    json_object_set_new(cap, "online", online);
    json_object_set_new(svc, "storagecapacity", cap);

    /* storageendpoints[] (attached empty, then populated) */    eps = json_array();
    if (eps == NULL) {
        json_decref(root);
        return NGX_ERROR;
    }
    json_object_set_new(svc, "storageendpoints", eps);

    if (lcf->endpoints != NULL) {
        xrootd_srr_endpoint_t *ep = lcf->endpoints->elts;

        for (i = 0; i < lcf->endpoints->nelts; i++) {
            json_t *e = json_object();

            if (e == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            json_array_append_new(eps, e);

            json_object_set_new(e, "name", SRR_JSTR(ep[i].name));
            json_object_set_new(e, "endpointurl", SRR_JSTR(ep[i].url));
            json_object_set_new(e, "interfacetype", SRR_JSTR(ep[i].interfacetype));
            json_object_set_new(e, "qualitylevel",
                lcf->quality.len ? SRR_JSTR(lcf->quality)
                                 : json_string("production"));

            node = srr_share_names(lcf);
            if (node == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            json_object_set_new(e, "assignedshares", node);
        }
    }

    /* serialise into the request pool (two-pass, dashboard idiom) */    needed = json_dumpb(root, NULL, 0, JSON_INDENT(2));
    if (needed == 0) {
        json_decref(root);
        return NGX_ERROR;
    }
    buf = ngx_pnalloc(r->pool, needed);
    if (buf == NULL) {
        json_decref(root);
        return NGX_ERROR;
    }
    json_dumpb(root, (char *) buf, needed, JSON_INDENT(2));
    json_decref(root);

    *out = buf;
    *len = needed;
    return NGX_OK;
}
