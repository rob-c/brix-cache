/*
 * builder.c — assemble the WLCG SRR "storageservice" JSON document.
 *
 * WHAT: ngx_http_brix_srr_build_json() constructs the Storage Resource
 *   Reporting document (schema v4.x) with jansson and serialises it into a
 *   request-pool buffer.  Per-share total/used bytes come from statvfs(2) via
 *   the shared brix_fs_usage_stat() helper; identity, share, and endpoint
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
#include "core/compat/fs_usage.h"
#include "core/ident.h"
#include "core/compat/cstr.h"

#include <jansson.h>
#include <stdint.h>
#include <time.h>

/* json_stringn from an ngx_str_t (handles the not-NUL-terminated wire form). */
#define SRR_JSTR(s)  json_stringn((const char *) (s).data, (s).len)


/* A total/used byte pair.  Used both as one share's stat result and as the
 * saturating site-wide accumulator, so the shares section can carry both
 * without a fistful of loose uint64_t out-params. */
typedef struct {
    uint64_t  total;
    uint64_t  used;
} srr_cap_t;


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
srr_share_names(ngx_http_brix_srr_loc_conf_t *lcf)
{
    json_t             *arr = json_array();
    brix_srr_share_t *sh;
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
srr_endpoint_names(ngx_http_brix_srr_loc_conf_t *lcf)
{
    json_t                *arr = json_array();
    brix_srr_endpoint_t *ep;
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


/*
 * Emit the "storageservice" identity scalars (name / id / servicetype /
 * implementation / implementationversion / qualitylevel / latestupdate).
 *
 * WHAT: sets the fixed identity properties on the already-attached svc object.
 * WHY:  these SRR fields never fail-allocate on their own (json_string /
 *   json_integer + json_object_set_new steal the ref and cannot signal
 *   allocation failure back here), so this is a pure emit with no error path —
 *   splitting it out keeps the orchestrator flat.
 * HOW:  ngx_str_t config values via SRR_JSTR (not NUL-terminated); id falls
 *   back to name, version/quality fall back to their compiled/default strings,
 *   exactly as before. `now` is threaded in so every timestamp in one document
 *   shares a single time(NULL) sample.
 */
static void
srr_emit_identity(json_t *svc, ngx_http_brix_srr_loc_conf_t *lcf, time_t now)
{
    if (lcf->name.len) {
        json_object_set_new(svc, "name", SRR_JSTR(lcf->name));
    }
    if (lcf->id.len) {
        json_object_set_new(svc, "id", SRR_JSTR(lcf->id));
    } else if (lcf->name.len) {
        json_object_set_new(svc, "id", SRR_JSTR(lcf->name));
    }
    json_object_set_new(svc, "servicetype", json_string("disk"));
    json_object_set_new(svc, "implementation",
        json_string(BRIX_SERVER_NAME));
    json_object_set_new(svc, "implementationversion",
        lcf->version.len ? SRR_JSTR(lcf->version)
                         : json_string(BRIX_SERVER_VERSION_BARE));
    json_object_set_new(svc, "qualitylevel",
        lcf->quality.len ? SRR_JSTR(lcf->quality) : json_string("production"));
    json_object_set_new(svc, "latestupdate", json_integer((json_int_t) now));
}


/*
 * Stat one share's filesystem and saturating-accumulate it into the site total.
 *
 * WHAT: statvfs(2) the configured path via brix_fs_usage_stat(); return this
 *   share's total / used bytes in *share_cap and fold them into *site_cap.
 * WHY:  isolates the only side-effecting step of the shares loop (the stat +
 *   WARN log) from the JSON emit, and keeps the 2^64-wrap saturation guard in
 *   one place shared by every share.
 * HOW:  a stat failure reports 0 bytes (never fatal) with the same WARN line as
 *   before; the accumulate clamps to UINT64_MAX on overflow.  Returns NGX_ERROR
 *   only when the path cannot be NUL-terminated (allocation failure).
 */
static ngx_int_t
srr_share_usage(ngx_http_request_t *r, brix_srr_share_t *sh,
    srr_cap_t *share_cap, srr_cap_t *site_cap)
{
    brix_fs_usage_t  usage;
    u_char          *pathz;

    share_cap->total = 0;
    share_cap->used  = 0;

    /* statvfs(2) needs a NUL-terminated path; the configured path is an
     * operator-controlled string (not request input), so a direct stat
     * is safe — no confinement resolver needed here. */
    pathz = (u_char *) brix_pstrdup_z(r->pool, &sh->path);
    if (pathz == NULL) {
        return NGX_ERROR;
    }

    if (brix_fs_usage_stat((const char *) pathz, &usage) == NGX_OK) {
        share_cap->total = usage.total_bytes;
        share_cap->used  = usage.used_bytes;
    } else {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
            "srr: statvfs failed for share \"%V\" path \"%V\" "
            "(reporting 0 bytes)", &sh->name, &sh->path);
    }

    /* Saturating accumulate — guards the (astronomical) 2^64 wrap. */
    site_cap->total += share_cap->total;
    if (site_cap->total < share_cap->total) { site_cap->total = UINT64_MAX; }
    site_cap->used += share_cap->used;
    if (site_cap->used < share_cap->used) { site_cap->used = UINT64_MAX; }

    return NGX_OK;
}


/*
 * Build and append one "storageshares[]" item (name / timestamp / sizes / path /
 * vos / assignedendpoints).
 *
 * WHAT: allocate the share object, attach it to the shares array immediately,
 *   then populate its REQUIRED properties.
 * WHY:  keeping the object attached the moment it is allocated preserves the
 *   single-json_decref(root) cleanup contract — any failure here just returns
 *   NGX_ERROR and the orchestrator frees the whole (partial) tree.
 * HOW:  clamps the byte counts into json_int_t; the path array and the vos /
 *   endpoint-name sub-arrays are the only allocations that can fail, and each
 *   is checked, matching the pre-split ordering byte-for-byte.
 */
static ngx_int_t
srr_emit_share(ngx_http_brix_srr_loc_conf_t *lcf, json_t *shares,
    brix_srr_share_t *sh, const srr_cap_t *cap, time_t now)
{
    json_t *share, *patharr, *node;

    share = json_object();
    if (share == NULL) {
        return NGX_ERROR;
    }
    json_array_append_new(shares, share);

    json_object_set_new(share, "name", SRR_JSTR(sh->name));
    json_object_set_new(share, "timestamp", json_integer((json_int_t) now));
    json_object_set_new(share, "totalsize",
                        json_integer(srr_clamp_size(cap->total)));
    json_object_set_new(share, "usedsize",
                        json_integer(srr_clamp_size(cap->used)));

    patharr = json_array();
    if (patharr == NULL) {
        return NGX_ERROR;
    }
    json_object_set_new(share, "path", patharr);
    json_array_append_new(patharr, SRR_JSTR(sh->path));

    node = srr_vos_array(&sh->vos);
    if (node == NULL) {
        return NGX_ERROR;
    }
    json_object_set_new(share, "vos", node);

    node = srr_endpoint_names(lcf);
    if (node == NULL) {
        return NGX_ERROR;
    }
    json_object_set_new(share, "assignedendpoints", node);

    return NGX_OK;
}


/*
 * Emit the whole "storageshares[]" section and return the site-wide capacity.
 *
 * WHAT: allocate + attach the shares array, then for each configured share stat
 *   its filesystem and append its JSON item, accumulating the byte totals into
 *   *site_cap across all shares.
 * WHY:  this is the one section that both emits JSON and produces a value the
 *   later storagecapacity section needs, so the accumulation and emission stay
 *   together here rather than leaking into the orchestrator.
 * HOW:  a NULL lcf->shares still leaves an attached empty array (REQUIRED
 *   field); any sub-step returning NGX_ERROR propagates up so the orchestrator's
 *   single json_decref(root) frees the tree.
 */
static ngx_int_t
srr_emit_shares(ngx_http_request_t *r, ngx_http_brix_srr_loc_conf_t *lcf,
    json_t *svc, time_t now, srr_cap_t *site_cap)
{
    json_t            *shares;
    brix_srr_share_t  *sh;
    ngx_uint_t         i;

    shares = json_array();
    if (shares == NULL) {
        return NGX_ERROR;
    }
    json_object_set_new(svc, "storageshares", shares);

    if (lcf->shares == NULL) {
        return NGX_OK;
    }

    sh = lcf->shares->elts;
    for (i = 0; i < lcf->shares->nelts; i++) {
        srr_cap_t  share_cap;

        if (srr_share_usage(r, &sh[i], &share_cap, site_cap) != NGX_OK) {
            return NGX_ERROR;
        }
        if (srr_emit_share(lcf, shares, &sh[i], &share_cap, now) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * Emit "storagecapacity.online" from the accumulated site-wide byte totals.
 *
 * WHAT: build the capacity / online objects and attach them under svc.
 * WHY:  the two objects are allocated before either is attached, so they are
 *   momentarily disjoint from the tree — a failure here must free them itself
 *   (the root cleanup cannot reach them yet), so this stays a distinct step.
 * HOW:  clamps both totals into json_int_t; on partial allocation the
 *   not-yet-attached objects are individually decref'd and NGX_ERROR returned.
 */
static ngx_int_t
srr_emit_capacity(json_t *svc, uint64_t cap_total, uint64_t cap_used)
{
    json_t *cap, *online;

    cap    = json_object();
    online = json_object();
    if (cap == NULL || online == NULL) {
        if (cap)    { json_decref(cap); }      /* disjoint: not yet attached */
        if (online) { json_decref(online); }
        return NGX_ERROR;
    }
    json_object_set_new(online, "totalsize",
        json_integer(srr_clamp_size(cap_total)));
    json_object_set_new(online, "usedsize",
        json_integer(srr_clamp_size(cap_used)));
    json_object_set_new(cap, "online", online);
    json_object_set_new(svc, "storagecapacity", cap);

    return NGX_OK;
}


/*
 * Emit the whole "storageendpoints[]" section.
 *
 * WHAT: allocate + attach the endpoints array, then append one JSON item per
 *   configured endpoint (name / endpointurl / interfacetype / qualitylevel /
 *   assignedshares).
 * WHY:  mirrors srr_emit_shares — self-contained REQUIRED-field section with its
 *   own empty-array fallback, kept out of the orchestrator.
 * HOW:  each endpoint object is attached the instant it is allocated (single
 *   root-cleanup contract); the assignedshares sub-array is the only allocation
 *   that can fail and is checked, preserving the pre-split field order.
 */
static ngx_int_t
srr_emit_endpoints(ngx_http_brix_srr_loc_conf_t *lcf, json_t *svc)
{
    json_t               *eps, *node;
    brix_srr_endpoint_t  *ep;
    ngx_uint_t            i;

    eps = json_array();
    if (eps == NULL) {
        return NGX_ERROR;
    }
    json_object_set_new(svc, "storageendpoints", eps);

    if (lcf->endpoints == NULL) {
        return NGX_OK;
    }

    ep = lcf->endpoints->elts;
    for (i = 0; i < lcf->endpoints->nelts; i++) {
        json_t *e = json_object();

        if (e == NULL) {
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
            return NGX_ERROR;
        }
        json_object_set_new(e, "assignedshares", node);
    }

    return NGX_OK;
}


/*
 * Serialise the completed JSON tree into a request-pool buffer.
 *
 * WHAT: two-pass json_dumpb (NULL sizes the payload, then dump for real) into a
 *   freshly ngx_pnalloc'd buffer; hand it back via *out / *len.
 * WHY:  the dashboard idiom, isolated so the orchestrator's tail is a single
 *   call; the buffer lives in r->pool and outlives this function.
 * HOW:  a zero size or an allocation failure returns NGX_ERROR; the caller owns
 *   the json_decref(root) either way, so this never frees the tree itself.
 */
static ngx_int_t
srr_serialise(ngx_http_request_t *r, json_t *root, u_char **out, size_t *len)
{
    size_t   needed;
    u_char  *buf;

    needed = json_dumpb(root, NULL, 0, JSON_INDENT(2));
    if (needed == 0) {
        return NGX_ERROR;
    }
    buf = ngx_pnalloc(r->pool, needed);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    json_dumpb(root, (char *) buf, needed, JSON_INDENT(2));

    *out = buf;
    *len = needed;
    return NGX_OK;
}


ngx_int_t
ngx_http_brix_srr_build_json(ngx_http_request_t *r,
    ngx_http_brix_srr_loc_conf_t *lcf, u_char **out, size_t *len)
{
    json_t     *root, *svc;
    srr_cap_t   site_cap = { 0, 0 };
    time_t      now = time(NULL);

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

    srr_emit_identity(svc, lcf, now);

    if (srr_emit_shares(r, lcf, svc, now, &site_cap) != NGX_OK) {
        json_decref(root);
        return NGX_ERROR;
    }
    if (srr_emit_capacity(svc, site_cap.total, site_cap.used) != NGX_OK) {
        json_decref(root);
        return NGX_ERROR;
    }
    if (srr_emit_endpoints(lcf, svc) != NGX_OK) {
        json_decref(root);
        return NGX_ERROR;
    }

    if (srr_serialise(r, root, out, len) != NGX_OK) {
        json_decref(root);
        return NGX_ERROR;
    }

    json_decref(root);
    return NGX_OK;
}
