/*
 * tape_rest_ops.c — WLCG HTTP Tape REST API endpoint bodies (Phase 35 / Phase 2).
 *
 * WHAT: Implements the per-endpoint handlers behind the /api/v1/ Tape REST router:
 *   POST /stage (bulk submit), GET /stage/{id} (status), GET /stage (list),
 *   DELETE /stage/{id} (delete), POST /stage/{id}/cancel, POST /release[/unpin],
 *   and POST /archiveinfo[/fileinfo]. Each returns an NGX_HTTP_* status the router
 *   surfaces for the request.
 *
 * WHY: Split from tape_rest.c (phase-79) so each unit owns one concept and stays
 *   under the 500-line file cap. tape_rest.c keeps the response marshalling +
 *   resolve/authz/residency helpers + URL routing; this file holds only the
 *   endpoint bodies that consume the parsed JSON and drive the stage registry.
 *
 * HOW: The router in tape_rest.c parses the body and dispatches here by verb +
 *   URL segment. Every wire path is resolved + confined + authorised (via the
 *   shared tape_authz_path helper) BEFORE any queue mutation, so a single denial
 *   never leaves orphan records (WLCG bulk stage has no partial side effects). The
 *   shared helpers and cross-boundary declarations live in tape_rest_internal.h.
 */

#include "webdav.h"
#include "tape_rest_internal.h"
#include "fs/vfs/vfs.h"                        /* brix_sd_residency_t             */
#include "fs/xfer/stage_request_registry.h"
#include "core/http/http_headers.h"           /* brix_http_set_header (Location) */
#include "core/compat/safe_size.h"   /* Phase 27 W1: brix_palloc_array + size math */
#include "core/compat/alloc_guard.h"

#include <jansson.h>
#include <string.h>

#define TAPE_MAX_FILES      4096           /* bulk request fan-out cap        */


/*
 * Resolve + authorise EVERY stage path before any queue mutation (Pass 1).
 *
 * WHAT: For each of the n entries in the `files` array, extracts its string
 *   "path", resolves+confines+authorises it under storage.stage, and records the
 *   confined absolute path in abs[i] plus the borrowed logical pointer in
 *   logical[i]. Returns NGX_OK when the whole batch is known-good; otherwise
 *   sends the error body and returns the NGX_HTTP_* status the caller must
 *   surface for the WHOLE request.
 *
 * WHY: WLCG bulk stage must have NO partial side effects — a single denial cannot
 *   leave orphan queue records. Authorising the entire batch up front guarantees
 *   Pass 2 only enqueues once every path has passed confinement + scope checks.
 *
 * HOW:
 *   1. For each element pull object→"path" as a string; 400 if absent.
 *   2. Allocate a per-file confined-path buffer from the request pool.
 *   3. tape_authz_path() with need_write=1; on non-OK emit tape_error(rc).
 *   4. Store the confined abs path and the borrowed logical pointer.
 */
static ngx_int_t
tape_stage_resolve_all(ngx_http_request_t *r,
                       ngx_http_brix_webdav_loc_conf_t *conf,
                       ngx_http_brix_webdav_req_ctx_t *ctx,
                       json_t *files, size_t n,
                       char **abs, const char **logical)
{
    size_t i;

    for (i = 0; i < n; i++) {
        json_t     *elem = json_array_get(files, i);
        json_t     *p    = json_is_object(elem)
                               ? json_object_get(elem, "path") : NULL;
        const char *lp   = json_is_string(p) ? json_string_value(p) : NULL;
        char       *buf;
        ngx_int_t   rc;

        if (lp == NULL) {
            return tape_error(r, NGX_HTTP_BAD_REQUEST,
                              "each file needs a string \"path\"");
        }
        BRIX_PNALLOC_OR_RETURN(buf, r->pool, TAPE_PATH_MAX, NGX_HTTP_INTERNAL_SERVER_ERROR);
        rc = tape_authz_path(r, conf, ctx, lp, 1, buf, TAPE_PATH_MAX);
        if (rc != NGX_OK) {
            return tape_error(r, rc, "path not permitted");
        }
        abs[i] = buf;
        logical[i] = lp;
    }
    return NGX_OK;
}

/*
 * Apply an optional per-file WLCG checksum request onto a stage-request view.
 *
 * WHAT: Reads the "checksum"/"checksumType" fields of one file object and, when a
 *   string checksum is present, populates v->cs_value + v->cs_type (defaulting the
 *   type to adler32 when checksumType is absent). No-op when no checksum is given.
 *
 * WHY: F5 integrity — the stage worker verifies the recalled file against this
 *   checksum and fails the recall on mismatch. Isolating the jansson field
 *   plumbing keeps the enqueue step readable.
 *
 * HOW:
 *   1. Look up "checksum" and "checksumType" on the file object.
 *   2. If "checksum" is a string, copy it and map the type name via
 *      tape_cstype_from_name() (adler32 default).
 */
static void
tape_stage_apply_checksum(json_t *file_elem, brix_stage_request_view_t *v)
{
    json_t *jcs  = json_object_get(file_elem, "checksum");
    json_t *jcst = json_object_get(file_elem, "checksumType");

    if (json_is_string(jcs)) {
        v->cs_value = json_string_value(jcs);
        v->cs_type  = tape_cstype_from_name(
            json_is_string(jcst) ? json_string_value(jcst) : "adler32");
    }
}

/*
 * Enqueue one already-resolved file and build its per-file response object (Pass 2).
 *
 * WHAT: Enqueues abs[i] into the durable stage registry with the requester DN and
 *   optional integrity checksum, updates the externally visible request id from
 *   the first file's durable reqid (i == 0), and returns a newly-created JSON
 *   object describing the file's logical path plus its resulting state (or error).
 *
 * WHY: Splits the per-file enqueue body out of the batch loop so the orchestrator
 *   stays a flat sequence. The first durable reqid stands in for the opaque bulk
 *   id because Phase 0/1 tracks one lfn per FRM reqid (full bulk grouping deferred).
 *
 * HOW:
 *   1. Zero a stage view, set lfn + requester DN, apply the optional checksum.
 *   2. brix_stage_request_add(); on NGX_OK/NGX_DECLINED, seed id from reqid when
 *      i == 0 and report SUBMITTED (queued) or STARTED (already active/declined).
 *   3. On any other rc, report an "could not enqueue" error field.
 */
static json_t *
tape_stage_enqueue_one(ngx_http_request_t *r, brix_stage_registry_t *q,
                       json_t *files, size_t i, char **abs,
                       const char **logical, char *id, size_t idsz,
                       ngx_http_brix_webdav_req_ctx_t *ctx)
{
    brix_stage_request_view_t v;
    char       reqid[BRIX_STAGE_REQID_LEN];
    json_t    *jf = json_object();
    ngx_int_t  rc;

    ngx_memzero(&v, sizeof(v));
    v.lfn = abs[i];
    v.requester_dn = brix_identity_dn_cstr(ctx->identity);
    tape_stage_apply_checksum(json_array_get(files, i), &v);

    rc = brix_stage_request_add(q, &v, reqid, sizeof(reqid), r->connection->log);
    if (rc == NGX_OK || rc == NGX_DECLINED) {
        if (i == 0) {
            ngx_memcpy(id, reqid, ngx_min(sizeof(reqid), idsz));
            id[idsz - 1] = '\0';
        }
        /* recall driving (former frm_stage_kick) → engine-integration step */
        json_object_set_new(jf, "path", json_string(logical[i]));
        json_object_set_new(jf, "state",
            json_string(rc == NGX_DECLINED ? "STARTED" : "SUBMITTED"));
    } else {
        json_object_set_new(jf, "path", json_string(logical[i]));
        json_object_set_new(jf, "error", json_string("could not enqueue"));
    }
    return jf;
}

/* POST /api/v1/stage*/
ngx_int_t
tape_stage_post(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
                ngx_http_brix_webdav_req_ctx_t *ctx, json_t *root)
{
    json_t      *files, *resp, *jfiles;
    size_t       i, n;
    brix_stage_registry_t *q = tape_queue();
    char         id[TAPE_ID_LEN];
    char       **abs;     /* resolved paths (pass 1) */
    const char **logical;
    ngx_int_t    rc;

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE,
                          "tape staging is not configured");
    }
    files = json_object_get(root, "files");
    if (!json_is_array(files) || json_array_size(files) == 0) {
        return tape_error(r, NGX_HTTP_BAD_REQUEST,
                          "body must contain a non-empty \"files\" array");
    }
    n = json_array_size(files);
    if (n > TAPE_MAX_FILES) {
        return tape_error(r, NGX_HTTP_BAD_REQUEST, "too many files");
    }

    abs     = brix_palloc_array(r->pool, n, sizeof(*abs));
    logical = brix_palloc_array(r->pool, n, sizeof(*logical));
    if (abs == NULL || logical == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Pass 1: resolve + authorise EVERY path before any queue mutation, so a
     * single denial cannot leave orphan records (no partial side effects). */
    rc = tape_stage_resolve_all(r, conf, ctx, files, n, abs, logical);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Pass 2: enqueue. The bulk request id is opaque; Phase 0/1 tracks one lfn
     * per FRM reqid, so we use the first file's durable reqid as the externally
     * visible request id (full bulk grouping is deferred per §3.3). */
    tape_mint_id(id, sizeof(id));
    jfiles = json_array();
    for (i = 0; i < n; i++) {
        json_array_append_new(jfiles,
            tape_stage_enqueue_one(r, q, files, i, abs, logical,
                                   id, sizeof(id), ctx));
    }

    resp = json_object();
    json_object_set_new(resp, "requestId", json_string(id));
    json_object_set_new(resp, "id", json_string(id));
    json_object_set_new(resp, "files", jfiles);

    {
        char buf[64 + TAPE_ID_LEN];
        ngx_snprintf((u_char *) buf, sizeof(buf), "%s%s%Z",
                     "/api/v1/stage/", id);
        (void) brix_http_set_header(r, "Location", buf, NULL);
    }
    return tape_send_object(r, NGX_HTTP_CREATED, resp);
}


/* GET /api/v1/stage/{id}*/
ngx_int_t
tape_stage_get(ngx_http_request_t *r, const char *id)
{
    brix_stage_registry_t *q = tape_queue();
    brix_stage_request_t   rec;
    json_t       *o, *jfiles, *jf;
    brix_sd_residency_t res;
    int           nearline = 0;
    int           on_disk = 0;

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    if (brix_stage_request_get(q, id, &rec, r->connection->log) != NGX_OK) {
        return tape_error(r, NGX_HTTP_NOT_FOUND, "no such request");
    }
    if (tape_residency(r, rec.lfn, &res, &nearline) == NGX_OK) {
        on_disk = (res == BRIX_SD_RES_ONLINE);
    }

    jf = json_object();
    json_object_set_new(jf, "path", json_string(rec.lfn));
    json_object_set_new(jf, "state", json_string(tape_state_name(rec.status)));
    json_object_set_new(jf, "onDisk", json_boolean(on_disk));
    if (rec.status == BRIX_STAGE_REQ_FAILED) {
        json_object_set_new(jf, "error", json_string("stage failed"));
    }
    jfiles = json_array();
    json_array_append_new(jfiles, jf);

    o = json_object();
    json_object_set_new(o, "id", json_string(id));
    json_object_set_new(o, "createdAt", json_integer((json_int_t) rec.tod_added));
    json_object_set_new(o, "files", jfiles);
    return tape_send_object(r, NGX_HTTP_OK, o);
}


/* GET /api/v1/stage  (list active)*/
ngx_int_t
tape_stage_list(ngx_http_request_t *r)
{
    brix_stage_registry_t *q = tape_queue();
    brix_stage_request_t   rec;
    ngx_uint_t    cursor = 0;
    json_t       *arr, *o;

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    arr = json_array();
    while (brix_stage_request_list_active(q, &cursor, &rec,
                                         r->connection->log) == NGX_OK)
    {
        json_t *e = json_object();
        json_object_set_new(e, "id", json_string(rec.reqid));
        json_object_set_new(e, "path", json_string(rec.lfn));
        json_object_set_new(e, "state", json_string(tape_state_name(rec.status)));
        json_array_append_new(arr, e);
    }
    o = json_object();
    json_object_set_new(o, "requests", arr);
    return tape_send_object(r, NGX_HTTP_OK, o);
}


/* DELETE /api/v1/stage/{id}*/
ngx_int_t
tape_stage_delete(ngx_http_request_t *r,
                  ngx_http_brix_webdav_req_ctx_t *ctx, const char *id)
{
    brix_stage_registry_t *q = tape_queue();

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    /* only the owning principal may delete the request (fail-open for anonymous
     * callers / owner-less records — see brix_stage_request_owner_check). */
    if (brix_stage_request_owner_check(q, id,
                                brix_identity_dn_cstr(ctx->identity),
                                r->connection->log) != NGX_OK)
    {
        return tape_error(r, NGX_HTTP_FORBIDDEN, "not the owner of this request");
    }
    (void) brix_stage_request_delete(q, id, r->connection->log); /* idempotent */
    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


/* POST /api/v1/stage/{id}/cancel*/
ngx_int_t
tape_stage_cancel(ngx_http_request_t *r,
                  ngx_http_brix_webdav_req_ctx_t *ctx, const char *id)
{
    brix_stage_registry_t *q = tape_queue();

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    /* only the owning principal may cancel the request. */
    if (brix_stage_request_owner_check(q, id,
                                brix_identity_dn_cstr(ctx->identity),
                                r->connection->log) != NGX_OK)
    {
        return tape_error(r, NGX_HTTP_FORBIDDEN, "not the owner of this request");
    }
    (void) brix_stage_request_cancel(q, id, r->connection->log); /* idempotent */
    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


/* POST /api/v1/release  (alias /unpin)*/
ngx_int_t
tape_release(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
             ngx_http_brix_webdav_req_ctx_t *ctx, json_t *root)
{
    json_t   *paths;
    size_t    i, n;
    json_t   *unpinned, *not_unpinned, *o;
    char     *abs;

    paths = json_object_get(root, "paths");
    if (!json_is_array(paths)) {
        return tape_error(r, NGX_HTTP_BAD_REQUEST,
                          "body must contain a \"paths\" array");
    }
    n = json_array_size(paths);
    BRIX_PNALLOC_OR_RETURN(abs, r->pool, TAPE_PATH_MAX, NGX_HTTP_INTERNAL_SERVER_ERROR);

    /* authorise all paths first (no partial side effects) */
    for (i = 0; i < n; i++) {
        json_t     *p = json_array_get(paths, i);
        const char *lp = json_is_string(p) ? json_string_value(p) : NULL;
        ngx_int_t   rc;
        if (lp == NULL) {
            return tape_error(r, NGX_HTTP_BAD_REQUEST, "path must be a string");
        }
        rc = tape_authz_path(r, conf, ctx, lp, 1, abs, TAPE_PATH_MAX);
        if (rc != NGX_OK) {
            return tape_error(r, rc, "path not permitted");
        }
    }

    unpinned = json_array();
    not_unpinned = json_array();
    for (i = 0; i < n; i++) {
        const char *lp = json_string_value(json_array_get(paths, i));
        if (tape_authz_path(r, conf, ctx, lp, 1, abs,
                            TAPE_PATH_MAX) == NGX_OK
            && brix_stage_request_pin_release(tape_queue(), abs,
                                                r->connection->log) == NGX_OK)
        {
            json_array_append_new(unpinned, json_string(lp));
        } else {
            json_array_append_new(not_unpinned, json_string(lp));
        }
    }
    o = json_object();
    json_object_set_new(o, "unpinnedFiles", unpinned);
    json_object_set_new(o, "nonUnpinnedFiles", not_unpinned);
    return tape_send_object(r, NGX_HTTP_OK, o);
}


/* POST /api/v1/archiveinfo  (alias /fileinfo)*/
ngx_int_t
tape_archiveinfo(ngx_http_request_t *r,
                 ngx_http_brix_webdav_loc_conf_t *conf,
                 ngx_http_brix_webdav_req_ctx_t *ctx, json_t *root)
{
    json_t *paths, *arr;
    size_t  i, n;
    char   *abs;

    paths = json_object_get(root, "paths");
    if (!json_is_array(paths) || json_array_size(paths) == 0) {
        return tape_error(r, NGX_HTTP_BAD_REQUEST,
                          "body must contain a non-empty \"paths\" array");
    }
    n = json_array_size(paths);
    BRIX_PNALLOC_OR_RETURN(abs, r->pool, TAPE_PATH_MAX, NGX_HTTP_INTERNAL_SERVER_ERROR);

    /* read scope for all paths first (no partial disclosure on a later 403) */
    for (i = 0; i < n; i++) {
        json_t     *p = json_array_get(paths, i);
        const char *lp = json_is_string(p) ? json_string_value(p) : NULL;
        ngx_int_t   rc;
        if (lp == NULL) {
            return tape_error(r, NGX_HTTP_BAD_REQUEST, "path must be a string");
        }
        rc = tape_authz_path(r, conf, ctx, lp, 0, abs, TAPE_PATH_MAX);
        if (rc != NGX_OK) {
            return tape_error(r, rc, "path not permitted");
        }
    }

    arr = json_array();
    for (i = 0; i < n; i++) {
        const char     *lp = json_string_value(json_array_get(paths, i));
        json_t         *e = json_object();
        brix_sd_residency_t res;
        int             nearline = 0;
        ngx_int_t       rc;

        json_object_set_new(e, "path", json_string(lp));
        if (tape_authz_path(r, conf, ctx, lp, 0, abs,
                            TAPE_PATH_MAX) != NGX_OK)
        {
            json_object_set_new(e, "error", json_string("denied"));
            json_array_append_new(arr, e);
            continue;
        }
        rc = tape_residency(r, abs, &res, &nearline);
        if (rc == NGX_DECLINED || rc == NGX_ERROR) {
            json_object_set_new(e, "exists", json_false());
            json_object_set_new(e, "locality", json_string("NONE"));
        } else {
            const char *loc = tape_locality_name(res, nearline);
            json_object_set_new(e, "exists", json_true());
            json_object_set_new(e, "onDisk",
                json_boolean(res == BRIX_SD_RES_ONLINE));
            json_object_set_new(e, "onTape", json_boolean(nearline
                || res == BRIX_SD_RES_NEARLINE
                || res == BRIX_SD_RES_OFFLINE));
            json_object_set_new(e, "locality", json_string(loc));
        }
        json_array_append_new(arr, e);
    }
    {
        json_t *o = json_object();
        json_object_set_new(o, "files", arr);
        return tape_send_object(r, NGX_HTTP_OK, o);
    }
}
