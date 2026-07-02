/*
 * tape_rest.c — WLCG HTTP Tape REST API (Phase 35 / Phase 2).
 *
 * WHAT: Implements the standard WLCG Tape REST surface under /api/v1/ so FTS and
 *   gfal2 drive tape staging over davs:// against the durable stage request registry that
 *   root:// uses:
 *     POST   /api/v1/stage              submit a bulk stage request
 *     GET    /api/v1/stage/{id}         poll its status
 *     DELETE /api/v1/stage/{id}         delete the request
 *     POST   /api/v1/stage/{id}/cancel  cancel it
 *     POST   /api/v1/release[/{id}]     release disk pins (alias: /unpin)
 *     POST   /api/v1/archiveinfo        synchronous locality (alias: /fileinfo)
 *     GET    /api/v1/stage              list active requests
 *
 * WHY: This is blocker B2's HTTP face. The durable store (Phase 0) and residency
 *   (Phase 1) already exist; this unit is the endpoint router + the WLCG JSON
 *   schema marshalling on top of the stage registry + residency seam. It mirrors macaroon_endpoint.c
 *   (POST body read → NGX_DONE, jansson build, send_json).
 *
 * HOW: every wire path is resolved + confined under root_canon BEFORE any frm_*
 *   call (INVARIANT 4), and authorised per-path (storage.stage for mutating
 *   verbs, storage.read for archiveinfo) with NO partial side effects — all paths
 *   are resolved+authorised first, then the queue is mutated, so a single 403
 *   never leaves orphan records. Anonymous → 401; cert-auth writes are gated on
 *   allow_write (INVARIANT 11). JSON is built with jansson (already a dep).
 */

#include "webdav.h"
#include "tape_rest.h"
#include "fs/vfs.h"                        /* xrootd_vfs_residency (sd_frm seam) */
#include "fs/xfer/stage_request_registry.h"
#include "compat/http_body.h"
#include "compat/http_headers.h"
#include "shared/safe_size.h"   /* Phase 27 W1: overflow-checked size math */

#include <jansson.h>
#include <openssl/rand.h>
#include <string.h>
#include "compat/alloc_guard.h"

#define TAPE_PATH_MAX       4096           /* confined absolute-path buffer   */
#define TAPE_API_PREFIX     "/api/v1/"
#define TAPE_BODY_MAX       (1u << 20)     /* 1 MiB of request JSON           */
#define TAPE_MAX_FILES      4096           /* bulk request fan-out cap        */
#define TAPE_ID_LEN         33             /* 16 random bytes as hex + NUL    */


/* small helpers*/
static xrootd_stage_registry_t *
tape_queue(void)
{
    return xrootd_stage_registry_singleton();
}

/* Send a JSON body (clone of macaroon_endpoint.c send_json — kept local so we
 * never extern a static across translation units). */
static ngx_int_t
tape_send_json(ngx_http_request_t *r, ngx_int_t status, const char *json)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    u_char      *buf;
    size_t       len = json ? ngx_strlen(json) : 0;

    XROOTD_PNALLOC_OR_RETURN(buf, r->pool, len ? len : 1, NGX_HTTP_INTERNAL_SERVER_ERROR);
    if (len) {
        ngx_memcpy(buf, json, len);
    }

    XROOTD_PCALLOC_OR_RETURN(b, r->pool, sizeof(*b), NGX_HTTP_INTERNAL_SERVER_ERROR);
    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) len;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    {
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }
    return ngx_http_output_filter(r, &out);
}

/* Build a {"detail":"..."} error body at `status`. Always returns `status`. */
static ngx_int_t
tape_error(ngx_http_request_t *r, ngx_int_t status, const char *detail)
{
    json_t    *o = json_object();
    char      *s;
    ngx_int_t  rc;

    if (o == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    json_object_set_new(o, "detail", json_string(detail ? detail : ""));
    s = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    if (s == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = tape_send_json(r, status, s);
    free(s);
    return rc;                      /* NGX_OK once the body is sent (already set
                                    * r->headers_out.status for the metrics) */
}

/* Send an object body at `status`, taking ownership of `o` (decref'd here). */
static ngx_int_t
tape_send_object(ngx_http_request_t *r, ngx_int_t status, json_t *o)
{
    char      *s;
    ngx_int_t  rc;

    if (o == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    s = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    if (s == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = tape_send_json(r, status, s);
    free(s);
    return rc;                      /* NGX_OK once the body is sent */
}

static void
tape_mint_id(char *buf, size_t sz)
{
    static const char hex[] = "0123456789abcdef";
    u_char            rnd[16];
    size_t            i;

    if (sz < TAPE_ID_LEN) {
        if (sz) { buf[0] = '\0'; }
        return;
    }
    if (RAND_bytes(rnd, (int) sizeof(rnd)) != 1) {
        /* deterministic, non-crypto fallback — ids are opaque handles, not keys */
        for (i = 0; i < sizeof(rnd); i++) {
            rnd[i] = (u_char) ((ngx_pid << 3) ^ (i * 131));
        }
    }
    for (i = 0; i < sizeof(rnd); i++) {
        buf[i * 2]     = hex[rnd[i] >> 4];
        buf[i * 2 + 1] = hex[rnd[i] & 0xf];
    }
    buf[sizeof(rnd) * 2] = '\0';
}

/* Map a WLCG checksumType name to the stage-registry checksum enum (F5). */
static xrootd_stage_cstype_t
tape_cstype_from_name(const char *name)
{
    if (name == NULL)                          { return XROOTD_STAGE_CS_NONE; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "adler32") == 0)
                                               { return XROOTD_STAGE_CS_ADLER32; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "md5") == 0)
                                               { return XROOTD_STAGE_CS_MD5; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "crc32") == 0)
                                               { return XROOTD_STAGE_CS_CRC32; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "sha1") == 0)
                                               { return XROOTD_STAGE_CS_SHA1; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "sha256") == 0
        || ngx_strcasecmp((u_char *) name, (u_char *) "sha2") == 0)
                                               { return XROOTD_STAGE_CS_SHA2; }
    return XROOTD_STAGE_CS_NONE;
}

/* Map a stage-request status to a WLCG file state string. */
static const char *
tape_state_name(xrootd_stage_req_status_t status)
{
    switch (status) {
    case XROOTD_STAGE_REQ_QUEUED:    return "SUBMITTED";
    case XROOTD_STAGE_REQ_ACTIVE:    return "STARTED";
    case XROOTD_STAGE_REQ_DONE:      return "COMPLETED";
    case XROOTD_STAGE_REQ_FAILED:    return "FAILED";
    case XROOTD_STAGE_REQ_CANCELLED: return "CANCELLED";
    default:                         return "UNKNOWN";
    }
}

/* Resolve residency via the VFS seam (sd_frm). `abs` is a confined absolute path;
 * fills *state and *nearline (1 = a nearline/tape-backed export). */
static ngx_int_t
tape_residency(ngx_http_request_t *r, const char *abs,
               xrootd_sd_residency_t *state, int *nearline)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    xrootd_vfs_ctx_t vctx;

    *nearline = 0;
    xrootd_vfs_ctx_init(&vctx, r->pool, r->connection->log,
        XROOTD_PROTO_WEBDAV, conf->common.root_canon, conf->cache_root_canon,
        conf->common.allow_write, 0 /* is_tls */, NULL, abs);
    return xrootd_vfs_residency(&vctx, state, nearline);
}

/* Map the sd residency + nearline flag to the WLCG locality vocabulary. On a
 * nearline (tape) export an online object is ONLINE_AND_NEARLINE (resident AND on
 * the backend); a plain export online object is ONLINE. */
static const char *
tape_locality_name(xrootd_sd_residency_t state, int nearline)
{
    switch (state) {
    case XROOTD_SD_RES_ONLINE:
        return nearline ? "ONLINE_AND_NEARLINE" : "ONLINE";
    case XROOTD_SD_RES_NEARLINE:
    case XROOTD_SD_RES_OFFLINE:
        return "NEARLINE";
    case XROOTD_SD_RES_LOST:
        return "LOST";
    default:
        return "NONE";
    }
}

/*
 * Resolve + authorise one logical path. need_write selects storage.stage vs
 * storage.read scope and the cert-auth allow_write gate. On success fills
 * abs[abssz] with the confined absolute path and returns NGX_OK; otherwise
 * returns an NGX_HTTP_* status the caller must surface for the WHOLE request.
 */
static ngx_int_t
tape_authz_path(ngx_http_request_t *r, ngx_http_xrootd_webdav_loc_conf_t *conf,
                ngx_http_xrootd_webdav_req_ctx_t *ctx, const char *logical,
                int need_write, char *abs, size_t abssz)
{
    ngx_int_t rc;

    if (logical == NULL || logical[0] != '/') {
        return NGX_HTTP_BAD_REQUEST;
    }
    rc = webdav_resolve_destination_path(r->connection->log, "tape",
                                         conf->common.root_canon, logical,
                                         abs, abssz);
    if (rc != NGX_OK) {
        return rc;                              /* 403 confine / 404 / 409 / 400 */
    }
    /* cert/anonymous-but-verified writes require the server to allow writes */
    if (need_write && !ctx->token_auth && !conf->common.allow_write) {
        return NGX_HTTP_FORBIDDEN;
    }
    /* token principals must carry the right scope for this path (a non-token or
     * anonymous identity is allowed unconditionally — writes were already gated
     * on allow_write above). */
    if (ctx->identity != NULL
        && xrootd_identity_check_token_scope(ctx->identity, logical, need_write)
           != NGX_OK)
    {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_OK;
}


/* POST /api/v1/stage*/
static ngx_int_t
tape_stage_post(ngx_http_request_t *r, ngx_http_xrootd_webdav_loc_conf_t *conf,
                ngx_http_xrootd_webdav_req_ctx_t *ctx, json_t *root)
{
    json_t      *files, *elem, *resp, *jfiles;
    size_t       i, n;
    xrootd_stage_registry_t *q = tape_queue();
    char         id[TAPE_ID_LEN];
    char       **abs;     /* resolved paths (pass 1) */
    const char **logical;

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

    abs     = xrootd_palloc_array(r->pool, n, sizeof(*abs));
    logical = xrootd_palloc_array(r->pool, n, sizeof(*logical));
    if (abs == NULL || logical == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Pass 1: resolve + authorise EVERY path before any queue mutation, so a
     * single denial cannot leave orphan records (no partial side effects). */
    for (i = 0; i < n; i++) {
        json_t     *p;
        const char *lp;
        char       *buf;
        ngx_int_t   rc;

        elem = json_array_get(files, i);
        p = json_is_object(elem) ? json_object_get(elem, "path") : NULL;
        lp = json_is_string(p) ? json_string_value(p) : NULL;
        if (lp == NULL) {
            return tape_error(r, NGX_HTTP_BAD_REQUEST,
                              "each file needs a string \"path\"");
        }
        XROOTD_PNALLOC_OR_RETURN(buf, r->pool, TAPE_PATH_MAX, NGX_HTTP_INTERNAL_SERVER_ERROR);
        rc = tape_authz_path(r, conf, ctx, lp, 1, buf, TAPE_PATH_MAX);
        if (rc != NGX_OK) {
            return tape_error(r, rc, "path not permitted");
        }
        abs[i] = buf;
        logical[i] = lp;
    }

    /* Pass 2: enqueue. The bulk request id is opaque; Phase 0/1 tracks one lfn
     * per FRM reqid, so we use the first file's durable reqid as the externally
     * visible request id (full bulk grouping is deferred per §3.3). */
    tape_mint_id(id, sizeof(id));
    jfiles = json_array();
    for (i = 0; i < n; i++) {
        xrootd_stage_request_view_t v;
        char           reqid[XROOTD_STAGE_REQID_LEN];
        json_t        *jf = json_object();
        ngx_int_t      rc;

        ngx_memzero(&v, sizeof(v));
        v.lfn = abs[i];
        v.requester_dn = xrootd_identity_dn_cstr(ctx->identity);
        /* F5: optional per-file integrity request — the stage worker verifies the
         * recalled file against this checksum and fails the recall on mismatch. */
        {
            json_t     *jcs  = json_object_get(json_array_get(files, i),
                                               "checksum");
            json_t     *jcst = json_object_get(json_array_get(files, i),
                                               "checksumType");
            if (json_is_string(jcs)) {
                v.cs_value = json_string_value(jcs);
                v.cs_type  = tape_cstype_from_name(
                    json_is_string(jcst) ? json_string_value(jcst) : "adler32");
            }
        }
        rc = xrootd_stage_request_add(q, &v, reqid, sizeof(reqid),
                                      r->connection->log);
        if (rc == NGX_OK || rc == NGX_DECLINED) {
            if (i == 0) {
                ngx_memcpy(id, reqid, ngx_min(sizeof(reqid), sizeof(id)));
                id[sizeof(id) - 1] = '\0';
            }
            /* recall driving (former frm_stage_kick) → engine-integration step */
            json_object_set_new(jf, "path", json_string(logical[i]));
            json_object_set_new(jf, "state",
                json_string(rc == NGX_DECLINED ? "STARTED" : "SUBMITTED"));
        } else {
            json_object_set_new(jf, "path", json_string(logical[i]));
            json_object_set_new(jf, "error", json_string("could not enqueue"));
        }
        json_array_append_new(jfiles, jf);
    }

    resp = json_object();
    json_object_set_new(resp, "requestId", json_string(id));
    json_object_set_new(resp, "id", json_string(id));
    json_object_set_new(resp, "files", jfiles);

    {
        char buf[64 + TAPE_ID_LEN];
        ngx_snprintf((u_char *) buf, sizeof(buf), "%s%s%Z",
                     "/api/v1/stage/", id);
        (void) xrootd_http_set_header(r, "Location", buf, NULL);
    }
    return tape_send_object(r, NGX_HTTP_CREATED, resp);
}


/* GET /api/v1/stage/{id}*/
static ngx_int_t
tape_stage_get(ngx_http_request_t *r, const char *id)
{
    xrootd_stage_registry_t *q = tape_queue();
    xrootd_stage_request_t   rec;
    json_t       *o, *jfiles, *jf;
    xrootd_sd_residency_t res;
    int           nearline = 0;
    int           on_disk = 0;

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    if (xrootd_stage_request_get(q, id, &rec, r->connection->log) != NGX_OK) {
        return tape_error(r, NGX_HTTP_NOT_FOUND, "no such request");
    }
    if (tape_residency(r, rec.lfn, &res, &nearline) == NGX_OK) {
        on_disk = (res == XROOTD_SD_RES_ONLINE);
    }

    jf = json_object();
    json_object_set_new(jf, "path", json_string(rec.lfn));
    json_object_set_new(jf, "state", json_string(tape_state_name(rec.status)));
    json_object_set_new(jf, "onDisk", json_boolean(on_disk));
    if (rec.status == XROOTD_STAGE_REQ_FAILED) {
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
static ngx_int_t
tape_stage_list(ngx_http_request_t *r)
{
    xrootd_stage_registry_t *q = tape_queue();
    xrootd_stage_request_t   rec;
    ngx_uint_t    cursor = 0;
    json_t       *arr, *o;
    ngx_int_t     rc;

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    arr = json_array();
    while ((rc = xrootd_stage_request_list_active(q, &cursor, &rec,
                                         r->connection->log)) == NGX_OK)
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
static ngx_int_t
tape_stage_delete(ngx_http_request_t *r,
                  ngx_http_xrootd_webdav_req_ctx_t *ctx, const char *id)
{
    xrootd_stage_registry_t *q = tape_queue();

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    /* only the owning principal may delete the request (fail-open for anonymous
     * callers / owner-less records — see xrootd_stage_request_owner_check). */
    if (xrootd_stage_request_owner_check(q, id,
                                xrootd_identity_dn_cstr(ctx->identity),
                                r->connection->log) != NGX_OK)
    {
        return tape_error(r, NGX_HTTP_FORBIDDEN, "not the owner of this request");
    }
    (void) xrootd_stage_request_delete(q, id, r->connection->log); /* idempotent */
    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


/* POST /api/v1/stage/{id}/cancel*/
static ngx_int_t
tape_stage_cancel(ngx_http_request_t *r,
                  ngx_http_xrootd_webdav_req_ctx_t *ctx, const char *id)
{
    xrootd_stage_registry_t *q = tape_queue();

    if (q == NULL) {
        return tape_error(r, NGX_HTTP_SERVICE_UNAVAILABLE, "not configured");
    }
    /* only the owning principal may cancel the request. */
    if (xrootd_stage_request_owner_check(q, id,
                                xrootd_identity_dn_cstr(ctx->identity),
                                r->connection->log) != NGX_OK)
    {
        return tape_error(r, NGX_HTTP_FORBIDDEN, "not the owner of this request");
    }
    (void) xrootd_stage_request_cancel(q, id, r->connection->log); /* idempotent */
    r->headers_out.status = NGX_HTTP_NO_CONTENT;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    return ngx_http_send_header(r);
}


/* POST /api/v1/release  (alias /unpin)*/
static ngx_int_t
tape_release(ngx_http_request_t *r, ngx_http_xrootd_webdav_loc_conf_t *conf,
             ngx_http_xrootd_webdav_req_ctx_t *ctx, json_t *root)
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
    XROOTD_PNALLOC_OR_RETURN(abs, r->pool, TAPE_PATH_MAX, NGX_HTTP_INTERNAL_SERVER_ERROR);

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
            && xrootd_stage_request_pin_release(tape_queue(), abs,
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
static ngx_int_t
tape_archiveinfo(ngx_http_request_t *r,
                 ngx_http_xrootd_webdav_loc_conf_t *conf,
                 ngx_http_xrootd_webdav_req_ctx_t *ctx, json_t *root)
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
    XROOTD_PNALLOC_OR_RETURN(abs, r->pool, TAPE_PATH_MAX, NGX_HTTP_INTERNAL_SERVER_ERROR);

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
        xrootd_sd_residency_t res;
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
                json_boolean(res == XROOTD_SD_RES_ONLINE));
            json_object_set_new(e, "onTape", json_boolean(nearline
                || res == XROOTD_SD_RES_NEARLINE
                || res == XROOTD_SD_RES_OFFLINE));
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


/* routing*/
/*
 * Split the path after /api/v1/ into up to three NUL-terminated segments in a
 * caller buffer. Returns the segment count. e.g. "stage/abc/cancel" → 3.
 */
static ngx_uint_t
tape_split(ngx_http_request_t *r, char *buf, size_t bufsz, char *seg[3])
{
    size_t      plen = sizeof(TAPE_API_PREFIX) - 1;
    size_t      tail, i;
    ngx_uint_t  nseg = 0;

    seg[0] = seg[1] = seg[2] = NULL;
    if (r->uri.len <= plen) {
        return 0;
    }
    tail = r->uri.len - plen;
    if (tail >= bufsz) {
        tail = bufsz - 1;
    }
    ngx_memcpy(buf, r->uri.data + plen, tail);
    buf[tail] = '\0';

    for (i = 0; i < tail && nseg < 3; ) {
        seg[nseg++] = &buf[i];
        while (i < tail && buf[i] != '/') { i++; }
        if (i < tail) { buf[i++] = '\0'; }
    }
    /* trim a trailing empty segment from a path ending in '/' */
    while (nseg > 0 && seg[nseg - 1][0] == '\0') {
        nseg--;
    }
    return nseg;
}

/* Parse the JSON body (already read) into a root object. Caller decrefs. */
static json_t *
tape_parse_body(ngx_http_request_t *r)
{
    u_char    *body = NULL;
    size_t     blen = 0;
    json_error_t err;

    if (xrootd_http_body_read_all(r, TAPE_BODY_MAX, &body, &blen) != NGX_OK
        || body == NULL || blen == 0)
    {
        return NULL;
    }
    return json_loadb((const char *) body, blen, 0, &err);
}

/* POST dispatch (after the body has been read). */
static ngx_int_t
tape_dispatch_post(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ngx_http_xrootd_webdav_req_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    char       sbuf[TAPE_PATH_MAX];
    char      *seg[3];
    ngx_uint_t nseg;
    json_t    *root;
    ngx_int_t  rc;

    nseg = tape_split(r, sbuf, sizeof(sbuf), seg);
    if (nseg == 0) {
        return tape_error(r, NGX_HTTP_NOT_FOUND, "unknown endpoint");
    }

    /* POST /stage/{id}/cancel acts on the URL id and consumes NO request body —
     * route it before the mandatory body parse so the body-less cancel that real
     * FTS/gfal2 clients send is not rejected with 400. */
    if (ngx_strcmp(seg[0], "stage") == 0 && nseg == 3
        && ngx_strcmp(seg[2], "cancel") == 0) {
        return tape_stage_cancel(r, ctx, seg[1]);
    }

    root = tape_parse_body(r);
    if (root == NULL) {
        return tape_error(r, NGX_HTTP_BAD_REQUEST, "invalid or empty JSON body");
    }

    if (ngx_strcmp(seg[0], "stage") == 0 && nseg == 1) {
        rc = tape_stage_post(r, conf, ctx, root);
    } else if ((ngx_strcmp(seg[0], "release") == 0
                || ngx_strcmp(seg[0], "unpin") == 0)) {
        rc = tape_release(r, conf, ctx, root);
    } else if (ngx_strcmp(seg[0], "archiveinfo") == 0
               || ngx_strcmp(seg[0], "fileinfo") == 0) {
        rc = tape_archiveinfo(r, conf, ctx, root);
    } else {
        rc = tape_error(r, NGX_HTTP_NOT_FOUND, "unknown endpoint");
    }

    json_decref(root);
    return rc;
}

/* nginx body-completion handler for POST endpoints. */
static void
tape_post_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = tape_dispatch_post(r);
    webdav_metrics_finalize_request(r, rc);
}

ngx_int_t
webdav_tape_handle(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    ngx_http_xrootd_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    char       sbuf[TAPE_PATH_MAX];
    char      *seg[3];
    ngx_uint_t nseg;

    if (ctx == NULL) {
        return tape_error(r, NGX_HTTP_INTERNAL_SERVER_ERROR, "no auth context");
    }
    /* On a server that requires auth, an unauthenticated caller is rejected.
     * On an auth=none / auth=optional server, anonymous is allowed through to
     * the per-verb checks below (writes still gated on allow_write; token
     * scopes still enforced when a token is present). */
    if (!ctx->verified && conf->auth == WEBDAV_AUTH_REQUIRED) {
        return tape_error(r, NGX_HTTP_UNAUTHORIZED, "authentication required");
    }

    if (r->method == NGX_HTTP_POST) {
        ngx_int_t rc = xrootd_http_read_body(r, tape_post_body_handler);
        return (rc == NGX_DONE) ? NGX_DONE : rc;
    }

    nseg = tape_split(r, sbuf, sizeof(sbuf), seg);
    if (nseg == 0) {
        return tape_error(r, NGX_HTTP_NOT_FOUND, "unknown endpoint");
    }

    if (r->method == NGX_HTTP_GET) {
        if (ngx_strcmp(seg[0], "stage") == 0 && nseg == 2) {
            return tape_stage_get(r, seg[1]);
        }
        if (ngx_strcmp(seg[0], "stage") == 0 && nseg == 1) {
            return tape_stage_list(r);
        }
        return tape_error(r, NGX_HTTP_NOT_FOUND, "unknown endpoint");
    }

    if (r->method == NGX_HTTP_DELETE) {
        if (ngx_strcmp(seg[0], "stage") == 0 && nseg == 2) {
            return tape_stage_delete(r, ctx, seg[1]);
        }
        return tape_error(r, NGX_HTTP_NOT_FOUND, "unknown endpoint");
    }

    return tape_error(r, NGX_HTTP_NOT_ALLOWED, "method not allowed");
}
