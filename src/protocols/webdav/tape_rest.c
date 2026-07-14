/*
 * tape_rest.c — WLCG HTTP Tape REST API router (Phase 35 / Phase 2).
 *
 * WHAT: The endpoint router + response marshalling + resolve/authz/residency
 *   helpers for the standard WLCG Tape REST surface under /api/v1/ so FTS and
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
 *   (POST body read → NGX_DONE, jansson build, send_json). The per-endpoint bodies
 *   live in tape_rest_ops.c (phase-79 file-size split); the shared seam is
 *   tape_rest_internal.h.
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
#include "tape_rest_internal.h"                /* shared helpers + endpoint decls */
#include "fs/vfs/vfs.h"                        /* brix_vfs_residency (sd_frm seam) */
#include "fs/xfer/stage_request_registry.h"
#include "core/http/http_body.h"

#include <jansson.h>
#include <openssl/rand.h>
#include <string.h>
#include "core/compat/alloc_guard.h"

#define TAPE_API_PREFIX     "/api/v1/"
#define TAPE_BODY_MAX       (1u << 20)     /* 1 MiB of request JSON           */


/* small helpers*/
brix_stage_registry_t *
tape_queue(void)
{
    return brix_stage_registry_singleton();
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

    BRIX_PNALLOC_OR_RETURN(buf, r->pool, len ? len : 1, NGX_HTTP_INTERNAL_SERVER_ERROR);
    if (len) {
        ngx_memcpy(buf, json, len);
    }

    BRIX_PCALLOC_OR_RETURN(b, r->pool, sizeof(*b), NGX_HTTP_INTERNAL_SERVER_ERROR);
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
ngx_int_t
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
ngx_int_t
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

void
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
brix_stage_cstype_t
tape_cstype_from_name(const char *name)
{
    if (name == NULL)                          { return BRIX_STAGE_CS_NONE; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "adler32") == 0)
                                               { return BRIX_STAGE_CS_ADLER32; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "md5") == 0)
                                               { return BRIX_STAGE_CS_MD5; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "crc32") == 0)
                                               { return BRIX_STAGE_CS_CRC32; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "sha1") == 0)
                                               { return BRIX_STAGE_CS_SHA1; }
    if (ngx_strcasecmp((u_char *) name, (u_char *) "sha256") == 0
        || ngx_strcasecmp((u_char *) name, (u_char *) "sha2") == 0)
                                               { return BRIX_STAGE_CS_SHA2; }
    return BRIX_STAGE_CS_NONE;
}

/* Map a stage-request status to a WLCG file state string. */
const char *
tape_state_name(brix_stage_req_status_t status)
{
    switch (status) {
    case BRIX_STAGE_REQ_QUEUED:    return "SUBMITTED";
    case BRIX_STAGE_REQ_ACTIVE:    return "STARTED";
    case BRIX_STAGE_REQ_DONE:      return "COMPLETED";
    case BRIX_STAGE_REQ_FAILED:    return "FAILED";
    case BRIX_STAGE_REQ_CANCELLED: return "CANCELLED";
    default:                         return "UNKNOWN";
    }
}

/* Resolve residency via the VFS seam (sd_frm). `abs` is a confined absolute path;
 * fills *state and *nearline (1 = a nearline/tape-backed export). */
ngx_int_t
tape_residency(ngx_http_request_t *r, const char *abs,
               brix_sd_residency_t *state, int *nearline)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    brix_vfs_ctx_t vctx;

    *nearline = 0;
    brix_vfs_ctx_init(&vctx, r->pool, r->connection->log,
        BRIX_PROTO_WEBDAV, conf->common.root_canon, conf->cache_root_canon,
        conf->common.allow_write, 0 /* is_tls */, NULL, abs);
    return brix_vfs_residency(&vctx, state, nearline);
}

/* Map the sd residency + nearline flag to the WLCG locality vocabulary. On a
 * nearline (tape) export an online object is ONLINE_AND_NEARLINE (resident AND on
 * the backend); a plain export online object is ONLINE. */
const char *
tape_locality_name(brix_sd_residency_t state, int nearline)
{
    switch (state) {
    case BRIX_SD_RES_ONLINE:
        return nearline ? "ONLINE_AND_NEARLINE" : "ONLINE";
    case BRIX_SD_RES_NEARLINE:
    case BRIX_SD_RES_OFFLINE:
        return "NEARLINE";
    case BRIX_SD_RES_LOST:
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
ngx_int_t
tape_authz_path(ngx_http_request_t *r, ngx_http_brix_webdav_loc_conf_t *conf,
                ngx_http_brix_webdav_req_ctx_t *ctx, const char *logical,
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
        && brix_identity_check_token_scope(ctx->identity, logical, need_write)
           != NGX_OK)
    {
        return NGX_HTTP_FORBIDDEN;
    }
    return NGX_OK;
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

    if (brix_http_body_read_all(r, TAPE_BODY_MAX, &body, &blen) != NGX_OK
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
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
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
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
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
        ngx_int_t rc = brix_http_read_body(r, tape_post_body_handler);
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
