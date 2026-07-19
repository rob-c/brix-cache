#ifndef NGX_BRIX_WEBDAV_TAPE_REST_INTERNAL_H
#define NGX_BRIX_WEBDAV_TAPE_REST_INTERNAL_H

/*
 * tape_rest_internal.h - declarations shared between the two halves of the WLCG
 * HTTP Tape REST API after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the shared request-scoped constants, the small marshalling
 *   and authorisation helpers that live in tape_rest.c, and the per-endpoint
 *   handlers that live in tape_rest_ops.c - i.e. exactly the symbols that cross the
 *   tape_rest.c / tape_rest_ops.c boundary.
 * WHY:  tape_rest.c (the router core: response marshalling, the resolve+authz +
 *   residency helpers, JSON id/state/locality mapping, and the GET/DELETE/POST URL
 *   routing) and tape_rest_ops.c (the endpoint bodies: stage submit/status/list/
 *   delete/cancel, release/unpin, archiveinfo/fileinfo) were one 865-line unit;
 *   splitting keeps each focused and under the 500-line cap. The router calls the
 *   endpoint handlers and the handlers call the shared helpers, so exactly those
 *   symbols become non-static and are declared here.
 * HOW:  Both translation units include this header; nothing here is exported beyond
 *   the WebDAV Tape REST surface.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>

#include "webdav.h"                          /* loc conf + req ctx types         */
#include "fs/vfs/vfs.h"                       /* brix_sd_residency_t              */
#include "fs/xfer/stage_request_registry.h"  /* brix_stage_* registry + enums    */

/* Confined absolute-path buffer size - used by the router (segment buffers) and by
 * every endpoint that resolves a logical path, so it is shared here. */
#define TAPE_PATH_MAX       4096

/* Externally-visible stage-request id buffer. tape_mint_id() seeds a random hex
 * placeholder, but POST /stage OVERWRITES it with the first file's DURABLE reqid
 * ("<seq>.<pid>@<host>") — which is the key DELETE/cancel look the record up by.
 * It MUST therefore be sized to the on-disk reqid width (stage_request_registry
 * SRQ_REQID_LEN = 40): sized smaller (the old 33, from the retired 16-byte-hex
 * design) a longer-hostname reqid is truncated in the response, so the client's
 * DELETE/cancel id no longer matches the stored key — the record is "not found",
 * the owner check is skipped as idempotent, and a foreign principal deletes it. */
#define TAPE_ID_LEN         40

/* ---- shared helpers implemented in tape_rest.c, called by the endpoint bodies
 *      in tape_rest_ops.c. ------------------------------------------------------ */

/* The durable stage-request registry singleton (NULL when staging is unconfigured). */
brix_stage_registry_t *tape_queue(void);

/* Build a {"detail":"..."} error body at `status`; always returns `status`. */
ngx_int_t tape_error(ngx_http_request_t *r, ngx_int_t status, const char *detail);

/* Send an object body at `status`, taking ownership of `o` (decref'd here). */
ngx_int_t tape_send_object(ngx_http_request_t *r, ngx_int_t status, json_t *o);

/* Mint an opaque request id into buf[sz] (needs sz >= TAPE_ID_LEN). */
void tape_mint_id(char *buf, size_t sz);

/* Map a WLCG checksumType name to the stage-registry checksum enum. */
brix_stage_cstype_t tape_cstype_from_name(const char *name);

/* Map a stage-request status to a WLCG file state string. */
const char *tape_state_name(brix_stage_req_status_t status);

/* Resolve residency via the VFS seam; fills *state and *nearline for a confined
 * absolute path. Returns NGX_OK / NGX_DECLINED / NGX_ERROR. */
ngx_int_t tape_residency(ngx_http_request_t *r, const char *abs,
    brix_sd_residency_t *state, int *nearline);

/* Map an sd residency + nearline flag to the WLCG locality vocabulary. */
const char *tape_locality_name(brix_sd_residency_t state, int nearline);

/* Resolve + authorise one logical path (need_write selects storage.stage vs
 * storage.read). On success fills abs[abssz] and returns NGX_OK; otherwise returns
 * the NGX_HTTP_* status the caller must surface for the WHOLE request. */
ngx_int_t tape_authz_path(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_http_brix_webdav_req_ctx_t *ctx,
    const char *logical, int need_write, char *abs, size_t abssz);

/* ---- endpoint bodies implemented in tape_rest_ops.c, dispatched from the router
 *      in tape_rest.c. ----------------------------------------------------------- */

/* POST /api/v1/stage - submit a bulk stage request. */
ngx_int_t tape_stage_post(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *ctx, json_t *root);

/* GET /api/v1/stage/{id} - poll one request's status. */
ngx_int_t tape_stage_get(ngx_http_request_t *r, const char *id);

/* GET /api/v1/stage - list active requests. */
ngx_int_t tape_stage_list(ngx_http_request_t *r);

/* DELETE /api/v1/stage/{id} - delete the request (owner-gated). */
ngx_int_t tape_stage_delete(ngx_http_request_t *r,
    ngx_http_brix_webdav_req_ctx_t *ctx, const char *id);

/* POST /api/v1/stage/{id}/cancel - cancel the request (owner-gated). */
ngx_int_t tape_stage_cancel(ngx_http_request_t *r,
    ngx_http_brix_webdav_req_ctx_t *ctx, const char *id);

/* POST /api/v1/release (alias /unpin) - release disk pins. */
ngx_int_t tape_release(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *ctx, json_t *root);

/* POST /api/v1/archiveinfo (alias /fileinfo) - synchronous locality. */
ngx_int_t tape_archiveinfo(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_req_ctx_t *ctx, json_t *root);

#endif /* NGX_BRIX_WEBDAV_TAPE_REST_INTERNAL_H */
