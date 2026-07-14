/*
 * tpc_internal_split.h — cross-file declarations shared between the four
 * translation units of the WebDAV HTTP-TPC COPY handler after the phase-79
 * file-size split.
 *
 * WHAT: Publishes the pull-context struct and the small set of file-local helpers
 *       that are called across the tpc.c / tpc_copy.c / tpc_push.c / tpc_pull.c
 *       boundaries: the shared request helpers (identity, session-xfer note,
 *       authorize, registry add, subject-token extract, bearer-header append)
 *       that stay in tpc.c; the COPY request parsing/credential helpers in
 *       tpc_copy.c; the push entry in tpc_push.c; and the pull prepare/accounting/
 *       execute entries in tpc_pull.c.
 *
 * WHY:  tpc.c was one 1324-line file — far over the 500-line cap. It is split by
 *       concept into the shared helpers + COPY dispatcher (stays in tpc.c), the
 *       COPY request parsing + OAuth2/OIDC credential + user-proxy helpers
 *       (tpc_copy.c), the push handler (tpc_push.c), and the staged pull
 *       execution — target prepare, the marker/thread/sync tiers, commit and
 *       success finalisation (tpc_pull.c). Each file reaches the others only
 *       through the entry points declared here, so exactly those helpers become
 *       non-static. Nothing here is exported beyond the WebDAV TPC module — the
 *       public COPY entry remains ngx_http_brix_webdav_tpc_handle_copy in
 *       webdav_tpc.h.
 *
 * HOW:  All four translation units include this header (in addition to webdav.h
 *       and webdav_tpc.h). No behaviour changes: the split only relocates the
 *       same functions and un-statics the ones called across the new boundary.
 *
 * Requires: webdav.h (request/config types), core/compat/staged_file.h
 *           (brix_staged_file_t), <sys/stat.h> (struct stat) before inclusion.
 */
#ifndef NGX_HTTP_BRIX_WEBDAV_TPC_INTERNAL_SPLIT_H
#define NGX_HTTP_BRIX_WEBDAV_TPC_INTERNAL_SPLIT_H

#include "webdav.h"
#include "core/compat/staged_file.h"

#include <sys/stat.h>

/*
 * WHAT: Bundle of the shared state threaded through the file-local HTTP-TPC pull
 *       exec helpers (target preparation, the three transfer tiers, commit and
 *       success finalisation).
 * WHY:  Each pull helper otherwise repeated the same long positional parameter
 *       list (request, config, source URL, staged temp file, transfer headers,
 *       stream count and the overwrite/existed flags). Collecting them into one
 *       stack-local context keeps every helper at =5 params and makes the shared
 *       pull state explicit without any global state.
 * HOW:  Zero-initialised with ngx_memzero by ngx_http_brix_webdav_tpc_handle_copy,
 *       populated once with the exact values previously passed positionally, then
 *       handed to each helper by pointer. `path`/`path_len`/`sb`/`staged` alias
 *       the caller's own stack storage (unchanged addresses); `transfer_id` is
 *       produced by the sync tier and consumed by commit/finish. Field values and
 *       read order are identical, so the pull semantics (probe, authorize, staged
 *       open, marker/thread/sync tiers, link-vs-rename commit, registry/dashboard
 *       ordering) are unchanged.
 */
typedef struct {
    ngx_http_request_t              *r;             /* current request */
    ngx_http_brix_webdav_loc_conf_t *conf;          /* location config */
    const char                      *source_url;    /* remote https source */
    char                            *path;          /* confined local target path */
    size_t                           path_len;      /* capacity of `path` */
    struct stat                     *sb;            /* target stat (existence/size) */
    ngx_array_t                     *transfer_headers; /* outbound curl headers */
    brix_staged_file_t              *staged;        /* atomic-commit temp file */
    const char                      *user_cert;     /* per-user pull-leg cert (or NULL) */
    const char                      *user_key;      /* per-user pull-leg key  (or NULL) */
    uint64_t                         transfer_id;   /* registry id (sync tier) */
    ngx_uint_t                       n_streams;     /* negotiated parallel streams */
    ngx_flag_t                       overwrite;     /* Overwrite: T/F policy */
    ngx_flag_t                       existed;       /* target pre-existed */
} webdav_tpc_pull_ctx_t;

/* ---- shared request helpers (defined in tpc.c) -------------------------- */

/* Display identity for the live-transfer dashboard: the authenticated DN, or
 * "anonymous" when the request carried no usable identity. */
const char *webdav_dashboard_identity(ngx_http_request_t *r);

/* Fold a completed client-side COPY byte count into the request's session-xfer
 * accumulator (no-op when no session transfer was started). */
void webdav_tpc_note_client_copy_xfer(ngx_http_request_t *r, off_t bytes,
    int64_t expected);

/* Access-control gate before any data movement: src_path is the read scope,
 * dst_path the write scope (NULL for a push). NGX_OK if permitted, else
 * NGX_HTTP_FORBIDDEN (and bumps the bad-request metric). */
ngx_int_t webdav_tpc_authorize(ngx_http_request_t *r, const ngx_str_t *src_path,
    const ngx_str_t *dst_path);

/* Register a new in-flight transfer in the cross-process TPC registry; returns a
 * non-zero transfer id, or 0 when the registry is full (caller maps to 503). */
uint64_t webdav_tpc_register_transfer(ngx_http_request_t *r,
    ngx_uint_t direction, const char *src, const char *dst, off_t bytes_total);

/* Copy the Authorization: Bearer token from `auth_hdr` (NUL-terminated, into the
 * request pool) as the OAuth2 token-exchange subject token; *subject_token stays
 * NULL for a missing/non-bearer header. NGX_OK / NGX_ERROR (OOM). */
ngx_int_t webdav_tpc_extract_subject_token(ngx_http_request_t *r,
    ngx_table_elt_t *auth_hdr, const char **subject_token);

/* Append "Authorization: Bearer <delegated_token>" to `headers` (from r->pool,
 * NUL-terminated). NGX_OK / NGX_HTTP_INTERNAL_SERVER_ERROR on OOM. */
ngx_int_t webdav_tpc_add_bearer_header(ngx_http_request_t *r,
    ngx_array_t *headers, ngx_str_t *delegated_token);

/* ---- COPY request parsing + credential helpers (defined in tpc_copy.c) --- */

/* Enforce the pull-xor-push COPY contract: exactly one of Source/Destination
 * must be present. NGX_OK, or NGX_HTTP_BAD_REQUEST (bad-request metric bumped). */
ngx_int_t webdav_tpc_validate_copy_headers(ngx_table_elt_t *source_hdr,
    ngx_table_elt_t *dest_hdr);

/* Parse X-Number-Of-Streams (default 1), capped at conf->tpc_max_streams. */
ngx_uint_t webdav_tpc_parse_stream_count(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf);

/* Validate + copy the Source header (https only, no control bytes) into
 * *source_url (r->pool). NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_source_url(ngx_http_request_t *r,
    ngx_table_elt_t *source_hdr, char **source_url);

/* Parse the Overwrite header into *overwrite (default 1; T/F recognised).
 * NGX_OK / NGX_HTTP_BAD_REQUEST on an unrecognised value. */
ngx_int_t webdav_tpc_parse_overwrite(ngx_http_request_t *r,
    ngx_flag_t *overwrite);

/* OAuth2/OIDC credential delegation for a pull: parse the Credential header and,
 * unless absent/"none", obtain a delegated token for source_url and inject it as
 * an Authorization: Bearer transfer header. NGX_OK to continue, or an NGX_HTTP_*
 * status on parse/obtain/alloc failure. */
ngx_int_t webdav_tpc_apply_credential_delegation(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *source_url,
    ngx_array_t *transfer_headers);

/* Opportunistic default: when credential forwarding is on and no Authorization
 * transfer header is present, append the requesting user's own captured bearer
 * token. NGX_OK (never a denial); NGX_HTTP_* only on OOM. */
ngx_int_t webdav_tpc_forward_user_bearer(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_array_t *transfer_headers);

/* Resolve the requesting user's per-user pull-leg x509 proxy into
 * pl->user_cert / pl->user_key (both NULL when none is available, downgrading to
 * the service cert). NGX_OK, or NGX_HTTP_INTERNAL_SERVER_ERROR when an explicitly
 * delegated proxy could not be materialised (up.deny). */
ngx_int_t webdav_tpc_apply_user_proxy(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, webdav_tpc_pull_ctx_t *pl);

/* ---- push handler (defined in tpc_push.c) ------------------------------- */

/* HTTP-TPC push: read the local file named by the request URI and PUT it to the
 * remote HTTPS Destination, applying OAuth2/OIDC credential delegation. Prefers
 * the thread pool, falling back to a synchronous curl push. NGX_OK (201 sent),
 * an NGX_HTTP_* status, or NGX_DONE for the async path. */
ngx_int_t webdav_tpc_handle_push(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_table_elt_t *dest_hdr);

/* ---- staged pull execution (defined in tpc_pull.c) ---------------------- */

/* Resolve/confine the target path, probe for an existing target (enforcing the
 * dir/overwrite rules), authorize the pull, and open the atomic-commit staged
 * temp file. NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_prepare_pull_target(webdav_tpc_pull_ctx_t *pl);

/* Emit the dashboard start record, the remote endpoint, and the pull-started
 * metrics for a prepared pull. */
void webdav_tpc_pull_start_accounting(ngx_http_request_t *r, const char *path,
    const char *source_url);

/* Run the prepared pull to completion across the marker/thread/sync tiers, then
 * commit the staged temp file and finalise. Returns the terminal NGX_HTTP_* /
 * NGX_OK / NGX_DONE status from whichever tier or stage produced it. */
ngx_int_t webdav_tpc_pull_execute(webdav_tpc_pull_ctx_t *pl);

#endif /* NGX_HTTP_BRIX_WEBDAV_TPC_INTERNAL_SPLIT_H */
