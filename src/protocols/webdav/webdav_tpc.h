/*
 * webdav/webdav_tpc.h
 *
 * HTTP third-party-copy (TPC): the multi-stream cap + shared progress struct,
 * the loc-conf create/merge helpers, the curl pull/push/multi workers, the
 * 202-marker streaming entry, the COPY dispatcher, and the OAuth2/OIDC
 * credential-delegation helpers.  Split out of webdav.h so the TPC surface is
 * grouped by concern and individually reviewable.  Includes webdav.h for the
 * shared request/config types and the tpc_cred.h enums.
 */

#ifndef NGX_HTTP_BRIX_WEBDAV_TPC_H
#define NGX_HTTP_BRIX_WEBDAV_TPC_H

#include "webdav.h"

/* Max parallel streams for HTTP-TPC multi-stream pull (X-Number-Of-Streams). */
#define BRIX_TPC_MAX_STREAMS  16

/*
 * Progress counters shared between the curl background thread and the
 * nginx event-loop poll timer during 202-streaming TPC transfers.
 * Allocated from r->pool before the thread is posted; valid until
 * ngx_http_finalize_request is called.
 */
typedef struct {
    volatile ngx_atomic_t  bytes_per_stream[BRIX_TPC_MAX_STREAMS];
    volatile ngx_atomic_t  completed;  /* 1 when thread is done */
    ngx_int_t              result;     /* HTTP status; set before completed=1 */
    ngx_uint_t             n_streams;
    off_t                  total_size; /* from HEAD; -1 if unknown */
} tpc_ms_progress_t;

/* HTTP-TPC */
/* Set the TPC-related loc-conf fields to NGX_CONF_UNSET[_UINT] (called from the
 * module's create_loc_conf). */
void ngx_http_brix_webdav_tpc_create_loc_conf(
    ngx_http_brix_webdav_loc_conf_t *conf);
/* Merge the TPC-related fields, inheriting unset values from `prev` and applying
 * defaults (called from the module's merge_loc_conf). */
void ngx_http_brix_webdav_tpc_merge_loc_conf(
    ngx_http_brix_webdav_loc_conf_t *conf,
    ngx_http_brix_webdav_loc_conf_t *prev);
/* TPC header lookup, value comparison, and NUL-copy helpers.
 * Macro aliases to compat equivalents — call sites unchanged, no wrapper functions. */
#define webdav_tpc_find_header(r, name, name_len) \
    brix_http_find_header(r, name, name_len)
#define webdav_tpc_str_has_ctl(data, len) \
    brix_http_str_has_ctl(data, len)
#define webdav_tpc_header_value_equals(value, literal) \
    brix_http_header_value_equals(value, literal)

/* Copy data[len] into a fresh NUL-terminated `pool` buffer; NULL on OOM. */
static inline char *
webdav_tpc_pstrndup0(ngx_pool_t *pool, const u_char *data, size_t len)
{
    char *out = ngx_pnalloc(pool, len + 1);
    if (out != NULL) {
        ngx_memcpy(out, data, len);
        out[len] = '\0';
    }
    return out;
}
/* Gather every "TransferHeaderX-Foo: bar" request header into a fresh r->pool
 * ngx_array_t of ngx_str_t "X-Foo: bar" (NUL-terminated), capped at
 * WEBDAV_TPC_MAX_HEADERS, for forwarding by curl.  *out set on NGX_OK; 400 if a
 * name/value has control bytes or the cap is exceeded; NGX_ERROR on OOM. */
ngx_int_t webdav_tpc_collect_transfer_headers(ngx_http_request_t *r,
    ngx_array_t **out);
/* Blocking single-stream curl pull (source_url -> tmp_path); runs on a thread,
 * not the event loop.  transfer_id keys the live-transfer registry; bumps the
 * TPC success/error metric.  NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_run_curl_pull(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *source_url,
    const char *tmp_path, ngx_array_t *transfer_headers,
    uint64_t transfer_id);
/* Blocking curl push (local_path -> dest_url); thread-only, mirror of the pull
 * above.  NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_run_curl_push(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf, const char *dest_url,
    const char *local_path, ngx_array_t *transfer_headers,
    uint64_t transfer_id);
/* Post a curl pull/push to conf->common.thread_pool (the 201 non-marker path).
 * local_path/dest_path are copied into the task ctx (caller stack buffers safe to
 * reuse).  On NGX_DONE it has taken a request ref (r->main->count++) and the
 * done-handler finalises; the caller must propagate NGX_DONE.  NGX_DECLINED if no
 * thread pool (use the sync path); 503 if the transfer registry is full;
 * NGX_ERROR on alloc/post failure or bad args. */
ngx_int_t webdav_tpc_post_thread_task(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    int is_push, ngx_flag_t existed, ngx_flag_t overwrite,
    const char *url, const char *local_path, const char *dest_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams);
/* Blocking parallel-range curl_multi pull into tmp_path: HEADs for size, splits
 * into n_streams disjoint ranges each pwrite-ing in place (no merge), capped at
 * BRIX_TPC_MAX_STREAMS.  Falls back to single-stream when size is unknown or
 * n_streams <= 1.  progress may be NULL; when set, each stream atomically updates
 * bytes_per_stream[i] for the poll timer.  NGX_OK / NGX_HTTP_* on failure. */
ngx_int_t webdav_tpc_run_curl_pull_multi(ngx_log_t *log,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const char *source_url, const char *tmp_path,
    ngx_array_t *transfer_headers, ngx_uint_t n_streams,
    uint64_t transfer_id, tpc_ms_progress_t *progress);
/* 202-streaming TPC with Performance-Markers and optional multi-stream.
 * Returns NGX_DONE (202 sent, poll timer running) or NGX_DECLINED (no thread
 * pool configured; caller falls back to the 201 path). */
ngx_int_t webdav_tpc_marker_start(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_uint_t n_streams,
    const char *url, const char *tmp_path, const char *final_path,
    ngx_flag_t is_pull, ngx_flag_t overwrite, ngx_flag_t existed,
    ngx_array_t *transfer_headers, uint64_t transfer_id);
/* HTTP-TPC COPY dispatcher: routes by Source (pull, https only) vs Destination
 * (push) header, parses X-Number-Of-Streams (capped at conf->tpc_max_streams),
 * stages a pull through a temp file (atomic rename/link on success, unlink on
 * failure), and tries marker -> thread-pool -> sync tiers.  NGX_OK (201/204 sent
 * via webdav_send_no_body), an NGX_HTTP_* status for the dispatcher to finalise,
 * or NGX_DONE when an async (202 marker / thread) path self-finalises. */
ngx_int_t ngx_http_brix_webdav_tpc_handle_copy(ngx_http_request_t *r);

/* HTTP-TPC credential delegation */
/* Map a Credential-mode token value[len] to the enum; "none"/"oidc-agent"/
 * "token-exchange" recognised, else BRIX_TPC_CRED_UNKNOWN. */
brix_tpc_cred_mode_e webdav_tpc_cred_parse_mode(const char *value, size_t len);
/* Obtain a delegated bearer token for the TPC transfer via the given mode
 * (oidc-agent fetch, or RFC 8693 token-exchange of subject_token at the
 * configured token_endpoint), validating the result.  On NGX_OK *token_out is
 * filled from r->pool (NUL-terminated); bumps the tpc_cred started/success/error
 * metrics.  NGX_ERROR on misconfig, missing subject token, fetch, or validation
 * failure. */
ngx_int_t webdav_tpc_cred_obtain_token(ngx_http_request_t *r,
    brix_tpc_cred_mode_e mode, const char *source_url,
    const char *subject_token, const char *scope, ngx_str_t *token_out);
/* Static metric-name string for a tpc_cred metric index (never NULL; do not
 * free). */
const char *webdav_tpc_cred_metric_name(brix_tpc_cred_metrics_e idx);

#endif /* NGX_HTTP_BRIX_WEBDAV_TPC_H */
