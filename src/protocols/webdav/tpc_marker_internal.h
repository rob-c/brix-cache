/*
 * tpc_marker_internal.h — shared state and helper declarations for the
 * WebDAV 202-streaming Performance-Marker path.
 *
 * Split out of tpc_marker.c (mechanical file-size split): the marker/progress
 * cluster lives in tpc_marker.c while the transfer-thread + start/setup cluster
 * lives in tpc_marker_start.c.  This header carries the two state structs, the
 * poll interval, and the handful of helpers that are defined in one translation
 * unit but referenced from the other.  No behaviour change.
 */
#ifndef BRIX_TPC_MARKER_INTERNAL_H
#define BRIX_TPC_MARKER_INTERNAL_H

#include "webdav.h"

#include <time.h>

/* Poll the transfer thread status every 200 ms. */
#define TPC_MARKER_POLL_MSEC  200u


/*
 * Event-loop side state for a 202-streaming TPC transfer.
 * Allocated from r->pool; accessed only from the nginx event loop thread.
 */
typedef struct {
    ngx_http_request_t  *r;
    tpc_ms_progress_t   *progress;         /* shared with transfer thread */
    ngx_event_t          timer;
    time_t               last_marker_time;
    ngx_uint_t           marker_interval_secs;
    char                 tmp_path[WEBDAV_MAX_PATH];   /* pull: in-progress file */
    char                 final_path[WEBDAV_MAX_PATH]; /* pull: commit target */
    const char          *root_canon;
    ngx_flag_t           overwrite;
    ngx_flag_t           existed;
    ngx_flag_t           is_pull;
    off_t                push_file_size;   /* push: local file size for final marker */
    uint64_t             transfer_id;
} tpc_marker_ctx_t;

/*
 * Thread task context — carries everything the transfer thread needs.
 * Allocated from r->pool before the task is posted; the thread only reads it.
 */
typedef struct {
    tpc_marker_ctx_t                  *marker_ctx;
    ngx_log_t                         *log;
    ngx_http_brix_webdav_loc_conf_t *conf;
    int                                is_push;
    char                               url[4096];
    char                               local_path[WEBDAV_MAX_PATH];
    ngx_array_t                       *transfer_headers;
    const char                        *user_cert; /* per-user pull-leg cert (r->pool, or NULL) */
    const char                        *user_key;  /* per-user pull-leg key  (r->pool, or NULL) */
} tpc_marker_thread_ctx_t;


/*
 * Cross-file helpers: defined in tpc_marker.c, referenced from
 * tpc_marker_start.c.  (Everything else stays file-static.)
 */
void tpc_marker_send_all(ngx_http_request_t *r, time_t ts,
    tpc_marker_ctx_t *ctx);
void tpc_marker_poll(ngx_event_t *ev);
void tpc_marker_thread_done(ngx_event_t *ev);
void tpc_marker_cleanup(void *data);

#endif /* BRIX_TPC_MARKER_INTERNAL_H */
