#ifndef XROOTD_ASYNC_JOB_H
#define XROOTD_ASYNC_JOB_H

#include <ngx_config.h>
#include <ngx_core.h>

/*
 * async_job.h — minimal async job lifecycle helpers.
 *
 * Several features (WebDAV HTTP-TPC, S3 PUT, native read/write AIO, Qckscan)
 * run work outside the main request path.  They all repeat the same lifecycle
 * mechanics: allocate per-job state, register cleanup, finalize metrics exactly
 * once, and abort staged temp files on failure.
 *
 * This is deliberately small.  It provides:
 *   xrootd_async_job_t  — per-job lifecycle state
 *   xrootd_async_job_init()        — zero and link the job to its owner
 *   xrootd_async_job_set_cleanup() — register a cleanup callback
 *   xrootd_async_job_cleanup_once() — idempotent cleanup (safe to call twice)
 *
 * Each protocol surface wraps the job in its own struct; this helper only
 * manages the lifecycle, not the I/O or the wire response.
 */

typedef void (*xrootd_job_cleanup_pt)(void *data);

/*
 * xrootd_async_job_t — lifecycle state for a single background operation.
 *
 *   log          logger for cleanup-path messages
 *   owner        opaque pointer to the owning request/session context
 *   finalized    non-zero after xrootd_async_job_cleanup_once() runs
 *   cleanup      callback invoked exactly once on job completion or abort
 *   cleanup_data opaque argument forwarded to cleanup
 */
typedef struct {
    ngx_log_t             *log;
    void                  *owner;
    ngx_uint_t             finalized;
    xrootd_job_cleanup_pt  cleanup;
    void                  *cleanup_data;
} xrootd_async_job_t;

/*
 * xrootd_async_job_init — initialise a job struct.
 *
 * Zeroes all fields, then sets log and owner.  cleanup and cleanup_data
 * remain NULL until set via xrootd_async_job_set_cleanup().
 */
void xrootd_async_job_init(xrootd_async_job_t *job, ngx_log_t *log,
    void *owner);

/*
 * xrootd_async_job_set_cleanup — register a cleanup callback.
 *
 * Can be called multiple times; each call replaces the previous registration.
 * Must be called before the job is dispatched to a background thread.
 */
void xrootd_async_job_set_cleanup(xrootd_async_job_t *job,
    xrootd_job_cleanup_pt cleanup, void *data);

/*
 * xrootd_async_job_cleanup_once — run the cleanup callback exactly once.
 *
 * Sets job->finalized = 1 before invoking the callback so that concurrent
 * or repeated calls are safe.  Idempotent: a second call is a no-op.
 * If no cleanup was registered, only marks the job finalized.
 */
void xrootd_async_job_cleanup_once(xrootd_async_job_t *job);

#endif /* XROOTD_ASYNC_JOB_H */
