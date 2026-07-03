/*
 * async_job.c — minimal async job lifecycle helpers.
 *
 * See async_job.h for the public API.
 *
 * WHAT: Three thin functions that manage the finalized flag and dispatch the
 *       cleanup callback exactly once.
 * WHY:  Double-free and double-finalize bugs in background job teardown paths
 *       (TPC threads, PUT body callbacks, Qckscan) share the same root cause:
 *       cleanup logic is not idempotent.  Centralising the once-run guard
 *       prevents diverging fixes across protocol surfaces.
 * HOW:  brix_async_job_cleanup_once() checks and sets job->finalized under
 *       no lock — callers must ensure the function is not called concurrently.
 *       The nginx model (main-thread completion callbacks) naturally provides
 *       this guarantee for HTTP and stream request paths.
 */

#include "async_job.h"

void
brix_async_job_init(brix_async_job_t *job, ngx_log_t *log, void *owner)
{
    ngx_memzero(job, sizeof(*job));
    job->log   = log;
    job->owner = owner;
}

void
brix_async_job_set_cleanup(brix_async_job_t *job,
    brix_job_cleanup_pt cleanup, void *data)
{
    job->cleanup      = cleanup;
    job->cleanup_data = data;
}

void
brix_async_job_cleanup_once(brix_async_job_t *job)
{
    if (job->finalized) {
        return;
    }

    job->finalized = 1;

    if (job->cleanup != NULL) {
        job->cleanup(job->cleanup_data);
    }
}
