/* fill_retry.h — upstream-outcome classification + deadline'd backoff for
 * never-drop cache fills (phase-68 T20, convention #7).
 *
 * WHAT: classifies one fill attempt's outcome (retry vs definitive) and
 *       sleeps the jittered exponential backoff between attempts, bounded by
 *       the client-hold deadline while a client is parked on the fill and by
 *       the detached-fill max-life once every client has gone.
 * WHY:  a CVMFS client that sees connection errors or fast 5xx storms marks
 *       its proxy failed and escalates (next proxy group, then DIRECT) — the
 *       cache must absorb origin trouble, not re-emit it.
 * HOW:  pure C besides ngx_msec_t; runs on fill worker threads (sleeping
 *       there is correct — blocking I/O already lives on these threads).
 *       The waiter count is the owning fill's atomic, written by the event
 *       loop as clients attach/detach.
 */
#ifndef BRIX_CACHE_FILL_RETRY_H
#define BRIX_CACHE_FILL_RETRY_H

#include <ngx_core.h>

#include <stdatomic.h>

typedef enum {
    BRIX_FILL_OK = 0,
    BRIX_FILL_RETRY,        /* transient: backoff, retry the ranked walk   */
    BRIX_FILL_DEFINITIVE    /* 404/403: the origin's answer — never retry  */
} brix_fill_class_e;

typedef struct {
    ngx_msec_t    backoff_ms;     /* next delay, starts 250, caps 8000      */
    time_t        start;          /* first-attempt wall clock               */
    time_t        client_hold;    /* conf: brix_cvmfs_client_hold         */
    time_t        max_life;       /* conf: brix_cvmfs_fill_max_life       */
    _Atomic int  *waiters;        /* the owning fill's waiter count         */
    unsigned      verify_budget;  /* MISMATCH retries left (≈ n endpoints)  */
} brix_fill_retry_t;

void brix_fill_retry_init(brix_fill_retry_t *rs, time_t client_hold,
    time_t max_life, _Atomic int *waiters, unsigned n_endpoints);

/* Classify one attempt: fill_rc is the fill's NGX_* result, err its errno.
 * ENOENT/ENOTDIR/EACCES/EPERM are the origin's definitive answers; EBADMSG
 * is a digest MISMATCH (retried while verify_budget lasts — corruption is
 * often path-local); everything else transient. */
brix_fill_class_e brix_fill_classify(ngx_int_t fill_rc, int err,
    brix_fill_retry_t *rs);

/* 1 = slept the backoff, try again; 0 = deadline passed, give up. The
 * deadline is client_hold while >=1 waiter is attached, max_life once
 * detached; zero-configured holds (non-CVMFS exports) fail on the first
 * call — single-pass, the pre-phase-68 semantics. */
int  brix_fill_retry_wait(brix_fill_retry_t *rs);

#endif /* BRIX_CACHE_FILL_RETRY_H */
