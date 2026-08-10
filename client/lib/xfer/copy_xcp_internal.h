/*
 * copy_xcp_internal.h — private split contract of the extreme-copy engine.
 *
 * WHAT: One concept: the shared engine/worker state the two phase-100 xcp TUs
 *       exchange — copy_xcp_sources.c builds the replica list into worker
 *       slots; copy_xcp.c runs the block-stealing engine over them.
 * WHY:  copy_xcp.c alone crossed the 600-line file gate; the replica-list
 *       policy (mirrors / locate / duplication) is a separable concern with
 *       its own doc surface, so it owns the sibling TU.
 * HOW:  Both TUs include this after copy_internal.h (which supplies
 *       download_job_t, brix_* types and stdatomic.h).
 *
 * Requires: copy_internal.h before inclusion. Not a public API: include only
 * from client/lib/xfer/.
 */
#pragma once

#define XRDC_XCP_MAX_SRCS   16
#define XRDC_XCP_URL_MAX    2560          /* scheme + host + ":port" + path    */
#define XRDC_XCP_BLOCK_MIN  (64u * 1024u)
#define XRDC_XCP_BLOCK_MAX  (64u * 1024u * 1024u)

/* Join gate: block claiming starts when every source has RESOLVED its open
 * attempt (succeeded or failed), so a fast-opening source cannot drain the
 * table before a slower sibling ever gets a claim.  The grace cap bounds the
 * wait when a mirror black-holes (SYN drop / tarpit): after this many
 * milliseconds the opened workers proceed without the stragglers. */
#define XRDC_XCP_JOIN_GRACE_MS  1000

/* Per-block lifecycle: claimed exactly once, stolen at most once more. */
#define XCP_TODO 0u
#define XCP_BUSY 1u
#define XCP_DONE 2u
#define XCP_RESERVED 3u

/* Shared engine state — read-mostly after setup; the atomics coordinate. */
typedef struct {
    brix_vfs_file        *vf;         /* dest temp; disjoint pwrites          */
    int64_t               size;
    size_t                block;      /* block size in bytes                  */
    size_t                nblocks;
    atomic_uchar         *state;      /* XCP_TODO/BUSY/DONE per block         */
    atomic_uchar         *stealer;    /* 1 = a stealer already races this one */
    atomic_ullong         done_bytes; /* progress feed (coordinator reports)  */
    atomic_uint           live;       /* workers still running                */
    atomic_uint           resolved;   /* sources whose open attempt finished  */
    unsigned              nworkers;   /* spawn width (join-gate target)       */
    atomic_uint           steals;     /* stolen-block fetches (observability) */
    atomic_int            have_err;   /* first dead worker claims this        */
    brix_status           first_err;
    const brix_opts      *co;         /* connection options (cred store)      */
} xcp_shared_t;

typedef struct {
    xcp_shared_t *sh;
    char          url[XRDC_XCP_URL_MAX];
    unsigned      blocks_done;        /* per-source block count (debug line)  */
    unsigned      claim_hint;         /* rotating scan start (spreads workers) */
    size_t        initial_idx;        /* startup block reserved for this worker */
    int           initial_reserved;   /* reservation still belongs to worker */
    int           rc;
    brix_status   st;
} xcp_worker_t;

/* copy_xcp_sources.c — replica-list policy. */
size_t xcp_block_size(void);
size_t xcp_build_sources(const download_job_t *job, xcp_worker_t *w,
                         size_t want);
