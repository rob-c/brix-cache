#ifndef BRIX_SSI_CTA_SHM_H
#define BRIX_SSI_CTA_SHM_H

/*
 * cta_shm.h — the CTA request queue's shared-memory home.
 *
 * WHAT: one SHM zone holding ONE brix_cta_queue_t for the whole worker set,
 *       plus lock-taking wrappers around the pure-C queue operations.
 * WHY:  the queue used to be a per-worker `static brix_cta_queue_t *`. Every
 *       worker replayed the same journal, so every worker set next_id to the
 *       same value and then allocated from its own copy — TWO WORKERS HANDED
 *       OUT THE SAME REQUEST ID. A `query` or `cancel` for id 7 landed on
 *       whichever worker the connection happened to reach and could act on a
 *       different request than the one the client was told about. This retires
 *       the "cross-worker SHM queue is deferred" ADR in svc_cta/README.md.
 * HOW:  brix_shm_table_alloc() per INVARIANT 10 — the table is allocated FROM
 *       the slab pool (never laid over shm.addr, which nginx's SIGCHLD handler
 *       walks as an ngx_slab_pool_t) and the mutex is bound to the pool's own
 *       lock word, so a worker that dies holding it is recovered. The locking
 *       lives HERE and not in cta_queue.c, which stays pure C so that
 *       cta_queue_unittest.c keeps compiling with `gcc -Isrc` and no nginx.
 *
 * The journal fd is opened ONCE, during zone init, which runs in the master
 * BEFORE fork — so every worker inherits the same open file description and
 * its shared O_APPEND offset, and one journal serves the whole set. That is
 * also why journal_append() emits each record with a single write(2): the
 * atomicity of one append per record is what makes the sharing safe.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "cta_queue.h"

/*
 * Declare the zone. Call once from postconfiguration when ANY enabled server
 * block has `brix_ssi_service cta`. `journal` may be an empty string (no
 * restart journal). Returns NGX_OK/NGX_ERROR.
 */
ngx_int_t brix_cta_shm_configure(ngx_conf_t *cf, ngx_str_t *journal);

/*
 * The shared queue, or NULL when the zone is absent or not yet initialised.
 * A NULL return means the service is unconfigured: callers must refuse, NOT
 * fall back to a private queue — that fallback is the defect this file fixes.
 */
brix_cta_queue_t *brix_cta_shm_queue(void);

/* Locked wrappers. Each takes the zone mutex for the duration of one short
 * queue operation and never across an executor run. */
cta_req_t *brix_cta_shm_submit(const cta_request_t *r, const char *owner);

/* Signature-compatible with cta_progress_t::transition, so the executor can
 * hold this directly and take the lock once per transition rather than for the
 * length of an archive or retrieve. `q` must be brix_cta_shm_queue(). */
int        brix_cta_shm_transition(brix_cta_queue_t *q, cta_req_t *e,
                                   cta_state_t to);
int        brix_cta_shm_cancel(uint64_t id, const char *requester, int is_admin);
int        brix_cta_shm_active_count(void);

#endif /* BRIX_SSI_CTA_SHM_H */
