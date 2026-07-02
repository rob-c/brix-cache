#ifndef XROOTD_SSI_CTA_QUEUE_H
#define XROOTD_SSI_CTA_QUEUE_H

/*
 * cta_queue.h — CTA request-queue state machine.
 *
 * WHAT: a per-worker registry of archive/retrieve/cancel/query requests with a
 *       lifecycle state machine and an owner/admin-gated cancel.
 * WHY:  the flagship CTA SSI service tracks each request's progress; `query`
 *       lists the queue and `cancel` aborts a prior request.
 * HOW:  a fixed table allocated once per worker (long-lived, so malloc — not a
 *       connection pool). Transitions are validated against a table, never an
 *       ad-hoc branch ladder. Pure C, standalone-testable.
 */

#include "cta_pb.h"

#define CTA_QUEUE_MAX 256

typedef enum {
    CTA_ST_SUBMITTED,
    CTA_ST_QUEUED,
    CTA_ST_ACTIVE,
    CTA_ST_COMPLETE,
    CTA_ST_FAILED,
    CTA_ST_CANCELED
} cta_state_t;

typedef struct {
    cta_request_t req;
    cta_state_t   state;
    char          owner[64];
    uint64_t      id;
    int           in_use;
    void         *queue;   /* owning queue (for journaling transitions); opaque */
} cta_req_t;

typedef struct {
    cta_req_t slots[CTA_QUEUE_MAX];
    uint64_t  next_id;
    void     *journal;   /* open FILE* for append, or NULL (opaque) */
} xrootd_cta_queue_t;

/* Allocate a queue (malloc; free with cta_queue_destroy). NULL on OOM. */
xrootd_cta_queue_t *cta_queue_create(void);
void cta_queue_destroy(xrootd_cta_queue_t *q);

/* Submit a request; records it as CTA_ST_SUBMITTED and assigns an id. Returns the
 * entry, or NULL if the queue is full. */
cta_req_t *cta_queue_submit(xrootd_cta_queue_t *q, const cta_request_t *r,
                            const char *owner);

/* Find an entry by id, or NULL. */
cta_req_t *cta_queue_find(xrootd_cta_queue_t *q, uint64_t id);

/* Attempt a state transition. Returns 0 if legal (state updated), -1 otherwise. */
int cta_queue_transition(cta_req_t *e, cta_state_t to);

/* Cancel the entry `id` on behalf of `requester`. Returns 0 on success,
 * CTA_QUEUE_EACCES if requester is neither owner nor admin, CTA_QUEUE_ENOENT if
 * the id is unknown, or -1 if the entry cannot be cancelled (terminal state). */
#define CTA_QUEUE_EACCES (-13)   /* mirrors EACCES */
#define CTA_QUEUE_ENOENT (-2)    /* mirrors ENOENT */
int cta_queue_cancel(xrootd_cta_queue_t *q, uint64_t id, const char *requester,
                     int is_admin);

/* Count entries currently in a non-terminal state (for `query` summaries). */
int cta_queue_active_count(const xrootd_cta_queue_t *q);

/*
 * Open a journal at `path` for restart recovery: replay any existing records into
 * the queue, then keep the file open so subsequent submit/transition calls append
 * to it. Returns 0 on success, -1 on error. Idempotent records (latest state per
 * id wins on replay). Mirrors the frm/ journal style; per-worker only.
 */
int cta_queue_open_journal(xrootd_cta_queue_t *q, const char *path);

#endif /* XROOTD_SSI_CTA_QUEUE_H */
