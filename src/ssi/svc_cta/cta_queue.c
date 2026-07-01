/*
 * cta_queue.c — CTA request-queue state machine. See cta_queue.h.
 */

#include "cta_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Append one entry's current state to the journal (tab-delimited record). */
static void
journal_append(xrootd_cta_queue_t *q, const cta_req_t *e)
{
    FILE *f = q->journal;

    if (f == NULL) {
        return;
    }
    fprintf(f, "%llu\t%d\t%d\t%s\t%s\n",
            (unsigned long long) e->id, (int) e->req.op, (int) e->state,
            e->owner, e->req.path);
    fflush(f);
}

/* Legal transitions, table-driven. A request may advance SUBMITTED→QUEUED→ACTIVE
 * →COMPLETE, fail from ACTIVE, or be cancelled from any non-terminal state. */
static int
transition_ok(cta_state_t from, cta_state_t to)
{
    switch (from) {
    case CTA_ST_SUBMITTED:
        return to == CTA_ST_QUEUED || to == CTA_ST_CANCELED;
    case CTA_ST_QUEUED:
        return to == CTA_ST_ACTIVE || to == CTA_ST_CANCELED ||
               to == CTA_ST_FAILED;
    case CTA_ST_ACTIVE:
        return to == CTA_ST_COMPLETE || to == CTA_ST_FAILED ||
               to == CTA_ST_CANCELED;
    case CTA_ST_COMPLETE:
    case CTA_ST_FAILED:
    case CTA_ST_CANCELED:
        return 0;   /* terminal */
    }
    return 0;
}

static int
is_terminal(cta_state_t s)
{
    return s == CTA_ST_COMPLETE || s == CTA_ST_FAILED || s == CTA_ST_CANCELED;
}

xrootd_cta_queue_t *
cta_queue_create(void)
{
    xrootd_cta_queue_t *q = calloc(1, sizeof(*q));
    if (q != NULL) {
        q->next_id = 1;
    }
    return q;
}

void
cta_queue_destroy(xrootd_cta_queue_t *q)
{
    if (q != NULL && q->journal != NULL) {
        fclose((FILE *) q->journal);
    }
    free(q);
}

/* Find an existing slot for id, or claim a free one (replay only). */
static cta_req_t *
replay_slot(xrootd_cta_queue_t *q, uint64_t id)
{
    int i, free_slot = -1;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (q->slots[i].in_use && q->slots[i].id == id) {
            return &q->slots[i];
        }
        if (!q->slots[i].in_use && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        return NULL;
    }
    memset(&q->slots[free_slot], 0, sizeof(q->slots[free_slot]));
    q->slots[free_slot].in_use = 1;
    q->slots[free_slot].id     = id;
    q->slots[free_slot].queue  = q;
    return &q->slots[free_slot];
}

int
cta_queue_open_journal(xrootd_cta_queue_t *q, const char *path)
{
    FILE *f = fopen(path, "a+");
    char  line[1280];

    if (f == NULL) {
        return -1;
    }
    rewind(f);
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long id;
        int        op = 0, state = 0;
        char       owner[64] = "", pathbuf[1024] = "";
        cta_req_t *e;
        /* "id\top\tstate\towner\tpath" — owner/path are tab-free single tokens.
         * owner/path may be empty (their conversions then fail harmlessly). */
        if (sscanf(line, "%llu\t%d\t%d\t%63[^\t]\t%1023[^\n]",
                   &id, &op, &state, owner, pathbuf) < 3) {
            continue;   /* need at least id/op/state */
        }
        e = replay_slot(q, (uint64_t) id);
        if (e == NULL) {
            break;
        }
        e->req.op = (cta_op_t) op;
        e->state  = (cta_state_t) state;
        snprintf(e->owner, sizeof(e->owner), "%s", owner);
        snprintf(e->req.path, sizeof(e->req.path), "%s", pathbuf);
        if ((uint64_t) id >= q->next_id) {
            q->next_id = (uint64_t) id + 1;
        }
    }
    q->journal = f;   /* keep open for append */
    return 0;
}

cta_req_t *
cta_queue_submit(xrootd_cta_queue_t *q, const cta_request_t *r, const char *owner)
{
    int i;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (!q->slots[i].in_use) {
            cta_req_t *e = &q->slots[i];
            memset(e, 0, sizeof(*e));
            e->req    = *r;
            e->state  = CTA_ST_SUBMITTED;
            e->id     = q->next_id++;
            e->in_use = 1;
            e->queue  = q;
            if (owner != NULL) {
                size_t n = strlen(owner);
                if (n >= sizeof(e->owner)) {
                    n = sizeof(e->owner) - 1;
                }
                memcpy(e->owner, owner, n);
                e->owner[n] = '\0';
            }
            journal_append(q, e);
            return e;
        }
    }
    return NULL;   /* full */
}

cta_req_t *
cta_queue_find(xrootd_cta_queue_t *q, uint64_t id)
{
    int i;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (q->slots[i].in_use && q->slots[i].id == id) {
            return &q->slots[i];
        }
    }
    return NULL;
}

int
cta_queue_transition(cta_req_t *e, cta_state_t to)
{
    if (!transition_ok(e->state, to)) {
        return -1;
    }
    e->state = to;
    if (e->queue != NULL) {
        journal_append((xrootd_cta_queue_t *) e->queue, e);
    }
    return 0;
}

int
cta_queue_cancel(xrootd_cta_queue_t *q, uint64_t id, const char *requester,
                 int is_admin)
{
    cta_req_t *e = cta_queue_find(q, id);

    if (e == NULL) {
        return CTA_QUEUE_ENOENT;
    }
    if (!is_admin && (requester == NULL || strcmp(requester, e->owner) != 0)) {
        return CTA_QUEUE_EACCES;
    }
    return cta_queue_transition(e, CTA_ST_CANCELED);
}

int
cta_queue_active_count(const xrootd_cta_queue_t *q)
{
    int i, n = 0;

    for (i = 0; i < CTA_QUEUE_MAX; i++) {
        if (q->slots[i].in_use && !is_terminal(q->slots[i].state)) {
            n++;
        }
    }
    return n;
}
