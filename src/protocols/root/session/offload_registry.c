/*
 * offload_registry.c — per-worker (sessid, pathid) -> secondary-connection map
 * for pathid response offloading (audit §1.1/§7.3). See offload_registry.h.
 *
 * Pure C (no nginx dependency): the connection is an opaque `void *`, so the
 * table is unit-testable with plain pointers. One nginx worker runs a single-
 * threaded event loop, so no locking is needed.
 */

#include "offload_registry.h"

#include <string.h>

typedef struct {
    unsigned char sessid[BRIX_SESSION_ID_LEN];
    unsigned      pathid;
    void         *conn;      /* NULL = free slot */
} brix_offload_slot_t;

static brix_offload_slot_t s_binds[BRIX_OFFLOAD_MAX];
static size_t              s_count;   /* live entries (conn != NULL) */

static int
slot_matches(const brix_offload_slot_t *s, const unsigned char *sessid,
    unsigned pathid)
{
    return s->conn != NULL
        && s->pathid == pathid
        && memcmp(s->sessid, sessid, BRIX_SESSION_ID_LEN) == 0;
}

int
brix_offload_register(const unsigned char *sessid, unsigned pathid, void *conn)
{
    size_t i;
    int    free_idx = -1;

    if (sessid == NULL || conn == NULL) {
        return 0;
    }

    /* Re-point an existing (sessid, pathid) in place; remember the first free
     * slot for the insert case in the same pass. */
    for (i = 0; i < BRIX_OFFLOAD_MAX; i++) {
        if (s_binds[i].conn == NULL) {
            if (free_idx < 0) {
                free_idx = (int) i;
            }
            continue;
        }
        if (slot_matches(&s_binds[i], sessid, pathid)) {
            s_binds[i].conn = conn;
            return 1;
        }
    }

    if (free_idx < 0) {
        return 0;                                /* table full — no offload slot */
    }

    memcpy(s_binds[free_idx].sessid, sessid, BRIX_SESSION_ID_LEN);
    s_binds[free_idx].pathid = pathid;
    s_binds[free_idx].conn   = conn;
    s_count++;
    return 1;
}

void *
brix_offload_lookup(const unsigned char *sessid, unsigned pathid)
{
    size_t i;

    if (sessid == NULL || pathid == 0) {
        return NULL;                             /* pathid 0 = the primary */
    }
    for (i = 0; i < BRIX_OFFLOAD_MAX; i++) {
        if (slot_matches(&s_binds[i], sessid, pathid)) {
            return s_binds[i].conn;
        }
    }
    return NULL;
}

void
brix_offload_unregister(void *conn)
{
    size_t i;

    if (conn == NULL) {
        return;
    }
    for (i = 0; i < BRIX_OFFLOAD_MAX; i++) {
        if (s_binds[i].conn == conn) {
            s_binds[i].conn   = NULL;
            s_binds[i].pathid = 0;
            memset(s_binds[i].sessid, 0, BRIX_SESSION_ID_LEN);
            if (s_count > 0) {
                s_count--;
            }
        }
    }
}

size_t
brix_offload_count(void)
{
    return s_count;
}

size_t
brix_offload_foreach(int (*cb)(void *ud, const unsigned char *sessid,
    unsigned pathid, void *conn), void *ud)
{
    size_t i, visited = 0;

    if (cb == NULL) {
        return 0;
    }
    for (i = 0; i < BRIX_OFFLOAD_MAX; i++) {
        if (s_binds[i].conn == NULL) {
            continue;
        }
        visited++;
        if (cb(ud, s_binds[i].sessid, s_binds[i].pathid, s_binds[i].conn)) {
            break;
        }
    }
    return visited;
}
