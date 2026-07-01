/*
 * registry.c — per-worker SSI session registry. See registry.h.
 *
 * A fixed table is the right shape here: the entry count is bounded by concurrent
 * SSI connections on one worker, lookups are µs-rare (only on async delivery), and
 * a flat array keeps the lookup a pointer-free integer scan (no allocation, no
 * locking — single worker thread).
 */

#include "registry.h"
#include <stddef.h>

static struct {
    uintptr_t              conn_id;
    uint64_t               generation;
    xrootd_ssi_session_t  *s;
    int                    in_use;
} ssi_reg[XROOTD_SSI_REGISTRY_SLOTS];

void
xrootd_ssi_registry_add(uintptr_t conn_id, xrootd_ssi_session_t *s)
{
    int i, free_slot = -1;

    if (s == NULL) {
        return;
    }
    for (i = 0; i < XROOTD_SSI_REGISTRY_SLOTS; i++) {
        if (ssi_reg[i].in_use && ssi_reg[i].conn_id == conn_id) {
            ssi_reg[i].generation = s->generation;   /* refresh a recycled id */
            ssi_reg[i].s = s;
            return;
        }
        if (!ssi_reg[i].in_use && free_slot < 0) {
            free_slot = i;
        }
    }
    if (free_slot < 0) {
        return;   /* table full: async delivery for this conn fails safe (drops) */
    }
    ssi_reg[free_slot].conn_id    = conn_id;
    ssi_reg[free_slot].generation = s->generation;
    ssi_reg[free_slot].s          = s;
    ssi_reg[free_slot].in_use     = 1;
}

void
xrootd_ssi_registry_remove(uintptr_t conn_id)
{
    int i;

    for (i = 0; i < XROOTD_SSI_REGISTRY_SLOTS; i++) {
        if (ssi_reg[i].in_use && ssi_reg[i].conn_id == conn_id) {
            ssi_reg[i].in_use = 0;
            ssi_reg[i].s = NULL;
            return;
        }
    }
}

xrootd_ssi_session_t *
xrootd_ssi_registry_find(uintptr_t conn_id, uint64_t generation)
{
    int i;

    for (i = 0; i < XROOTD_SSI_REGISTRY_SLOTS; i++) {
        if (ssi_reg[i].in_use && ssi_reg[i].conn_id == conn_id) {
            return ssi_reg[i].generation == generation ? ssi_reg[i].s : NULL;
        }
    }
    return NULL;
}
