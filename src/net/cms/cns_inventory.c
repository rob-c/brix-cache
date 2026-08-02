/*
 * cns_inventory.c — the pure CNS inventory table ops. See cns_inventory.h.
 *
 * No nginx, no locking, no I/O: just the linear-probe slot logic over a POD
 * block that cns.c hosts either on the heap (single worker) or in an SHM slab
 * (shared across manager workers). Every mutation runs under a lock cns.c holds.
 */

#include "cns_inventory.h"

#include <string.h>

size_t
brix_cns_inv_bytes(uint32_t capacity)
{
    return sizeof(brix_cns_inv_t) + (size_t) capacity * sizeof(brix_cns_entry_t);
}

void
brix_cns_inv_init(brix_cns_inv_t *inv, uint32_t capacity)
{
    if (inv == NULL) {
        return;
    }
    inv->capacity = capacity;
    inv->count    = 0;
    /* slots are already zeroed by the (calloc / slab-alloc) that produced the
     * block; init only stamps the header, so a re-attach preserves live state. */
}

static brix_cns_entry_t *
inv_find(const brix_cns_inv_t *inv, const char *path)
{
    uint32_t i;

    for (i = 0; i < inv->capacity; i++) {
        const brix_cns_entry_t *e = &inv->slots[i];
        if (e->used && strcmp(e->path, path) == 0) {
            return (brix_cns_entry_t *) e;
        }
    }
    return NULL;
}

static brix_cns_entry_t *
inv_free_slot(brix_cns_inv_t *inv)
{
    uint32_t i;

    for (i = 0; i < inv->capacity; i++) {
        if (!inv->slots[i].used) {
            return &inv->slots[i];
        }
    }
    return NULL;
}

int
brix_cns_inv_apply(brix_cns_inv_t *inv, uint8_t op, const char *path,
    uint64_t size, uint64_t mtime, uint32_t server_id)
{
    brix_cns_entry_t *e;
    size_t            plen;

    if (inv == NULL || path == NULL) {
        return -1;
    }
    plen = strlen(path);
    if (plen == 0 || plen > BRIX_CNS_PATH_MAX) {
        return -1;
    }

    if (op == BRIX_CNS_DEL || op == BRIX_CNS_RMDIR) {
        e = inv_find(inv, path);
        if (e != NULL) {
            e->used = 0;
            if (inv->count > 0) { inv->count--; }
        }
        return 0;                          /* removing an absent path is a no-op */
    }

    if (op != BRIX_CNS_ADD && op != BRIX_CNS_MKDIR) {
        return -1;
    }

    e = inv_find(inv, path);
    if (e == NULL) {
        e = inv_free_slot(inv);
        if (e == NULL) {
            return -1;                     /* inventory full (fixed cap) */
        }
        memcpy(e->path, path, plen);
        e->path[plen] = '\0';
        e->used = 1;
        inv->count++;
    }
    e->size      = size;
    e->mtime     = mtime;
    e->server_id = server_id;
    e->is_dir    = (op == BRIX_CNS_MKDIR) ? 1 : 0;
    return 0;
}

int
brix_cns_inv_stat(const brix_cns_inv_t *inv, const char *path,
    uint64_t *size, uint64_t *mtime, int *is_dir)
{
    brix_cns_entry_t *e;

    if (inv == NULL || path == NULL) {
        return -1;
    }
    e = inv_find(inv, path);
    if (e == NULL) {
        return 1;                          /* miss */
    }
    if (size)   { *size   = e->size; }
    if (mtime)  { *mtime  = e->mtime; }
    if (is_dir) { *is_dir = e->is_dir; }
    return 0;
}

uint32_t
brix_cns_inv_count(const brix_cns_inv_t *inv)
{
    return inv ? inv->count : 0;
}
