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

/*
 * inv_is_under — is `path` a strict descendant of directory `dir`?
 *
 * Component-boundary aware on purpose: "/a/bc" is NOT under "/a/b" even though
 * it shares the prefix, so a rename of /a/b must leave /a/bc alone. The check is
 * therefore prefix + an explicit '/' at the boundary.
 */
static int
inv_is_under(const char *path, const char *dir, size_t dlen)
{
    return strncmp(path, dir, dlen) == 0 && path[dlen] == '/';
}

/*
 * inv_reprefix — rewrite one child entry from the old directory to the new one.
 *
 * Returns 0 when the entry was rewritten, -1 when the resulting path would not
 * fit — the caller then drops the entry rather than storing a truncated (and so
 * fabricated) path.
 */
static int
inv_reprefix(brix_cns_entry_t *e, size_t oldlen, const char *newp, size_t newlen)
{
    const char *tail = e->path + oldlen;          /* starts at the '/' boundary */
    size_t      tlen = strlen(tail);

    if (newlen + tlen > BRIX_CNS_PATH_MAX) {
        return -1;
    }
    /* Build in place back-to-front: the tail may overlap its destination, so
     * memmove it clear of the new prefix before writing the prefix in. */
    memmove(e->path + newlen, tail, tlen + 1);
    memcpy(e->path, newp, newlen);
    return 0;
}

/*
 * inv_rename_subtree — carry every recorded descendant of `oldp` across to
 * `newp`.
 *
 * Runs BEFORE the parent entry moves: the parent itself never matches
 * inv_is_under (an exact match has no '/' boundary at oldlen), so that ordering
 * keeps this a single pass with no entry visited twice. An entry whose new path
 * would not fit is dropped rather than truncated — a truncated path is a
 * fabricated one, and the next inventory sync re-learns the real entry.
 */
static void
inv_rename_subtree(brix_cns_inv_t *inv, const char *oldp, size_t oldlen,
    const char *newp, size_t newlen)
{
    uint32_t i;

    for (i = 0; i < inv->capacity; i++) {
        brix_cns_entry_t *e = &inv->slots[i];

        if (!e->used || !inv_is_under(e->path, oldp, oldlen)) {
            continue;
        }
        if (inv_reprefix(e, oldlen, newp, newlen) != 0) {
            e->used = 0;
            if (inv->count > 0) { inv->count--; }
        }
    }
}

/*
 * inv_rename_dest_slot — the entry that will hold `newp` once the rename lands.
 *
 * An existing destination is overwritten and the now-stale source entry retired
 * — exactly what the data server's rename(2) already did on disk. Otherwise the
 * source entry is reused in place, or a free slot claimed when the source was
 * never recorded. NULL only when the fixed-capacity inventory is full.
 */
static brix_cns_entry_t *
inv_rename_dest_slot(brix_cns_inv_t *inv, const char *oldp, const char *newp)
{
    brix_cns_entry_t *dst = inv_find(inv, newp);
    brix_cns_entry_t *src = inv_find(inv, oldp);

    if (dst != NULL) {
        if (src != NULL && src != dst) {
            src->used = 0;
            if (inv->count > 0) { inv->count--; }
        }
        return dst;
    }
    if (src != NULL) {
        return src;
    }

    dst = inv_free_slot(inv);
    if (dst == NULL) {
        return NULL;
    }
    dst->used = 1;
    inv->count++;
    return dst;
}

int
brix_cns_inv_rename(brix_cns_inv_t *inv, const char *oldp, const char *newp,
    uint64_t size, uint64_t mtime, int is_dir, uint32_t server_id)
{
    brix_cns_entry_t *e;
    size_t            oldlen, newlen;

    if (inv == NULL || oldp == NULL || newp == NULL) {
        return -1;
    }
    oldlen = strlen(oldp);
    newlen = strlen(newp);
    if (oldlen == 0 || oldlen > BRIX_CNS_PATH_MAX
        || newlen == 0 || newlen > BRIX_CNS_PATH_MAX)
    {
        return -1;
    }

    inv_rename_subtree(inv, oldp, oldlen, newp, newlen);

    e = inv_rename_dest_slot(inv, oldp, newp);
    if (e == NULL) {
        return -1;                         /* inventory full (fixed cap) */
    }
    memcpy(e->path, newp, newlen);
    e->path[newlen] = '\0';
    e->size      = size;
    e->mtime     = mtime;
    e->server_id = server_id;
    e->is_dir    = is_dir ? 1 : 0;
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
