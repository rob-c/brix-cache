#ifndef NGX_BRIX_CMS_CNS_INVENTORY_H
#define NGX_BRIX_CMS_CNS_INVENTORY_H

/*
 * cns_inventory.h — the CNS path→metadata inventory table (pure, nginx-free).
 *
 * WHAT: a fixed-capacity, pointer-free (POD) table of file/dir entries the CNS
 *       manager keeps for the whole federation namespace. The layout is
 *       deliberately plain-old-data — no embedded pointers, no per-entry heap —
 *       so the SAME struct can live either in a per-worker heap block (the v1
 *       single-worker path) or in an nginx shared-memory slab region shared
 *       across every manager worker (the v2 multi-worker path). cns.c owns the
 *       backing store and the mutex; these ops assume the caller holds it.
 * WHY:  a multi-worker redirector had a per-worker inventory, so a mutation that
 *       landed on worker A was invisible to a stat that landed on worker B. A
 *       shared table fixes that; keeping the table logic pure (this file) from
 *       the SHM plumbing (cns.c) lets the slot/upsert/delete semantics be unit-
 *       tested deterministically without an nginx runtime.
 * HOW:  linear-probe over `capacity` fixed slots (a small federation namespace);
 *       apply upserts on ADD/MKDIR and clears on DEL/RMDIR; stat is a lookup.
 */

#include <stddef.h>
#include <stdint.h>

/* Namespace-mutation opcodes (shared by the wire codec and the inventory). */
#define BRIX_CNS_ADD     1   /* file created / closed-after-write (size known) */
#define BRIX_CNS_DEL     2   /* file unlinked */
#define BRIX_CNS_MKDIR   3
#define BRIX_CNS_RMDIR   4

#define BRIX_CNS_PATH_MAX 512

typedef struct {
    char     path[BRIX_CNS_PATH_MAX + 1];
    uint64_t size;
    uint64_t mtime;
    uint32_t server_id;
    uint8_t  is_dir;
    uint8_t  used;
} brix_cns_entry_t;

/* Flexible table header + inline slot array. A single contiguous block, so one
 * slab allocation (or one calloc) holds the whole inventory — no pointers to
 * relocate when the block lives in SHM shared across workers. */
typedef struct {
    uint32_t         capacity;
    uint32_t         count;
    brix_cns_entry_t slots[];      /* [capacity] */
} brix_cns_inv_t;

/* Byte size of a `capacity`-slot table (for the allocator / SHM zone sizing). */
size_t brix_cns_inv_bytes(uint32_t capacity);

/* Initialise a freshly allocated (zeroed) block: stamp capacity, count=0. */
void brix_cns_inv_init(brix_cns_inv_t *inv, uint32_t capacity);

/* Apply one decoded event: upsert on ADD/MKDIR, remove on DEL/RMDIR. Returns 0
 * on success, -1 on a bad path / unknown op / table full. Caller holds the lock. */
int brix_cns_inv_apply(brix_cns_inv_t *inv, uint8_t op, const char *path,
        uint64_t size, uint64_t mtime, uint32_t server_id);

/* Look `path` up. On a hit fills size/mtime/is_dir (any may be NULL) and returns
 * 0; returns 1 on a miss, -1 on a bad argument. Caller holds the lock. */
int brix_cns_inv_stat(const brix_cns_inv_t *inv, const char *path,
        uint64_t *size, uint64_t *mtime, int *is_dir);

/* Live entry count. */
uint32_t brix_cns_inv_count(const brix_cns_inv_t *inv);

#endif /* NGX_BRIX_CMS_CNS_INVENTORY_H */
