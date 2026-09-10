#ifndef BRIX_SD_RAM_INTERNAL_H
#define BRIX_SD_RAM_INTERNAL_H

/*
 * sd_ram_internal.h — shared types for the RAM object store (sd_ram.c and
 * sd_ram_staged.c). Not a public header: nothing outside src/fs/backend/ram/
 * includes it (the driver is reached through brix_sd_ram_driver alone).
 *
 * WHAT: a per-worker hash table of heap-resident objects, its byte accounting,
 *       and the one mutex that guards both.
 * WHY:  the store is mutated from the event loop (open/stat/unlink) AND from
 *       cache-fill worker threads (staged_write/commit), exactly the mix that
 *       cost cinfo_l1 a TSan-found corruption before it grew a lock — so the
 *       table carries the same pthread mutex, for the same reason.
 * HOW:  entries are refcounted like POSIX links: unlink detaches the name and
 *       drops a reference, and the bytes are freed by whichever holder puts the
 *       last one down, so an open handle keeps reading an evicted object rather
 *       than following a dangling pointer.
 */

#include "fs/backend/sd.h"

#include <pthread.h>
#include <stdint.h>

/* One user.* extended attribute on an entry (the cinfo carrier in XATTR meta
 * mode). A short singly-linked list: an entry carries a handful at most. */
typedef struct sd_ram_xattr_s {
    struct sd_ram_xattr_s *next;
    char                  *name;   /* NUL-terminated, owned */
    u_char                *val;    /* opaque bytes, owned   */
    size_t                 len;
} sd_ram_xattr_t;

/* One stored object (or directory). `path` is the store-relative logical name
 * with a leading '/'; `data`/`size` are the object bytes (NULL/0 for a dir and
 * for a zero-length object). `cap` is the allocation behind `data` — growth is
 * amortised, so cap >= size and the accounting charges `cap`, never `size`. */
typedef struct sd_ram_ent_s {
    struct sd_ram_ent_s *hnext;    /* hash-bucket chain            */
    struct sd_ram_ent_s *lru_prev; /* MRU-first eviction list      */
    struct sd_ram_ent_s *lru_next;
    char                *path;
    u_char              *data;
    size_t               size;
    size_t               cap;
    sd_ram_xattr_t      *xattrs;
    time_t               mtime;
    time_t               ctime;
    uint64_t             ino;
    unsigned             refs;     /* names + open handles         */
    unsigned             is_dir:1;
    unsigned             unlinked:1; /* name detached; bytes await the last ref */
    unsigned             charged:1;  /* ent->cap is counted in st->used — set by
                                      * insert, cleared only by the free that
                                      * discounts it, so unlink-while-open (which
                                      * frees LATER, from close) still discounts
                                      * exactly once */
} sd_ram_ent_t;

/* Per-instance state: the table, the cap, and the accounting the `space` slot
 * reports. `reserved` holds bytes claimed by fills that have not committed yet
 * (a declared_size reservation), so two concurrent fills cannot both be told
 * there is room for the same bytes. */
typedef struct {
    sd_ram_ent_t   **buckets;
    sd_ram_ent_t    *lru_head;     /* most recently used            */
    sd_ram_ent_t    *lru_tail;     /* the next eviction victim      */
    size_t            nbuckets;
    size_t            count;
    uint64_t          used;        /* committed object bytes        */
    uint64_t          reserved;    /* in-flight fill reservations   */
    uint64_t          capacity;    /* the ram:<size> hard cap       */
    uint64_t          next_ino;
    pthread_mutex_t   mtx;
    ngx_log_t        *log;
} sd_ram_state_t;

/* What an open handle points at (brix_sd_obj_t::state). */
typedef struct {
    sd_ram_ent_t *ent;
} sd_ram_open_t;

/* An uncommitted fill (brix_sd_staged_t::state): a detached entry plus the
 * bytes reserved for it, released by commit or abort and by nothing else. */
typedef struct {
    sd_ram_ent_t *ent;
    uint64_t      reserved;
} sd_ram_staged_state_t;

/* ---- table primitives (sd_ram_table.c) ------------------------------------
 * Every primitive below is called with st->mtx already held; none takes it.
 * brix_sd_ram_path_ok is the exception — a pure string check, lock-free. */

/* 1 iff `path` is a clean absolute store path (no ".." component). SECURITY:
 * the table is keyed on the raw string, so a ".." would let two logical paths
 * collide on one entry — a cache-poisoning primitive. Checked at every slot
 * rather than trusted from the caller. */
int brix_sd_ram_path_ok(const char *path);

/* Look up `path`, or NULL. */
sd_ram_ent_t *brix_sd_ram_find(sd_ram_state_t *st, const char *path);

/* Detach `path` from the table and drop its name reference (freeing the bytes
 * when no open handle holds one). Returns NGX_OK, or NGX_DECLINED when absent. */
ngx_int_t brix_sd_ram_detach(sd_ram_state_t *st, const char *path);

/* Insert `ent` under its own path, replacing any entry already there. */
void brix_sd_ram_insert(sd_ram_state_t *st, sd_ram_ent_t *ent);

/* Drop one reference to `ent`, freeing it at zero and discounting its bytes
 * from st->used iff ent->charged (never guessed by the caller — the bit is the
 * accounting's single source of truth). */
void brix_sd_ram_unref(sd_ram_state_t *st, sd_ram_ent_t *ent);

/* Move `ent` to the head of the eviction list (it was just used). */
void brix_sd_ram_lru_touch(sd_ram_state_t *st, sd_ram_ent_t *ent);

/* Evict least-recently-used entries until `want` more bytes fit under the cap.
 * Returns NGX_OK, or NGX_ERROR with errno ENOSPC when even a full eviction pass
 * cannot make room (every remaining object is open, or `want` exceeds the cap). */
ngx_int_t brix_sd_ram_make_room(sd_ram_state_t *st, uint64_t want);

/* Allocate a detached entry naming `path` (refs = 1). NULL + errno on failure. */
sd_ram_ent_t *brix_sd_ram_ent_new(sd_ram_state_t *st, const char *path,
    int is_dir);

/* Grow `ent`'s buffer so it can hold `want` bytes, keeping the WHOLE allocation
 * covered by the caller's store reservation: `*covered` is that reservation in
 * bytes and is raised in step with the allocation (the store's `reserved` with
 * it), so an object whose origin declared no length cannot outgrow the cap one
 * increment at a time. Returns NGX_OK, or NGX_ERROR with errno ENOSPC (`want`
 * exceeds the store, or the store cannot evict enough) or ENOMEM. */
ngx_int_t brix_sd_ram_ent_grow(sd_ram_state_t *st, sd_ram_ent_t *ent,
    size_t want, uint64_t *covered);

/* Free every xattr on `ent`. */
void brix_sd_ram_xattrs_free(sd_ram_ent_t *ent);

/* ---- slot groups implemented in sd_ram_staged.c --------------------------- */

brix_sd_staged_t *brix_sd_ram_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, off_t declared_size, int *err_out);
ssize_t   brix_sd_ram_staged_write(brix_sd_staged_t *sh, const void *buf,
    size_t len, off_t off);
ngx_int_t brix_sd_ram_staged_commit(brix_sd_staged_t *sh,
    brix_sd_precond_t *pre);
void      brix_sd_ram_staged_abort(brix_sd_staged_t *sh);

brix_sd_dir_t *brix_sd_ram_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
ngx_int_t brix_sd_ram_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t brix_sd_ram_closedir(brix_sd_dir_t *d);

ssize_t   brix_sd_ram_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t   brix_sd_ram_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t brix_sd_ram_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t brix_sd_ram_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);

#endif /* BRIX_SD_RAM_INTERNAL_H */
