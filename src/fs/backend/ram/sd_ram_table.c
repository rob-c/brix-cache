/*
 * sd_ram_table.c — the RAM store's object table: path hygiene, hashing, entry
 * allocation, refcounting and the byte accounting the cap is enforced on.
 *
 * WHAT: every mutation of sd_ram_state_t's hash table lives here; sd_ram.c and
 *       sd_ram_staged.c reach it only through the primitives in
 *       sd_ram_internal.h.
 * WHY:  one place owns the invariant that ties st->used to the sum of the
 *       entries' `cap` fields — split that across three files and a leak or a
 *       double-discount is a matter of time.
 * HOW:  callers hold st->mtx; nothing here takes it. Allocation is plain
 *       malloc/free (never an nginx pool): entries are created and destroyed
 *       from cache-fill worker threads, where pools are not safe.
 */

#include "sd_ram_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Growth floor for an object buffer with no declared size (an origin that
 * answered without a length): grow geometrically from here rather than
 * reallocating per write. */
#define SD_RAM_GROW_MIN  (64 * 1024)

/* ---- path hygiene --------------------------------------------------------- */

/*
 * SECURITY: paths reach a driver already confined by the VFS, but this store
 * keys its table on the raw string, so a name carrying a ".." component would
 * make two different logical paths collide on one entry — a cache poisoning
 * primitive rather than a traversal one (there is no filesystem to escape to).
 * The store therefore refuses anything that is not a clean absolute path, and
 * refuses it at every slot rather than trusting its caller.
 */
int
brix_sd_ram_path_ok(const char *path)
{
    const char *p;

    if (path == NULL || path[0] != '/') {
        return 0;
    }
    for (p = path; *p != '\0'; p++) {
        if (p[0] != '.' || p[1] != '.') {
            continue;
        }
        if ((p == path || p[-1] == '/') && (p[2] == '/' || p[2] == '\0')) {
            return 0;
        }
    }
    return 1;
}

/* FNV-1a over a NUL-terminated path (the cinfo_l1 spelling). */
static uint64_t
sd_ram_hash(const char *path)
{
    uint64_t             h = 1469598103934665603ULL;
    const unsigned char *p = (const unsigned char *) path;

    while (*p != '\0') {
        h ^= (uint64_t) *p++;
        h *= 1099511628211ULL;
    }
    return h;
}

/* ---- table primitives (callers hold st->mtx) ------------------------------ */

sd_ram_ent_t *
brix_sd_ram_find(sd_ram_state_t *st, const char *path)
{
    sd_ram_ent_t *e = st->buckets[sd_ram_hash(path) % st->nbuckets];

    for ( ; e != NULL; e = e->hnext) {
        if (strcmp(e->path, path) == 0) {
            return e;
        }
    }
    return NULL;
}

void
brix_sd_ram_xattrs_free(sd_ram_ent_t *ent)
{
    sd_ram_xattr_t *x = ent->xattrs;

    while (x != NULL) {
        sd_ram_xattr_t *next = x->next;

        free(x->name);
        free(x->val);
        free(x);
        x = next;
    }
    ent->xattrs = NULL;
}

void
brix_sd_ram_unref(sd_ram_state_t *st, sd_ram_ent_t *ent)
{
    if (ent == NULL || --ent->refs > 0) {
        return;
    }
    /* The charge follows the BYTES, not the name: an entry unlinked while a
     * handle still reads it stays counted until this free, which is the only
     * moment the memory actually goes back. */
    if (ent->charged && st->used >= ent->cap) {
        st->used -= ent->cap;
    }
    brix_sd_ram_xattrs_free(ent);
    free(ent->data);
    free(ent->path);
    free(ent);
}

sd_ram_ent_t *
brix_sd_ram_ent_new(sd_ram_state_t *st, const char *path, int is_dir)
{
    sd_ram_ent_t *e = calloc(1, sizeof(*e));

    if (e == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    e->path = strdup(path);
    if (e->path == NULL) {
        free(e);
        errno = ENOMEM;
        return NULL;
    }
    e->refs   = 1;
    e->is_dir = is_dir ? 1 : 0;
    e->mtime  = time(NULL);
    e->ctime  = e->mtime;
    e->ino    = ++st->next_ino;
    return e;
}

/* ---- eviction list -------------------------------------------------------- */

/* Unlink `ent` from the LRU list (a no-op for an entry not on it). */
static void
sd_ram_lru_unlink(sd_ram_state_t *st, sd_ram_ent_t *ent)
{
    if (ent->lru_prev != NULL) {
        ent->lru_prev->lru_next = ent->lru_next;
    } else if (st->lru_head == ent) {
        st->lru_head = ent->lru_next;
    }
    if (ent->lru_next != NULL) {
        ent->lru_next->lru_prev = ent->lru_prev;
    } else if (st->lru_tail == ent) {
        st->lru_tail = ent->lru_prev;
    }
    ent->lru_prev = NULL;
    ent->lru_next = NULL;
}

/* Push `ent` on as the most recently used. */
static void
sd_ram_lru_push(sd_ram_state_t *st, sd_ram_ent_t *ent)
{
    ent->lru_prev = NULL;
    ent->lru_next = st->lru_head;
    if (st->lru_head != NULL) {
        st->lru_head->lru_prev = ent;
    }
    st->lru_head = ent;
    if (st->lru_tail == NULL) {
        st->lru_tail = ent;
    }
}

void
brix_sd_ram_lru_touch(sd_ram_state_t *st, sd_ram_ent_t *ent)
{
    if (st->lru_head == ent) {
        return;
    }
    sd_ram_lru_unlink(st, ent);
    sd_ram_lru_push(st, ent);
}

/*
 * Make room for `want` more bytes by evicting from the cold end.
 *
 * WHY the store evicts itself: the shared cache reaper is a watermark pass over
 * a PHYSICAL cache root, taken under a lock-file in that root — a per-worker RAM
 * store has neither, and a cross-worker lock would be wrong for it anyway (each
 * worker owns a separate store, so one worker's reaper must not gate another's).
 * A hard cap with no eviction is a store that fills once and then refuses every
 * fill forever, so the cap and the LRU are one mechanism, not two.
 *
 * An entry with an open handle (refs > 1) is SKIPPED, never evicted: detaching
 * it would drop the name while the bytes stay live and charged, so a pass that
 * evicted open objects could report room it has not got.
 */
ngx_int_t
brix_sd_ram_make_room(sd_ram_state_t *st, uint64_t want)
{
    sd_ram_ent_t *victim;
    sd_ram_ent_t *prev;

    if (want > st->capacity) {
        errno = ENOSPC;                      /* never fits, whatever we drop */
        return NGX_ERROR;
    }
    victim = st->lru_tail;
    while (st->used + st->reserved + want > st->capacity && victim != NULL) {
        prev = victim->lru_prev;
        if (victim->refs == 1) {
            (void) brix_sd_ram_detach(st, victim->path);
        }
        victim = prev;
    }
    if (st->used + st->reserved + want > st->capacity) {
        errno = ENOSPC;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- table primitives, continued ------------------------------------------ */

/* Detach whatever entry currently answers to `ent->path`, then chain `ent` in.
 * The replaced entry keeps serving any handle still holding it (POSIX rename
 * semantics: the name moves, an open fd does not). */
void
brix_sd_ram_insert(sd_ram_state_t *st, sd_ram_ent_t *ent)
{
    size_t b;

    (void) brix_sd_ram_detach(st, ent->path);
    b = sd_ram_hash(ent->path) % st->nbuckets;
    ent->hnext = st->buckets[b];
    st->buckets[b] = ent;
    st->count++;
    ent->charged = 1;
    st->used += ent->cap;
    sd_ram_lru_push(st, ent);
}

ngx_int_t
brix_sd_ram_detach(sd_ram_state_t *st, const char *path)
{
    size_t         b = sd_ram_hash(path) % st->nbuckets;
    sd_ram_ent_t **pp;

    for (pp = &st->buckets[b]; *pp != NULL; pp = &(*pp)->hnext) {
        sd_ram_ent_t *e = *pp;

        if (strcmp(e->path, path) != 0) {
            continue;
        }
        *pp = e->hnext;
        e->hnext    = NULL;
        e->unlinked = 1;
        st->count--;
        sd_ram_lru_unlink(st, e);
        brix_sd_ram_unref(st, e);
        return NGX_OK;
    }
    return NGX_DECLINED;
}

ngx_int_t
brix_sd_ram_ent_grow(sd_ram_state_t *st, sd_ram_ent_t *ent, size_t want,
    uint64_t *covered)
{
    size_t   ncap;
    u_char  *nd;

    if (want <= ent->cap) {
        return NGX_OK;
    }
    ncap = ent->cap * 2;
    if (ncap < want) {
        ncap = want;
    }
    if (ncap < SD_RAM_GROW_MIN) {
        ncap = SD_RAM_GROW_MIN;
    }
    if ((uint64_t) ncap > st->capacity) {
        /* An object bigger than the whole store can never be admitted, however
         * much is evicted first. A DOUBLING that overshoots is a different
         * thing — clamp it to the cap and keep the fill alive. */
        if ((uint64_t) want > st->capacity) {
            errno = ENOSPC;
            return NGX_ERROR;
        }
        ncap = (size_t) st->capacity;
    }

    /* `*covered` is what this fill has already charged to st->reserved. The
     * allocation itself must stay covered — charging only each growth's DELTA
     * (the pre-2.0 behaviour) left the entry's own bytes uncounted until commit,
     * so a fill whose origin declared no length could reach twice the cap before
     * anything refused it: every individual doubling was smaller than the store.
     * Raise the reservation to the new allocation and the store sees the whole
     * in-flight object, not its last increment. */
    if ((uint64_t) ncap > *covered) {
        uint64_t extra = (uint64_t) ncap - *covered;

        /* A fill whose origin declared no length outgrows its reservation by
         * design; evict for the overshoot rather than failing a fill that the
         * store has cold objects to make room for. */
        if (st->used + st->reserved + extra > st->capacity
            && brix_sd_ram_make_room(st, extra) != NGX_OK)
        {
            errno = ENOSPC;
            return NGX_ERROR;
        }
        st->reserved += extra;
        *covered      = (uint64_t) ncap;
    }
    nd = realloc(ent->data, ncap);
    if (nd == NULL) {
        errno = ENOMEM;
        return NGX_ERROR;
    }
    memset(nd + ent->cap, 0, ncap - ent->cap);   /* holes read as zeroes */
    ent->data = nd;
    ent->cap  = ncap;
    return NGX_OK;
}

