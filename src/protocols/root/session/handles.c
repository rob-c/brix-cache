/*
 * WHAT: This file implements the shared memory handle table used by kXR_bind
 * secondary connections.  Primary connections publish readable file handle
 * metadata so another nginx worker can reopen and validate the same file.
 *
 * WHY: nginx workers do not share descriptors opened after fork.  Bound
 * streams therefore cannot inherit a raw fd from the primary connection; they
 * need a shared, validated description of the handle instead.
 *
 * HOW: All operations are serialized by the handle-zone mutex.  Entries are
 * keyed by sessid + handle_index and carry path, readable/writable flags,
 * cache status, device, inode, and size metadata for reopen validation.
 */

#include "registry.h"
#include "core/compat/shm_slots.h"
#include <ngx_shmtx.h>
#include <string.h>

static ngx_shmtx_t  brix_handle_mutex;

static brix_shared_handle_table_t *
handle_table(void)
{
    if (brix_handle_shm_zone == NULL
        || brix_handle_shm_zone->data == NULL
        || brix_handle_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (brix_shared_handle_table_t *) brix_handle_shm_zone->data;
}

ngx_int_t
brix_handle_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t                    fresh;
    brix_shared_handle_table_t *tbl;

    /*
     * Allocate the table FROM the slab pool (not over shm.addr) so nginx's
     * ngx_unlock_mutexes() — which treats shm.addr as an ngx_slab_pool_t and
     * force-unlocks its mutex on every child death — finds an intact slab
     * header instead of our clobbered struct. brix_shm_table_alloc() also
     * zeroes the table and creates the process-local mutex from the table's
     * first member (the ngx_shmtx_sh_t lock).
     */
    tbl = brix_shm_table_alloc(shm_zone, data,
                                 sizeof(brix_shared_handle_table_t),
                                 &brix_handle_mutex, &fresh);
    if (tbl == NULL) {
        return NGX_ERROR;
    }

    /*
     * The fixed-size slots[] array has no extra fields to initialise beyond the
     * zeroing the helper already performed on a fresh allocation, so there is
     * nothing more to do here (live state must be preserved on reuse).
     */
    (void) fresh;
    return NGX_OK;
}

static ngx_flag_t
brix_shared_handle_same_key(const brix_shared_handle_entry_t *entry,
    const u_char sessid[BRIX_SESSION_ID_LEN], int handle_index)
{
    return entry->in_use
           && entry->handle_index == (uint8_t) handle_index
           && ngx_memcmp(entry->sessid, sessid, BRIX_SESSION_ID_LEN) == 0;
}

/*
 *
 * WHAT: Shares file handle metadata with other workers enabling bound stream
 * secondary connections to read primary-published handles.  Write-only
 * handles are not published because bound streams are read-only data channels.
 *
 * WHY: xrdcp secondary connections established via kXR_bind may arrive at
 * different workers than the primary connection.  Device/inode metadata lets
 * the secondary verify the reopened path still refers to the original file.
 */
void
brix_session_handle_publish(const u_char sessid[BRIX_SESSION_ID_LEN],
    int handle_index, const brix_file_t *file)
{
    brix_shared_handle_table_t *tbl;
    brix_shared_handle_entry_t *entry;
    ngx_uint_t                    i, free_slot;
    size_t                        path_len;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES
        || file == NULL || file->fd < 0)
    {
        return;
    }

    tbl = handle_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_handle_mutex);

    free_slot = BRIX_SESSION_HANDLE_SLOTS;
    entry = NULL;

    for (i = 0; i < BRIX_SESSION_HANDLE_SLOTS; i++) {
        if (brix_shared_handle_same_key(&tbl->slots[i], sessid,
                                          handle_index))
        {
            entry = &tbl->slots[i];
            break;
        }

        if (!tbl->slots[i].in_use
            && free_slot == BRIX_SESSION_HANDLE_SLOTS)
        {
            free_slot = i;
        }
    }

    /*
     * Bound streams are read-only data channels.  Publishing a write-only
     * primary handle would create an attractive misuse path, so treat it as
     * removal of any stale shared entry for the same slot.
     */
    if (!file->readable || file->path == NULL) {
        if (entry != NULL) {
            ngx_memzero(entry, sizeof(*entry));
        }
        ngx_shmtx_unlock(&brix_handle_mutex);
        return;
    }

    path_len = ngx_strlen(file->path);
    if (path_len > BRIX_MAX_PATH) {
        if (entry != NULL) {
            ngx_memzero(entry, sizeof(*entry));
        }
        ngx_shmtx_unlock(&brix_handle_mutex);
        return;
    }

    if (entry == NULL) {
        if (free_slot == BRIX_SESSION_HANDLE_SLOTS) {
            ngx_shmtx_unlock(&brix_handle_mutex);
            return;
        }
        entry = &tbl->slots[free_slot];
    }

    ngx_memzero(entry, sizeof(*entry));
    ngx_memcpy(entry->sessid, sessid, BRIX_SESSION_ID_LEN);
    entry->handle_index = (uint8_t) handle_index;
    entry->readable = file->readable ? 1 : 0;
    entry->writable = file->writable ? 1 : 0;
    entry->from_cache = file->from_cache ? 1 : 0;
    entry->is_regular = file->is_regular ? 1 : 0;
    entry->device = file->device;
    entry->inode = file->inode;
    entry->cached_size = file->cached_size;
    ngx_cpystrn((u_char *) entry->path, (u_char *) file->path,
                sizeof(entry->path));
    entry->in_use = 1;

    ngx_shmtx_unlock(&brix_handle_mutex);
}

/*
 *
 * WHAT: Retrieves published handle metadata for bound stream read requests.
 *
 * WHY: Bound streams can reopen a primary-published handle in their own worker
 * and validate path identity against the stored device/inode tuple.
 */
/*
 *
 * WHAT: Same as brix_session_handle_lookup() but with a caller-owned slot
 * hint (Phase 33 C2).  A bound secondary re-validates its published handle on
 * EVERY read; *inout_slot remembers the slot matched last time so the common
 * case becomes an O(1) direct check instead of a full table scan.
 *
 * WHY: The scan is the per-read cost on parallel bound streams (xrdcp
 * --sources).  Correctness is unchanged: the lock is still held and the FULL
 * key (in_use + sessid + handle_index) is re-checked, so a primary close/reuse
 * (which clears in_use) fails the fast path and falls through to the scan →
 * revocation, exactly as before.  *inout_slot is refreshed on a scan match and
 * reset to -1 on a miss (and may be NULL for callers that don't cache).
 */
int
brix_session_handle_lookup_hint(const u_char sessid[BRIX_SESSION_ID_LEN],
    int handle_index, int *inout_slot, brix_shared_handle_entry_t *out)
{
    brix_shared_handle_table_t *tbl;
    ngx_uint_t                    i;
    int                           found = 0;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES || out == NULL) {
        return 0;
    }

    tbl = handle_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&brix_handle_mutex);

    /*
     * Fast path: re-check the slot matched on the previous read directly.  Still
     * under the lock and still verifying the full key, so this is a pure scan
     * elimination — never a weaker check.
     */
    if (inout_slot != NULL && *inout_slot >= 0
        && (ngx_uint_t) *inout_slot < BRIX_SESSION_HANDLE_SLOTS
        && brix_shared_handle_same_key(&tbl->slots[*inout_slot], sessid,
                                         handle_index))
    {
        ngx_memcpy(out, &tbl->slots[*inout_slot], sizeof(*out));
        out->path[BRIX_MAX_PATH] = '\0';
        ngx_shmtx_unlock(&brix_handle_mutex);
        return 1;
    }

    for (i = 0; i < BRIX_SESSION_HANDLE_SLOTS; i++) {
        if (brix_shared_handle_same_key(&tbl->slots[i], sessid,
                                          handle_index))
        {
            ngx_memcpy(out, &tbl->slots[i], sizeof(*out));
            out->path[BRIX_MAX_PATH] = '\0';
            if (inout_slot != NULL) {
                *inout_slot = (int) i;   /* refresh the hint for next read */
            }
            found = 1;
            break;
        }
    }

    if (!found && inout_slot != NULL) {
        *inout_slot = -1;   /* drop a now-stale hint so the next read rescans */
    }

    ngx_shmtx_unlock(&brix_handle_mutex);
    return found;
}

int
brix_session_handle_lookup(const u_char sessid[BRIX_SESSION_ID_LEN],
    int handle_index, brix_shared_handle_entry_t *out)
{
    return brix_session_handle_lookup_hint(sessid, handle_index, NULL, out);
}

/*
 *
 * WHAT: Removes one published handle entry during kXR_close.
 *
 * WHY: Secondary connections must not continue reading a primary handle after
 * that handle has been closed or reused.
 */
void
brix_session_handle_unpublish(const u_char sessid[BRIX_SESSION_ID_LEN],
    int handle_index)
{
    brix_shared_handle_table_t *tbl;
    ngx_uint_t                    i;

    if (handle_index < 0 || handle_index >= BRIX_MAX_FILES) {
        return;
    }

    tbl = handle_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_handle_mutex);

    for (i = 0; i < BRIX_SESSION_HANDLE_SLOTS; i++) {
        if (brix_shared_handle_same_key(&tbl->slots[i], sessid,
                                          handle_index))
        {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
            break;
        }
    }

    ngx_shmtx_unlock(&brix_handle_mutex);
}

/*
 *
 * WHAT: Removes all published handles for a session during session teardown.
 *
 * WHY: kXR_endsess and disconnect cleanup must revoke every bound-stream
 * handle regardless of which worker originally published it.
 */
void
brix_session_handle_unpublish_all(
    const u_char sessid[BRIX_SESSION_ID_LEN])
{
    brix_shared_handle_table_t *tbl;
    ngx_uint_t                    i;

    tbl = handle_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&brix_handle_mutex);

    for (i = 0; i < BRIX_SESSION_HANDLE_SLOTS; i++) {
        if (tbl->slots[i].in_use
            && ngx_memcmp(tbl->slots[i].sessid, sessid,
                          BRIX_SESSION_ID_LEN) == 0)
        {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
        }
    }

    ngx_shmtx_unlock(&brix_handle_mutex);
}
