#ifndef XROOTD_SESSION_REGISTRY_H
#define XROOTD_SESSION_REGISTRY_H

/*
 * session/registry.h — shared-memory registries for kXR_bind.
 *
 * When a primary connection completes authentication the server inserts an
 * entry mapping sessid → {dn, vo_list, token_auth}.  A secondary connection
 * presenting kXR_bind can then look up the sessid and inherit the same
 * identity without re-authenticating.
 *
 * Primary connections also publish their readable file handles in a separate
 * shared-memory table.  Bound secondary connections never inherit raw file
 * descriptor numbers because nginx workers do not share descriptors opened
 * after fork.  Instead they look up {sessid, handle_index} and reopen the
 * same canonical path inside their own worker, validating dev/inode so a
 * replaced path cannot be mistaken for the primary's open file.
 *
 * The table lives in a dedicated ngx_shm_zone_t so all worker processes share
 * one consistent view.  Concurrent access is serialised by a single
 * ngx_shmtx_t spinlock embedded at the start of the shared region.
 *
 * Capacity: XROOTD_SESSION_REGISTRY_SLOTS entries (default 1024).  When the
 * table is full, new inserts fail gracefully — the primary session continues
 * normally and secondaries fall back to single-stream I/O.
 */

#include "../ngx_xrootd_module.h"

#define XROOTD_SESSION_REGISTRY_SLOTS  1024

/*
 * Published-handle table capacity (Phase 31).
 *
 * The handle table is the single largest fixed shared-memory allocation in the
 * module: every slot carries a full path (~4 KB), so sizing it at
 * registry_slots (1024) x XROOTD_MAX_FILES (16) = 16384 slots cost ~68 MB of
 * RAM at idle — paid by every deployment regardless of load.
 *
 * Handles are published here only so that kXR_bind secondary streams (and proxy
 * mode) can reach a primary session's open files across worker boundaries; the
 * common single-stream case never publishes.  We therefore size this table
 * independently of the per-connection open-file limit (XROOTD_MAX_FILES, which
 * must stay 16) using a deliberately smaller pair of factors: a modest number of
 * sessions that use bound streams, each publishing a handful of handles.  When
 * the table is full, publishing fails gracefully (the primary keeps working;
 * secondaries fall back to single-stream I/O) — see xrootd_session_handle_*.
 *
 * Default 512 x 8 = 4096 slots ~= 17 MB, a ~50 MB saving.  Raise these factors
 * if a deployment genuinely runs many concurrent multi-file bound-stream
 * transfers and observes handle-publish failures in the access log.
 */
#define XROOTD_SESSION_HANDLE_SESSIONS      512
#define XROOTD_SESSION_HANDLES_PER_SESSION  8
#define XROOTD_SESSION_HANDLE_SLOTS \
    (XROOTD_SESSION_HANDLE_SESSIONS * XROOTD_SESSION_HANDLES_PER_SESSION)

/* ---- Struct: xrootd_session_entry_t ----
 *
 * WHAT: Single entry in the shared-memory session registry mapping sessid → {dn, vo_list, token_auth}. sessid[16] uniquely identifies an XRootD session; dn (distinguished name from GSI certificate) and vo_list (virtual organization authorization list) determine client identity and eligibility for operations. token_auth flag indicates whether JWT bearer token was used instead of GSI certificate. in_use marks slot occupancy — 0 means free, 1 means registered. Capacity: XROOTD_SESSION_REGISTRY_SLOTS entries (default 1024).
 */

typedef struct {
    u_char     sessid[XROOTD_SESSION_ID_LEN]; /* unique session identifier (16 bytes) */
    char       dn[512];                       /* distinguished name from GSI certificate */
    char       vo_list[512];                  /* virtual organization authorization list */
    ngx_uint_t token_auth;                    /* 1 if JWT bearer token used, 0 for GSI */
    ngx_uint_t in_use;                        /* slot occupancy: 0=free, 1=registered */
    ngx_msec_t last_seen;                     /* Phase 27 F4: register/lookup time (ms);
                                                 LRU key for reap-on-full anti-exhaustion */
} xrootd_session_entry_t;

/* Phase 27 F4: a slot that is the global-LRU AND older than this minimum age is
 * eligible for eviction when the table is full, so a slot-exhaustion attacker
 * cannot permanently deny new logins.  Sessions younger than this are never
 * reaped (avoids thrashing freshly-registered legitimate sessions). */
#define XROOTD_SESSION_REAP_MIN_AGE_MS  60000

/* ---- Struct: xrootd_shared_handle_entry_t ----
 *
 * WHAT: Single entry in the shared-memory handle table publishing file metadata for bound stream secondary connections. sessid+handle_index form a unique key identifying which primary session and which open handle this entry describes. readable/writable flags indicate channel direction; from_cache marks if the handle was opened via read-through cache. is_regular distinguishes files from directories. device/inode provide file identity verification so bound streams can detect path replacement after publish (stale reference attack prevention). cached_size stores file size at publish time for bound stream read length validation.
 */

typedef struct {
    u_char     sessid[XROOTD_SESSION_ID_LEN]; /* primary session identifier — key component */
    uint8_t    handle_index;                  /* open handle index (0–255) — key component */
    uint8_t    readable;                      /* 1 if channel supports reading */
    uint8_t    writable;                      /* 1 if channel supports writing */
    uint8_t    from_cache;                    /* 1 if handle opened via read-through cache */
    uint8_t    is_regular;                    /* 1 for regular files, 0 for directories/collections */
    ngx_uint_t in_use;                        /* slot occupancy: 0=free, 1=published */
    dev_t      device;                        /* file device number — stale reference verification */
    ino_t      inode;                         /* file inode number — stale reference verification */
    off_t      cached_size;                   /* file size at publish time — read length validation */
    char       path[XROOTD_MAX_PATH + 1];     /* canonical confined path for reopen by secondary */
} xrootd_shared_handle_entry_t;

/* ---- Struct: xrootd_session_table_t ----
 *
 * WHAT: Shared-memory session registry table containing slot array for client session metadata. lock (ngx_shmtx_sh_t) must be first field — required by ngx_shmtx_create() which embeds the spinlock at the start of the shared region. slots array provides XROOTD_SESSION_REGISTRY_SLOTS entries (default 1024) for concurrent cross-worker session lookup, registration, and unregistration operations.
 */

typedef struct {
    ngx_shmtx_sh_t          lock;           /* must be first — shmtx init req */
    ngx_uint_t              capacity;       /* usable slot count (xrootd_session_slots) */
    xrootd_session_entry_t  slots[];        /* session registry entries — `capacity` long */
} xrootd_session_table_t;

/* ---- Struct: xrootd_shared_handle_table_t ----
 *
 * WHAT: Shared-memory handle table containing slot array for published file metadata. lock (ngx_shmtx_sh_t) must be first field — required by ngx_shmtx_create() which embeds the spinlock at the start of the shared region. slots array provides XROOTD_SESSION_HANDLE_SLOTS entries (= registry_slots × max_files) for concurrent cross-worker handle lookup, publishing, and unpublishing operations enabling bound stream secondary connections to access primary-published handles across worker boundaries.
 */

typedef struct {
    ngx_shmtx_sh_t                lock;     /* must be first — shmtx init req */
    xrootd_shared_handle_entry_t  slots[XROOTD_SESSION_HANDLE_SLOTS]; /* published handle entries */
} xrootd_shared_handle_table_t;

extern ngx_shm_zone_t *xrootd_session_shm_zone;     /* shared memory zone for session registry */
extern ngx_shm_zone_t *xrootd_handle_shm_zone;       /* shared memory zone for handle table */

/* ---- Function: xrootd_session_shm_init_zone() ----
 * WHAT: Shared-memory zone init callback — allocates mutex and initializes session table when zone first mapped by any worker process. Called during postconfiguration phase. Returns NGX_OK on success, NGX_ERROR if mutex creation fails. */
ngx_int_t xrootd_session_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);

/* ---- Function: xrootd_handle_shm_init_zone() ----
 * WHAT: Shared-memory zone init callback — allocates mutex and initializes handle table when zone first mapped by any worker process. Called during postconfiguration phase alongside session registry zone initialization. Returns NGX_OK on success, NGX_ERROR if mutex creation fails. */
ngx_int_t xrootd_handle_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);

/* ---- Function: xrootd_configure_session_registry() ----
 * WHAT: Creates two shared memory zones during nginx postconfiguration phase enabling cross-worker session persistence and handle publishing. First zone (xrootd_sessions): session registry for client metadata; second zone (xrootd_session_handles): handle table for published file metadata. Each zone registers init callback ensuring single initialization across all workers via sentinel value detection. Returns NGX_OK if both zones created successfully, NGX_ERROR otherwise. */
ngx_int_t xrootd_configure_session_registry(ngx_conf_t *cf, ngx_uint_t slots);

/* ---- Function: xrootd_session_register() ----
 * WHAT: Stores client session metadata in shared memory registry slot during login completion. Scans all slots finding first free entry — copies sessid[16], dn, vo_list, and token_auth flag into new slot setting e->in_use=1. Protected by zone-specific mutex ensuring thread-safe cross-worker access during concurrent registration attempts. */
void xrootd_session_register(const u_char sessid[XROOTD_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth);

/* ---- Function: xrootd_session_lookup() ----
 * WHAT: Retrieves session metadata for bound stream secondary connections or proxy mode — scans all slots comparing sessid via ngx_memcmp returning DN/VO list/token_auth if match found. Called by kXR_bind handler to inherit authentication state from primary session, and by proxy forwarding code to determine auth gate enforcement path based on token_auth flag. Returns 1 on success with output parameters populated, 0 indicating no match found. */
int xrootd_session_lookup(const u_char sessid[XROOTD_SESSION_ID_LEN],
    char *dn_out, size_t dn_size,
    char *vo_out, size_t vo_size,
    ngx_uint_t *token_auth_out);

/* ---- Function: xrootd_session_unregister() ----
 * WHAT: Clears session entry during kXR_endsess or disconnect cleanup — scans all slots comparing sessid, memzeros matching entry clearing session metadata; additionally unpublishing all associated handles via xrootd_session_handle_unpublish_all(). Called by kXR_endsess handler and xrootd_on_disconnect() ensuring complete cross-worker cleanup regardless of which worker originally registered the session. */
void xrootd_session_unregister(const u_char sessid[XROOTD_SESSION_ID_LEN]);

/* ---- Function: xrootd_session_handle_publish() ----
 * WHAT: Shares file handle metadata with other workers enabling bound stream secondary connections to read primary-published handles. Validates handle_index (0–255 range) and file state — searches handle table slots finding matching sessid+handle_index key or free slot; copies readable/writable/from_cache/is_regular/device/inode/cached_size/path metadata into entry setting e->in_use=1. Write-only handles rejected from publishing preventing bound stream misuse of write channels. */
void xrootd_session_handle_publish(
    const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, const xrootd_file_t *file);

/* ---- Function: xrootd_session_handle_lookup() ----
 * WHAT: Retrieves published handle metadata for bound stream read requests — searches slots by sessid+handle_index key matching returning copy of entry if found. Called by bound stream secondary connections to access primary-published handles when those handles were opened by a different worker process. Returns 1 on success with out populated, 0 indicating no published handle found for requested combination. */
int xrootd_session_handle_lookup(
    const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, xrootd_shared_handle_entry_t *out);

/* ---- Function: xrootd_session_handle_lookup_hint() ----
 * WHAT: As xrootd_session_handle_lookup() but with a caller-owned *inout_slot
 * cache (Phase 33 C2).  Re-checks the previously matched slot directly under the
 * lock before scanning, turning the per-read bound-stream lookup into O(1) while
 * preserving the full key (in_use+sessid+handle_index) revocation check.
 * *inout_slot is refreshed on a scan match, reset to -1 on miss; may be NULL. */
int xrootd_session_handle_lookup_hint(
    const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, int *inout_slot, xrootd_shared_handle_entry_t *out);

/* ---- Function: xrootd_session_handle_unpublish() ----
 * WHAT: Removes individual handle entry from shared table during kXR_close — searches slots by sessid+handle_index key matching, memzeros entry clearing all metadata preventing bound stream access to closed primary handles. Called after every file close operation ensuring no stale published references remain. */
void xrootd_session_handle_unpublish(
    const u_char sessid[XROOTD_SESSION_ID_LEN], int handle_index);

/* ---- Function: xrootd_session_handle_unpublish_all() ----
 * WHAT: Removes all handles associated with specific sessid during session termination — scans all in_use entries comparing sessid, memzeros matching entries ensuring no stale handle references remain after session end. Called by kXR_endsess handler and xrootd_session_unregister() to ensure complete cross-worker cleanup of published handles regardless of which worker originally published each handle. */
void xrootd_session_handle_unpublish_all(
    const u_char sessid[XROOTD_SESSION_ID_LEN]);

#endif /* XROOTD_SESSION_REGISTRY_H */
