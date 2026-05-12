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
 * Capacity: XROOTD_SESSION_REGISTRY_SLOTS entries (default 256).  When the
 * table is full, new inserts fail gracefully — the primary session continues
 * normally and secondaries fall back to single-stream I/O.
 */

#include "../ngx_xrootd_module.h"

#define XROOTD_SESSION_REGISTRY_SLOTS  256
#define XROOTD_SESSION_HANDLE_SLOTS \
    (XROOTD_SESSION_REGISTRY_SLOTS * XROOTD_MAX_FILES)

typedef struct {
    u_char     sessid[XROOTD_SESSION_ID_LEN];
    char       dn[512];
    char       vo_list[512];
    ngx_uint_t token_auth;
    ngx_uint_t in_use;
} xrootd_session_entry_t;

typedef struct {
    u_char     sessid[XROOTD_SESSION_ID_LEN];
    uint8_t    handle_index;
    uint8_t    readable;
    uint8_t    writable;
    uint8_t    from_cache;
    uint8_t    is_regular;
    ngx_uint_t in_use;
    dev_t      device;
    ino_t      inode;
    off_t      cached_size;
    char       path[XROOTD_MAX_PATH + 1];
} xrootd_shared_handle_entry_t;

typedef struct {
    ngx_shmtx_sh_t          lock;           /* must be first — shmtx init req */
    xrootd_session_entry_t  slots[XROOTD_SESSION_REGISTRY_SLOTS];
} xrootd_session_table_t;

typedef struct {
    ngx_shmtx_sh_t                lock;     /* must be first — shmtx init req */
    xrootd_shared_handle_entry_t  slots[XROOTD_SESSION_HANDLE_SLOTS];
} xrootd_shared_handle_table_t;

extern ngx_shm_zone_t *xrootd_session_shm_zone;
extern ngx_shm_zone_t *xrootd_handle_shm_zone;

ngx_int_t xrootd_session_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t xrootd_configure_session_registry(ngx_conf_t *cf);

void xrootd_session_register(const u_char sessid[XROOTD_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth);

int xrootd_session_lookup(const u_char sessid[XROOTD_SESSION_ID_LEN],
    char *dn_out, size_t dn_size,
    char *vo_out, size_t vo_size,
    ngx_uint_t *token_auth_out);

void xrootd_session_unregister(const u_char sessid[XROOTD_SESSION_ID_LEN]);

void xrootd_session_handle_publish(
    const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, const xrootd_file_t *file);

int xrootd_session_handle_lookup(
    const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, xrootd_shared_handle_entry_t *out);

void xrootd_session_handle_unpublish(
    const u_char sessid[XROOTD_SESSION_ID_LEN], int handle_index);

void xrootd_session_handle_unpublish_all(
    const u_char sessid[XROOTD_SESSION_ID_LEN]);

#endif /* XROOTD_SESSION_REGISTRY_H */
