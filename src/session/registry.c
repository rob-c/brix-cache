#include "registry.h"
#include <ngx_shmtx.h>
#include <string.h>

ngx_shm_zone_t *xrootd_session_shm_zone;
ngx_shm_zone_t *xrootd_handle_shm_zone;

static ngx_shmtx_t  xrootd_session_mutex;
static ngx_shmtx_t  xrootd_handle_mutex;

static xrootd_session_table_t *
session_table(void)
{
    if (xrootd_session_shm_zone == NULL
        || xrootd_session_shm_zone->data == NULL
        || xrootd_session_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_session_table_t *) xrootd_session_shm_zone->data;
}

static xrootd_shared_handle_table_t *
handle_table(void)
{
    if (xrootd_handle_shm_zone == NULL
        || xrootd_handle_shm_zone->data == NULL
        || xrootd_handle_shm_zone->data == (void *) 1)
    {
        return NULL;
    }
    return (xrootd_shared_handle_table_t *) xrootd_handle_shm_zone->data;
}

ngx_int_t
xrootd_session_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_session_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (xrootd_session_table_t *) data;
        if (ngx_shmtx_create(&xrootd_session_mutex, &tbl->lock, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (xrootd_session_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&xrootd_session_mutex, &tbl->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

static ngx_int_t
xrootd_handle_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_shared_handle_table_t *tbl;

    if (data) {
        shm_zone->data = data;
        tbl = (xrootd_shared_handle_table_t *) data;
        if (ngx_shmtx_create(&xrootd_handle_mutex, &tbl->lock, NULL)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        return NGX_OK;
    }

    tbl = (xrootd_shared_handle_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&xrootd_handle_mutex, &tbl->lock, NULL) != NGX_OK) {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

ngx_int_t
xrootd_configure_session_registry(ngx_conf_t *cf)
{
    ngx_str_t  zone_name = ngx_string("xrootd_sessions");
    ngx_str_t  handle_zone_name = ngx_string("xrootd_session_handles");
    size_t     zone_size;

    zone_size = sizeof(xrootd_session_table_t) + ngx_pagesize;
    xrootd_session_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                     zone_size,
                                                     &ngx_stream_xrootd_module);
    if (xrootd_session_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_session_shm_zone->init = xrootd_session_shm_init_zone;
    xrootd_session_shm_zone->data = (void *) 1;

    zone_size = sizeof(xrootd_shared_handle_table_t) + ngx_pagesize;
    xrootd_handle_shm_zone = ngx_shared_memory_add(cf, &handle_zone_name,
                                                   zone_size,
                                                   &ngx_stream_xrootd_module);
    if (xrootd_handle_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_handle_shm_zone->init = xrootd_handle_shm_init_zone;
    xrootd_handle_shm_zone->data = (void *) 1;

    return NGX_OK;
}

void
xrootd_session_register(const u_char sessid[XROOTD_SESSION_ID_LEN],
    const char *dn, const char *vo_list, ngx_uint_t token_auth)
{
    xrootd_session_table_t *tbl;
    xrootd_session_entry_t *e;
    ngx_uint_t              i, free_slot;
    int                     found;

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_session_mutex);

    free_slot = XROOTD_SESSION_REGISTRY_SLOTS;
    found = 0;

    for (i = 0; i < XROOTD_SESSION_REGISTRY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            if (free_slot == XROOTD_SESSION_REGISTRY_SLOTS) {
                free_slot = i;
            }
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0) {
            found = 1;
            break;
        }
    }

    if (!found && free_slot < XROOTD_SESSION_REGISTRY_SLOTS) {
        e = &tbl->slots[free_slot];
        ngx_memcpy(e->sessid, sessid, XROOTD_SESSION_ID_LEN);
        ngx_cpystrn((u_char *) e->dn, (u_char *) (dn ? dn : ""),
                    sizeof(e->dn));
        ngx_cpystrn((u_char *) e->vo_list,
                    (u_char *) (vo_list ? vo_list : ""),
                    sizeof(e->vo_list));
        e->token_auth = token_auth;
        e->in_use = 1;
    }

    ngx_shmtx_unlock(&xrootd_session_mutex);
}

int
xrootd_session_lookup(const u_char sessid[XROOTD_SESSION_ID_LEN],
    char *dn_out, size_t dn_size,
    char *vo_out, size_t vo_size,
    ngx_uint_t *token_auth_out)
{
    xrootd_session_table_t *tbl;
    xrootd_session_entry_t *e;
    ngx_uint_t              i;
    int                     found = 0;

    tbl = session_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_session_mutex);

    for (i = 0; i < XROOTD_SESSION_REGISTRY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (!e->in_use) {
            continue;
        }
        if (ngx_memcmp(e->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0) {
            ngx_cpystrn((u_char *) dn_out, (u_char *) e->dn, dn_size);
            ngx_cpystrn((u_char *) vo_out, (u_char *) e->vo_list, vo_size);
            *token_auth_out = e->token_auth;
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_session_mutex);
    return found;
}

static ngx_flag_t
xrootd_shared_handle_same_key(const xrootd_shared_handle_entry_t *entry,
    const u_char sessid[XROOTD_SESSION_ID_LEN], int handle_index)
{
    return entry->in_use
           && entry->handle_index == (uint8_t) handle_index
           && ngx_memcmp(entry->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0;
}

void
xrootd_session_handle_publish(const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, const xrootd_file_t *file)
{
    xrootd_shared_handle_table_t *tbl;
    xrootd_shared_handle_entry_t *entry;
    ngx_uint_t                    i, free_slot;
    size_t                        path_len;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES
        || file == NULL || file->fd < 0)
    {
        return;
    }

    tbl = handle_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_handle_mutex);

    free_slot = XROOTD_SESSION_HANDLE_SLOTS;
    entry = NULL;

    for (i = 0; i < XROOTD_SESSION_HANDLE_SLOTS; i++) {
        if (xrootd_shared_handle_same_key(&tbl->slots[i], sessid,
                                          handle_index))
        {
            entry = &tbl->slots[i];
            break;
        }

        if (!tbl->slots[i].in_use
            && free_slot == XROOTD_SESSION_HANDLE_SLOTS)
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
        ngx_shmtx_unlock(&xrootd_handle_mutex);
        return;
    }

    path_len = ngx_strlen(file->path);
    if (path_len > XROOTD_MAX_PATH) {
        if (entry != NULL) {
            ngx_memzero(entry, sizeof(*entry));
        }
        ngx_shmtx_unlock(&xrootd_handle_mutex);
        return;
    }

    if (entry == NULL) {
        if (free_slot == XROOTD_SESSION_HANDLE_SLOTS) {
            ngx_shmtx_unlock(&xrootd_handle_mutex);
            return;
        }
        entry = &tbl->slots[free_slot];
    }

    ngx_memzero(entry, sizeof(*entry));
    ngx_memcpy(entry->sessid, sessid, XROOTD_SESSION_ID_LEN);
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

    ngx_shmtx_unlock(&xrootd_handle_mutex);
}

int
xrootd_session_handle_lookup(const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index, xrootd_shared_handle_entry_t *out)
{
    xrootd_shared_handle_table_t *tbl;
    ngx_uint_t                    i;
    int                           found = 0;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES || out == NULL) {
        return 0;
    }

    tbl = handle_table();
    if (tbl == NULL) {
        return 0;
    }

    ngx_shmtx_lock(&xrootd_handle_mutex);

    for (i = 0; i < XROOTD_SESSION_HANDLE_SLOTS; i++) {
        if (xrootd_shared_handle_same_key(&tbl->slots[i], sessid,
                                          handle_index))
        {
            ngx_memcpy(out, &tbl->slots[i], sizeof(*out));
            out->path[XROOTD_MAX_PATH] = '\0';
            found = 1;
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_handle_mutex);
    return found;
}

void
xrootd_session_handle_unpublish(const u_char sessid[XROOTD_SESSION_ID_LEN],
    int handle_index)
{
    xrootd_shared_handle_table_t *tbl;
    ngx_uint_t                    i;

    if (handle_index < 0 || handle_index >= XROOTD_MAX_FILES) {
        return;
    }

    tbl = handle_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_handle_mutex);

    for (i = 0; i < XROOTD_SESSION_HANDLE_SLOTS; i++) {
        if (xrootd_shared_handle_same_key(&tbl->slots[i], sessid,
                                          handle_index))
        {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_handle_mutex);
}

void
xrootd_session_handle_unpublish_all(
    const u_char sessid[XROOTD_SESSION_ID_LEN])
{
    xrootd_shared_handle_table_t *tbl;
    ngx_uint_t                    i;

    tbl = handle_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_handle_mutex);

    for (i = 0; i < XROOTD_SESSION_HANDLE_SLOTS; i++) {
        if (tbl->slots[i].in_use
            && ngx_memcmp(tbl->slots[i].sessid, sessid,
                          XROOTD_SESSION_ID_LEN) == 0)
        {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
        }
    }

    ngx_shmtx_unlock(&xrootd_handle_mutex);
}

void
xrootd_session_unregister(const u_char sessid[XROOTD_SESSION_ID_LEN])
{
    xrootd_session_table_t *tbl;
    xrootd_session_entry_t *e;
    ngx_uint_t              i;

    tbl = session_table();
    if (tbl == NULL) {
        return;
    }

    ngx_shmtx_lock(&xrootd_session_mutex);

    for (i = 0; i < XROOTD_SESSION_REGISTRY_SLOTS; i++) {
        e = &tbl->slots[i];
        if (e->in_use
            && ngx_memcmp(e->sessid, sessid, XROOTD_SESSION_ID_LEN) == 0)
        {
            ngx_memzero(e, sizeof(*e));
            break;
        }
    }

    ngx_shmtx_unlock(&xrootd_session_mutex);
    xrootd_session_handle_unpublish_all(sessid);
}
