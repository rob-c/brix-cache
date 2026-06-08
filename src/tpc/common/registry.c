#include "registry.h"

#include "../../ngx_xrootd_module.h"

#include <string.h>

typedef struct {
    ngx_uint_t              in_use;
    xrootd_tpc_transfer_t   transfer;
    u_char                  src_url_data[XROOTD_TPC_SRC_URL_MAX];
    u_char                  dst_path_data[XROOTD_TPC_DST_PATH_MAX];
} xrootd_tpc_registry_entry_t;

typedef struct {
    ngx_shmtx_sh_t              lock;
    xrootd_tpc_registry_entry_t slots[XROOTD_TPC_REGISTRY_SLOTS];
} xrootd_tpc_registry_table_t;

static ngx_shm_zone_t *xrootd_tpc_registry_shm_zone;
static ngx_shmtx_t     xrootd_tpc_registry_mutex;
static uint64_t        xrootd_tpc_registry_sequence;

static xrootd_tpc_registry_table_t *
xrootd_tpc_registry_table(void)
{
    if (xrootd_tpc_registry_shm_zone == NULL
        || xrootd_tpc_registry_shm_zone->data == NULL
        || xrootd_tpc_registry_shm_zone->data == (void *) 1)
    {
        return NULL;
    }

    return (xrootd_tpc_registry_table_t *) xrootd_tpc_registry_shm_zone->data;
}

static ngx_int_t
xrootd_tpc_registry_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    xrootd_tpc_registry_table_t *tbl;

    if (data != NULL) {
        shm_zone->data = data;
        tbl = data;
        return ngx_shmtx_create(&xrootd_tpc_registry_mutex, &tbl->lock,
                                NULL);
    }

    tbl = (xrootd_tpc_registry_table_t *) shm_zone->shm.addr;
    ngx_memzero(tbl, sizeof(*tbl));

    if (ngx_shmtx_create(&xrootd_tpc_registry_mutex, &tbl->lock, NULL)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    shm_zone->data = tbl;
    return NGX_OK;
}

ngx_int_t
xrootd_tpc_registry_configure(ngx_conf_t *cf)
{
    ngx_str_t zone_name = ngx_string("xrootd_tpc_transfers");
    size_t    zone_size;

    zone_size = sizeof(xrootd_tpc_registry_table_t) + ngx_pagesize;
    xrootd_tpc_registry_shm_zone = ngx_shared_memory_add(
        cf, &zone_name, zone_size, &ngx_stream_xrootd_module);

    if (xrootd_tpc_registry_shm_zone == NULL) {
        return NGX_ERROR;
    }

    xrootd_tpc_registry_shm_zone->init = xrootd_tpc_registry_shm_init;
    xrootd_tpc_registry_shm_zone->data = (void *) 1;

    return NGX_OK;
}

static uint64_t
xrootd_tpc_registry_next_id(void)
{
    uint64_t id;

    xrootd_tpc_registry_sequence++;
    id = (((uint64_t) ngx_time()) << 32)
         ^ (((uint64_t) ngx_pid) << 16)
         ^ xrootd_tpc_registry_sequence;

    return id == 0 ? 1 : id;
}

static void
xrootd_tpc_registry_copy_str(ngx_str_t *dst, u_char *storage,
    size_t storage_len, const ngx_str_t *src)
{
    size_t copy_len;

    if (dst == NULL || storage == NULL || storage_len == 0) {
        return;
    }

    dst->data = storage;
    dst->len = 0;
    storage[0] = '\0';

    if (src == NULL || src->data == NULL || src->len == 0) {
        return;
    }

    copy_len = src->len;
    if (copy_len >= storage_len) {
        copy_len = storage_len - 1;
    }

    ngx_memcpy(storage, src->data, copy_len);
    storage[copy_len] = '\0';
    dst->len = copy_len;
}

uint64_t
xrootd_tpc_registry_add(const xrootd_tpc_transfer_t *transfer, ngx_log_t *log)
{
    xrootd_tpc_registry_table_t *tbl;
    xrootd_tpc_registry_entry_t *entry;
    ngx_uint_t                   i;
    ngx_uint_t                   free_slot;
    time_t                       now;
    uint64_t                     id;

    tbl = xrootd_tpc_registry_table();
    if (tbl == NULL || transfer == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_tpc: transfer registry is unavailable");
        return 0;
    }

    now = ngx_time();
    id = xrootd_tpc_registry_next_id();

    ngx_shmtx_lock(&xrootd_tpc_registry_mutex);

    free_slot = XROOTD_TPC_REGISTRY_SLOTS;
    for (i = 0; i < XROOTD_TPC_REGISTRY_SLOTS; i++) {
        if (!tbl->slots[i].in_use) {
            free_slot = i;
            break;
        }
    }

    if (free_slot == XROOTD_TPC_REGISTRY_SLOTS) {
        ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_tpc: transfer registry is full");
        return 0;
    }

    entry = &tbl->slots[free_slot];
    ngx_memzero(entry, sizeof(*entry));

    entry->in_use = 1;
    entry->transfer = *transfer;
    entry->transfer.id = id;
    entry->transfer.started_at = now;
    entry->transfer.updated_at = now;
    if (entry->transfer.state == 0) {
        entry->transfer.state = XROOTD_TPC_STATE_PENDING;
    }

    xrootd_tpc_registry_copy_str(&entry->transfer.src_url,
                                 entry->src_url_data,
                                 sizeof(entry->src_url_data),
                                 &transfer->src_url);
    xrootd_tpc_registry_copy_str(&entry->transfer.dst_path,
                                 entry->dst_path_data,
                                 sizeof(entry->dst_path_data),
                                 &transfer->dst_path);

    ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);

    return id;
}

ngx_int_t
xrootd_tpc_registry_update(uint64_t id, off_t bytes_done, ngx_uint_t state,
    ngx_log_t *log)
{
    xrootd_tpc_registry_table_t *tbl;
    xrootd_tpc_registry_entry_t *entry;
    ngx_uint_t                   i;

    if (id == 0) {
        return NGX_OK;
    }

    tbl = xrootd_tpc_registry_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&xrootd_tpc_registry_mutex);

    for (i = 0; i < XROOTD_TPC_REGISTRY_SLOTS; i++) {
        entry = &tbl->slots[i];
        if (entry->in_use && entry->transfer.id == id) {
            entry->transfer.bytes_done = bytes_done;
            if (state != 0) {
                entry->transfer.state = state;
            }
            entry->transfer.updated_at = ngx_time();
            ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);
            return NGX_OK;
        }
    }

    ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);
    if (log != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, log, 0,
                       "xrootd_tpc: transfer id %uL not found for update",
                       id);
    }
    return NGX_DECLINED;
}

ngx_int_t
xrootd_tpc_registry_remove(uint64_t id, ngx_log_t *log)
{
    xrootd_tpc_registry_table_t *tbl;
    ngx_uint_t                   i;

    (void) log;

    if (id == 0) {
        return NGX_OK;
    }

    tbl = xrootd_tpc_registry_table();
    if (tbl == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&xrootd_tpc_registry_mutex);

    for (i = 0; i < XROOTD_TPC_REGISTRY_SLOTS; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].transfer.id == id) {
            ngx_memzero(&tbl->slots[i], sizeof(tbl->slots[i]));
            ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);
            return NGX_OK;
        }
    }

    ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);
    return NGX_DECLINED;
}

ngx_uint_t
xrootd_tpc_registry_snapshot(xrootd_tpc_transfer_snapshot_t *out,
    ngx_uint_t max_transfers)
{
    xrootd_tpc_registry_table_t *tbl;
    xrootd_tpc_registry_entry_t *entry;
    ngx_uint_t                   i;
    ngx_uint_t                   n;

    if (out == NULL || max_transfers == 0) {
        return 0;
    }

    tbl = xrootd_tpc_registry_table();
    if (tbl == NULL) {
        return 0;
    }

    n = 0;
    ngx_shmtx_lock(&xrootd_tpc_registry_mutex);

    for (i = 0; i < XROOTD_TPC_REGISTRY_SLOTS && n < max_transfers; i++) {
        entry = &tbl->slots[i];
        if (!entry->in_use) {
            continue;
        }

        out[n].id = entry->transfer.id;
        out[n].protocol = entry->transfer.protocol;
        out[n].direction = entry->transfer.direction;
        out[n].bytes_total = entry->transfer.bytes_total;
        out[n].bytes_done = entry->transfer.bytes_done;
        out[n].started_at = entry->transfer.started_at;
        out[n].updated_at = entry->transfer.updated_at;
        out[n].state = entry->transfer.state;

        ngx_memcpy(out[n].src_url, entry->src_url_data,
                   sizeof(out[n].src_url));
        ngx_memcpy(out[n].dst_path, entry->dst_path_data,
                   sizeof(out[n].dst_path));
        out[n].src_url[sizeof(out[n].src_url) - 1] = '\0';
        out[n].dst_path[sizeof(out[n].dst_path) - 1] = '\0';
        n++;
    }

    ngx_shmtx_unlock(&xrootd_tpc_registry_mutex);

    return n;
}

const xrootd_tpc_transfer_t *
xrootd_tpc_registry_find(uint64_t id)
{
    xrootd_tpc_registry_table_t *tbl;
    ngx_uint_t                   i;

    if (id == 0) {
        return NULL;
    }

    tbl = xrootd_tpc_registry_table();
    if (tbl == NULL) {
        return NULL;
    }

    for (i = 0; i < XROOTD_TPC_REGISTRY_SLOTS; i++) {
        if (tbl->slots[i].in_use && tbl->slots[i].transfer.id == id) {
            return &tbl->slots[i].transfer;
        }
    }

    return NULL;
}
