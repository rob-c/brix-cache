/*
 * cns.c — Composite Cluster Name Space event codec + inventory host (§6). See cns.h.
 *
 * The inventory slot logic lives in cns_inventory.c (pure, POD). This file hosts
 * the backing store: an nginx SHM slab shared across every manager worker when a
 * `brix_cns_zone` is registered (brix_cns_configure, wired from
 * postconfiguration), else a lazily-allocated per-worker heap table for the
 * common single-worker redirector. All apply/stat/count run under the zone's
 * slab lock (SHM path) so concurrent workers never corrupt a slot.
 */

#include "cns.h"
#include "cns_inventory.h"
#include "core/compat/shm_slots.h"

#include <ngx_shmtx.h>
#include <stdlib.h>
#include <string.h>

extern ngx_module_t  ngx_stream_brix_module;

/* wire codec */
static void
put_u64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t) (v >> 56); p[1] = (uint8_t) (v >> 48);
    p[2] = (uint8_t) (v >> 40); p[3] = (uint8_t) (v >> 32);
    p[4] = (uint8_t) (v >> 24); p[5] = (uint8_t) (v >> 16);
    p[6] = (uint8_t) (v >> 8);  p[7] = (uint8_t) v;
}

static uint64_t
get_u64(const uint8_t *p)
{
    return ((uint64_t) p[0] << 56) | ((uint64_t) p[1] << 48)
         | ((uint64_t) p[2] << 40) | ((uint64_t) p[3] << 32)
         | ((uint64_t) p[4] << 24) | ((uint64_t) p[5] << 16)
         | ((uint64_t) p[6] << 8)  | (uint64_t) p[7];
}

size_t
brix_cns_event_encode(uint8_t op, const char *path, uint64_t size,
                        uint64_t mtime, uint8_t *buf, size_t bufsz)
{
    size_t plen = path ? strlen(path) : 0;

    if (plen == 0 || plen > BRIX_CNS_PATH_MAX
        || bufsz < BRIX_CNS_HDR_LEN + plen)
    {
        return 0;
    }
    buf[0] = op;
    buf[1] = buf[2] = buf[3] = 0;
    put_u64(buf + 4, size);
    put_u64(buf + 12, mtime);
    buf[20] = (uint8_t) (plen >> 8);
    buf[21] = (uint8_t) plen;
    memcpy(buf + BRIX_CNS_HDR_LEN, path, plen);
    return BRIX_CNS_HDR_LEN + plen;
}

ngx_int_t
brix_cns_event_decode(const uint8_t *buf, size_t len, uint8_t *op,
                        uint64_t *size, uint64_t *mtime, char *path,
                        size_t pathsz)
{
    size_t plen;

    if (buf == NULL || len < BRIX_CNS_HDR_LEN) {
        return NGX_ERROR;
    }
    plen = ((size_t) buf[20] << 8) | buf[21];
    if (plen == 0 || plen > BRIX_CNS_PATH_MAX
        || len < BRIX_CNS_HDR_LEN + plen || plen >= pathsz)
    {
        return NGX_ERROR;
    }
    *op    = buf[0];
    *size  = get_u64(buf + 4);
    *mtime = get_u64(buf + 12);
    memcpy(path, buf + BRIX_CNS_HDR_LEN, plen);
    path[plen] = '\0';
    return NGX_OK;
}

size_t
brix_cns_event_encode_mv(const char *oldpath, const char *newpath,
                           uint64_t size, uint64_t mtime, int is_dir,
                           uint8_t *buf, size_t bufsz)
{
    size_t olen = oldpath ? strlen(oldpath) : 0;
    size_t nlen = newpath ? strlen(newpath) : 0;
    size_t need;

    if (olen == 0 || olen > BRIX_CNS_PATH_MAX
        || nlen == 0 || nlen > BRIX_CNS_PATH_MAX)
    {
        return 0;
    }
    need = BRIX_CNS_HDR_LEN + olen + 2 + nlen;
    if (bufsz < need) {
        return 0;
    }

    if (brix_cns_event_encode(BRIX_CNS_MV, oldpath, size, mtime, buf,
                                bufsz) == 0)
    {
        return 0;
    }
    buf[1] = is_dir ? 1 : 0;               /* rsvd[0] carries the dest's dir-ness */
    buf[BRIX_CNS_HDR_LEN + olen]     = (uint8_t) (nlen >> 8);
    buf[BRIX_CNS_HDR_LEN + olen + 1] = (uint8_t) nlen;
    memcpy(buf + BRIX_CNS_HDR_LEN + olen + 2, newpath, nlen);
    return need;
}

ngx_int_t
brix_cns_event_decode_mv(const uint8_t *buf, size_t len, int *is_dir,
                           char *newpath, size_t newsz)
{
    size_t olen, nlen, off;

    if (buf == NULL || newpath == NULL || len < BRIX_CNS_HDR_LEN) {
        return NGX_ERROR;
    }
    olen = ((size_t) buf[20] << 8) | buf[21];
    off  = BRIX_CNS_HDR_LEN + olen;
    if (olen == 0 || olen > BRIX_CNS_PATH_MAX || len < off + 2) {
        return NGX_ERROR;
    }
    nlen = ((size_t) buf[off] << 8) | buf[off + 1];
    if (nlen == 0 || nlen > BRIX_CNS_PATH_MAX || len < off + 2 + nlen
        || nlen >= newsz)
    {
        return NGX_ERROR;
    }
    memcpy(newpath, buf + off + 2, nlen);
    newpath[nlen] = '\0';
    if (is_dir != NULL) {
        *is_dir = (buf[1] != 0);
    }
    return NGX_OK;
}

/* ===================== inventory backing store ===================== */

/* Cross-worker SHM zone (registered by brix_cns_configure). When present, the
 * inventory lives in its slab and cns_mtx (bound to the slab-pool lock) serialises
 * every worker's access. When absent, s_heap is a per-worker fallback table. */
static ngx_shm_zone_t  *cns_zone;
static ngx_shmtx_t      cns_mtx;
static ngx_uint_t       cns_slots_req;

static brix_cns_inv_t  *s_heap;              /* lazy per-worker fallback table */

static ngx_int_t
cns_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    brix_cns_inv_t *inv;
    ngx_flag_t      fresh;
    ngx_uint_t      cap = cns_slots_req ? cns_slots_req : BRIX_CNS_DEFAULT_SLOTS;

    inv = brix_shm_table_alloc(shm_zone, data,
                                 brix_cns_inv_bytes((uint32_t) cap),
                                 &cns_mtx, &fresh);
    if (inv == NULL) {
        return NGX_ERROR;
    }
    if (fresh) {
        brix_cns_inv_init(inv, (uint32_t) cap);   /* helper already zeroed slots */
    }
    return NGX_OK;
}

ngx_int_t
brix_cns_configure(ngx_conf_t *cf, ngx_uint_t slots)
{
    ngx_str_t  zone_name = ngx_string("brix_cns_inventory");
    size_t     zone_size;

    if (slots == 0) { slots = BRIX_CNS_DEFAULT_SLOTS; }
    cns_slots_req = slots;

    zone_size = brix_shm_zone_size(brix_cns_inv_bytes((uint32_t) slots));
    cns_zone  = ngx_shared_memory_add(cf, &zone_name, zone_size,
                                        &ngx_stream_brix_module);
    if (cns_zone == NULL) {
        return NGX_ERROR;
    }
    cns_zone->init = cns_init_zone;
    cns_zone->data = (void *) 1;
    return NGX_OK;
}

/* Resolve the live table. SHM when the zone is initialised; else the per-worker
 * heap fallback (lazily allocated). *shared reports whether cns_mtx must be held. */
static brix_cns_inv_t *
cns_active_table(ngx_flag_t *shared)
{
    if (cns_zone != NULL
        && cns_zone->data != NULL
        && cns_zone->data != (void *) 1)
    {
        *shared = 1;
        return (brix_cns_inv_t *) cns_zone->data;
    }
    *shared = 0;
    if (s_heap == NULL) {
        s_heap = calloc(1, brix_cns_inv_bytes(BRIX_CNS_DEFAULT_SLOTS));
        if (s_heap != NULL) {
            brix_cns_inv_init(s_heap, BRIX_CNS_DEFAULT_SLOTS);
        }
    }
    return s_heap;
}

ngx_int_t
brix_cns_apply(uint8_t op, const char *path, uint64_t size, uint64_t mtime,
                 uint32_t server_id)
{
    ngx_flag_t       shared;
    brix_cns_inv_t  *inv = cns_active_table(&shared);
    int              rc;

    if (inv == NULL) {
        return NGX_ERROR;
    }
    if (shared) { ngx_shmtx_lock(&cns_mtx); }
    rc = brix_cns_inv_apply(inv, op, path, size, mtime, server_id);
    if (shared) { ngx_shmtx_unlock(&cns_mtx); }
    return (rc == 0) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_cns_rename(const char *oldpath, const char *newpath, uint64_t size,
                  uint64_t mtime, int is_dir, uint32_t server_id)
{
    ngx_flag_t       shared;
    brix_cns_inv_t  *inv = cns_active_table(&shared);
    int              rc;

    if (inv == NULL) {
        return NGX_ERROR;
    }
    if (shared) { ngx_shmtx_lock(&cns_mtx); }
    rc = brix_cns_inv_rename(inv, oldpath, newpath, size, mtime, is_dir,
                               server_id);
    if (shared) { ngx_shmtx_unlock(&cns_mtx); }
    return (rc == 0) ? NGX_OK : NGX_ERROR;
}

ngx_int_t
brix_cns_stat(const char *path, struct stat *out)
{
    ngx_flag_t       shared;
    brix_cns_inv_t  *inv = cns_active_table(&shared);
    uint64_t         csize = 0, cmtime = 0;
    int              is_dir = 0, rc;

    if (out == NULL) {
        return NGX_ERROR;
    }
    if (inv == NULL) {
        return NGX_DECLINED;
    }
    if (shared) { ngx_shmtx_lock(&cns_mtx); }
    rc = brix_cns_inv_stat(inv, path, &csize, &cmtime, &is_dir);
    if (shared) { ngx_shmtx_unlock(&cns_mtx); }

    if (rc != 0) {
        return (rc < 0) ? NGX_ERROR : NGX_DECLINED;
    }
    ngx_memzero(out, sizeof(*out));
    out->st_size  = (off_t) csize;
    out->st_mtime = (time_t) cmtime;
    out->st_mode  = is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    out->st_nlink = 1;
    return NGX_OK;
}

static ngx_flag_t s_collect;

void
brix_cns_set_collect(ngx_flag_t on)
{
    if (on) {
        s_collect = 1;
    }
}

ngx_flag_t
brix_cns_collecting(void)
{
    return s_collect;
}
