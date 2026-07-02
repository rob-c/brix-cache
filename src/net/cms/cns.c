/*
 * cns.c — Composite Cluster Name Space inventory + event codec (§6). See cns.h.
 *
 * v1 inventory: a per-worker linear table (correct for a single-worker manager).
 * Each op is O(n) over a small federation namespace; a cross-worker SHM table and
 * a hashed index are documented follow-ups.
 */

#include "cns.h"

#include <stdlib.h>
#include <string.h>

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
xrootd_cns_event_encode(uint8_t op, const char *path, uint64_t size,
                        uint64_t mtime, uint8_t *buf, size_t bufsz)
{
    size_t plen = path ? strlen(path) : 0;

    if (plen == 0 || plen > XROOTD_CNS_PATH_MAX
        || bufsz < XROOTD_CNS_HDR_LEN + plen)
    {
        return 0;
    }
    buf[0] = op;
    buf[1] = buf[2] = buf[3] = 0;
    put_u64(buf + 4, size);
    put_u64(buf + 12, mtime);
    buf[20] = (uint8_t) (plen >> 8);
    buf[21] = (uint8_t) plen;
    memcpy(buf + XROOTD_CNS_HDR_LEN, path, plen);
    return XROOTD_CNS_HDR_LEN + plen;
}

ngx_int_t
xrootd_cns_event_decode(const uint8_t *buf, size_t len, uint8_t *op,
                        uint64_t *size, uint64_t *mtime, char *path,
                        size_t pathsz)
{
    size_t plen;

    if (buf == NULL || len < XROOTD_CNS_HDR_LEN) {
        return NGX_ERROR;
    }
    plen = ((size_t) buf[20] << 8) | buf[21];
    if (plen == 0 || plen > XROOTD_CNS_PATH_MAX
        || len < XROOTD_CNS_HDR_LEN + plen || plen >= pathsz)
    {
        return NGX_ERROR;
    }
    *op    = buf[0];
    *size  = get_u64(buf + 4);
    *mtime = get_u64(buf + 12);
    memcpy(path, buf + XROOTD_CNS_HDR_LEN, plen);
    path[plen] = '\0';
    return NGX_OK;
}

/* inventory (per-worker, v1) */
typedef struct {
    char     path[XROOTD_CNS_PATH_MAX + 1];
    uint64_t size;
    uint64_t mtime;
    uint32_t server_id;
    uint8_t  is_dir;
    uint8_t  used;
} cns_entry_t;

#define CNS_CAP 8192

static cns_entry_t *s_inv;       /* lazily allocated CNS_CAP-entry table */
static ngx_uint_t   s_count;

static cns_entry_t *
cns_find(const char *path)
{
    ngx_uint_t i;
    if (s_inv == NULL) {
        return NULL;
    }
    for (i = 0; i < CNS_CAP; i++) {
        if (s_inv[i].used && strcmp(s_inv[i].path, path) == 0) {
            return &s_inv[i];
        }
    }
    return NULL;
}

static cns_entry_t *
cns_free_slot(void)
{
    ngx_uint_t i;
    for (i = 0; i < CNS_CAP; i++) {
        if (!s_inv[i].used) {
            return &s_inv[i];
        }
    }
    return NULL;
}

ngx_int_t
xrootd_cns_apply(uint8_t op, const char *path, uint64_t size, uint64_t mtime,
                 uint32_t server_id)
{
    cns_entry_t *e;
    size_t       plen;

    if (path == NULL) {
        return NGX_ERROR;
    }
    plen = strlen(path);
    if (plen == 0 || plen > XROOTD_CNS_PATH_MAX) {
        return NGX_ERROR;
    }

    if (op == XROOTD_CNS_DEL || op == XROOTD_CNS_RMDIR) {
        e = cns_find(path);
        if (e != NULL) {
            e->used = 0;
            if (s_count > 0) { s_count--; }
        }
        return NGX_OK;
    }

    if (op != XROOTD_CNS_ADD && op != XROOTD_CNS_MKDIR) {
        return NGX_ERROR;
    }

    if (s_inv == NULL) {
        s_inv = calloc(CNS_CAP, sizeof(*s_inv));
        if (s_inv == NULL) {
            return NGX_ERROR;
        }
    }

    e = cns_find(path);
    if (e == NULL) {
        e = cns_free_slot();
        if (e == NULL) {
            return NGX_ERROR;   /* inventory full (v1 fixed cap) */
        }
        memcpy(e->path, path, plen);
        e->path[plen] = '\0';
        e->used = 1;
        s_count++;
    }
    e->size      = size;
    e->mtime     = mtime;
    e->server_id = server_id;
    e->is_dir    = (op == XROOTD_CNS_MKDIR) ? 1 : 0;
    return NGX_OK;
}

ngx_int_t
xrootd_cns_stat(const char *path, struct stat *out)
{
    cns_entry_t *e;

    if (path == NULL || out == NULL) {
        return NGX_ERROR;
    }
    e = cns_find(path);
    if (e == NULL) {
        return NGX_DECLINED;
    }
    ngx_memzero(out, sizeof(*out));
    out->st_size  = (off_t) e->size;
    out->st_mtime = (time_t) e->mtime;
    out->st_mode  = e->is_dir ? (S_IFDIR | 0755) : (S_IFREG | 0644);
    out->st_nlink = 1;
    return NGX_OK;
}

ngx_uint_t
xrootd_cns_count(void)
{
    return s_count;
}

static ngx_flag_t s_collect;

void
xrootd_cns_set_collect(ngx_flag_t on)
{
    if (on) {
        s_collect = 1;
    }
}

ngx_flag_t
xrootd_cns_collecting(void)
{
    return s_collect;
}
