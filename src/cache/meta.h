#ifndef XROOTD_CACHE_META_H
#define XROOTD_CACHE_META_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <sys/stat.h>

#define XROOTD_CACHE_META_ETAG_MAX 55

typedef struct {
    uint64_t mtime;
    uint64_t size;
    uint8_t  etag_len;
    char     etag[XROOTD_CACHE_META_ETAG_MAX];
} xrootd_cache_meta_t;

int xrootd_cache_meta_path(char *dst, size_t dstsz, const char *cache_path);
ngx_int_t xrootd_cache_meta_from_stat(const struct stat *st, const char *etag,
    xrootd_cache_meta_t *meta);
ngx_int_t xrootd_cache_meta_read(ngx_log_t *log, const char *cache_path,
    xrootd_cache_meta_t *meta);
ngx_int_t xrootd_cache_meta_write(ngx_log_t *log, const char *cache_path,
    const xrootd_cache_meta_t *meta);

#endif /* XROOTD_CACHE_META_H */
