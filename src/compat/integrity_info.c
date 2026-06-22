/*
 * integrity_info.c — shared checksum metadata and xattr cache service.
 *
 * WHAT: Provides a unified API for checksum retrieval that combines an
 *       xattr-backed cache layer with on-demand computation via the existing
 *       checksum helpers.
 * WHY:  Multiple protocol surfaces (native kXR_Qcksum, XrdHttp Want-Digest,
 *       dirlist dcksm, S3 ETag) need the same xattr cache key, cache trust
 *       policy, and HTTP Digest formatting.  Centralising this prevents drift
 *       in cache key names and format conversions.
 * HOW:  On a cache hit, reads "user.XrdCks.<alg>" xattr and validates hex
 *       digits.  On a cache miss, delegates to xrootd_checksum_hex_fd() and
 *       optionally writes the result back.  Invalidation removes all known
 *       algorithm xattrs so write paths can keep the cache consistent.
 */

#include "integrity_info.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <openssl/evp.h>

/* Format: "<hexval> <mtime_sec> <mtime_nsec> <size>" — 64 hex + " " + 3×20 + 3 seps + NUL */
#define INTEGRITY_XATTR_VAL_MAX  160

/* Supported algorithm names used for bulk xattr invalidation. */
static const char *const s_algorithms[] = {
    "adler32", "crc32", "crc32c", "md5", "sha1", "sha256",
    "crc64", "crc64nvme", "zcrc32", NULL
};

static const char *
integrity_xattr_key(const char *algo, char *buf, size_t bufsz)
{
    int n = snprintf(buf, bufsz, "user.XrdCks.%s", algo);
    if (n < 0 || (size_t) n >= bufsz) {
        return NULL;
    }
    return buf;
}

/* Returns 1 and populates out->hex if a valid, still-current cached value exists.
 * The xattr is stored as "<hex> <mtime_sec> <mtime_nsec> <size>"; if the file's
 * current mtime or size differs from what was stored the entry is treated as a
 * miss so the caller recomputes and refreshes the xattr. */
static int
integrity_xattr_read(int fd, const char *algo,
    xrootd_integrity_info_t *out)
{
    char        key[64];
    char        val[INTEGRITY_XATTR_VAL_MAX];
    char        cached_hex[INTEGRITY_XATTR_VAL_MAX];
    ssize_t     n;
    long        mtime_sec, mtime_nsec;
    long long   file_size;
    struct stat st;
    int         nread;
    size_t      i;

    if (integrity_xattr_key(algo, key, sizeof(key)) == NULL) {
        return 0;
    }

    n = fgetxattr(fd, key, val, sizeof(val) - 1);
    if (n <= 0) {
        return 0;
    }
    val[n] = '\0';

    nread = sscanf(val, "%127s %ld %ld %lld",
                   cached_hex, &mtime_sec, &mtime_nsec, &file_size);
    if (nread != 4) {
        return 0;   /* old format or corrupt — treat as miss */
    }

    /* Validate hex digits */
    for (i = 0; cached_hex[i] != '\0'; i++) {
        if (!isxdigit((unsigned char) cached_hex[i])) {
            return 0;
        }
    }
    if (i == 0) {
        return 0;
    }

    /* Check mtime+size against the live file — stale if changed */
    if (fstat(fd, &st) != 0) {
        return 0;
    }
    if ((long) st.st_mtim.tv_sec  != mtime_sec
        || (long) st.st_mtim.tv_nsec != mtime_nsec
        || (long long) st.st_size    != file_size)
    {
        return 0;
    }

    ngx_cpystrn((u_char *) out->hex, (u_char *) cached_hex, sizeof(out->hex));
    out->from_cache = 1;
    return 1;
}

static void
integrity_xattr_write(int fd, const char *algo, const char *hexval)
{
    char        key[64];
    char        val[INTEGRITY_XATTR_VAL_MAX];
    struct stat st;
    int         n;

    if (integrity_xattr_key(algo, key, sizeof(key)) == NULL) {
        return;
    }

    if (fstat(fd, &st) != 0) {
        return;   /* can't store mtime+size — skip cache write */
    }

    n = snprintf(val, sizeof(val), "%s %ld %ld %lld",
                 hexval,
                 (long) st.st_mtim.tv_sec, (long) st.st_mtim.tv_nsec,
                 (long long) st.st_size);
    if (n < 0 || (size_t) n >= sizeof(val)) {
        return;
    }

    (void) fsetxattr(fd, key, val, (size_t) n, 0);
}

/* Default policy when opts is NULL. */
static const xrootd_integrity_opts_t s_default_opts = {
    .allow_xattr_cache    = 1,
    .update_xattr_cache   = 1,
    .require_regular_file = 0,
};

ngx_int_t
xrootd_integrity_get_fd(ngx_log_t *log, int fd,
    const char *path, const char *alg_name,
    const xrootd_integrity_opts_t *opts,
    xrootd_integrity_info_t *out)
{
    char                          hex[EVP_MAX_MD_SIZE * 2 + 1];
    const xrootd_integrity_opts_t *o = (opts != NULL) ? opts : &s_default_opts;
    ngx_int_t                     parse_rc;

    ngx_memzero(out, sizeof(*out));

    /* Reject non-regular files early when required. */
    if (o->require_regular_file) {
        struct stat st;

        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            return NGX_DECLINED;
        }
    }

    /* Parse and canonicalize the algorithm name once. */
    parse_rc = xrootd_checksum_parse(alg_name, strlen(alg_name),
                                      &out->alg, out->alg_name,
                                      sizeof(out->alg_name));
    if (parse_rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check the xattr cache first when allowed. */
    if (o->allow_xattr_cache && integrity_xattr_read(fd, out->alg_name, out)) {
        return NGX_OK;
    }

    /* Cache-only callers (e.g. S3 GET/HEAD echo) decline on a miss rather than
     * pay a full-file read on a latency-sensitive path. */
    if (o->no_compute) {
        return NGX_DECLINED;
    }

    /* Compute the checksum. */
    if (xrootd_checksum_hex_fd(out->alg, fd, path, log,
                                hex, sizeof(hex)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) out->hex, (u_char *) hex, sizeof(out->hex));
    out->from_cache = 0;

    /* Update xattr cache on successful computation when permitted. */
    if (o->allow_xattr_cache && o->update_xattr_cache) {
        integrity_xattr_write(fd, out->alg_name, hex);
    }

    return NGX_OK;
}

ngx_int_t
xrootd_integrity_format_http_digest(const xrootd_integrity_info_t *info,
    char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%s=%s", info->alg_name, info->hex);

    if (n < 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
xrootd_integrity_invalidate_fd(ngx_log_t *log, int fd)
{
    char key[64];
    int  i;

    (void) log;

    for (i = 0; s_algorithms[i] != NULL; i++) {
        if (integrity_xattr_key(s_algorithms[i], key, sizeof(key)) != NULL) {
            (void) fremovexattr(fd, key);
        }
    }
}

void
xrootd_integrity_invalidate_path(ngx_log_t *log, const char *path)
{
    char key[64];
    int  i;

    (void) log;

    for (i = 0; s_algorithms[i] != NULL; i++) {
        if (integrity_xattr_key(s_algorithms[i], key, sizeof(key)) != NULL) {
            (void) removexattr(path, key);
        }
    }
}
