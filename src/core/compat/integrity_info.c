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
 *       digits.  On a cache miss, delegates to brix_checksum_hex_fd() and
 *       optionally writes the result back.  Invalidation removes all known
 *       algorithm xattrs so write paths can keep the cache consistent.
 */

#include "integrity_info.h"
#include "integrity_info_internal.h"   /* INTEGRITY_XATTR_VAL_MAX + record-fallback decls */
#include "fs/vfs/vfs.h"   /* fd-based xattr via the VFS seam */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>

/* INTEGRITY_XATTR_VAL_MAX (the shared xattr/record value-buffer size) now lives
 * in integrity_info_internal.h so both this file and integrity_info_record.c use
 * one definition. */

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

/* official XrdCks/XrdCksData binary record (§8.1 interop) * Stock xrootd stores the checksum in the SAME xattr ("user.XrdCks.<alg>") as a
 * binary XrdCksData struct (host byte order, ADR-4). We can both read and (opt-in)
 * write it so `xrdfs query checksum` / XrdOss interoperate. Layout mirrors
 * XrdCks/XrdCksData.hh. */
struct xrd_cks_data {
    char      Name[16];   /* algo name, NUL-padded */
    long long fmTime;     /* file mtime (sec) when computed */
    int       csTime;     /* delta secs fmTime→compute */
    short     Rsvd1;
    char      Rsvd2;
    char      Length;     /* digest length in bytes */
    char      Value[64];  /* binary digest */
};

static int
cks_hex_nibble(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

size_t
brix_cksdata_encode(const brix_integrity_info_t *in, time_t fmtime,
    unsigned char *out)
{
    struct xrd_cks_data d;
    size_t              hexlen = ngx_strlen(in->hex);
    int                 i, dl = (int) (hexlen / 2);

    ngx_memzero(&d, sizeof(d));
    ngx_cpystrn((u_char *) d.Name, (u_char *) in->alg_name, sizeof(d.Name));
    d.fmTime = (long long) fmtime;
    d.csTime = 0;
    if (dl > (int) sizeof(d.Value)) { dl = (int) sizeof(d.Value); }
    d.Length = (char) dl;
    for (i = 0; i < dl; i++) {
        int hi = cks_hex_nibble((unsigned char) in->hex[2 * i]);
        int lo = cks_hex_nibble((unsigned char) in->hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { return 0; }
        d.Value[i] = (char) ((hi << 4) | lo);
    }
    ngx_memcpy(out, &d, sizeof(d));
    return sizeof(d);
}

int
brix_cksdata_decode(const unsigned char *buf, size_t len, time_t cur_mtime,
    brix_integrity_info_t *out)
{
    static const char hx[] = "0123456789abcdef";
    struct xrd_cks_data d;
    int                 i;

    if (len != sizeof(d)) {
        return 0;
    }
    ngx_memcpy(&d, buf, sizeof(d));
    if (d.Length <= 0 || d.Length > (char) sizeof(d.Value)) {
        return 0;
    }
    if (cur_mtime != (time_t) 0 && (time_t) d.fmTime != cur_mtime) {
        return 0;   /* stale → recompute */
    }
    for (i = 0; i < d.Length; i++) {
        out->hex[2 * i]     = hx[(d.Value[i] >> 4) & 0xf];
        out->hex[2 * i + 1] = hx[d.Value[i] & 0xf];
    }
    out->hex[2 * d.Length] = '\0';
    /* Name in the record is authoritative for the algorithm label. */
    {
        size_t j;
        for (j = 0; j < sizeof(d.Name) && d.Name[j]; j++) { }
        if (j > 0 && j < sizeof(out->alg_name)) {
            ngx_memcpy(out->alg_name, d.Name, j);
            out->alg_name[j] = '\0';
        }
    }
    out->from_cache = 1;
    return 1;
}

/* Returns 1 and populates out->hex if a valid, still-current cached value exists.
 * The xattr is stored as "<hex> <mtime_sec> <mtime_nsec> <size>"; if the file's
 * current mtime or size differs from what was stored the entry is treated as a
 * miss so the caller recomputes and refreshes the xattr. */
static int
integrity_xattr_read(int fd, const char *algo,
    brix_integrity_info_t *out)
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

    n = brix_vfs_fgetxattr(NULL, fd, key, val, sizeof(val) - 1);
    if (n <= 0) {
        return 0;
    }

    /* §8.1: a stock-xrootd value is a binary XrdCksData record (exact size). Decode
     * it (mtime-validated against the live file) so we interoperate with
     * `xrdfs query checksum` / XrdOss without recomputing. */
    if ((size_t) n == sizeof(struct xrd_cks_data)) {
        struct stat bst;
        time_t      cur = (fstat(fd, &bst) == 0) ? bst.st_mtim.tv_sec : (time_t) 0;
        if (brix_cksdata_decode((const unsigned char *) val, (size_t) n,
                                  cur, out))
        {
            return 1;
        }
        return 0;   /* binary-sized but stale/invalid → miss */
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

/* §8.x process-global WRITE format (default text; reader handles either). */
static ngx_uint_t s_xattr_format = BRIX_CKS_FMT_TEXT;

void
brix_integrity_set_xattr_format(ngx_uint_t fmt)
{
    if (fmt == BRIX_CKS_FMT_TEXT || fmt == BRIX_CKS_FMT_XRDCKS) {
        s_xattr_format = fmt;
    }
}

/* Writes the checksum xattr and reports the fsetxattr errno (0 on success) so the
 * caller can fall back to a sidecar file when the filesystem lacks user xattrs.
 * Emits the binary XrdCksData record (stock-interoperable) when the configured
 * format is XRDCKS, else our text record. */
static int
integrity_xattr_write_rc(int fd, const char *algo, const char *hexval)
{
    char        key[64];
    char        val[INTEGRITY_XATTR_VAL_MAX];
    struct stat st;
    int         n;

    if (integrity_xattr_key(algo, key, sizeof(key)) == NULL) {
        return EINVAL;
    }
    if (fstat(fd, &st) != 0) {
        return errno;
    }

    if (s_xattr_format == BRIX_CKS_FMT_XRDCKS) {
        brix_integrity_info_t tmp;
        unsigned char           rec[sizeof(struct xrd_cks_data)];
        size_t                  rn;

        ngx_memzero(&tmp, sizeof(tmp));
        ngx_cpystrn((u_char *) tmp.alg_name, (u_char *) algo,
                    sizeof(tmp.alg_name));
        ngx_cpystrn((u_char *) tmp.hex, (u_char *) hexval, sizeof(tmp.hex));
        rn = brix_cksdata_encode(&tmp, st.st_mtim.tv_sec, rec);
        if (rn == 0) {
            return EINVAL;
        }
        if (brix_vfs_fsetxattr(NULL, fd, key, rec, rn, 0) != NGX_OK) {
            return errno;
        }
        return 0;
    }

    n = snprintf(val, sizeof(val), "%s %ld %ld %lld", hexval,
                 (long) st.st_mtim.tv_sec, (long) st.st_mtim.tv_nsec,
                 (long long) st.st_size);
    if (n < 0 || (size_t) n >= sizeof(val)) {
        return EINVAL;
    }
    if (brix_vfs_fsetxattr(NULL, fd, key, val, (size_t) n, 0) != NGX_OK) {
        return errno;
    }
    return 0;
}

/* The §8.2 record-DIGEST fallback (integrity_alg_id / integrity_record_read /
 * integrity_record_write) lives in integrity_info_record.c; the read/write
 * entry points are declared in integrity_info_internal.h. */

/* Default policy when opts is NULL. */
static const brix_integrity_opts_t s_default_opts = {
    .allow_xattr_cache    = 1,
    .update_xattr_cache   = 1,
    .require_regular_file = 0,
};

/*
 * WHAT: Reports whether the target is NOT a regular file.
 * WHY:  Checksum callers that set require_regular_file must decline on
 *       directories/devices, but the file type lives in different places for
 *       the two object kinds.
 * HOW:  A driver-backed object carries its type in the open snapshot (its bare
 *       fd is only block 0); a plain fd is queried via fstat().
 */
static int
integrity_is_nonregular(int fd, const brix_sd_obj_t *obj, int driver_backed)
{
    struct stat st;

    if (driver_backed) {
        return !obj->snap.is_reg;
    }
    return (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode));
}

/*
 * WHAT: Looks up a still-current cached checksum for out->alg_name.
 * WHY:  Two cache layers must be tried in a fixed order so a hit in either
 *       short-circuits the (expensive) full-file recompute.
 * HOW:  Tries the xattr cache first, then the record-DIGEST fallback (§8.2) for
 *       exports without user xattrs; either populates out and returns 1 on hit.
 */
static int
integrity_cache_lookup(int fd, const char *path, brix_integrity_info_t *out)
{
    if (integrity_xattr_read(fd, out->alg_name, out)) {
        return 1;
    }
    if (integrity_record_read(path, out->alg_name, out)) {
        return 1;
    }
    return 0;
}

/*
 * WHAT: Computes the checksum hex for the target object.
 * WHY:  A backend-bound object must be read through its driver (every block),
 *       whereas a plain fd uses the default POSIX-fd kernel.
 * HOW:  Dispatches on driver_backed and returns the underlying helper's status
 *       (NGX_OK on success) verbatim.
 */
static ngx_int_t
integrity_compute_hex(ngx_log_t *log, int fd, brix_sd_obj_t *obj,
    const char *path, int driver_backed, const brix_integrity_info_t *out,
    char *hex, size_t hexsz)
{
    if (driver_backed) {
        return brix_checksum_hex_obj(out->alg, obj, path, log, hex, hexsz);
    }
    return brix_checksum_hex_fd(out->alg, fd, path, log, hex, hexsz);
}

/*
 * WHAT: Persists a freshly computed checksum back to the cache.
 * WHY:  The xattr cache is preferred, but filesystems without user xattrs must
 *       still cache the value so future reads avoid a recompute.
 * HOW:  Writes the xattr first; on ENOTSUP/EOPNOTSUPP/EPERM falls back to a
 *       DIGEST entry in the file's unified xmeta record (§8.2, xmeta P4).
 */
static void
integrity_persist_computed(int fd, const char *path, const char *alg_name,
    const char *hex)
{
    int wrc = integrity_xattr_write_rc(fd, alg_name, hex);

    if (wrc == ENOTSUP
#ifdef EOPNOTSUPP
        || wrc == EOPNOTSUPP
#endif
        || wrc == EPERM) {
        integrity_record_write(path, alg_name, hex);
    }
}

ngx_int_t
brix_integrity_get_fd(ngx_log_t *log, int fd,
    brix_sd_obj_t *obj, const char *path, const char *alg_name,
    const brix_integrity_opts_t *opts,
    brix_integrity_info_t *out)
{
    int driver_backed = (obj != NULL && obj->driver != NULL);

    char                          hex[EVP_MAX_MD_SIZE * 2 + 1];
    const brix_integrity_opts_t *o = (opts != NULL) ? opts : &s_default_opts;
    ngx_int_t                     parse_rc;

    ngx_memzero(out, sizeof(*out));

    /* Reject non-regular files early when required. */
    if (o->require_regular_file
        && integrity_is_nonregular(fd, obj, driver_backed))
    {
        return NGX_DECLINED;
    }

    /* Parse and canonicalize the algorithm name once. */
    parse_rc = brix_checksum_parse(alg_name, strlen(alg_name),
                                      &out->alg, out->alg_name,
                                      sizeof(out->alg_name));
    if (parse_rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check the xattr cache first when allowed, then the record-DIGEST
     * fallback (§8.2) for exports without user xattrs. */
    if (o->allow_xattr_cache && integrity_cache_lookup(fd, path, out)) {
        return NGX_OK;
    }

    /* Cache-only callers (e.g. S3 GET/HEAD echo) decline on a miss rather than
     * pay a full-file read on a latency-sensitive path. */
    if (o->no_compute) {
        return NGX_DECLINED;
    }

    if (integrity_compute_hex(log, fd, obj, path, driver_backed, out,
                              hex, sizeof(hex)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) out->hex, (u_char *) hex, sizeof(out->hex));
    out->from_cache = 0;

    /* Persist the computed value: xattr first, xmeta-record fallback (§8.2). */
    if (o->allow_xattr_cache && o->update_xattr_cache) {
        integrity_persist_computed(fd, path, out->alg_name, hex);
    }

    return NGX_OK;
}

ngx_int_t
brix_integrity_format_http_digest(const brix_integrity_info_t *info,
    char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%s=%s", info->alg_name, info->hex);

    if (n < 0 || (size_t) n >= outsz) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
brix_integrity_invalidate_fd(ngx_log_t *log, int fd)
{
    char key[64];
    int  i;

    (void) log;

    for (i = 0; s_algorithms[i] != NULL; i++) {
        if (integrity_xattr_key(s_algorithms[i], key, sizeof(key)) != NULL) {
            (void) brix_vfs_fremovexattr(NULL, fd, key);
        }
    }
}

void
brix_integrity_invalidate_path(ngx_log_t *log, const char *root_canon,
    const char *path)
{
    brix_vfs_ctx_t vctx;
    char             key[64];
    int              i;

    brix_vfs_ctx_init(&vctx, NULL, log, BRIX_PROTO_ROOT, root_canon,
        NULL, 1 /* allow_write */, 0 /* is_tls */, NULL, path);

    for (i = 0; s_algorithms[i] != NULL; i++) {
        if (integrity_xattr_key(s_algorithms[i], key, sizeof(key)) != NULL) {
            (void) brix_vfs_removexattr(&vctx, key);
        }
    }
}
