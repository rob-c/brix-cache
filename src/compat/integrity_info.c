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
#include "fs/vfs.h"   /* fd-based xattr via the VFS seam */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
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
xrootd_cksdata_encode(const xrootd_integrity_info_t *in, time_t fmtime,
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
xrootd_cksdata_decode(const unsigned char *buf, size_t len, time_t cur_mtime,
    xrootd_integrity_info_t *out)
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

    n = xrootd_vfs_fgetxattr(NULL, fd, key, val, sizeof(val) - 1);
    if (n <= 0) {
        return 0;
    }

    /* §8.1: a stock-xrootd value is a binary XrdCksData record (exact size). Decode
     * it (mtime-validated against the live file) so we interoperate with
     * `xrdfs query checksum` / XrdOss without recomputing. */
    if ((size_t) n == sizeof(struct xrd_cks_data)) {
        struct stat bst;
        time_t      cur = (fstat(fd, &bst) == 0) ? bst.st_mtim.tv_sec : (time_t) 0;
        if (xrootd_cksdata_decode((const unsigned char *) val, (size_t) n,
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
static ngx_uint_t s_xattr_format = XROOTD_CKS_FMT_TEXT;

void
xrootd_integrity_set_xattr_format(ngx_uint_t fmt)
{
    if (fmt == XROOTD_CKS_FMT_TEXT || fmt == XROOTD_CKS_FMT_XRDCKS) {
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

    if (s_xattr_format == XROOTD_CKS_FMT_XRDCKS) {
        xrootd_integrity_info_t tmp;
        unsigned char           rec[sizeof(struct xrd_cks_data)];
        size_t                  rn;

        ngx_memzero(&tmp, sizeof(tmp));
        ngx_cpystrn((u_char *) tmp.alg_name, (u_char *) algo,
                    sizeof(tmp.alg_name));
        ngx_cpystrn((u_char *) tmp.hex, (u_char *) hexval, sizeof(tmp.hex));
        rn = xrootd_cksdata_encode(&tmp, st.st_mtim.tv_sec, rec);
        if (rn == 0) {
            return EINVAL;
        }
        if (xrootd_vfs_fsetxattr(NULL, fd, key, rec, rn, 0) != NGX_OK) {
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
    if (xrootd_vfs_fsetxattr(NULL, fd, key, val, (size_t) n, 0) != NGX_OK) {
        return errno;
    }
    return 0;
}

/* .cks sidecar fallback (§8.2) — for exports without user xattrs * "<path>.cks" holds one text record per algorithm:
 *   "<algo> <hex> <mtime_sec> <mtime_nsec> <size>\n"
 * keyed/validated on the live file's mtime+size, mirroring the xattr policy. The
 * sidecar is our own fallback cache (stock interop uses the xattr), opened
 * O_NOFOLLOW|O_CLOEXEC. */
#define INTEGRITY_SIDECAR_MAX (64 * 1024)

static int
integrity_sidecar_path(const char *path, char *buf, size_t bufsz)
{
    int n = snprintf(buf, bufsz, "%s.cks", path);
    return (n > 0 && (size_t) n < bufsz) ? 0 : -1;
}

static int
integrity_sidecar_read(const char *path, const char *algo,
    xrootd_integrity_info_t *out)
{
    char        scpath[4096];
    char        line[INTEGRITY_XATTR_VAL_MAX + 64];
    struct stat st;
    FILE       *fp;
    int         fd, found = 0;

    if (path == NULL
        || integrity_sidecar_path(path, scpath, sizeof(scpath)) != 0
        || stat(path, &st) != 0)
    {
        return 0;
    }
    fd = open(scpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return 0;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return 0;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char      ralgo[32], rhex[INTEGRITY_XATTR_VAL_MAX];
        long      ms, mn;
        long long sz;
        if (sscanf(line, "%31s %159s %ld %ld %lld",
                   ralgo, rhex, &ms, &mn, &sz) != 5) {
            continue;
        }
        if (strcmp(ralgo, algo) != 0) {
            continue;
        }
        if ((long) st.st_mtim.tv_sec == ms && (long) st.st_mtim.tv_nsec == mn
            && (long long) st.st_size == sz)
        {
            ngx_cpystrn((u_char *) out->hex, (u_char *) rhex, sizeof(out->hex));
            out->from_cache = 1;
            found = 1;
        }
        break;   /* algo line found (fresh or stale) */
    }
    fclose(fp);
    return found;
}

static void
integrity_sidecar_write(const char *path, const char *algo, const char *hexval)
{
    char        scpath[4096];
    char       *buf;
    size_t      cap = INTEGRITY_SIDECAR_MAX, len = 0;
    char        line[INTEGRITY_XATTR_VAL_MAX + 64];
    struct stat st;
    FILE       *fp;
    int         fd, ln;

    if (path == NULL
        || integrity_sidecar_path(path, scpath, sizeof(scpath)) != 0
        || stat(path, &st) != 0)
    {
        return;
    }

    /* Build the new content: existing lines (minus this algo) + the fresh record. */
    buf = malloc(cap);
    if (buf == NULL) {
        return;
    }
    fd = open(scpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) {
        fp = fdopen(fd, "r");
        if (fp != NULL) {
            char  rd[INTEGRITY_XATTR_VAL_MAX + 64];
            size_t alen = strlen(algo);
            while (fgets(rd, sizeof(rd), fp) != NULL) {
                if (strncmp(rd, algo, alen) == 0 && rd[alen] == ' ') {
                    continue;   /* drop the stale record for this algo */
                }
                {
                    size_t rl = strlen(rd);
                    if (len + rl < cap) {
                        memcpy(buf + len, rd, rl);
                        len += rl;
                    }
                }
            }
            fclose(fp);
        } else {
            close(fd);
        }
    }
    ln = snprintf(line, sizeof(line), "%s %s %ld %ld %lld\n", algo, hexval,
                  (long) st.st_mtim.tv_sec, (long) st.st_mtim.tv_nsec,
                  (long long) st.st_size);
    if (ln > 0 && len + (size_t) ln < cap) {
        memcpy(buf + len, line, (size_t) ln);
        len += (size_t) ln;
    }

    fd = open(scpath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd >= 0) {
        ssize_t w = 0;
        while ((size_t) w < len) {
            ssize_t k = write(fd, buf + w, len - (size_t) w);
            if (k <= 0) { break; }
            w += k;
        }
        close(fd);
    }
    free(buf);
}

/* Default policy when opts is NULL. */
static const xrootd_integrity_opts_t s_default_opts = {
    .allow_xattr_cache    = 1,
    .update_xattr_cache   = 1,
    .require_regular_file = 0,
};

ngx_int_t
xrootd_integrity_get_fd(ngx_log_t *log, int fd,
    xrootd_sd_obj_t *obj, const char *path, const char *alg_name,
    const xrootd_integrity_opts_t *opts,
    xrootd_integrity_info_t *out)
{
    int driver_backed = (obj != NULL && obj->driver != NULL);

    char                          hex[EVP_MAX_MD_SIZE * 2 + 1];
    const xrootd_integrity_opts_t *o = (opts != NULL) ? opts : &s_default_opts;
    ngx_int_t                     parse_rc;

    ngx_memzero(out, sizeof(*out));

    /* Reject non-regular files early when required. A driver-backed object knows
     * its own type from the open snapshot (its bare fd is only block 0). */
    if (o->require_regular_file) {
        if (driver_backed) {
            if (!obj->snap.is_reg) {
                return NGX_DECLINED;
            }
        } else {
            struct stat st;

            if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
                return NGX_DECLINED;
            }
        }
    }

    /* Parse and canonicalize the algorithm name once. */
    parse_rc = xrootd_checksum_parse(alg_name, strlen(alg_name),
                                      &out->alg, out->alg_name,
                                      sizeof(out->alg_name));
    if (parse_rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* Check the xattr cache first when allowed, then the .cks sidecar fallback
     * (§8.2) for exports without user xattrs. */
    if (o->allow_xattr_cache) {
        if (integrity_xattr_read(fd, out->alg_name, out)) {
            return NGX_OK;
        }
        if (integrity_sidecar_read(path, out->alg_name, out)) {
            return NGX_OK;
        }
    }

    /* Cache-only callers (e.g. S3 GET/HEAD echo) decline on a miss rather than
     * pay a full-file read on a latency-sensitive path. */
    if (o->no_compute) {
        return NGX_DECLINED;
    }

    /* Compute the checksum — through the driver for a backend-bound object (reads
     * every block), else the default POSIX-fd kernel. */
    if (driver_backed) {
        if (xrootd_checksum_hex_obj(out->alg, obj, path, log,
                                    hex, sizeof(hex)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    } else if (xrootd_checksum_hex_fd(out->alg, fd, path, log,
                                      hex, sizeof(hex)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) out->hex, (u_char *) hex, sizeof(out->hex));
    out->from_cache = 0;

    /* Persist the computed value: xattr first; if the filesystem lacks user
     * xattrs (ENOTSUP/EOPNOTSUPP/EPERM) fall back to the .cks sidecar (§8.2). */
    if (o->allow_xattr_cache && o->update_xattr_cache) {
        int wrc = integrity_xattr_write_rc(fd, out->alg_name, hex);
        if (wrc == ENOTSUP
#ifdef EOPNOTSUPP
            || wrc == EOPNOTSUPP
#endif
            || wrc == EPERM) {
            integrity_sidecar_write(path, out->alg_name, hex);
        }
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
            (void) xrootd_vfs_fremovexattr(NULL, fd, key);
        }
    }
}

void
xrootd_integrity_invalidate_path(ngx_log_t *log, const char *root_canon,
    const char *path)
{
    xrootd_vfs_ctx_t vctx;
    char             key[64];
    int              i;

    xrootd_vfs_ctx_init(&vctx, NULL, log, XROOTD_PROTO_STREAM, root_canon,
        NULL, 1 /* allow_write */, 0 /* is_tls */, NULL, path);

    for (i = 0; s_algorithms[i] != NULL; i++) {
        if (integrity_xattr_key(s_algorithms[i], key, sizeof(key)) != NULL) {
            (void) xrootd_vfs_removexattr(&vctx, key);
        }
    }
}
