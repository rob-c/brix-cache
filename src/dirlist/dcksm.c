/*
 * Checksum computation helpers for kXR_dcksm mode.
 * When the dirlist request includes the kXR_dcksm flag, each directory entry
 * is accompanied by a reference checksum (adler32, crc32, crc32c, md5, sha1,
 * or sha256). These functions parse the requested algorithm from the CGI
 * parameter and compute the corresponding digest on disk.
 */

#include "dcksm.h"
#include "core/compat/checksum.h"
#include "core/compat/integrity_info.h"

#include <ctype.h>
#include <string.h>
#include <sys/xattr.h>

/*
 * Parse a raw algorithm string into lowercase and validate it.
 * Returns NGX_OK if supported, NGX_DECLINED for unsupported algorithms,
 * or NGX_ERROR on invalid input (e.g., non-alphanumeric characters).
 */

static ngx_int_t
xrootd_dirlist_parse_algorithm(const u_char *src, size_t len,
    char *algo, size_t algo_sz)
{
    xrootd_checksum_alg_t alg;

    return xrootd_checksum_parse((const char *) src, len, &alg, algo,
                                 algo_sz);
}

/*
 * Extract the requested checksum algorithm from the dirlist request payload.
 * The client may append a CGI parameter like "?cks.type=sha256" to specify
 * which algorithm to use. If no parameter is present, defaults to adler32.
 * Returns NGX_OK on success, NGX_DECLINED if an unsupported algorithm was
 * requested (bad_algo contains the rejected name for error reporting).
 */

ngx_int_t
xrootd_dirlist_checksum_algorithm(const u_char *payload, size_t payload_len,
    char *algo, size_t algo_sz, char *bad_algo, size_t bad_algo_sz)
{
    const u_char *qmark, *p, *end;

    ngx_cpystrn((u_char *) algo, (u_char *) "adler32", algo_sz);
    bad_algo[0] = '\0';

    if (payload == NULL || payload_len == 0) {
        return NGX_OK;
    }

    if (payload[payload_len - 1] == '\0') {
        payload_len--;
    }

    qmark = memchr(payload, '?', payload_len);
    if (qmark == NULL) {
        return NGX_OK;
    }

    p = qmark + 1;
    end = payload + payload_len;

    while (p < end) {
        const u_char *amp;
        size_t        field_len;
        static const char key[] = "cks.type=";

        amp = memchr(p, '&', (size_t) (end - p));
        field_len = amp ? (size_t) (amp - p) : (size_t) (end - p);

        if (field_len > sizeof(key) - 1
            && ngx_strncmp(p, key, sizeof(key) - 1) == 0)
        {
            const u_char *value = p + sizeof(key) - 1;
            size_t        value_len = field_len - (sizeof(key) - 1);
            ngx_int_t     rc;

            rc = xrootd_dirlist_parse_algorithm(value, value_len,
                                                algo, algo_sz);
            if (rc == NGX_DECLINED || rc == NGX_ERROR) {
                size_t copy_len = value_len;

                if (copy_len >= bad_algo_sz) {
                    copy_len = bad_algo_sz - 1;
                }
                ngx_memcpy(bad_algo, value, copy_len);
                bad_algo[copy_len] = '\0';
                return NGX_DECLINED;
            }

            return NGX_OK;
        }

        if (amp == NULL) {
            break;
        }
        p = amp + 1;
    }

    return NGX_OK;
}

/*
 * Compute a checksum token for a single directory entry.
 * Opens the file, computes the digest using the requested algorithm (adler32,
 * crc32, crc32c, md5, sha1, or sha256), and writes the result as
 * "algo:hexvalue" to out.  Returns "algo:none" if the file is not regular or
 * checksum fails.
 */
void
xrootd_dirlist_checksum_token(ngx_log_t *log, int dfd,
    const char *name, const char *path, const struct stat *st,
    const char *algo, char *out, size_t outsz)
{
    int   fd;

    if (!S_ISREG(st->st_mode)) {
        snprintf(out, outsz, "%s:none", algo);
        return;
    }

    fd = openat(dfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);  /* vfs-seam-allow: dirfd-relative open within an already-VFS-opened confined dir stream (xrootd_vfs_dir_fd) */
    if (fd < 0) {
        snprintf(out, outsz, "%s:none", algo);
        return;
    }

    {
        xrootd_integrity_info_t  info;
        xrootd_integrity_opts_t  iopts;

        ngx_memzero(&iopts, sizeof(iopts));
        iopts.allow_xattr_cache  = 1;
        iopts.update_xattr_cache = 1;

        if (xrootd_integrity_get_fd(log, fd, NULL, path, algo, &iopts, &info) == NGX_OK) {
            snprintf(out, outsz, "%s:%s", info.alg_name, info.hex);
        } else {
            snprintf(out, outsz, "%s:none", algo);
        }
    }

    close(fd);
}

/*
 * Format a dcksm stat body for one directory entry.
 * Produces the 9-field line: inode size flags mtime ctime atime mode uid gid.
 * Sets kXR_isDir or kXR_other flags based on file type, and readable/writable/xset
 * flags based on permission bits. This is used when kXR_dcksm is requested.
 */
void
xrootd_dirlist_make_dcksm_stat_body(const struct stat *st, char *out,
    size_t outsz)
{
    int flags = 0;

    if (S_ISDIR(st->st_mode)) {
        flags |= kXR_isDir;

    } else if (!S_ISREG(st->st_mode)) {
        flags |= kXR_other;
    }

    if (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
        flags |= kXR_readable;
    }

    if (st->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
        flags |= kXR_writable;
    }

    if (st->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
        flags |= kXR_xset;
    }

    snprintf(out, outsz, "%llu %lld %d %ld %ld %ld %04o %u %u",
             (unsigned long long) st->st_ino,
             (long long) st->st_size,
             flags,
             (long) st->st_mtime,
             (long) st->st_ctime,
             (long) st->st_atime,
             (unsigned int) (st->st_mode & 07777),
             (unsigned int) st->st_uid,
             (unsigned int) st->st_gid);
}
