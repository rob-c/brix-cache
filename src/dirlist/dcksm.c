#include "dcksm.h"
#include "../query/query_internal.h"

#include <ctype.h>
#include <string.h>


static void
xrootd_dirlist_hex_digest(const unsigned char *digest, unsigned int digest_len,
    char *hex)
{
    unsigned int i;

    for (i = 0; i < digest_len; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
}


static ngx_flag_t
xrootd_dirlist_algorithm_supported(const char *algo)
{
    return (strcmp(algo, "adler32") == 0
            || strcmp(algo, "md5") == 0
            || strcmp(algo, "sha1") == 0
            || strcmp(algo, "sha256") == 0);
}


static ngx_int_t
xrootd_dirlist_parse_algorithm(const u_char *src, size_t len,
    char *algo, size_t algo_sz)
{
    size_t i;

    if (len == 0 || len >= algo_sz) {
        return NGX_ERROR;
    }

    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char) src[i])) {
            return NGX_ERROR;
        }
        algo[i] = (char) tolower((unsigned char) src[i]);
    }
    algo[len] = '\0';

    return xrootd_dirlist_algorithm_supported(algo) ? NGX_OK : NGX_DECLINED;
}


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


void
xrootd_dirlist_checksum_token(ngx_connection_t *c, int dfd,
    const char *name, const char *path, const struct stat *st,
    const char *algo, char *out, size_t outsz)
{
    const EVP_MD *md = NULL;
    int           fd;

    if (!S_ISREG(st->st_mode)) {
        snprintf(out, outsz, "%s:none", algo);
        return;
    }

    fd = openat(dfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        snprintf(out, outsz, "%s:none", algo);
        return;
    }

    if (strcmp(algo, "adler32") == 0) {
        uint32_t cksum;

        cksum = xrootd_query_adler32_fd(fd, path, c->log);
        if (cksum == 0xFFFFFFFF) {
            close(fd);
            snprintf(out, outsz, "%s:none", algo);
            return;
        }

        snprintf(out, outsz, "%s:%08x", algo, (unsigned int) cksum);
        close(fd);
        return;
    }

    if (strcmp(algo, "md5") == 0) {
        md = EVP_md5();

    } else if (strcmp(algo, "sha1") == 0) {
        md = EVP_sha1();

    } else if (strcmp(algo, "sha256") == 0) {
        md = EVP_sha256();
    }

    if (md != NULL) {
        unsigned char mdout[EVP_MAX_MD_SIZE];
        unsigned int  mdlen = 0;
        char          hex[EVP_MAX_MD_SIZE * 2 + 1];

        if (xrootd_query_digest_fd(fd, path, md, mdout, &mdlen, c->log)) {
            xrootd_dirlist_hex_digest(mdout, mdlen, hex);
            snprintf(out, outsz, "%s:%s", algo, hex);
            close(fd);
            return;
        }
    }

    close(fd);
    snprintf(out, outsz, "%s:none", algo);
}


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
