#include "query_internal.h"

#include <errno.h>

/*
 * File checksum helpers shared by kXR_Qcksum path and handle queries.
 */

uint32_t
xrootd_query_adler32_fd(int fd, const char *path, ngx_log_t *log)
{
    ssize_t        n;
    off_t          offset = 0;
    uint32_t       A = 1, B = 0;
    const uint32_t MOD = 65521;
    u_char         buf[65536];
    char           safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));

    for (;;) {
        n = pread(fd, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: adler32 read(\"%s\") failed", safe_path);
            return 0xFFFFFFFF;
        }
        if (n == 0) {
            break;
        }
        offset += n;

        for (ssize_t i = 0; i < n; i++) {
            A = (A + buf[i]) % MOD;
            B = (B + A) % MOD;
        }
    }

    return (B << 16) | A;
}


uint32_t
xrootd_query_adler32_file(const ngx_str_t *root, const char *path,
    ngx_log_t *log)
{
    int      fd;
    uint32_t cksum;
    char     safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));

    fd = xrootd_open_confined(log, root, path, O_RDONLY, 0);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: adler32 open(\"%s\") failed", safe_path);
        return 0xFFFFFFFF;
    }

    cksum = xrootd_query_adler32_fd(fd, path, log);
    close(fd);
    return cksum;
}


ngx_flag_t
xrootd_query_digest_fd(int fd, const char *path, const EVP_MD *md,
    unsigned char *out, unsigned int *outlen, ngx_log_t *log)
{
    ssize_t     n;
    off_t       offset = 0;
    u_char      buf[65536];
    EVP_MD_CTX *mdctx;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    for (;;) {
        n = pread(fd, buf, sizeof(buf), offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            {
                char safe[512];

                xrootd_sanitize_log_string(path, safe, sizeof(safe));
                ngx_log_error(NGX_LOG_ERR, log, errno,
                              "xrootd: digest read(\"%s\") failed", safe);
            }
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
        if (n == 0) {
            break;
        }
        offset += n;

        if (EVP_DigestUpdate(mdctx, buf, (size_t) n) != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, out, outlen) != 1) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    return 1;
}


ngx_flag_t
xrootd_query_digest_file(const ngx_str_t *root, const char *path,
    const EVP_MD *md, unsigned char *out, unsigned int *outlen,
    ngx_log_t *log)
{
    int  fd;
    char safe[512];
    ngx_flag_t ok;

    fd = xrootd_open_confined(log, root, path, O_RDONLY, 0);
    if (fd < 0) {
        xrootd_sanitize_log_string(path, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: digest open(\"%s\") failed", safe);
        return 0;
    }

    ok = xrootd_query_digest_fd(fd, path, md, out, outlen, log);
    close(fd);
    return ok;
}
