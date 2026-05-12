#include "query_internal.h"

#include <ctype.h>

/*
 * kXR_Qcksum: checksum by path or open file handle.
 */

static void
xrootd_query_hex_digest(const unsigned char *digest, unsigned int digest_len,
    char *hex)
{
    unsigned int i;

    for (i = 0; i < digest_len; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
}


static ngx_flag_t
xrootd_query_parse_algorithm(const u_char *src, size_t len, char *algo,
    size_t algo_sz)
{
    size_t i;

    if (len == 0 || len >= algo_sz) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        if (!isalnum((unsigned char) src[i])) {
            return 0;
        }
        algo[i] = (char) tolower((unsigned char) src[i]);
    }
    algo[len] = '\0';
    return 1;
}


static ngx_int_t
xrootd_query_cksum_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *errmsg)
{
    ngx_int_t rc;

    rc = xrootd_send_error(ctx, c, errcode, errmsg);
    return (rc == NGX_OK) ? NGX_DONE : rc;
}


static ngx_int_t
xrootd_query_build_checksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int fd, const char *resolved, const char *algo, char *resp, size_t resp_sz)
{
    if (strcmp(algo, "adler32") == 0) {
        uint32_t cksum;

        cksum = xrootd_query_adler32_fd(fd, resolved, c->log);
        if (cksum == 0xFFFFFFFF) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
            return xrootd_query_cksum_send_error(ctx, c, kXR_IOError,
                                                 "checksum computation failed");
        }
        snprintf(resp, resp_sz, "adler32 %08x", (unsigned int) cksum);
        return NGX_OK;
    }

    {
        const EVP_MD *md = NULL;

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

            if (!xrootd_query_digest_fd(fd, resolved, md, mdout, &mdlen,
                                        c->log))
            {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_query_cksum_send_error(ctx, c, kXR_IOError,
                                                     "checksum computation failed");
            }

            xrootd_query_hex_digest(mdout, mdlen, hex);
            snprintf(resp, resp_sz, "%s %s", algo, hex);
            return NGX_OK;
        }
    }

    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
    return xrootd_query_cksum_send_error(ctx, c, kXR_ArgInvalid,
                                         "unknown checksum algorithm");
}


static ngx_int_t
xrootd_query_cksum_path(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, char *algo, size_t algo_sz)
{
    char          resolved[PATH_MAX];
    char          pathbuf[XROOTD_MAX_PATH + 1];
    char          resp[256];
    int           fd;
    const u_char *payload = ctx->payload;
    size_t        payload_len = (size_t) ctx->cur_dlen;
    size_t        wire_len;
    const u_char *sep = NULL;
    size_t        alg_len = 0;
    const u_char *path_payload = payload;
    size_t        path_payload_len = payload_len;
    ngx_int_t     rc;

    wire_len = strnlen((const char *) payload, payload_len);

    for (size_t i = 0; i < wire_len; i++) {
        if (payload[i] == ':' || payload[i] == ' ') {
            sep = payload + i;
            alg_len = i;
            break;
        }
    }

    if (sep != NULL && alg_len > 0 && alg_len + 1 < payload_len) {
        if (xrootd_query_parse_algorithm(payload, alg_len, algo, algo_sz)) {
            path_payload = sep + 1;
            path_payload_len = payload_len - (alg_len + 1);
        }
    }

    if (!xrootd_extract_path(c->log, path_payload, path_payload_len,
                             pathbuf, sizeof(pathbuf), 1)) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                             pathbuf, resolved, sizeof(resolved))) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                          pathbuf, "cksum", kXR_NotFound, "file not found");
    }

    if (xrootd_check_authdb(ctx, resolved, XROOTD_AUTH_READ) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                          resolved, "cksum", kXR_NotAuthorized, "not authorized");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                            ctx->vo_list) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                          resolved, "cksum", kXR_NotAuthorized, "VO not authorized");
    }

    fd = xrootd_open_confined(c->log, &conf->root, resolved, O_RDONLY, 0);
    if (fd < 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSUM, "QUERY",
                          resolved, "cksum", kXR_IOError, strerror(errno));
    }

    rc = xrootd_query_build_checksum(ctx, c, fd, resolved, algo, resp,
                                     sizeof(resp));
    close(fd);
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}


static ngx_int_t
xrootd_query_cksum_handle(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ClientQueryRequest *req, char *algo, size_t algo_sz)
{
    char      resolved[PATH_MAX];
    char      resp[256];
    int       idx;
    ngx_int_t rc;

    if (ctx->payload != NULL && ctx->cur_dlen > 1 && ctx->payload[0] == 0) {
        const u_char *ap = ctx->payload + 1;
        size_t        alen;

        alen = strnlen((const char *) ap, (size_t) (ctx->cur_dlen - 1));
        if (alen > 0) {
            (void) xrootd_query_parse_algorithm(ap, alen, algo, algo_sz);
        }
    }

    idx = (int) (unsigned char) req->fhandle[0];
    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_cpystrn((u_char *) resolved,
                (u_char *) (ctx->files[idx].path != NULL
                            ? ctx->files[idx].path : "-"),
                sizeof(resolved));

    rc = xrootd_query_build_checksum(ctx, c, ctx->files[idx].fd, resolved,
                                     algo, resp, sizeof(resp));
    if (rc == NGX_DONE) {
        return NGX_OK;
    }
    if (rc != NGX_OK) {
        return rc;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
    xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) (strlen(resp) + 1));
}


ngx_int_t
xrootd_query_cksum(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf, ClientQueryRequest *req)
{
    char algo[32];

    ngx_cpystrn((u_char *) algo, (u_char *) "adler32", sizeof(algo));

    if (ctx->cur_dlen > 0 && ctx->payload != NULL && ctx->payload[0] != 0) {
        return xrootd_query_cksum_path(ctx, c, conf, algo, sizeof(algo));
    }

    return xrootd_query_cksum_handle(ctx, c, req, algo, sizeof(algo));
}


ngx_int_t
xrootd_query_ckscan(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char resolved[PATH_MAX];
    char pathbuf[XROOTD_MAX_PATH + 1];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                          "-", "ckscan", kXR_ArgMissing, "no path given");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             pathbuf, sizeof(pathbuf), 1)) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                          "-", "ckscan", kXR_ArgInvalid, "invalid path payload");
    }

    if (!xrootd_resolve_path_noexist(c->log, &conf->root,
                                     pathbuf, resolved, sizeof(resolved))) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                          pathbuf, "ckscan", kXR_NotFound, "invalid path");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                            ctx->vo_list) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                          pathbuf, "ckscan", kXR_NotAuthorized, "VO not authorized");
    }

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_QUERY_CKSCAN, "QUERY",
                     pathbuf, "ckscan", 0);
}
