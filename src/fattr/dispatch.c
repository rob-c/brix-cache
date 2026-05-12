#include "fattr/ngx_xrootd_fattr.h"

#include <string.h>

ngx_int_t
xrootd_handle_fattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientFattrRequest *req = (ClientFattrRequest *) ctx->hdr_buf;
    int                 subcode = req->subcode;
    int                 numattr = req->numattr;
    int                 options = req->options;
    char                resolved[PATH_MAX];
    char                pathbuf[XROOTD_MAX_PATH + 1];
    const char         *path = NULL;
    int                 fd = -1;
    u_char             *args_buf = NULL;
    size_t              args_len = 0;

    if (subcode > kXR_fattrMaxSC) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "fattr: invalid subcode");
    }
    if (subcode == kXR_fattrList) {
        if (numattr != 0) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr list: numattr must be 0");
        }
    } else if (numattr == 0 || numattr > kXR_faMaxVars) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "fattr: invalid numattr");
    }

    if ((subcode == kXR_fattrSet || subcode == kXR_fattrDel) &&
        !conf->allow_write)
    {
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "fattr: server is read-only");
    }

    if (ctx->cur_dlen == 0) {
        if (subcode != kXR_fattrList) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr: missing arguments");
        }

        {
            int idx = (int) (unsigned char) req->fhandle[0];

            if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
                return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                         "fattr: invalid file handle");
            }
            fd = ctx->files[idx].fd;
        }

    } else if (ctx->payload != NULL && ctx->payload[0] == 0) {
        int idx = (int) (unsigned char) req->fhandle[0];

        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "fattr: invalid file handle");
        }

        fd = ctx->files[idx].fd;
        if (ctx->cur_dlen > 1) {
            args_buf = ctx->payload + 1;
            args_len = ctx->cur_dlen - 1;
        }

    } else {
        size_t path_wire_len;
        size_t path_payload_len;

        if (ctx->payload == NULL || ctx->cur_dlen == 0) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr: missing path");
        }

        path_wire_len = strnlen((char *) ctx->payload, ctx->cur_dlen);
        path_payload_len = path_wire_len + 1;

        if (!xrootd_extract_path(c->log, ctx->payload, path_payload_len,
                                 pathbuf, sizeof(pathbuf), 1)) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr: invalid path");
        }
        if (!xrootd_resolve_path(c->log, &conf->root, pathbuf,
                                 resolved, sizeof(resolved))) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "fattr: file not found");
        }
        {
            int need_write = (subcode == kXR_fattrSet
                              || subcode == kXR_fattrDel) ? 1 : 0;
            uint32_t needed = need_write ? XROOTD_AUTH_UPDATE : XROOTD_AUTH_READ;
            if (xrootd_check_authdb(ctx, resolved, needed) != NGX_OK) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "fattr: not authorized");
            }
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                ctx->vo_list) != NGX_OK) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "fattr: VO not authorized");
        }

        {
            int need_write = (subcode == kXR_fattrSet
                              || subcode == kXR_fattrDel) ? 1 : 0;
            if (xrootd_check_token_scope(ctx, pathbuf, need_write) != NGX_OK) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "fattr: token scope denied");
            }
        }

        path = resolved;
        if (path_payload_len < ctx->cur_dlen) {
            args_buf = ctx->payload + path_payload_len;
            args_len = ctx->cur_dlen - path_payload_len;
        }
    }

    if (subcode == kXR_fattrList) {
        return fattr_list(ctx, c, path, fd, options);
    }

    if (args_buf == NULL || args_len == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                 "fattr: missing nvec");
    }

    {
        u_char              *nvec_copy;
        xrootd_fattr_entry_t attrs[kXR_faMaxVars];
        ssize_t              nvec_used;
        size_t               nvec_len;
        u_char              *vvec_buf;
        size_t               vvec_len;

        nvec_copy = ngx_palloc(c->pool, args_len);
        if (nvec_copy == NULL) {
            return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
        }
        ngx_memcpy(nvec_copy, args_buf, args_len);

        nvec_used = fattr_parse_nvec(c->log, nvec_copy, args_len,
                                     numattr, attrs);
        if (nvec_used < 0) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr: malformed nvec");
        }

        nvec_len = (size_t) nvec_used;
        vvec_buf = nvec_copy + nvec_len;
        vvec_len = args_len - nvec_len;

        switch (subcode) {
        case kXR_fattrGet:
            return fattr_get(ctx, c, path, fd, nvec_copy, nvec_len,
                             numattr, attrs);
        case kXR_fattrSet:
            return fattr_set(ctx, c, path, fd, options,
                             nvec_copy, nvec_len, vvec_buf, vvec_len,
                             numattr, attrs);
        case kXR_fattrDel:
            return fattr_del(ctx, c, path, fd, nvec_copy, nvec_len,
                             numattr, attrs);
        }
    }

    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "fattr: unknown subcode");
}
