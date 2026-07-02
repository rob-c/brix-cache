/*
 * Fattr dispatcher — routes kXR_fattr requests to the appropriate sub-handler.
 * The fattr operation has four sub-codes: get (read attributes), set (write
 * attributes), del (delete attributes), and list (enumerate all attributes).
 * This function validates parameters, resolves path or file handle, checks
 * authorization, then dispatches to the specific handler based on sub-code.
 */

#include "ngx_xrootd_fattr.h"
#include "fs/vfs/vfs.h"   /* confinement check via the VFS seam */

#include <string.h>
#include "core/compat/alloc_guard.h"

/*
 *
 * WHAT: Validates the fattr request header, determines whether it targets an open
 *       file handle or a filesystem path, enforces read-only and auth gating, then
 *       splits the payload into the name-vector (nvec) and value-vector (vvec) and
 *       dispatches to fattr_get/set/del/list.
 *
 * WHY: The fattr wire frame is overloaded across four sub-codes whose argument
 *       layout differs (list takes no nvec; set carries an extra vvec) and whose
 *       target can be either an fhandle or an inline path. Centralising the
 *       parsing/validation here keeps each sub-handler free of framing concerns.
 *
 * HOW: A three-way branch on the payload shape selects the target (see inline
 *       notes): (a) no payload → fhandle in req->fhandle (list only); (b) payload
 *       begins with a 0 byte → fhandle followed by args; (c) otherwise → leading
 *       NUL-terminated path followed by args. Path targets are auth-gated and
 *       confined-open verified. The args region is then parsed into attrs[]: nvec
 *       first, vvec is whatever follows it. close_fd guards any fd we own. */
ngx_int_t
xrootd_handle_fattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    /* hdr_buf aliases the fixed request header; payload/cur_dlen hold the body. */
    xrdw_fattr_req_t    req;
    int                 subcode;
    int                 numattr;
    int                 options;
    char                full_path[PATH_MAX];
    char                pathbuf[XROOTD_MAX_PATH + 1];
    const char         *path = NULL;
    int                 fd = -1;
    int                 close_fd = 0;
    u_char             *args_buf = NULL;
    size_t              args_len = 0;
    /* One VFS ctx for the whole request: in path mode it carries the resolved
     * confined path the xattr ops act on; in fd mode it carries only proto/log
     * for metric attribution (the fd is the target). Lives for the handler
     * calls below. */
    xrootd_vfs_ctx_t    vctx;

    xrdw_fattr_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    subcode = req.subcode;
    numattr = req.numattr;
    options = req.options;

    if (subcode > kXR_fattrMaxSC) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "fattr: invalid subcode");
    }
    /* numattr rules differ by sub-code: list enumerates everything (must be 0);
     * get/set/del operate on an explicit name vector (1..kXR_faMaxVars). */
    if (subcode == kXR_fattrList) {
        if (numattr != 0) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr list: numattr must be 0");
        }
    } else if (numattr == 0 || numattr > kXR_faMaxVars) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "fattr: invalid numattr");
    }

    /* Mutating sub-codes are blocked up-front on read-only servers (invariant:
     * allow_write is checked globally before any per-path/token scope). */
    if ((subcode == kXR_fattrSet || subcode == kXR_fattrDel) &&
        !conf->common.allow_write)
    {
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "fattr: server is read-only");
    }

    /*
     * Target selection (three mutually exclusive payload shapes):
     *   (a) cur_dlen == 0      → no body: the target is the fhandle in the
     *                            request header. Only valid for fattrList.
     *   (b) payload[0] == 0    → leading 0 byte marks an fhandle target; the
     *                            file index is still req->fhandle[0] and any
     *                            args follow at payload+1.
     *   (c) otherwise          → payload starts with a NUL-terminated path;
     *                            args (if any) follow the path's terminator.
     */
    if (ctx->cur_dlen == 0) {
        /* (a) Empty body is only meaningful for list; others need an nvec. */
        if (subcode != kXR_fattrList) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr: missing arguments");
        }

        {
            /* fhandle index is one wire byte; bounds + open-state checked. */
            int idx = (int) (unsigned char) req.fhandle[0];

            if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
                return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                         "fattr: invalid file handle");
            }
            fd = ctx->files[idx].fd;
            /* A driver-backed handle (object store: ceph/s3/…) keeps its xattrs on
             * the BACKEND object, not the local placeholder fd — a raw fsetxattr on
             * that fd is lost. Route by the handle's resolved path through the driver
             * (path mode) so set/get/list hit the same store the bytes live in. */
            if (ctx->files[idx].sd_obj.driver != NULL
                && ctx->files[idx].path != NULL)
            {
                path = ctx->files[idx].path;
            }
        }
        /* fd target: vctx carries proto/log only (path NULL → fd mode); a driver-
         * backed handle set its resolved path above → driver path mode. */
        xrootd_vfs_ctx_init(&vctx, c->pool, c->log, XROOTD_PROTO_ROOT,
            conf->common.root_canon, NULL, conf->common.allow_write,
            0 /* is_tls */, NULL, path);

    } else if (ctx->payload != NULL && ctx->payload[0] == 0) {
        /* (b) fhandle-targeted request with a leading 0 marker byte. */
        int idx = (int) (unsigned char) req.fhandle[0];

        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "fattr: invalid file handle");
        }

        fd = ctx->files[idx].fd;
        /* Driver-backed handle: route xattrs by the resolved path through the driver
         * (path mode), not the local placeholder fd (see branch (a)). */
        if (ctx->files[idx].sd_obj.driver != NULL
            && ctx->files[idx].path != NULL)
        {
            path = ctx->files[idx].path;
        }
        /* fd target: vctx carries proto/log only (path NULL → fd mode); a driver-
         * backed handle set its resolved path above → driver path mode. */
        xrootd_vfs_ctx_init(&vctx, c->pool, c->log, XROOTD_PROTO_ROOT,
            conf->common.root_canon, NULL, conf->common.allow_write,
            0 /* is_tls */, NULL, path);
        /* Everything after the marker byte is the nvec/vvec args region. */
        if (ctx->cur_dlen > 1) {
            args_buf = ctx->payload + 1;
            args_len = ctx->cur_dlen - 1;
        }

    } else {
        /* (c) Path-targeted request: payload = "<path>\0[args...]". */
        size_t path_wire_len;
        size_t path_payload_len;

        if (ctx->payload == NULL || ctx->cur_dlen == 0) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr: missing path");
        }

        /* Bounded scan for the path's NUL; path_payload_len includes it so the
         * args region begins exactly at payload + path_payload_len below. */
        path_wire_len = strnlen((char *) ctx->payload, ctx->cur_dlen);
        path_payload_len = path_wire_len + 1;

        if (!xrootd_extract_path(c->log, ctx->payload, path_payload_len,
                                 pathbuf, sizeof(pathbuf), 1)) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr: invalid path");
        }
        /* Resolve the client path beneath the export root → full_path. */
        xrootd_beneath_full_path(conf->common.root_canon, pathbuf,
                                  full_path, sizeof(full_path));
        {
            /* set/del need UPDATE rights; get/list need only READ. */
            int need_write = (subcode == kXR_fattrSet
                              || subcode == kXR_fattrDel) ? 1 : 0;
            uint32_t auth_level = need_write ? XROOTD_AUTH_UPDATE
                                             : XROOTD_AUTH_READ;
            if (xrootd_auth_gate(ctx, c, XROOTD_OP_FATTR, "FATTR",
                                 pathbuf, full_path, conf,
                                 auth_level, need_write) != NGX_OK) {
                /* auth_gate already queued the error; ctx->write_rc is its rc. */
                return ctx->write_rc;
            }
        }

        {
            /* Confinement check via the VFS: a confined no-follow stat verifies
             * the path is within the export root (and exists) without a raw
             * open_beneath. The fattr ops then operate by path (through the same
             * vctx) so a directory list can recurse. */
            xrootd_vfs_stat_t vst;

            xrootd_vfs_ctx_init(&vctx, c->pool, c->log, XROOTD_PROTO_ROOT,
                conf->common.root_canon, NULL, conf->common.allow_write,
                0 /* is_tls */, NULL, full_path);
            if (xrootd_vfs_stat(&vctx, &vst) != NGX_OK) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
                return xrootd_send_error(ctx, c, xrootd_kxr_from_errno(errno),
                                         "fattr: cannot open path");
            }
            path = full_path;
        }
        /* Args (nvec/vvec) are whatever bytes follow the path's NUL. */
        if (path_payload_len < ctx->cur_dlen) {
            args_buf = ctx->payload + path_payload_len;
            args_len = ctx->cur_dlen - path_payload_len;
        }
    }

    /* list takes no nvec — dispatch directly. */
    if (subcode == kXR_fattrList) {
        ngx_int_t rc = fattr_list(ctx, c, &vctx, path, fd, options);
        if (close_fd) { close(fd); }
        return rc;
    }

    /* get/set/del all require a name vector. */
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

        /* Copy the args region so fattr_parse_nvec can record rc_ptr slots that
         * point into a buffer we own (the wire payload is overwritten in place
         * with status codes when building the response). */
        XROOTD_PALLOC_OR_RETURN(nvec_copy, c->pool, args_len, xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory"));
        ngx_memcpy(nvec_copy, args_buf, args_len);

        /* Parse the name vector; returns the byte count it consumed. */
        nvec_used = fattr_parse_nvec(c->log, nvec_copy, args_len,
                                     numattr, attrs);
        if (nvec_used < 0) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr: malformed nvec");
        }

        /* Whatever follows the nvec is the value vector (used by set only). */
        nvec_len = (size_t) nvec_used;
        vvec_buf = nvec_copy + nvec_len;
        vvec_len = args_len - nvec_len;

        {
            ngx_int_t dispatch_rc;
            switch (subcode) {
            case kXR_fattrGet:
                dispatch_rc = fattr_get(ctx, c, &vctx, path, fd,
                                        nvec_copy, nvec_len, numattr, attrs);
                break;
            case kXR_fattrSet:
                dispatch_rc = fattr_set(ctx, c, &vctx, path, fd, options,
                                        nvec_copy, nvec_len, vvec_buf, vvec_len,
                                        numattr, attrs);
                break;
            case kXR_fattrDel:
                dispatch_rc = fattr_del(ctx, c, &vctx, path, fd,
                                        nvec_copy, nvec_len, numattr, attrs);
                break;
            default:
                dispatch_rc = xrootd_send_error(ctx, c, kXR_Unsupported,
                                                "fattr: unknown subcode");
                break;
            }
            if (close_fd) { close(fd); }
            return dispatch_rc;
        }
    }

    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "fattr: unknown subcode");
}
