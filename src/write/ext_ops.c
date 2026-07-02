/*
 * ext_ops.c — vendor extension opcode handlers: kXR_setattr / kXR_symlink /
 *             kXR_readlink / kXR_link.
 *
 * WHAT: POSIX-completeness operations the base XRootD protocol has no wire op for:
 *       set-mtime/atime + chown (kXR_setattr), symbolic links (kXR_symlink /
 *       kXR_readlink) and hard links (kXR_link). They let a FUSE mount honour
 *       `cp -p`, `touch -d`, chown, and `ln`/`ln -s` against this gateway.
 * WHY:  Capability-negotiated extensions (advertised via kXR_Qconfig "xrdfs.ext");
 *       the native client only emits them when advertised, so a stock client never
 *       triggers these handlers and a stock server never receives the opcodes.
 * HOW:  Same shape as the other namespace handlers — extract + resolve the path(s)
 *       (xrootd_resolve_op_path / xrootd_path_resolve_beneath), run the three-tier
 *       auth gate, then perform the operation through a ROOT-CONFINED *at() helper
 *       (resolve_confined_ops.c) so a symlink/parent swap cannot escape the export
 *       root. setattr's variable attribute block is parsed from the payload prefix.
 *
 * Wire formats: see src/protocol/wire_vendor_ext.h.
 */
#include "core/ngx_xrootd_module.h"
#include "ext_ops.h"
#include "core/compat/error_mapping.h"
#include "core/compat/vendor_ext.h"   /* shared kXR_setattr prefix codec (libxrdproto) */
#include "path/op_path.h"
#include "path/auth_gate.h"
#include "path/path.h"
#include "fs/vfs.h"   /* xrootd_vfs_setattr — driver-routed metadata mutation */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <string.h>
#include <time.h>

/*
 * kXR_setattr — set timestamps (utimens) and/or owner (chown) on a path.
 * Payload = 44-byte big-endian attribute prefix + NUL-terminated path
 * (see wire_vendor_ext.h). mode is intentionally not handled (kXR_chmod covers it).
 */
ngx_int_t
xrootd_handle_setattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const u_char *p;
    int32_t       flags;
    struct timespec times[2];
    int32_t       uid, gid;
    char          reqpath[XROOTD_MAX_PATH + 1];
    char          resolved[PATH_MAX];

    if (ctx->payload == NULL
        || ctx->cur_dlen <= (uint32_t) XROOTD_SETATTR_PREFIX_LEN) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "setattr: short payload");
    }

    p = ctx->payload;
    {
        /* Shared 44-byte attribute-prefix codec (libxrdproto) — same offsets the
         * client encodes with, so the two cannot drift. */
        xrdp_setattr_t a;
        xrdp_setattr_prefix_unpack(p, &a);
        flags            = (int32_t) a.flags;
        times[0].tv_sec  = (time_t)  a.atime_sec;
        times[0].tv_nsec = (long)    a.atime_nsec;
        times[1].tv_sec  = (time_t)  a.mtime_sec;
        times[1].tv_nsec = (long)    a.mtime_nsec;
        uid              = a.uid;
        gid              = a.gid;
    }

    if (!xrootd_extract_path(c->log, p + XROOTD_SETATTR_PREFIX_LEN,
                             ctx->cur_dlen - XROOTD_SETATTR_PREFIX_LEN,
                             reqpath, sizeof(reqpath), 1)) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "setattr: invalid path");
    }

    if (xrootd_path_resolve_beneath(conf, c->log, reqpath, XROOTD_PATH_EXISTING,
                                    resolved, sizeof(resolved)) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "SETATTR", reqpath, "-",
                          kXR_NotFound, "not found");
    }

    if (xrootd_auth_gate(ctx, c, XROOTD_OP_CHMOD, "SETATTR",
                         reqpath, resolved, conf,
                         XROOTD_AUTH_UPDATE, 1) != NGX_OK) {
        return ctx->write_rc;
    }

    {
        xrootd_vfs_ctx_t    vctx;
        xrootd_sd_setattr_t attr;

        xrootd_vfs_ctx_init(&vctx, c->pool, c->log, XROOTD_PROTO_STREAM,
            conf->common.root_canon, NULL, conf->common.allow_write,
            0 /* is_tls */, NULL, resolved);

        ngx_memzero(&attr, sizeof(attr));
        attr.set_times = (flags & kXR_sa_times) ? 1 : 0;
        attr.set_owner = (flags & kXR_sa_owner) ? 1 : 0;
        attr.atime     = times[0];
        attr.mtime     = times[1];
        attr.uid       = (uid_t) uid;
        attr.gid       = (gid_t) gid;

        if (xrootd_vfs_setattr(&vctx, &attr) != NGX_OK) {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_CHMOD, "SETATTR", resolved, "-",
                              xrootd_kxr_from_errno(errno), strerror(errno));
        }
    }

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_CHMOD, "SETATTR", resolved, "-", 0);
}

/*
 * kXR_symlink — create a symbolic link. Wire (mirrors kXR_mv): payload =
 * target + ' ' + linkpath, arg1len = strlen(target). The target is stored
 * verbatim (NOT path-validated — it is link content, traversal-confined at open
 * time); only linkpath is resolved + confined.
 */
ngx_int_t
xrootd_handle_symlink(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    xrdw_twopath_req_t req;
    char     target[PATH_MAX];
    char     link_buf[XROOTD_MAX_PATH + 1];
    char     link_resolved[PATH_MAX];
    int16_t  tlen;
    size_t   link_len;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "symlink: no paths");
    }
    xrdw_twopath_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    tlen = req.arg1len;
    if (tlen <= 0 || (uint32_t) (tlen + 1) >= ctx->cur_dlen
        || (size_t) tlen >= sizeof(target)) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "symlink: bad arg1len");
    }
    if (ctx->payload[tlen] != ' ') {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "symlink: bad separator");
    }
    /* target is verbatim link content — copy as-is, reject an embedded NUL. */
    if (memchr(ctx->payload, '\0', (size_t) tlen) != NULL) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "symlink: NUL in target");
    }
    memcpy(target, ctx->payload, (size_t) tlen);
    target[tlen] = '\0';

    link_len = (size_t) ctx->cur_dlen - (size_t) tlen - 1;
    if (link_len == 0
        || !xrootd_extract_path(c->log, ctx->payload + tlen + 1, link_len,
                                link_buf, sizeof(link_buf), 1)) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "symlink: invalid linkpath");
    }

    /* The link location's parent must exist; the link itself must not (WRITE). */
    if (xrootd_path_resolve_beneath(conf, c->log, link_buf, XROOTD_PATH_WRITE,
                                    link_resolved, sizeof(link_resolved)) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "SYMLINK", link_buf, "-",
                          kXR_NotFound, "invalid link path");
    }
    if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "SYMLINK",
                         link_buf, link_resolved, conf,
                         XROOTD_AUTH_UPDATE, 1) != NGX_OK) {
        return ctx->write_rc;
    }

    if (xrootd_symlink_confined_canon(c->log, conf->common.root_canon,
                                      target, link_resolved) != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "SYMLINK", link_resolved, "-",
                          xrootd_kxr_from_errno(errno), strerror(errno));
    }

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MKDIR, "SYMLINK", link_resolved, "-", 0);
}

/*
 * kXR_link — create a hard link. Wire (mirrors kXR_mv): payload =
 * oldpath + ' ' + newpath, arg1len = strlen(oldpath). Both paths are resolved +
 * confined; the existing source is linked to a new destination.
 */
ngx_int_t
xrootd_handle_link(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    xrdw_twopath_req_t req;
    char     src_buf[XROOTD_MAX_PATH + 1];
    char     dst_buf[XROOTD_MAX_PATH + 1];
    char     src_resolved[PATH_MAX];
    char     dst_resolved[PATH_MAX];
    int16_t  src_len;
    size_t   dst_len;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "link: no paths");
    }
    xrdw_twopath_req_unpack(((ClientRequestHdr *) ctx->hdr_buf)->body, &req);
    src_len = req.arg1len;
    if (src_len <= 0 || (uint32_t) (src_len + 1) >= ctx->cur_dlen) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "link: bad arg1len");
    }
    if (ctx->payload[src_len] != ' ') {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "link: bad separator");
    }
    dst_len = (size_t) ctx->cur_dlen - (size_t) src_len - 1;
    if (dst_len == 0
        || !xrootd_extract_path(c->log, ctx->payload, (size_t) src_len,
                                src_buf, sizeof(src_buf), 1)
        || !xrootd_extract_path(c->log, ctx->payload + src_len + 1, dst_len,
                                dst_buf, sizeof(dst_buf), 1)) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid, "link: invalid path");
    }

    if (xrootd_path_resolve_beneath(conf, c->log, src_buf, XROOTD_PATH_EXISTING,
                                    src_resolved, sizeof(src_resolved)) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "LINK", src_buf, "-",
                          kXR_NotFound, "source not found");
    }
    if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "LINK",
                         src_buf, src_resolved, conf,
                         XROOTD_AUTH_UPDATE, 1) != NGX_OK) {
        return ctx->write_rc;
    }
    if (xrootd_path_resolve_beneath(conf, c->log, dst_buf, XROOTD_PATH_WRITE,
                                    dst_resolved, sizeof(dst_resolved)) != NGX_OK) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "LINK", dst_buf, "-",
                          kXR_NotFound, "invalid destination path");
    }
    if (xrootd_auth_gate(ctx, c, XROOTD_OP_MKDIR, "LINK",
                         dst_buf, dst_resolved, conf,
                         XROOTD_AUTH_UPDATE, 1) != NGX_OK) {
        return ctx->write_rc;
    }

    if (xrootd_link_confined_canon(c->log, conf->common.root_canon,
                                   src_resolved, dst_resolved) != 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_MKDIR, "LINK", dst_resolved, "-",
                          xrootd_kxr_from_errno(errno), strerror(errno));
    }

    XROOTD_RETURN_OK(ctx, c, XROOTD_OP_MKDIR, "LINK", dst_resolved, "-", 0);
}

/*
 * kXR_readlink — return a symlink's target. Read-side op (no write gate). The
 * response body is the raw target bytes (not NUL-terminated on the wire).
 */
ngx_int_t
xrootd_handle_readlink(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    char    reqpath[XROOTD_MAX_PATH + 1];
    char    resolved[PATH_MAX];
    char    target[PATH_MAX];
    ssize_t n;

    /* NOEXIST (not EXISTING): the EXISTING gate follow-stats the path, which fails
     * for a DANGLING symlink (target missing). readlinkat below is the real check —
     * it reads the link itself without following it, and ENOENTs a missing path. */
    if (xrootd_resolve_op_path(ctx, c, XROOTD_OP_STAT, "READLINK", conf,
                               XROOTD_PATH_NOEXIST,
                               reqpath, sizeof(reqpath),
                               resolved, sizeof(resolved)) != NGX_OK) {
        return ctx->write_rc;
    }
    if (xrootd_auth_gate(ctx, c, XROOTD_OP_STAT, "READLINK",
                         reqpath, resolved, conf,
                         XROOTD_AUTH_READ, 0) != NGX_OK) {
        return ctx->write_rc;
    }

    n = xrootd_readlink_confined_canon(c->log, conf->common.root_canon,
                                       resolved, target, sizeof(target) - 1);
    if (n < 0) {
        XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STAT, "READLINK", resolved, "-",
                          xrootd_kxr_from_errno(errno), strerror(errno));
    }

    /* Body = the link target. Log + count, then send (own body → not RETURN_OK). */
    xrootd_log_access(ctx, c, "READLINK", resolved, "-", 1, kXR_ok, NULL, (size_t) n);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);
    return xrootd_send_ok(ctx, c, target, (uint32_t) n);
}
