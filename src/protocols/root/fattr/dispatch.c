/*
 * Fattr dispatcher — routes kXR_fattr requests to the appropriate sub-handler.
 * The fattr operation has four sub-codes: get (read attributes), set (write
 * attributes), del (delete attributes), and list (enumerate all attributes).
 * This function validates parameters, resolves path or file handle, checks
 * authorization, then dispatches to the specific handler based on sub-code.
 */

#include "ngx_brix_fattr.h"
#include "fs/vfs/vfs.h"   /* confinement check via the VFS seam */
#include "protocols/root/path/op_path.h"  /* brix_root_vfs_bind_deleg (phase-70) */

#include <string.h>
#include "core/compat/alloc_guard.h"

/*
 * WHAT: Per-request dispatch state threaded through the fattr helpers: the
 *       decoded sub-code/numattr/options, the resolved target (path or fd),
 *       the raw nvec/vvec args region, the VFS context the xattr ops act
 *       through, and the error rc a failing helper queued.
 *
 * WHY: The four sub-codes share one wire frame whose target and argument
 *       layout differ; bundling the resolved pieces in one struct lets each
 *       helper stay under the 5-param gate while keeping data flow explicit.
 *
 * HOW: Declared on the dispatcher's stack (full_path/pathbuf live here so
 *       `path` may point into them); helpers fill it in and return
 *       NGX_OK/NGX_ERROR, recording the already-queued send-error rc in
 *       err_rc so the dispatcher can return it verbatim. */
typedef struct {
    int              subcode;
    int              numattr;
    int              options;
    const char      *path;       /* NULL → fd-mode target */
    int              fd;
    int              close_fd;   /* dispatcher owns fd → close after use */
    u_char          *args_buf;   /* nvec/vvec region within the payload */
    size_t           args_len;
    ngx_int_t        err_rc;     /* rc of the error a failing helper queued */
    char             full_path[PATH_MAX];
    char             pathbuf[BRIX_MAX_PATH + 1];
    /* One VFS ctx for the whole request: in path mode it carries the resolved
     * confined path the xattr ops act on; in fd mode it carries only proto/log
     * for metric attribution (the fd is the target). Lives for the handler
     * calls below. */
    brix_vfs_ctx_t   vctx;
} fattr_state_t;

/*
 * WHAT: Decoded name-vector products: the pool-owned copy of the args region,
 *       the byte count the nvec occupies within it, and the value vector
 *       (whatever follows the nvec — used by set only).
 *
 * WHY: fattr_decode_names produces four related values; returning them as one
 *       struct keeps the helper within the parameter gate.
 *
 * HOW: Filled by fattr_decode_names; nvec_copy is ngx_palloc'd from the
 *       connection pool so rc_ptr slots recorded by fattr_parse_nvec point
 *       into a buffer we own. */
typedef struct {
    u_char          *nvec_copy;
    size_t           nvec_len;
    u_char          *vvec_buf;
    size_t           vvec_len;
} fattr_names_t;

/*
 * WHAT: Records the rc of an already-queued error response in the dispatch
 *       state and returns NGX_ERROR.
 *
 * WHY: brix_send_error's return value must reach the dispatcher verbatim, but
 *       helpers signal failure with NGX_ERROR; this adapter carries the rc
 *       out-of-line so `return fattr_fail(st, brix_send_error(...))` reads as
 *       a single early-return.
 *
 * HOW: Stores rc into st->err_rc; the dispatcher returns st->err_rc whenever
 *       a helper reports NGX_ERROR. */
static ngx_int_t
fattr_fail(fattr_state_t *st, ngx_int_t rc)
{
    st->err_rc = rc;
    return NGX_ERROR;
}

/*
 * WHAT: Validates the decoded request header fields: sub-code range, the
 *       per-sub-code numattr rules, and the global read-only gate for the
 *       mutating sub-codes.
 *
 * WHY: All four sub-codes share these checks; performing them before target
 *       resolution rejects malformed frames without touching the filesystem.
 *
 * HOW: Early-returns a queued kXR error (via fattr_fail) on each violation;
 *       list must carry numattr == 0, get/set/del need 1..kXR_faMaxVars, and
 *       set/del are blocked up-front on read-only servers (invariant:
 *       allow_write is checked globally before any per-path/token scope). */
static ngx_int_t
fattr_check_request(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, fattr_state_t *st)
{
    if (st->subcode > kXR_fattrMaxSC) {
        return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgInvalid,
                                                "fattr: invalid subcode"));
    }
    /* numattr rules differ by sub-code: list enumerates everything (must be 0);
     * get/set/del operate on an explicit name vector (1..kXR_faMaxVars). */
    if (st->subcode == kXR_fattrList) {
        if (st->numattr != 0) {
            return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgInvalid,
                                                    "fattr list: numattr must be 0"));
        }
    } else if (st->numattr == 0 || st->numattr > kXR_faMaxVars) {
        return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgInvalid,
                                                "fattr: invalid numattr"));
    }

    if ((st->subcode == kXR_fattrSet || st->subcode == kXR_fattrDel) &&
        !conf->common.allow_write)
    {
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        return fattr_fail(st, brix_send_error(ctx, c, kXR_fsReadOnly,
                                                "fattr: server is read-only"));
    }

    return NGX_OK;
}

/*
 * WHAT: Initialises the request's VFS context from the resolved target and
 *       binds the per-user backend credential and delegated identity.
 *
 * WHY: All three target shapes end with this identical init/bind triple;
 *       centralising it keeps the credential threading uniform (a driver-path
 *       fattr on a remote-backed export must present the requesting user's
 *       cred).
 *
 * HOW: st->path NULL → fd mode (vctx carries proto/log only for metric
 *       attribution); non-NULL → driver/confined path mode. Then binds the
 *       storage credential directory/fallback and the phase-70 delegation. */
static void
fattr_bind_vctx(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, fattr_state_t *st)
{
    brix_vfs_ctx_init(&st->vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL, conf->common.allow_write,
        0 /* is_tls */, ctx->identity, st->path);
    brix_vfs_ctx_bind_backend_cred(&st->vctx,
        &conf->common.storage_credential_dir,
        conf->common.storage_credential_fallback);
    brix_root_vfs_bind_deleg(ctx, conf, &st->vctx);
}

/*
 * WHAT: Resolves an fhandle-targeted request: bounds/open-state checks the
 *       wire file-handle index and records the target fd (and, for
 *       driver-backed handles, the resolved path).
 *
 * WHY: Payload shapes (a) and (b) share this lookup verbatim; a driver-backed
 *       handle (object store: ceph/s3/…) keeps its xattrs on the BACKEND
 *       object, not the local placeholder fd — a raw fsetxattr on that fd is
 *       lost, so such handles are routed by path through the driver.
 *
 * HOW: fh0 is the one wire byte of the fhandle; validates the index against
 *       BRIX_MAX_FILES and the open-fd table, then flips to path mode when the
 *       handle carries a driver + resolved path (set/get/list then hit the
 *       same store the bytes live in). */
static ngx_int_t
fattr_fhandle_target(brix_ctx_t *ctx, ngx_connection_t *c,
    fattr_state_t *st, unsigned char fh0)
{
    /* fhandle index is one wire byte; bounds + open-state checked. */
    int idx = (int) fh0;

    if (idx < 0 || idx >= BRIX_MAX_FILES || ctx->files[idx].fd < 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        return fattr_fail(st, brix_send_error(ctx, c, kXR_FileNotOpen,
                                                "fattr: invalid file handle"));
    }
    st->fd = ctx->files[idx].fd;
    /* Driver-backed handle: route xattrs by the resolved path through the
     * driver (path mode), not the local placeholder fd. */
    if (ctx->files[idx].sd_obj.driver != NULL
        && ctx->files[idx].path != NULL)
    {
        st->path = ctx->files[idx].path;
    }

    return NGX_OK;
}

/*
 * WHAT: Resolves a path-targeted request (payload = "<path>\0[args...]"):
 *       extracts and confines the client path, auth-gates it, verifies it via
 *       a confined VFS stat, and records the trailing args region.
 *
 * WHY: The path shape is the only target that needs auth gating and
 *       confinement here (fhandle targets were gated at open); isolating it
 *       keeps the framing-only dispatcher free of filesystem concerns.
 *
 * HOW: Bounded strnlen finds the path's NUL (path_payload_len includes it so
 *       the args region begins exactly at payload + path_payload_len);
 *       brix_extract_path validates, brix_beneath_full_path resolves beneath
 *       the export root, brix_auth_gate enforces READ for get/list and UPDATE
 *       for set/del, and a confined no-follow brix_vfs_stat verifies the path
 *       is within the export root (and exists) without a raw open_beneath.
 *       The fattr ops then operate by path (through the same vctx) so a
 *       directory list can recurse. */
static ngx_int_t
fattr_path_target(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, fattr_state_t *st)
{
    size_t path_wire_len;
    size_t path_payload_len;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgMissing,
                                                "fattr: missing path"));
    }

    /* Bounded scan for the path's NUL; path_payload_len includes it so the
     * args region begins exactly at payload + path_payload_len below. */
    path_wire_len = strnlen((char *) ctx->recv.payload, ctx->recv.cur_dlen);
    path_payload_len = path_wire_len + 1;

    if (!brix_extract_path(c->log, ctx->recv.payload, path_payload_len,
                             st->pathbuf, sizeof(st->pathbuf), 1)) {
        BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
        return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgInvalid,
                                                "fattr: invalid path"));
    }
    /* Resolve the client path beneath the export root → full_path.
     * phase72-fp: pathbuf is the request path, full_path the output buf. */
    brix_beneath_full_path(conf->common.root_canon, st->pathbuf,  /* NOLINT(readability-suspicious-call-argument) */
                              st->full_path, sizeof(st->full_path));
    {
        /* set/del need UPDATE rights; get/list need only READ. */
        int need_write = (st->subcode == kXR_fattrSet
                          || st->subcode == kXR_fattrDel) ? 1 : 0;
        uint32_t auth_level = need_write ? BRIX_AUTH_UPDATE
                                         : BRIX_AUTH_READ;
        if (brix_auth_gate(ctx, c, BRIX_OP_FATTR, "FATTR",
                             st->pathbuf, st->full_path, conf,
                             auth_level, need_write) != NGX_OK) {
            /* auth_gate already queued the error; ctx->write_rc is its rc. */
            return fattr_fail(st, ctx->write_rc);
        }
    }

    {
        /* Confinement check via the VFS: a confined no-follow stat verifies
         * the path is within the export root (and exists). */
        brix_vfs_stat_t vst;

        st->path = st->full_path;
        fattr_bind_vctx(ctx, c, conf, st);
        if (brix_vfs_stat(&st->vctx, &vst) != NGX_OK) {
            BRIX_OP_ERR(ctx, BRIX_OP_FATTR);
            return fattr_fail(st, brix_send_error(ctx, c,
                                                    brix_kxr_from_errno(errno),
                                                    "fattr: cannot open path"));
        }
    }
    /* Args (nvec/vvec) are whatever bytes follow the path's NUL. */
    if (path_payload_len < ctx->recv.cur_dlen) {
        st->args_buf = ctx->recv.payload + path_payload_len;
        st->args_len = ctx->recv.cur_dlen - path_payload_len;
    }

    return NGX_OK;
}

/*
 * WHAT: Selects the request target from the payload shape and fills the
 *       dispatch state with the resolved fd/path, bound vctx, and args region.
 *
 * WHY: The fattr wire frame overloads three mutually exclusive payload shapes;
 *       resolving them in one place keeps the sub-handlers free of framing
 *       concerns.
 *
 * HOW: Three-way branch: (a) cur_dlen == 0 → no body: the target is the
 *       fhandle in the request header, only valid for fattrList (others need
 *       an nvec); (b) payload[0] == 0 → leading 0 byte marks an fhandle
 *       target, the file index is still req->fhandle[0] and any args follow
 *       at payload+1; (c) otherwise → payload starts with a NUL-terminated
 *       path, args (if any) follow the path's terminator
 *       (fattr_path_target binds the vctx itself, after auth). */
static ngx_int_t
fattr_select_target(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, fattr_state_t *st,
    const xrdw_fattr_req_t *req)
{
    if (ctx->recv.cur_dlen == 0) {
        /* (a) Empty body is only meaningful for list; others need an nvec. */
        if (st->subcode != kXR_fattrList) {
            return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgMissing,
                                                    "fattr: missing arguments"));
        }
        if (fattr_fhandle_target(ctx, c, st, (unsigned char) req->fhandle[0])
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        fattr_bind_vctx(ctx, c, conf, st);
        return NGX_OK;
    }

    if (ctx->recv.payload != NULL && ctx->recv.payload[0] == 0) {
        /* (b) fhandle-targeted request with a leading 0 marker byte. */
        if (fattr_fhandle_target(ctx, c, st, (unsigned char) req->fhandle[0])
            != NGX_OK)
        {
            return NGX_ERROR;
        }
        fattr_bind_vctx(ctx, c, conf, st);
        /* Everything after the marker byte is the nvec/vvec args region. */
        if (ctx->recv.cur_dlen > 1) {
            st->args_buf = ctx->recv.payload + 1;
            st->args_len = ctx->recv.cur_dlen - 1;
        }
        return NGX_OK;
    }

    /* (c) Path-targeted request: payload = "<path>\0[args...]". */
    return fattr_path_target(ctx, c, conf, st);
}

/*
 * WHAT: Copies the args region and parses it into the name vector (attrs[]),
 *       splitting off whatever follows as the value vector.
 *
 * WHY: fattr_parse_nvec records rc_ptr slots that point into the buffer, and
 *       the wire payload is overwritten in place with status codes when
 *       building the response — so the parse must run over a copy we own.
 *
 * HOW: ngx_palloc + ngx_memcpy the args region, run fattr_parse_nvec (returns
 *       the byte count it consumed, negative on malformed input), then set
 *       vvec_buf/vvec_len to the remainder (used by set only). */
static ngx_int_t
fattr_decode_names(brix_ctx_t *ctx, ngx_connection_t *c,
    fattr_state_t *st, brix_fattr_entry_t *attrs, fattr_names_t *names)
{
    ssize_t nvec_used;

    BRIX_PALLOC_OR_RETURN(names->nvec_copy, c->pool, st->args_len,
        fattr_fail(st, brix_send_error(ctx, c, kXR_NoMemory, "out of memory")));
    ngx_memcpy(names->nvec_copy, st->args_buf, st->args_len);

    /* Parse the name vector; returns the byte count it consumed. */
    nvec_used = fattr_parse_nvec(c->log, names->nvec_copy, st->args_len,
                                 st->numattr, attrs);
    if (nvec_used < 0) {
        return fattr_fail(st, brix_send_error(ctx, c, kXR_ArgInvalid,
                                                "fattr: malformed nvec"));
    }

    /* Whatever follows the nvec is the value vector (used by set only). */
    names->nvec_len = (size_t) nvec_used;
    names->vvec_buf = names->nvec_copy + names->nvec_len;
    names->vvec_len = st->args_len - names->nvec_len;

    return NGX_OK;
}

/*
 * WHAT: Decodes the name vector and dispatches the named sub-codes
 *       (get/set/del) to their handlers, closing any dispatcher-owned fd.
 *
 * WHY: The three named sub-codes share the nvec decode and the fd-cleanup
 *       tail; grouping them leaves the dispatcher a flat validate → resolve →
 *       dispatch sequence.
 *
 * HOW: fattr_decode_names produces the nvec/vvec split, then a switch on the
 *       sub-code calls fattr_get/set/del through the VFS xattr seam; an
 *       unknown sub-code (unreachable past fattr_check_request) answers
 *       kXR_Unsupported. close_fd guards any fd we own. */
static ngx_int_t
fattr_dispatch_named(brix_ctx_t *ctx, ngx_connection_t *c, fattr_state_t *st)
{
    brix_fattr_entry_t attrs[kXR_faMaxVars];
    fattr_names_t      names;
    ngx_int_t          dispatch_rc;

    if (fattr_decode_names(ctx, c, st, attrs, &names) != NGX_OK) {
        return st->err_rc;
    }

    switch (st->subcode) {
    case kXR_fattrGet:
        dispatch_rc = fattr_get(ctx, c, &st->vctx, st->path, st->fd,
                                names.nvec_copy, names.nvec_len,
                                st->numattr, attrs);
        break;
    case kXR_fattrSet:
        dispatch_rc = fattr_set(ctx, c, &st->vctx, st->path, st->fd,
                                st->options,
                                names.nvec_copy, names.nvec_len,
                                names.vvec_buf, names.vvec_len,
                                st->numattr, attrs);
        break;
    case kXR_fattrDel:
        dispatch_rc = fattr_del(ctx, c, &st->vctx, st->path, st->fd,
                                names.nvec_copy, names.nvec_len,
                                st->numattr, attrs);
        break;
    default:
        dispatch_rc = brix_send_error(ctx, c, kXR_Unsupported,
                                        "fattr: unknown subcode");
        break;
    }
    if (st->close_fd) { close(st->fd); }
    return dispatch_rc;
}

/*
 * WHAT: Validates the fattr request header, determines whether it targets an
 *       open file handle or a filesystem path, enforces read-only and auth
 *       gating, then splits the payload into the name-vector (nvec) and
 *       value-vector (vvec) and dispatches to fattr_get/set/del/list.
 *
 * WHY: The fattr wire frame is overloaded across four sub-codes whose argument
 *       layout differs (list takes no nvec; set carries an extra vvec) and
 *       whose target can be either an fhandle or an inline path. Centralising
 *       the parsing/validation here keeps each sub-handler free of framing
 *       concerns.
 *
 * HOW: Flat early-return sequence over the fattr_state_t: fattr_check_request
 *       validates the header, fattr_select_target resolves the fhandle/path
 *       target (auth-gating and confined-verifying path targets) and binds
 *       the VFS context, then list dispatches directly (it takes no nvec)
 *       while get/set/del go through fattr_dispatch_named. */
ngx_int_t
brix_handle_fattr(brix_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_brix_srv_conf_t *conf)
{
    /* hdr_buf aliases the fixed request header; payload/cur_dlen hold the body. */
    xrdw_fattr_req_t    req;
    fattr_state_t       st;

    xrdw_fattr_req_unpack(((ClientRequestHdr *) ctx->recv.hdr_buf)->body, &req);
    st.subcode = req.subcode;
    st.numattr = req.numattr;
    st.options = req.options;
    st.path = NULL;
    st.fd = -1;
    st.close_fd = 0;
    st.args_buf = NULL;
    st.args_len = 0;
    st.err_rc = NGX_ERROR;

    if (fattr_check_request(ctx, c, conf, &st) != NGX_OK) {
        return st.err_rc;
    }

    if (fattr_select_target(ctx, c, conf, &st, &req) != NGX_OK) {
        return st.err_rc;
    }

    /* list takes no nvec — dispatch directly. */
    if (st.subcode == kXR_fattrList) {
        ngx_int_t rc = fattr_list(ctx, c, &st.vctx, st.path, st.fd,
                                  st.options);
        if (st.close_fd) { close(st.fd); }
        return rc;
    }

    /* get/set/del all require a name vector. */
    if (st.args_buf == NULL || st.args_len == 0) {
        return brix_send_error(ctx, c, kXR_ArgMissing,
                                 "fattr: missing nvec");
    }

    return fattr_dispatch_named(ctx, c, &st);
}
