/*
 * op_path.c — unified path extractor + resolver for namespace operations.
 *
 * Centralises the repeated extract_path → depth_check → resolve sequence
 * that was previously duplicated across 10+ handler files.
 *
 * Phase 8: resolution no longer calls realpath(3).  Confinement is enforced by
 * the kernel at the actual filesystem operation (openat2 RESOLVE_BENEATH via the
 * beneath API), so this layer only has to (1) reject obviously-bad paths the same
 * way the old brix_validate_components_cstr() did — length, depth, and the
 * forbidden "."/".." components — and (2) reproduce the per-mode existence
 * semantics the old resolve_path* variants provided (EXISTING needs the target,
 * WRITE needs the parent directory) through the VFS seam (brix_vfs_probe, a
 * non-observing confined existence/type check) rather than a realpath() that
 * would have failed.  `resolved` is filled with the lexical
 * root_canon + reqpath join (brix_beneath_full_path); it is used downstream for
 * ACL prefix matching and access logging, NOT as a confinement boundary — the
 * boundary is RESOLVE_BENEATH at the op.  A path that escapes the export root is
 * rejected by the kernel (EXDEV) when the operation runs.
 */
#include "core/ngx_brix_module.h"
#include "op_path.h"
#include "fs/path/beneath.h"
#include "fs/path/reserved_names.h"   /* brix_is_internal_name — hide sidecars */
#include "fs/path/path_internal.h"
#include "fs/vfs/vfs.h"   /* existence/type pre-gate via the VFS seam */
#include "protocols/shared/deleg_wire.h"   /* §5.2 aud gate + §5.4 exchange */
#include "auth/krb5/deleg_capture.h"        /* §5.7 forwarded-TGT origin-SPN bind */
#include "fs/vfs/vfs_backend_registry.h"  /* POSIX-vs-driver existence-gate routing */

#include <sys/stat.h>

/*
 * Validate each path component the way the retired realpath resolver's
 * brix_validate_components_cstr() did: reject "." and ".." segments outright.
 * RESOLVE_BENEATH would block a "../" that escapes the root, but a within-root
 * "/a/../b" was historically rejected here too — keep that behaviour so the
 * resolver's contract is unchanged.  Returns 1 if any component is forbidden.
 */
int
brix_op_path_forbidden_component(const char *reqpath)
{
    const char *p = reqpath;
    const char *seg;

    while (*p != '\0') {
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        seg = p;
        while (*p != '\0' && *p != '/') {
            p++;
        }
        if (brix_path_component_forbidden(seg, (size_t) (p - seg))) {
            return 1;
        }
    }
    return 0;
}

/*
 * Existence gate replacing the realpath()-failure path of the old resolvers.
 *   want_dir < 0 : no check (NOEXIST).
 *   want_dir = 0 : the target itself must exist (EXISTING).
 *   want_dir = 1 : the target's PARENT directory must exist (WRITE).
 * Returns NGX_OK when the requirement is met, NGX_DECLINED otherwise.
 */
/* Build a probe VFS ctx for `reqpath` (joined beneath the export root) and run a
 * non-observing confined existence/type check (no phantom OP_STAT metric). */
static ngx_int_t
op_path_probe(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log,
              const char *reqpath, int nofollow, brix_vfs_stat_t *vst)
{
    brix_vfs_ctx_t vctx;
    char             full[PATH_MAX];

    brix_beneath_full_path(conf->common.root_canon, reqpath,
                             full, sizeof(full));
    brix_vfs_ctx_init(&vctx, NULL /* no alloc in a probe */, log,
        BRIX_PROTO_ROOT, conf->common.root_canon, NULL,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls */, NULL, full);
    /* This existence-only preflight intentionally precedes the protocol-edge
     * authorization gate and returns no metadata. Bind it explicitly OFF so
     * it is not reported as an accidentally-unbound storage operation; the
     * eventual VFS mutation/read uses the session-bound context. */
    brix_vfs_ctx_bind_authz(&vctx, conf->authdb_rules, conf->common.vo_rules,
        conf->common.acc.tables, conf->common.acc.format, NULL, BRIX_AUTHZ_BACKSTOP_OFF);
    /* Persistent per-worker confinement rootfd (op_vfs_ctx pattern). */
    vctx.rootfd = conf->rootfd;
    return brix_vfs_probe(&vctx, nofollow, vst);
}

static ngx_int_t
op_path_existence_gate(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log,
                       const char *reqpath, int want_dir)
{
    brix_vfs_stat_t vst;

    if (want_dir < 0) {
        return NGX_OK;                  /* NOEXIST: nothing to verify */
    }

    if (want_dir == 0) {
        /* For a NON-POSIX backend the operation's own driver call validates the
         * target and returns ENOENT→NotFound, so this gate's probe is a redundant
         * catalog lookup — skip it (the driver is the single existence check). The
         * default POSIX export keeps the probe below: its confined lstat is cheap
         * and preserves the existing existence-before-auth ordering exactly. */
        if (brix_vfs_backend_resolve(conf->common.root_canon, log) != NULL) {
            return NGX_OK;
        }
        /* EXISTING: the target name must resolve, confined, to something present.
         * nofollow (lstat semantics) so a symlink — including a dangling one —
         * counts as present: rm/chmod/mv operate on the name itself, and rm of a
         * symlink must succeed (it never dereferences the final component). This
         * gate is only the ACL/logging existence check; the confined VFS ops
         * remain the security boundary, so not following the final link here
         * weakens nothing. */
        return op_path_probe(conf, log, reqpath, 1 /* nofollow */, &vst) == NGX_OK
               ? NGX_OK : NGX_DECLINED;
    }

    /* WRITE: the parent directory must already exist (target may not). For a
     * NON-POSIX backend, skip this parent probe for the SAME reason the EXISTING
     * case above skips its target probe: the operation's own driver call
     * (mkpath/rename/open-write) validates the parent and returns
     * ENOENT→NotFound, so the probe is a redundant catalog lookup — and worse, it
     * runs on an UNAUTHENTICATED probe ctx (op_path_probe binds no per-user
     * credential/delegation), so on a delegated auth-required origin the parent
     * stat is rejected as the anonymous service identity and a perfectly valid
     * destination is wrongly refused ("invalid destination path"). That is the
     * same missing-credential-on-a-namespace-leg class as the mkdir_cred fix; the
     * driver is the single existence check. The default POSIX export keeps the
     * confined parent lstat below (its probe is local and needs no credential). */
    if (brix_vfs_backend_resolve(conf->common.root_canon, log) != NULL) {
        return NGX_OK;
    }

    /* Derive the parent by trimming the last '/'-separated component. */
    {
        char        parent[BRIX_MAX_PATH + 1];
        size_t      len = ngx_strlen(reqpath);
        const char *slash;

        while (len > 1 && reqpath[len - 1] == '/') {
            len--;                      /* ignore trailing slashes for the split */
        }
        slash = reqpath + len;
        while (slash > reqpath && *(slash - 1) != '/') {
            slash--;
        }
        /* slash now points just past the parent's trailing '/'. */
        {
            size_t plen = (size_t) (slash - reqpath);
            if (plen <= 1) {
                /* parent is the export root itself — always present. */
                return NGX_OK;
            }
            /* `slash` points just PAST the parent's trailing '/', so plen still
             * includes it. Drop it: a confined POSIX lstat tolerates a trailing
             * slash on a directory ("/w0/"), but a driver whose namespace lives
             * in a catalog (pblock) stores the key as "/w0" and a "/w0/" lookup
             * misses — which silently broke every non-recursive nested mkdir on a
             * non-POSIX backend. The parent path handed to the probe must be
             * slash-free. */
            plen--;
            if (plen >= sizeof(parent)) {
                return NGX_DECLINED;
            }
            ngx_memcpy(parent, reqpath, plen);
            parent[plen] = '\0';
        }
        if (op_path_probe(conf, log, parent, 0 /* follow */, &vst) != NGX_OK
            || !vst.is_directory)
        {
            return NGX_DECLINED;
        }
        return NGX_OK;
    }
}

/* ---- op_path_mode_flags — decode a path mode into gate parameters ----------
 *
 * WHAT: Map a brix_path_mode_t to the two scalars the resolver drives its
 *       existence check with: want_dir (see op_path_existence_gate) and
 *       strip_trailing_slash (whether a create target's trailing '/' is
 *       normalized away). Fills both out-params; no return value.
 *
 * WHY:  Keeps the mode→behavior table as one small, side-effect-free lookup so
 *       the resolver stays a flat sequence and the per-mode policy lives in a
 *       single place instead of inline in a larger function.
 *
 * HOW:  1. EXISTING gates on the target itself, keeps trailing slash.
 *       2. WRITE gates on the parent dir and strips a trailing slash.
 *       3. NOEXIST skips the existence gate (want_dir < 0), keeps slash.
 *       4. EITHER gates on the parent (with a target-retry upstream), keeps slash.
 *       5. Any other value falls back to EXISTING semantics.
 */
static void
op_path_mode_flags(brix_path_mode_t mode, int *want_dir,
                   int *strip_trailing_slash)
{
    switch (mode) {
    case BRIX_PATH_EXISTING: *want_dir = 0;  *strip_trailing_slash = 0; break;
    case BRIX_PATH_WRITE:    *want_dir = 1;  *strip_trailing_slash = 1; break;
    case BRIX_PATH_NOEXIST:  *want_dir = -1; *strip_trailing_slash = 0; break;
    case BRIX_PATH_EITHER:   *want_dir = 1;  *strip_trailing_slash = 0; break;
    default:                 *want_dir = 0;  *strip_trailing_slash = 0; break;
    }
}

/* ---- op_path_normalize_trailing — collapse a create target's trailing '/' ---
 *
 * WHAT: For create modes only, rewrite "*reqpath" into the caller-provided
 *       "norm" buffer with any trailing '/' characters removed, and repoint
 *       "*reqpath" at "norm". Returns NGX_ERROR if the copy would overflow
 *       "norm", NGX_OK otherwise (including the common no-op cases).
 *
 * WHY:  Reproduces the reference server's Squash of a trailing slash on a
 *       create target ("mkdir /d/" -> /d, "open /f/" -> /f) so stock-accepted
 *       requests are not rejected as ArgInvalid. Scoped to the create modes so a
 *       stat/cat of "/file/" keeps its existing file-vs-dir error behavior.
 *
 * HOW:  1. No-op when strip_trailing_slash is unset.
 *       2. No-op when the path is "/" or does not end in '/'.
 *       3. Reject when the path (plus its NUL) will not fit in norm_sz.
 *       4. Copy into norm, drop trailing '/' down to a length of 1, and
 *          repoint *reqpath at the normalized buffer.
 */
static ngx_int_t
op_path_normalize_trailing(int strip_trailing_slash, const char **reqpath,
                           char *norm, size_t norm_sz)
{
    size_t rl;

    if (!strip_trailing_slash) {
        return NGX_OK;
    }

    rl = ngx_strlen(*reqpath);
    if (rl <= 1 || (*reqpath)[rl - 1] != '/') {
        return NGX_OK;
    }

    if (rl >= norm_sz) {
        return NGX_ERROR;
    }

    ngx_memcpy(norm, *reqpath, rl + 1);
    while (rl > 1 && norm[rl - 1] == '/') {
        norm[--rl] = '\0';
    }
    *reqpath = norm;
    return NGX_OK;
}

/* ---- op_path_gate — run the per-mode existence gate with the EITHER retry ----
 *
 * WHAT: Apply op_path_existence_gate() with the mode's want_dir, and for
 *       BRIX_PATH_EITHER retry as a target-existence check when the first pass
 *       fails. Returns NGX_OK when the requirement is met, NGX_DECLINED when it
 *       is not (target/parent missing).
 *
 * WHY:  EITHER means "target may already exist OR its parent must exist" (used
 *       where an op accepts both a present target and a create). Folding the
 *       fallback here keeps the resolver's control flow linear and single-purpose.
 *
 * HOW:  1. Run the gate with want_dir; return NGX_OK on success.
 *       2. For EITHER, run the gate again with want_dir 0 (target must exist);
 *          return NGX_OK on success.
 *       3. Otherwise return NGX_DECLINED.
 */
static ngx_int_t
op_path_gate(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log,
             const char *reqpath, brix_path_mode_t mode, int want_dir)
{
    if (op_path_existence_gate(conf, log, reqpath, want_dir) == NGX_OK) {
        return NGX_OK;
    }
    if (mode == BRIX_PATH_EITHER
        && op_path_existence_gate(conf, log, reqpath, 0) == NGX_OK)
    {
        return NGX_OK;
    }
    return NGX_DECLINED;
}

/*
 * brix_path_resolve_beneath — validate reqpath and apply the per-mode
 * existence gate without realpath(), filling `resolved` with the confined
 * lexical join.  Shared by brix_resolve_op_path() and direct multi-path
 * callers (kXR_mv).  reqpath must already be extracted from the wire.
 *
 * A path naming an internal artifact (a cache sidecar, a stage-out marker, an
 * in-flight upload temp) is refused as ABSENT here, exactly as kXR_open/stat/
 * statx refuse it and exactly as the HTTP planes 404 it — unless the location is
 * a declared cache-STORE endpoint, the one surface for which those names are
 * legitimate request targets. Without this, the mutating opcodes that resolve
 * through here (rm, rmdir, chmod, mkdir, truncate, readlink, fattr, and mv on
 * both of its paths) would be the only ops in the tree able to act on a name no
 * op will show, stat, or open — unlink included.
 *
 * Returns:
 *   NGX_OK       — valid and the existence requirement is met; resolved filled.
 *   NGX_DECLINED — path is well-formed but reserved, or the existence gate
 *                  failed (EXISTING: target missing; WRITE: parent dir missing)
 *                  → 404. The two are deliberately indistinguishable.
 *   NGX_ERROR    — malformed path (depth, "."/"..", WRITE trailing slash, or
 *                  the join overflowed resolved_sz) → 4xx ArgInvalid.
 */
ngx_int_t
brix_path_resolve_beneath(ngx_stream_brix_srv_conf_t *conf, ngx_log_t *log,
                            const char *reqpath, brix_path_mode_t mode,
                            char *resolved, size_t resolved_sz)
{
    int  want_dir;
    int  strip_trailing_slash;
    char norm[BRIX_MAX_PATH + 1];

    if (brix_count_path_depth(reqpath) != NGX_OK
        || brix_op_path_forbidden_component(reqpath))
    {
        return NGX_ERROR;
    }

    /* Reserved before existent: NGX_DECLINED is the gate's own "missing" answer,
     * so a reserved name and an absent one leave here by the same door and the
     * caller's error text cannot tell a client which it was. */
    if (!conf->common.cache_store_endpoint && brix_is_internal_name(reqpath)) {
        return NGX_DECLINED;
    }

    op_path_mode_flags(mode, &want_dir, &strip_trailing_slash);

    /* Normalize a create target's trailing slash (see op_path_normalize_trailing).
     * A copy that would overflow `norm` is the only failure and maps to ArgInvalid. */
    if (op_path_normalize_trailing(strip_trailing_slash, &reqpath,
                                   norm, sizeof(norm)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (op_path_gate(conf, log, reqpath, mode, want_dir) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (brix_beneath_full_path(conf->common.root_canon, reqpath,
                                 resolved, resolved_sz) >= (int) resolved_sz)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}

int
brix_reject_dotdot_path(brix_ctx_t *ctx, ngx_connection_t *c,
                          ngx_uint_t op_id, const char *op_name,
                          const char *reqpath)
{
    if (!brix_path_has_dotdot(reqpath)) {
        return 0;
    }
    brix_log_path_warning(c->log, "brix: path traversal attempt", reqpath);
    brix_log_access(ctx, c, op_name, reqpath, "-",
                      0, kXR_ArgInvalid, "invalid path", 0);
    BRIX_OP_ERR(ctx, op_id);
    ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid, "invalid path");
    return 1;
}

ngx_int_t
brix_resolve_op_path(brix_ctx_t *ctx, ngx_connection_t *c,
                        ngx_uint_t op_id, const char *op_name,
                        ngx_stream_brix_srv_conf_t *conf,
                        brix_path_mode_t mode,
                        char *reqpath, size_t reqpath_sz,
                        char *resolved, size_t resolved_sz)
{
    ngx_int_t rc;

    if (ctx->recv.payload == NULL || ctx->recv.cur_dlen == 0) {
        brix_log_access(ctx, c, op_name, "-", "-",
                          0, kXR_ArgMissing, "no path given", 0);
        BRIX_OP_ERR(ctx, op_id);
        ctx->write_rc = brix_send_error(ctx, c, kXR_ArgMissing,
                                          "no path given");
        return NGX_DONE;
    }

    if (!brix_extract_path(c->log, ctx->recv.payload, ctx->recv.cur_dlen,
                             reqpath, reqpath_sz, 1)) {
        brix_log_access(ctx, c, op_name, "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        BRIX_OP_ERR(ctx, op_id);
        ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                          "invalid path payload");
        return NGX_DONE;
    }

    rc = brix_path_resolve_beneath(conf, c->log, reqpath, mode,
                                     resolved, resolved_sz);
    if (rc == NGX_ERROR) {
        /*
         * Restore the error-log diagnostic the retired realpath resolver
         * (brix_validate_components_cstr) emitted: a rejected "."/".."
         * traversal is recorded in the error log with control bytes escaped,
         * so operators retain visibility into traversal attempts.  Depth and
         * join-overflow rejections fall through to the access log only.
         */
        if (brix_op_path_forbidden_component(reqpath)) {
            brix_log_path_warning(c->log, "brix: path traversal attempt",
                                    reqpath);
        }
        brix_log_access(ctx, c, op_name, reqpath, "-",
                          0, kXR_ArgInvalid, "invalid path", 0);
        BRIX_OP_ERR(ctx, op_id);
        ctx->write_rc = brix_send_error(ctx, c, kXR_ArgInvalid,
                                          "invalid path");
        return NGX_DONE;
    }
    if (rc == NGX_DECLINED) {
        brix_log_access(ctx, c, op_name, reqpath, "-",
                          0, kXR_NotFound, "no such file or directory", 0);
        BRIX_OP_ERR(ctx, op_id);
        ctx->write_rc = brix_send_error(ctx, c, kXR_NotFound,
                                          "no such file or directory");
        return NGX_DONE;
    }

    return NGX_OK;
}
