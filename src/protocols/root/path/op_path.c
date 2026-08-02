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
        conf->common.allow_write, 0 /* is_tls */, NULL, full);
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

    /* WRITE: the parent directory must already exist (target may not). Derive
     * the parent by trimming the last '/'-separated component. */
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
 * Returns:
 *   NGX_OK       — valid and the existence requirement is met; resolved filled.
 *   NGX_DECLINED — path is well-formed but the existence gate failed
 *                  (EXISTING: target missing; WRITE: parent dir missing) → 404.
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

#if (BRIX_HAVE_KRB5)
/* ---- op_path_backend_host --------------------------------------------------
 *
 * WHAT: Extract the bare host from a "root://host:port" storage-backend URL as a
 *       borrowed view into `url` — handling the "roots://" scheme, bracketed IPv6
 *       ([::1]:port), and an optional trailing "/path". Empty view when absent.
 *
 * WHY:  §5.7 krb5 EXCHANGE. The modern brix_storage_backend grammar parses the
 *       driver host lazily in the sd_xroot factory, so conf->cache_origin_host is
 *       empty on a plain root:// export; the delegated-TGT origin SPN derivation
 *       (brix_krb5_deleg_origin_spn) needs the host, recovered from the URL here.
 *       The derived SPN is only a fallback — the origin's advertised "&P=krb5,<spn>"
 *       wins at auth time — but a non-empty host is required for the bind to run.
 *
 * HOW:  Strip the scheme prefix, then take the bracketed IPv6 body or the token up
 *       to the first ':' or '/'. A borrowed view (no allocation); the bytes live on
 *       the config and outlive the op. */
static ngx_str_t
op_path_backend_host(const ngx_str_t *url)
{
    ngx_str_t  h = { 0, NULL };
    u_char    *p, *end, *stop, *rb;

    if (url == NULL || url->len == 0) {
        return h;
    }
    p   = url->data;
    end = url->data + url->len;

    if ((size_t) (end - p) > sizeof("roots://") - 1
        && ngx_strncmp(p, "roots://", sizeof("roots://") - 1) == 0)
    {
        p += sizeof("roots://") - 1;
    } else if ((size_t) (end - p) > sizeof("root://") - 1
        && ngx_strncmp(p, "root://", sizeof("root://") - 1) == 0)
    {
        p += sizeof("root://") - 1;
    }

    if (p < end && *p == '[') {                 /* [IPv6]:port */
        rb = ngx_strlchr(p, end, ']');
        if (rb == NULL) {
            return h;
        }
        h.data = p + 1;
        h.len  = (size_t) (rb - (p + 1));
        return h;
    }

    stop = p;                                   /* host ends at ':' or '/' */
    while (stop < end && *stop != ':' && *stop != '/') {
        stop++;
    }
    h.data = p;
    h.len  = (size_t) (stop - p);
    return h;
}
#endif

/* ---- brix_root_vfs_bind_deleg ----------------------------------------------
 *
 * WHAT: Bind the session's captured raw bearer JWT onto a cred-bound VFS ctx for
 *       backend PASSTHROUGH. See op_path.h for the full contract.
 *
 * WHY:  Lets a remote-backed root:// export authenticate the backend leg AS the
 *       inbound user. Two forwardable credentials ride the GSI login: the raw
 *       bearer JWT (ctx->bearer_token) and — when the client opts in and the DN
 *       is proven (phase-70 §5.1, gsi_promote_fullproxy) — a full x509 proxy
 *       (ctx->deleg_proxy_pem, chain + private key) for backend PASSTHROUGH.
 *
 * HOW:  No-op on the default SELECT export. Otherwise wraps whichever
 *       credential(s) the session captured as ngx_str_t (bytes owned by the
 *       session ctx, outliving the op) and hands them to brix_vfs_deleg_bind on
 *       the VFS ctx's pool. The full proxy is forwarded only in PASSTHROUGH
 *       mode — the only strategy that replays the user's own credential
 *       verbatim. If neither credential is present, nothing is bound. */
void
brix_root_vfs_bind_deleg(brix_ctx_t *ctx,
                           ngx_stream_brix_srv_conf_t *conf,
                           brix_vfs_ctx_t *vctx)
{
    ngx_str_t         bearer;
    const ngx_str_t  *bearer_arg = NULL;
    const ngx_str_t  *proxy_arg = NULL;

    if (ctx == NULL || conf == NULL || vctx == NULL
        || conf->common.backend_delegation == BRIX_CRED_SELECT)
    {
        return;
    }

    bearer.data = (u_char *) ctx->bearer_token;
    bearer.len  = ngx_strlen(ctx->bearer_token);
    if (bearer.len > 0) {
        /* Backend audience gate (phase-70 §5.2 / P90-70.9): a bearer forwarded
         * verbatim must name the backend in its aud — on refusal nothing is
         * bound and the service-cred policy applies. */
        bearer_arg = brix_proto_deleg_gate_bearer(&bearer, &conf->common,
                                                  vctx->log);
    }

    /* A full proxy is a PASSTHROUGH-only credential: it is presented to the
     * upstream unmodified, so it makes sense only when the resolved mode replays
     * the user's own credential. */
    if (ctx->deleg_proxy_pem.len > 0
        && (enum brix_cred_mode) conf->common.backend_delegation
               == BRIX_CRED_PASSTHROUGH)
    {
        proxy_arg = &ctx->deleg_proxy_pem;
    }

    /* Phase 70 §5.7: an inbound-captured forwarded TGT (ctx->krb5.ccache) binds
     * as a krb5 EXCHANGE credential so the origin leg re-authenticates AS the
     * user over GSSAPI. The origin service principal is derived from the
     * configured origin host + the gateway realm; independent of the bearer/proxy
     * binding, and it allocates its own live-cred bag (like the STS/SSS stamps),
     * so it must run before the no-bearer/no-proxy early return. */
#if (BRIX_HAVE_KRB5)
    {
        ngx_str_t  cc;
        ngx_str_t  spn;
        ngx_str_t  origin_host = conf->cache_origin_host;

        /* The modern "brix_storage_backend root://host:port" grammar parses the
         * origin host lazily in the driver factory (sd_xroot), so on a plain
         * root:// export conf->cache_origin_host is empty here — only the legacy
         * tier grammar fills it. Recover the host from the backend URL so the
         * delegated-TGT origin SPN can still be derived; without it the krb5
         * EXCHANGE bind would silently no-op and the origin leg would fall back
         * to the (absent) service credential. */
        if (origin_host.len == 0) {
            origin_host = op_path_backend_host(&conf->common.storage_backend);
        }

        cc.data = (u_char *) ctx->krb5.ccache;
        cc.len  = ngx_strlen(ctx->krb5.ccache);

        if (brix_krb5_deleg_origin_spn(&cc, conf->common.backend_krb5_forwardable,
                &origin_host, &conf->krb5.principal,
                vctx->pool, &spn) == NGX_OK)
        {
            brix_vfs_deleg_set_krb5(vctx,
                (enum brix_cred_mode) conf->common.backend_delegation, &cc, &spn);
        }
    }
#endif

    if (bearer_arg == NULL && proxy_arg == NULL) {
        return;
    }

    (void) brix_vfs_deleg_bind(vctx->pool, vctx,
        (enum brix_cred_mode) conf->common.backend_delegation,
        bearer_arg, proxy_arg);

    brix_proto_deleg_stamp_conf(vctx, &conf->common);

    /* P90-70.4: stamp the server's GSI trust store so the VFS deleg gate
     * re-runs the RFC-3820 chain-trust check on the pushed proxy before
     * materialising it (gsi_promote_fullproxy only DN-matches the push).
     * Depth 0 = OpenSSL default, matching the root:// login verify. */
    brix_vfs_deleg_set_ca_store(vctx, conf->gsi_store, 0);
}
