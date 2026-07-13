/*
 * vfs_cred.c — VFS per-user backend credential gate
 * (Phase 1 + Phase 2 T1 + T3 + T9).
 *
 * WHAT: Implements the entry points that translate a request identity into a
 *       per-open / per-namespace backend credential:
 *       brix_vfs_ctx_bind_backend_cred() — wires the conf's credential directory
 *       and fallback policy onto a VFS ctx.
 *       brix_vfs_ctx_bind_backend_mint() — wires the conf's opt-in mint-CA
 *       cert/key/ttl onto a VFS ctx (Phase 2 Task 9).
 *       brix_vfs_backend_cred() — data-plane gate (open/staged_open), keyed on
 *       driver->open_cred capability.
 *       brix_vfs_ns_cred() — namespace gate (stat/unlink/mkdir/rename/…), keyed
 *       on driver->stat_cred capability (Phase 2 Task 1).
 *       Both gates share a single static decision body so the policy cannot drift.
 *       Phase 2 Task 3 adds per-proto Prometheus counters for each terminal outcome
 *       (USER / FALLBACK / DENY) via brix_metric_cred_result.
 *
 * WHY:  The credential gate must execute BEFORE any driver→open or driver→ns
 *       call so a request can never reach a remote origin under the service
 *       credential when the operator has set fallback=deny and no valid user
 *       credential exists.  A deny-mode probe (brix_vfs_probe) that runs the
 *       namespace gate closes the gap where the probe stat still reached the
 *       origin under the service credential (Phase-1 gap).  Phase 2 Task 9
 *       closes a different gap: identities with no NATIVE x509 (S3 access
 *       keys, WLCG tokens) can never have a pre-provisioned .pem, so without
 *       minting they are permanently stuck on FALLBACK/DENY. Minting is
 *       strictly opt-in (a mint CA must be configured) — see
 *       fs/backend/cred_mint.h for the trust-model note.
 *
 * HOW:  vfs_cred.c includes vfs_internal.h (for brix_vfs_ctx_t and
 *       brix_sd_cred_t), fs/backend/ucred.h (for brix_sd_ucred_select and
 *       brix_sd_ucred_t), and fs/backend/cred_mint.h (for brix_cred_mint).
 *       The shared vfs_backend_cred_decide() body performs the ucred_select +
 *       deny/fallback decision; both public gates call it with the relevant
 *       capability flag.  On a DECLINED select with cap_ok and a mint CA
 *       configured, it makes ONE brix_cred_mint() attempt then re-resolves by
 *       the same key before falling through to deny/fallback — a mint
 *       failure changes nothing (same deny/fallback path as Phase-1's
 *       DECLINED).  Outcome counters are emitted via brix_metric_cred_result
 *       (unified.h, pulled in transitively via vfs_internal.h → access_log.h
 *       → unified.h).
 */
#include "vfs_internal.h"
#include "fs/backend/cache/sd_cache.h"
#include "fs/backend/stage/sd_stage.h"
#include "fs/backend/cred_mint.h"

/* ---- brix_vfs_ctx_bind_backend_cred ----------------------------------------
 *
 * WHAT: Copies the conf's credential-dir pointer + fallback mode onto the ctx.
 *
 * WHY:  brix_vfs_ctx_init predates the feature and is called from ~30 sites;
 *       a separate bind keeps the signature stable and lets the data-plane
 *       callsites opt in explicitly.
 *
 * HOW:  nginx conf tokens are NUL-terminated, so the ngx_str_t data pointer is
 *       usable as a C string for the conf's lifetime (outlives every request).
 *       storage_cred_dir is set to NULL (feature off) when cred_dir is NULL or
 *       empty; storage_cred_deny mirrors the operator's fallback policy. */
void
brix_vfs_ctx_bind_backend_cred(brix_vfs_ctx_t *vctx,
    const ngx_str_t *cred_dir, ngx_uint_t fallback_deny)
{
    if (vctx == NULL) {
        return;
    }

    vctx->storage_cred_dir = (cred_dir != NULL && cred_dir->len > 0)
                           ? (const char *) cred_dir->data : NULL;
    vctx->storage_cred_deny = (fallback_deny == 1) ? 1u : 0u;
}

/* ---- brix_vfs_ctx_bind_backend_mint ----------------------------------------
 *
 * WHAT: Copies the conf's mint-CA cert/key paths + TTL onto the ctx.
 *
 * WHY:  Opt-in (phase-2 T9): only the data-plane sites that meaningfully
 *       benefit from minting (davs/S3 GET/PUT, where a bearer-only identity
 *       like an S3 access key has no native x509) call this; namespace-only
 *       call sites are unaffected and never mint. Kept as a separate bind
 *       (rather than extending brix_vfs_ctx_bind_backend_cred's signature) so
 *       the ~20 existing call sites of that function are untouched.
 *
 * HOW:  Same NUL-terminated-conf-string borrowing convention as
 *       brix_vfs_ctx_bind_backend_cred; ca_cert unset/empty leaves minting
 *       off for this ctx (the gate's DECLINED path is then identical to
 *       Phase-1). */
void
brix_vfs_ctx_bind_backend_mint(brix_vfs_ctx_t *vctx,
    const ngx_str_t *ca_cert, const ngx_str_t *ca_key, ngx_uint_t ttl_secs)
{
    if (vctx == NULL) {
        return;
    }

    vctx->storage_cred_mint_ca_cert = (ca_cert != NULL && ca_cert->len > 0)
                                     ? (const char *) ca_cert->data : NULL;
    vctx->storage_cred_mint_ca_key  = (ca_key != NULL && ca_key->len > 0)
                                     ? (const char *) ca_key->data : NULL;
    vctx->storage_cred_mint_ttl     = ttl_secs;
}

/* ---- vfs_cred_live_bag ------------------------------------------------------
 *
 * WHAT: If a PASSTHROUGH/EXCHANGE live-cred bag is bound on the ctx, materialise
 *       it via brix_vfs_deleg_live_cred and report handled=1 with the rc it
 *       returned; otherwise leaves *handled=0 (caller runs the SELECT path).
 *
 * WHY:  Phase-70 §4/§5.1/§5.4: when the front door bound a PASSTHROUGH or
 *       EXCHANGE live-cred bag (raw bearer / user-supplied full proxy), it must
 *       be materialised here instead of the directory SELECT.  EXCHANGE trades
 *       the bearer for a backend-audienced token when an exchange endpoint is
 *       configured, else forwards it verbatim (documented §5.4 fallback).
 *       DELEGATE/MINT are left to fall through to select+mint for now.
 *
 * HOW:  Reads the ctx cred mode once; only the two live-bag modes short-circuit.
 *       *handled tells the caller whether the returned rc is authoritative. */
static ngx_int_t
vfs_cred_live_bag(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred, int *use_cred,
    int *err_out, int *handled)
{
    enum brix_cred_mode m = brix_vfs_backend_mode(ctx);

    if (m == BRIX_CRED_PASSTHROUGH || m == BRIX_CRED_EXCHANGE) {
        *handled = 1;
        return brix_vfs_deleg_live_cred(ctx, cred, use_cred, err_out);
    }

    *handled = 0;
    return NGX_OK;
}

/* ---- vfs_cred_maybe_mint ----------------------------------------------------
 *
 * WHAT: Given the initial select rc, performs the opt-in mint+re-resolve and
 *       returns the (possibly updated) rc.
 *
 * WHY:  Phase-2 T9 opt-in minting: a DECLINED select (no pre-provisioned or
 *       previously-minted credential is currently valid) gets ONE mint attempt
 *       when a mint CA is configured AND the driver can actually use a per-user
 *       credential (cap_ok) — minting for a backend that cannot scope a session
 *       to a user credential would be pure waste.  On a successful mint,
 *       re-resolve by the SAME key select() already derived (store->key is set
 *       on DECLINED).  A mint failure is NOT a different denial reason: it
 *       simply leaves rc unchanged so the existing deny/fallback policy still
 *       applies.
 *
 * HOW:  No-op (returns rc unchanged) unless rc != NGX_OK, cap_ok, and a mint CA
 *       is configured; on a successful brix_cred_mint it returns the re-resolve
 *       rc. */
static ngx_int_t
vfs_cred_maybe_mint(brix_vfs_ctx_t *ctx, int cap_ok, brix_sd_ucred_t *store,
    ngx_int_t rc)
{
    if (rc != NGX_OK && cap_ok
        && ctx->storage_cred_mint_ca_cert != NULL
        && ctx->storage_cred_mint_ca_cert[0] != '\0') {
        if (brix_cred_mint(ctx->storage_cred_dir,
                ctx->storage_cred_mint_ca_cert, ctx->storage_cred_mint_ca_key,
                store->principal, store->key,
                (int) ctx->storage_cred_mint_ttl, ctx->log) == NGX_OK) {
            rc = brix_sd_ucred_resolve(ctx->storage_cred_dir, store->key,
                store);
        }
    }

    return rc;
}

/* ---- vfs_cred_no_cap --------------------------------------------------------
 *
 * WHAT: Terminal outcome for a found credential on a backend that cannot scope
 *       a session to a user credential (cap_ok=0): NGX_ERROR (EACCES) in deny
 *       mode, else NGX_OK using the service credential.
 *
 * WHY:  A user credential exists but the leaf backend has no per-user slot.  In
 *       fallback=deny this must refuse before any origin connection; otherwise
 *       it warns and falls back to the service credential.  Identical to the
 *       Phase-1 body — factored out only to bound the caller's complexity.
 *
 * HOW:  Sets errno/err_out=EACCES and emits the DENY counter on refusal; emits
 *       the FALLBACK counter and returns NGX_OK otherwise. */
static ngx_int_t
vfs_cred_no_cap(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store, int *err_out)
{
    if (ctx->storage_cred_deny) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: backend \"%s\" cannot scope a session to a user "
            "credential (fallback=deny) - refusing principal=\"%s\"",
            brix_sd_backend_name(ctx->sd), store->principal);
        errno = EACCES;
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        brix_metric_cred_result(brix_vfs_metrics_proto(ctx),
                                BRIX_CRED_OUTCOME_DENY);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_WARN, ctx->log, 0,
        "brix: backend \"%s\" cannot scope a session to a user "
        "credential - using the service credential for \"%s\"",
        brix_sd_backend_name(ctx->sd), store->principal);
    brix_metric_cred_result(brix_vfs_metrics_proto(ctx),
                            BRIX_CRED_OUTCOME_FALLBACK);
    return NGX_OK;
}

/* ---- vfs_cred_fill_user -----------------------------------------------------
 *
 * WHAT: Populates *cred from the resolved *store as an ordinary per-user
 *       credential and sets *use_cred=1.
 *
 * WHY:  x509, bearer, s3, and ceph are mutually exclusive: exactly one kind is
 *       ever populated by ucred_select/resolve (store->is_bearer / is_s3 /
 *       is_ceph).  Setting the inactive pointers to NULL prevents callers from
 *       accidentally using a stale value from a zeroed-struct default.
 *
 * HOW:  Copies the active kind's fields, borrows dir + fallback policy from the
 *       ctx, emits the USER counter, and flags use_cred. */
static void
vfs_cred_fill_user(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred)
{
    cred->x509_proxy    = (!store->is_bearer && !store->is_s3
                            && !store->is_ceph)
                         ? store->path : NULL;
    cred->bearer        = store->is_bearer ? store->bearer : NULL;
    cred->s3_ak         = store->is_s3 ? store->s3_ak     : NULL;
    cred->s3_sk         = store->is_s3 ? store->s3_sk     : NULL;
    cred->s3_region     = store->is_s3 ? store->s3_region : NULL;
    cred->ceph_keyring  = store->is_ceph ? store->ceph_keyring : NULL;
    cred->ceph_user     = store->is_ceph ? store->ceph_user    : NULL;
    cred->key           = store->key;
    cred->principal     = store->principal;
    cred->cred_dir      = ctx->storage_cred_dir;
    cred->fallback_deny = ctx->storage_cred_deny;
    *use_cred = 1;
    brix_metric_cred_result(brix_vfs_metrics_proto(ctx),
                            BRIX_CRED_OUTCOME_USER);
}

/* ---- vfs_cred_deny_or_fallback ---------------------------------------------
 *
 * WHAT: Terminal outcome for a select that did NOT yield a valid credential:
 *       NGX_ERROR (EACCES) in deny mode, else NGX_OK falling back to the service
 *       credential.
 *
 * WHY:  No pre-provisioned/minted credential is currently valid.  deny mode must
 *       refuse before any origin connection; otherwise the request proceeds on
 *       the service credential.  Identical to the Phase-1 tail.
 *
 * HOW:  Sets errno/err_out=EACCES and emits the DENY counter on refusal; emits
 *       the FALLBACK counter and returns NGX_OK otherwise. */
static ngx_int_t
vfs_cred_deny_or_fallback(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    int *err_out)
{
    if (ctx->storage_cred_deny) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: per-user backend credential %s for principal=\"%s\" "
            "key=%s dir=\"%s\" (fallback=deny) - refusing",
            store->expired ? "EXPIRED" : "missing", store->principal,
            store->key, ctx->storage_cred_dir);
        errno = EACCES;
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        brix_metric_cred_result(brix_vfs_metrics_proto(ctx),
                                BRIX_CRED_OUTCOME_DENY);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
        "brix: no per-user backend credential for principal=\"%s\" key=%s - "
        "falling back to the service credential",
        store->principal, store->key);
    brix_metric_cred_result(brix_vfs_metrics_proto(ctx),
                            BRIX_CRED_OUTCOME_FALLBACK);
    return NGX_OK;
}

/* ---- vfs_backend_cred_decide (static, shared by both gates) ----------------
 *
 * WHAT: Core select+deny+fallback policy executed for both the data-plane and
 *       namespace credential gates.  Returns NGX_OK with *use_cred=1+*cred
 *       filled (user cred), NGX_OK with *use_cred=0 (feature-off or fallback),
 *       or NGX_ERROR (errno/err_out = EACCES, deny mode).
 *
 * WHY:  Both brix_vfs_backend_cred and brix_vfs_ns_cred share IDENTICAL policy:
 *       ucred_select → if-found-but-not-capable → deny?refuse:warn+service;
 *       if-not-found → deny?refuse:info+service.  A single body guarantees the
 *       two gates never drift.
 *
 * HOW:  `cap_ok` is the caller's capability verdict (driver has the relevant
 *       *_cred slot).  The live-bag / mint / found / not-found decision branches
 *       are delegated to dedicated helpers so the order and return values are
 *       identical to Phase-1's brix_vfs_backend_cred body. */
static ngx_int_t
vfs_backend_cred_decide(brix_vfs_ctx_t *ctx, int cap_ok,
    brix_sd_ucred_t *store, brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    ngx_int_t rc;
    int       handled = 0;

    *use_cred = 0;

    rc = vfs_cred_live_bag(ctx, cred, use_cred, err_out, &handled);
    if (handled) {
        return rc;
    }

    if (ctx->storage_cred_dir == NULL || ctx->storage_cred_dir[0] == '\0') {
        return NGX_OK;
    }

    rc = brix_sd_ucred_select(ctx->storage_cred_dir, ctx->identity, store);
    rc = vfs_cred_maybe_mint(ctx, cap_ok, store, rc);

    if (rc == NGX_OK) {
        if (!cap_ok) {
            return vfs_cred_no_cap(ctx, store, err_out);
        }

        vfs_cred_fill_user(ctx, store, cred, use_cred);
        return NGX_OK;
    }

    return vfs_cred_deny_or_fallback(ctx, store, err_out);
}

/* ---- vfs_leaf_per_user_capable ---------------------------------------------
 *
 * WHAT: True when `leaf` (a decorator-unwrapped storage driver instance) can
 *       scope ANY operation to a per-user credential — i.e. it advertises at
 *       least one of the data-plane per-user slots (open_cred / staged_open_cred)
 *       OR the namespace per-user slot (stat_cred).
 *
 * WHY:  "Can this backend authenticate the origin leg AS the inbound user?" is a
 *       single backend property, not a per-op one.  A backend that scopes opens
 *       and staged writes to the user (sd_http: open_cred + staged_open_cred, but
 *       NO stat_cred) is fully per-user-capable — the user's bytes and objects
 *       are correctly isolated on the origin.  Keying the capability verdict on
 *       ONE slot per gate wrongly declared such a backend "cannot scope a session
 *       to a user credential" the moment a WRITE flow issued an auxiliary
 *       namespace op (the WebDAV PUT lock-state getxattr routes through the
 *       stat_cred-keyed ns gate): in fallback=deny that refused the whole PUT
 *       even though every user-facing open/write on that leaf IS user-scoped.
 *       A namespace op the leaf simply does not support must degrade to
 *       unsupported at dispatch (getxattr on a backend with no xattr → ENOTSUP,
 *       which the lock check reads as "unlocked"), never to a credential-scoping
 *       DENY at the gate.  Testing ANY per-user slot keeps the honest deny: a
 *       leaf with NONE of them still yields 0 and the refusal still fires.
 *
 * HOW:  Pure predicate over the leaf driver's *_cred slot pointers.  Shared by
 *       both cap_ok gates so the data-plane and namespace verdicts agree on the
 *       single "is this backend per-user capable" question. */
static int
vfs_leaf_per_user_capable(const brix_sd_instance_t *leaf)
{
    if (leaf == NULL || leaf->driver == NULL) {
        return 0;
    }

    return (leaf->driver->open_cred != NULL
            || leaf->driver->staged_open_cred != NULL
            || leaf->driver->stat_cred != NULL) ? 1 : 0;
}

/* ---- vfs_backend_cap_ok -----------------------------------------------------
 *
 * WHAT: Whether the leaf driver (below any stage/cache decorators) can scope a
 *       data-plane op (open / staged_open) to a per-user credential.
 *
 * WHY:  The stage and read-cache drivers are transparent decorators: they relay
 *       the origin open to their source driver via the plain slot and do NOT
 *       carry their own *_cred slots.  Keying cap_ok on the TOP instance
 *       therefore reads as cap_ok=0 for ANY stage- or cache-wrapped export —
 *       even when the LEAF (e.g. sd_http, sd_xroot) fully implements open_cred +
 *       staged_open_cred.  Unwrap to the leaf and test IT.  Both the READ open
 *       (driver->open_cred) and the staged WRITE (driver->staged_open_cred) are
 *       per-user-capable slots, so this gate — shared by open_resolved_file.c
 *       (read) and vfs_staged.c (write) — accepts a leaf that has EITHER.
 *
 * HOW:  Delegates to brix_vfs_ns_leaf() then vfs_leaf_per_user_capable(). */
static int
vfs_backend_cap_ok(const brix_vfs_ctx_t *ctx)
{
    return vfs_leaf_per_user_capable(brix_vfs_ns_leaf(ctx->sd));
}

/* ---- brix_vfs_backend_cred --------------------------------------------------
 *
 * WHAT: Data-plane credential gate: NGX_OK + use_cred=1 (user cred, *cred filled
 *       from *store); NGX_OK + use_cred=0 (feature-off or allowed fallback); or
 *       NGX_ERROR (errno/err_out = EACCES, deny mode, no valid cred).
 *
 * WHY:  The single policy gate for open/staged_open: deny mode must reject
 *       BEFORE any origin connection is attempted.
 *
 * HOW:  Delegates to vfs_backend_cred_decide with cap_ok = vfs_backend_cap_ok()
 *       — the leaf driver is per-user capable (open_cred OR staged_open_cred).
 *       Unwrapping the stage/cache decorators mirrors the namespace gate so a
 *       stage- or cache-wrapped https/xroot origin is correctly seen as capable —
 *       the actual open/staged_open runs on that leaf.  The deny/fallback
 *       semantics are unchanged: a leaf with NO per-user slot still yields
 *       cap_ok=0 and the "cannot scope a session" refusal still fires. */
ngx_int_t
brix_vfs_backend_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    int cap_ok = vfs_backend_cap_ok(ctx);

    return vfs_backend_cred_decide(ctx, cap_ok, store, cred, use_cred, err_out);
}

/* ---- brix_vfs_cred_gate_active ---------------------------------------------
 *
 * WHAT: True when a per-user backend credential SOURCE is bound on this ctx —
 *       either the directory-based SELECT policy (storage_cred_dir) or a live
 *       delegation bag (PASSTHROUGH/EXCHANGE). See vfs_internal.h for the full
 *       contract and the asymmetry it closes.
 *
 * WHY:  The namespace dispatch sites (vfs_xattr/stat/unlink/mkdir/rename/dir/
 *       copy) must run the cred gate whenever EITHER source is present; keying
 *       on storage_cred_dir alone dropped the passthrough bearer/proxy on ns
 *       ops (the data-plane gate already consults the deleg bag first).
 *
 * HOW:  storage_cred_dir non-empty OR a bound bag (mode != SELECT). Pure
 *       predicate — no I/O, no cred materialisation (the gate does that). */
int
brix_vfs_cred_gate_active(brix_vfs_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->storage_cred_dir != NULL && ctx->storage_cred_dir[0] != '\0') {
        return 1;
    }
    return (brix_vfs_backend_mode(ctx) != BRIX_CRED_SELECT) ? 1 : 0;
}

/* ---- brix_vfs_ns_leaf -------------------------------------------------------
 *
 * WHAT: Walk the stage/cache decorator chain from `top` to the leaf (the first
 *       non-decorator instance) and return it.  Returns `top` unchanged when it
 *       is already the leaf, or NULL when `top` is NULL.
 *
 * WHY:  The stage and read-cache decorators relay namespace ops (stat/unlink/
 *       rename/…) to their source through the PLAIN slot — they do not have
 *       their own *_cred slots.  Calling brix_sd_<op>_maybe_cred on the TOP
 *       instance therefore always falls back to the plain relay (because the
 *       decorator's driver->stat_cred is NULL), so the credential is silently
 *       dropped even when use_cred=1.  Dispatching on the LEAF instead lets the
 *       forwarder find the leaf driver's *_cred slot (e.g. sd_xroot) and
 *       correctly present the per-user proxy to the remote origin.
 *
 * HOW:  Peel off stage and cache decorator layers using their published
 *       source-instance accessors (brix_sd_stage_source_instance /
 *       brix_sd_cache_source_instance) until neither returns an inner instance.
 *       The result is the first non-decorator instance — the actual storage
 *       driver (sd_xroot, sd_pblock, sd_ceph, sd_posix, …). */
brix_sd_instance_t *
brix_vfs_ns_leaf(brix_sd_instance_t *top)
{
    brix_sd_instance_t *inst = top;
    brix_sd_instance_t *inner;

    if (inst == NULL) {
        return NULL;
    }

    for (;;) {
        inner = brix_sd_stage_source_instance(inst);
        if (inner == NULL) {
            inner = brix_sd_cache_source_instance(inst);
        }
        if (inner == NULL) {
            break;    /* inst is the leaf */
        }
        inst = inner;
    }

    return inst;
}

/* ---- vfs_ns_cap_ok ----------------------------------------------------------
 *
 * WHAT: Whether the leaf driver (below any stage/cache decorators) can scope a
 *       session to a per-user credential — the capability verdict for the
 *       namespace-op gate.
 *
 * WHY:  The stage and read-cache drivers are transparent decorators: they relay
 *       namespace ops (stat/unlink/rename/…) straight to their source driver via
 *       the plain slot.  They do NOT have their own *_cred slots — so we unwrap
 *       to the leaf and test IT.  The verdict is the SAME single question the
 *       data-plane gate asks (vfs_leaf_per_user_capable): can this backend
 *       authenticate the origin leg as the inbound user?  A leaf that scopes
 *       opens/staged writes to the user but does NOT implement a namespace *_cred
 *       slot (sd_http) is still per-user-capable — its user isolation holds — so
 *       an auxiliary namespace op in a WRITE flow (the WebDAV PUT lock-state
 *       getxattr) must NOT be refused here as "cannot scope a session".  When a
 *       namespace op is genuinely unsupported by the leaf, dispatch degrades to
 *       ENOTSUP (read as "unlocked" by the lock check), which is the correct
 *       outcome — not a credential DENY.  A leaf with NO per-user slot at all
 *       still yields 0 so the honest refusal is preserved.
 *
 * HOW:  Delegates to brix_vfs_ns_leaf() then vfs_leaf_per_user_capable() — the
 *       same predicate the data-plane gate uses, so the two gates cannot drift. */
static int
vfs_ns_cap_ok(const brix_vfs_ctx_t *ctx)
{
    return vfs_leaf_per_user_capable(brix_vfs_ns_leaf(ctx->sd));
}

/* ---- brix_vfs_ns_cred -------------------------------------------------------
 *
 * WHAT: Namespace-op credential gate (Phase 2 Task 1): same select+deny+fallback
 *       policy as brix_vfs_backend_cred, with the capability verdict from
 *       vfs_ns_cap_ok().
 *
 * WHY:  Namespace ops (stat/unlink/mkdir/rename/copy/setattr/xattr/opendir) need
 *       the same select+deny+fallback policy as data-plane opens.  A separate
 *       gate keeps the ns dispatch sites uniform, but the CAPABILITY verdict is
 *       the single "is this backend per-user capable" question shared with the
 *       data-plane gate (vfs_leaf_per_user_capable): a leaf that scopes
 *       opens/staged writes to the user (sd_http) is per-user capable even with
 *       no namespace *_cred slot, so a WRITE-flow namespace op (the WebDAV PUT
 *       lock-state getxattr) is NOT refused as "cannot scope a session" — it
 *       degrades to ENOTSUP at dispatch when the leaf lacks the op.  Both gates
 *       share vfs_backend_cred_decide so policy cannot drift.  vfs_ns_cap_ok()
 *       unwraps stage/cache decorators: decorators relay namespace ops to the
 *       leaf through the plain slot, so the leaf's capability is the right test.
 *
 * HOW:  cap_ok = vfs_ns_cap_ok() (leaf is per-user capable); remainder delegates
 *       to the shared decision body.  Callers are the VFS ns dispatch sites
 *       (vfs_stat.c, vfs_unlink.c, vfs_mkdir.c, vfs_rename.c, vfs_copy.c,
 *       vfs_xattr.c, vfs_dir.c) — each calls this gate once before dispatching
 *       through the brix_sd_<op>_maybe_cred forwarder. */
ngx_int_t
brix_vfs_ns_cred(brix_vfs_ctx_t *ctx, brix_sd_ucred_t *store,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    int cap_ok = vfs_ns_cap_ok(ctx);

    return vfs_backend_cred_decide(ctx, cap_ok, store, cred, use_cred, err_out);
}
