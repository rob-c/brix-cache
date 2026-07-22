/*
 * vfs_deleg_bind.c — VFS delegation bag binding + ctx mode reporting
 * (phase-70 §4, §5.1). Split verbatim from vfs_deleg.c.
 *
 * WHAT: The capture-side seam that constructs the per-request live-cred bag and
 *       reports the resolved delegation mode back to the cred gate:
 *       brix_vfs_ctx_bind_backend_deleg() — hang a borrowed bag on a VFS ctx.
 *       brix_vfs_deleg_set_exchange()      — stamp EXCHANGE conf onto the bag.
 *       brix_vfs_deleg_bind()              — allocate + fill + bind the bag.
 *       brix_vfs_backend_mode()            — report the ctx's resolved mode.
 *       brix_vfs_backend_accepts_proxy()   — does the leaf backend take a proxy?
 *       brix_vfs_deleg_snapshot()          — copy out mode+bearer for a child ctx.
 *
 * WHY:  These functions only touch the bag layout and the ctx; they share no
 *       statics with the PASSTHROUGH/EXCHANGE materialiser in vfs_deleg.c, so
 *       they live here to keep each file well under the size budget. All entry
 *       points are public (declared in vfs.h via vfs_internal.h).
 */
#include "vfs_internal.h"

/* ---- brix_vfs_ctx_bind_backend_deleg ---------------------------------------
 *
 * WHAT: Store a borrowed pointer to the front door's live-cred bag on the ctx.
 *
 * WHY:  Kept separate from brix_vfs_ctx_bind_backend_cred (dir-based select) so
 *       the ~35 existing bind sites are untouched and a request opts in to
 *       delegation explicitly. The bag carries BYTES, not a directory.
 *
 * HOW:  The bag (and its byte fields) are owned by the caller's request pool
 *       and must outlive the VFS op; a NULL bag leaves the ctx on the SELECT
 *       path. No copy is made. */
void
brix_vfs_ctx_bind_backend_deleg(brix_vfs_ctx_t *vctx, brix_deleg_live_t *live)
{
    if (vctx == NULL) {
        return;
    }

    vctx->deleg_live = live;
}

/* ---- brix_vfs_deleg_set_exchange -------------------------------------------
 *
 * WHAT: Populate the EXCHANGE conf (endpoint + client creds + audience) on the
 *       ctx's already-bound live-cred bag.
 *
 * WHY:  The cred gate needs the RFC-8693 endpoint to trade a live bearer for a
 *       backend-audienced token (§5.4). The bag layout is private to the VFS, so
 *       this setter is the one place the borrowed conf strings are stamped onto
 *       it — kept separate from brix_vfs_deleg_bind so the capture site stays a
 *       single call plus an optional exchange-conf call (no signature churn on
 *       the bind path shared by PASSTHROUGH).
 *
 * HOW:  A no-op when no bag is bound (nothing forwardable was captured) or the
 *       endpoint is empty (EXCHANGE then degrades to verbatim passthrough in the
 *       gate). All strings are borrowed (conf-owned, NUL-terminated). */
void
brix_vfs_deleg_set_exchange(brix_vfs_ctx_t *vctx,
    const ngx_str_t *endpoint, const ngx_str_t *client_id,
    const ngx_str_t *client_secret, const ngx_str_t *audience)
{
    brix_deleg_live_t *live;

    if (vctx == NULL || vctx->deleg_live == NULL) {
        return;
    }
    if (endpoint == NULL || endpoint->len == 0 || endpoint->data == NULL) {
        return;
    }

    live = vctx->deleg_live;
    live->tx.endpoint = *endpoint;
    if (client_id != NULL) {
        live->tx.client_id = *client_id;
    }
    if (client_secret != NULL) {
        live->tx.client_secret = *client_secret;
    }
    if (audience != NULL) {
        live->tx_audience = *audience;
    }
}

/* ---- brix_vfs_deleg_bind ---------------------------------------------------
 *
 * WHAT: Allocate a live-cred bag from `pool`, fill it with the captured
 *       forwardable credential bytes (bearer text and/or full proxy PEM) plus
 *       the resolved mode, and bind it onto `vctx`. A no-op (SELECT path) when
 *       `mode` is BRIX_CRED_SELECT or nothing forwardable was captured.
 *
 * WHY:  This is the single constructor for the bag, kept here (not in a protocol
 *       handler) because brix_deleg_live_t's layout is private to the VFS. Every
 *       front-door bind site calls this uniformly right after
 *       brix_vfs_ctx_bind_backend_cred, so the "conf mode + captured bytes →
 *       bound bag" step is stated once rather than copy-pasted per protocol.
 *
 * HOW:  Borrows the byte ranges (owned by the caller's request pool). When no
 *       credential bytes are present the bag is not bound and the ctx stays on
 *       the dir-based SELECT path — so an operator enabling passthrough without a
 *       forwardable credential in-hand degrades to SELECT rather than deny here
 *       (the deny decision belongs to the cred gate, not the capture). */
ngx_int_t
brix_vfs_deleg_bind(ngx_pool_t *pool, brix_vfs_ctx_t *vctx,
    enum brix_cred_mode mode, const ngx_str_t *bearer,
    const ngx_str_t *proxy_pem)
{
    brix_deleg_live_t *live;
    int                have_proxy;
    int                have_bearer;

    if (pool == NULL || vctx == NULL || mode == BRIX_CRED_SELECT) {
        return NGX_OK;
    }

    have_proxy  = (proxy_pem != NULL && proxy_pem->len > 0
                   && proxy_pem->data != NULL);
    have_bearer = (bearer != NULL && bearer->len > 0 && bearer->data != NULL);

    if (!have_proxy && !have_bearer) {
        return NGX_OK;   /* nothing forwardable captured — stay on SELECT */
    }

    live = ngx_pcalloc(pool, sizeof(*live));
    if (live == NULL) {
        return NGX_ERROR;
    }

    live->mode = mode;
    if (have_proxy) {
        live->have_proxy_pem = 1;
        live->proxy_pem      = *proxy_pem;
    }
    if (have_bearer) {
        live->bearer = *bearer;
    }

    brix_vfs_ctx_bind_backend_deleg(vctx, live);
    return NGX_OK;
}

/* ---- brix_vfs_backend_mode -------------------------------------------------
 *
 * WHAT: Report the delegation mode resolved for this ctx.
 *
 * WHY:  The cred gate (vfs_cred.c) branches on the mode before the SELECT logic;
 *       keeping the lookup here means the "no bag ⇒ SELECT" default is stated
 *       once.
 *
 * HOW:  Returns the bound bag's mode, or BRIX_CRED_SELECT when no bag is bound. */
enum brix_cred_mode
brix_vfs_backend_mode(brix_vfs_ctx_t *vctx)
{
    if (vctx == NULL || vctx->deleg_live == NULL) {
        return BRIX_CRED_SELECT;
    }

    return vctx->deleg_live->mode;
}

/* ---- brix_vfs_backend_accepts_proxy ----------------------------------------
 *
 * WHAT: Report whether the ctx's resolved leaf backend consumes a forwarded
 *       X.509 proxy PEM.
 *
 * WHY:  A protocol that forwards a captured proxy by default (the gsiftp→xrootd
 *       gateway) must not bind a proxy bag on a backend that cannot use one — the
 *       cred gate would then deny (EACCES) a request that should have served on
 *       the service credential. Gating the bind on this predicate keeps the
 *       default-on delegation scoped to proxy-capable backends (xroot, s3).
 *
 * HOW:  brix_sd_cred_accept on the resolved leaf; NULL-safe (default-POSIX
 *       resolves to a NULL sd whose accept mask is 0). */
int
brix_vfs_backend_accepts_proxy(brix_vfs_ctx_t *vctx)
{
    if (vctx == NULL || vctx->sd == NULL) {
        return 0;
    }
    return (brix_sd_cred_accept(brix_vfs_ns_leaf(vctx->sd))
            & BRIX_SD_CRED_PROXY_PEM) ? 1 : 0;
}

/* ---- brix_vfs_deleg_snapshot -----------------------------------------------
 *
 * WHAT: Copy out the ctx's bound delegation mode + bearer bytes so a derived
 *       ctx (e.g. a recurse-child) can re-bind the same credential.
 *
 * WHY:  Some ops build fresh child ctxs from a lightweight local struct rather
 *       than the parent ctx (root:// fattr recurse). Those children must carry
 *       the same passthrough credential; this borrows the mode+bearer so the
 *       child can re-bind via brix_vfs_deleg_bind without the bag layout leaking.
 *
 * HOW:  No bound bag ⇒ mode=SELECT + empty bearer. Otherwise the bag's mode and
 *       a borrowed view of its bearer (same lifetime as the source). The proxy
 *       PEM is deliberately not exposed — it is a materialised secret. */
void
brix_vfs_deleg_snapshot(const brix_vfs_ctx_t *vctx,
    enum brix_cred_mode *mode, ngx_str_t *bearer)
{
    if (mode != NULL) {
        *mode = BRIX_CRED_SELECT;
    }
    if (bearer != NULL) {
        ngx_str_null(bearer);
    }

    if (vctx == NULL || vctx->deleg_live == NULL) {
        return;
    }

    if (mode != NULL) {
        *mode = vctx->deleg_live->mode;
    }
    if (bearer != NULL) {
        *bearer = vctx->deleg_live->bearer;
    }
}
