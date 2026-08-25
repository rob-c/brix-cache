/*
 * vfs_deleg_bind.c — VFS delegation bag binding + ctx mode reporting
 * (phase-70 §4, §5.1). Split verbatim from vfs_deleg.c.
 *
 * WHAT: The capture-side seam that constructs the per-request live-cred bag and
 *       reports the resolved delegation mode back to the cred gate:
 *       brix_vfs_ctx_bind_backend_deleg() — hang a borrowed bag on a VFS ctx.
 *       brix_vfs_deleg_set_exchange()      — stamp EXCHANGE conf onto the bag.
 *       brix_vfs_deleg_set_ca_store()      — stamp the CA store for the in-gate
 *                                            chain re-verify (P90-70.4).
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

/* The metrics layer mirrors enum brix_cred_mode as a plain count so it never
 * imports fs headers (P90-70.6); hold the two in lock-step at compile time. */
typedef char brix_cred_mode_metric_count_check[
    (BRIX_CRED_AUTO + 1 == BRIX_CRED_MODE_METRIC_COUNT) ? 1 : -1];

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
 *       gate). All strings are borrowed (conf-owned, NUL-terminated).
 *       `tx_cache_slot` (optional) points at the conf's per-worker minted-token
 *       cache pointer so the gate can lazily create + reuse the RFC-8693 result
 *       cache across requests (P90-70.9); NULL disables caching. */
void
brix_vfs_deleg_set_exchange(brix_vfs_ctx_t *vctx,
    const ngx_str_t *endpoint, const ngx_str_t *client_id,
    const ngx_str_t *client_secret, const ngx_str_t *audience,
    void **tx_cache_slot)
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
    live->tx_cache_slot = tx_cache_slot;
}

/* ---- brix_vfs_deleg_set_ca_store -------------------------------------------
 *
 * WHAT: Stamp the export's trusted CA store (+ max proxy chain depth) onto the
 *       ctx's already-bound live-cred bag (phase-70 §5.1 / P90-70.4).
 *
 * WHY:  The capture sites validate transport + leaf DN, but the RFC-3820
 *       chain-trust check against the CA store must also hold at the single
 *       seam where the bytes become a backend credential — with a store bound,
 *       the materialiser no longer trusts the capture site alone, and a future
 *       capture site that forgets the check still fails closed.
 *
 * HOW:  Mirrors brix_vfs_deleg_set_exchange: a no-op when no bag is bound or
 *       the store is NULL (the gate then relies on the capture-side check).
 *       The store pointer is borrowed (conf-owned X509_STORE*, typed void* so
 *       vfs.h stays OpenSSL-free); depth 0 = OpenSSL default. */
void
brix_vfs_deleg_set_ca_store(brix_vfs_ctx_t *vctx, void *ca_store,
    ngx_uint_t verify_depth)
{
    brix_deleg_live_t *live;

    if (vctx == NULL || vctx->deleg_live == NULL || ca_store == NULL) {
        return;
    }

    live = vctx->deleg_live;
    live->ca_store        = ca_store;
    live->ca_verify_depth = verify_depth;
}

/* Absent-argument test shared by the injection/exchange setters below: a
 * missing, empty, or dataless ngx_str disables the leg. */
static int
deleg_str_absent(const ngx_str_t *s)
{
    return s == NULL || s->len == 0 || s->data == NULL;
}

/* Get the ctx's live-cred bag, allocating (and binding) one with `mode` set
 * when none is bound yet. Returns NULL on OOM — the caller returns silently
 * and the ctx stays on SELECT, the same degrade brix_vfs_deleg_bind's
 * no-bytes path produces (the cred gate, not the capture, owns deny
 * decisions). */
static brix_deleg_live_t *
deleg_live_get_or_bind(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode)
{
    brix_deleg_live_t *live = vctx->deleg_live;

    if (live == NULL) {
        live = ngx_pcalloc(vctx->pool, sizeof(*live));
        if (live == NULL) {
            return NULL;
        }
        live->mode = mode;
        brix_vfs_ctx_bind_backend_deleg(vctx, live);
    }
    return live;
}

/* ---- brix_vfs_deleg_set_sss ------------------------------------------------
 *
 * WHAT: Arm SSS identity injection (phase-70 §5.6 / P90-70.3): stamp the
 *       backend keytab path onto the ctx's live-cred bag, allocating the bag
 *       first when none is bound.
 *
 * WHY:  Injection is the leg for callers with NO forwardable bytes — exactly
 *       the case where brix_vfs_deleg_bind declines to bind a bag (it degrades
 *       to SELECT by design). So this setter cannot piggyback on an existing
 *       bag the way set_exchange/set_ca_store do; it must be able to create
 *       one. With the keytab stamped, the gate's no-bytes path asserts the
 *       caller's principal via SSS instead of denying / falling to SELECT.
 *
 * HOW:  No-op on NULL vctx, mode==SELECT, or an empty keytab (injection off).
 *       When no bag is bound: ngx_pcalloc one from vctx->pool with `mode` set;
 *       on OOM return silently — the ctx stays on SELECT, the same degrade
 *       brix_vfs_deleg_bind's no-bytes path produces (the cred gate, not the
 *       capture, owns deny decisions). `keytab` is borrowed conf bytes
 *       (NUL-terminated) and outlives every request. */
void
brix_vfs_deleg_set_sss(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const ngx_str_t *keytab)
{
    brix_deleg_live_t *live;

    if (vctx == NULL || mode == BRIX_CRED_SELECT || deleg_str_absent(keytab)) {
        return;
    }

    live = deleg_live_get_or_bind(vctx, mode);
    if (live != NULL) {
        live->sss_keytab = *keytab;
    }
}

/* ---- brix_vfs_deleg_set_sts ------------------------------------------------
 *
 * WHAT: Arm S3 STS credential EXCHANGE (phase-70 §5.5): stamp a borrowed STS
 *       conf onto the ctx's live-cred bag, allocating the bag first when none
 *       is bound.
 *
 * WHY:  Like SSS injection, STS is the leg for callers with NO forwardable
 *       bytes — an S3 SigV4 secret is never transmitted, so nothing of the
 *       caller's can be passed through; instead the node exchanges its own S3
 *       service credential for temporary creds scoped to the caller. So this
 *       setter, like set_sss, cannot piggyback on an existing bag and must be
 *       able to create one.
 *
 * HOW:  No-op on NULL vctx, mode==SELECT, or a NULL conf (STS off). When no bag
 *       is bound: ngx_pcalloc one from vctx->pool with `mode` set; on OOM return
 *       silently — the ctx stays on SELECT (deny decisions belong to the gate,
 *       not the capture). `cf` is borrowed and must outlive the op (the caller
 *       builds it on the request pool from conf-owned bytes). Proven credential
 *       bytes (proxy/bearer) always win over STS in the gate. */
void
brix_vfs_deleg_set_sts(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const brix_s3_sts_conf_t *cf)
{
    brix_deleg_live_t *live;

    if (vctx == NULL || mode == BRIX_CRED_SELECT || cf == NULL) {
        return;
    }

    live = deleg_live_get_or_bind(vctx, mode);
    if (live != NULL) {
        live->sts = cf;
    }
}

/* ---- brix_vfs_deleg_set_krb5 -----------------------------------------------
 *
 * WHAT: Arm krb5 GSSAPI EXCHANGE (phase-70 §5.7): stamp the async-safe FILE
 *       ccache PATH (the serialised forwarded TGT) + the origin service
 *       principal onto the ctx's live-cred bag, allocating the bag first when
 *       none is bound.
 *
 * WHY:  krb5 EXCHANGE does carry captured bytes (the user's forwarded TGT), but
 *       the front door serialises them to a FILE ccache before this call so a
 *       request-scoped gss_cred_id_t never has to survive onto the async fill
 *       task — only the path does. That path may arrive with or without a bag
 *       already bound (a bearer could co-exist), so like set_sss/set_sts this
 *       must be able to create one.
 *
 * HOW:  No-op on NULL vctx, mode==SELECT, or an empty ccache/principal. When no
 *       bag is bound: ngx_pcalloc one from vctx->pool with `mode` set; on OOM
 *       return silently (degrade to SELECT — deny decisions belong to the gate).
 *       Both strings are borrowed NUL-terminated request-pool bytes and must
 *       outlive the op. A full x509 proxy still wins over krb5 in the gate. */
void
brix_vfs_deleg_set_krb5(brix_vfs_ctx_t *vctx, enum brix_cred_mode mode,
    const ngx_str_t *ccache, const ngx_str_t *origin_princ)
{
    brix_deleg_live_t *live;

    if (vctx == NULL || mode == BRIX_CRED_SELECT
        || deleg_str_absent(ccache) || deleg_str_absent(origin_princ))
    {
        return;
    }

    live = deleg_live_get_or_bind(vctx, mode);
    if (live == NULL) {
        return;
    }
    live->krb5_ccache       = *ccache;
    live->krb5_origin_princ = *origin_princ;
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
