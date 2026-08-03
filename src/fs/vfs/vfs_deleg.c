/*
 * vfs_deleg.c — VFS delegation live-cred bag + PASSTHROUGH materialiser
 * (phase-70 §4, §5.1, §5.4).
 *
 * WHAT: Implements the per-request delegation seam that turns the raw
 *       forwardable credential the front door captured (a bearer JWT, or a
 *       user-supplied full x509 proxy PEM) into the exact brix_sd_cred_t form
 *       the backend GSI/ZTN presenter already consumes:
 *       brix_vfs_ctx_bind_backend_deleg() — hangs a live bag on a VFS ctx.
 *       brix_vfs_backend_mode()           — reports the ctx's resolved mode.
 *       brix_vfs_deleg_live_cred()        — validates + materialises the bag's
 *       bytes into *cred (bearer straight through; proxy PEM → 0600 temp path
 *       with an unlink+zero pool cleanup), honouring fallback-deny.
 *
 * WHY:  The whole point of phase-70 is to authenticate the backend leg AS the
 *       inbound user with zero admin provisioning. PASSTHROUGH is the only path
 *       that reuses the existing origin-leg code unchanged: a full proxy PEM at
 *       a 0600 path is precisely what brix_cache_origin_auth_gsi() loads, and a
 *       raw JWT is precisely what brix_cache_origin_auth_ztn() presents. This
 *       file is the single seam where captured BYTES become that cred form, so
 *       the decision (validate → materialise → deny-or-fallback) lives in one
 *       auditable place rather than smeared across the protocol handlers.
 *
 * HOW:  The bag is bound by reference (bytes owned by the request pool). The
 *       materialiser copies a bearer directly, or for a proxy writes the PEM to
 *       an owner-only temp via brix_proxy_gsi_write_pem_temp() (net/proxy) and
 *       registers a pool cleanup that unlink()s the file and zeroes the path
 *       string, so the private key never outlives the request. PEM_read_bio_X509
 *       rejects non-PEM bytes before materialising, and when the capture site
 *       bound a CA store (brix_vfs_deleg_set_ca_store) the full RFC-3820
 *       chain-trust check re-runs here via brix_gsi_verify_chain before the PEM
 *       is materialised (§5.1 / P90-70.4); the DN-match half of the gate is
 *       enforced at capture (deleg_capture.c / gsi_promote_fullproxy).
 */
#include "vfs_internal.h"
#include "net/proxy/gsi_upstream.h"
#include "auth/crypto/gsi_verify.h"      /* in-gate chain re-verify (P90-70.4)     */
#include "auth/token/exchange_cache.h"   /* §5.4 minted-token cache (P90-70.9)     */

#include <time.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "vfs_deleg_internal.h"

/* ---- brix_vfs_deleg_temp_cleanup -------------------------------------------
 *
 * WHAT: Pool-cleanup handler: unlink the materialised proxy temp and zero its
 *       path string.
 *
 * WHY:  §6 secret hygiene — the private key lives only in a 0600 tmpfs file for
 *       the op's duration; it must be unlinked (and the path scrubbed) the
 *       moment the request pool is torn down, success or failure.
 *
 * HOW:  data is a brix_deleg_temp_t*. unlink() ignores ENOENT (a driver may
 *       already have consumed+removed it); the path bytes are then zeroed. */
void
brix_vfs_deleg_temp_cleanup(void *data)
{
    brix_deleg_temp_t *t = data;

    if (t == NULL || t->path == NULL) {
        return;
    }

    (void) unlink(t->path);   /* vfs-seam-allow: config-domain PASSTHROUGH proxy credential temp (not export storage) */
    ngx_memzero(t->path, ngx_strlen(t->path));
    t->path = NULL;
}

/* Bag binding + ctx mode reporting (brix_vfs_ctx_bind_backend_deleg,
 * brix_vfs_deleg_set_exchange, brix_vfs_deleg_bind, brix_vfs_backend_mode,
 * brix_vfs_backend_accepts_proxy, brix_vfs_deleg_snapshot) live in the sibling
 * vfs_deleg_bind.c — they share no statics with this materialiser. */

/* ---- brix_vfs_deleg_pem_is_valid -------------------------------------------
 *
 * WHAT: True iff `pem`/`len` parses as at least one PEM X509 certificate.
 *
 * WHY:  Reject garbage / non-PEM bytes before writing them to a temp and
 *       handing the path to the GSI presenter (§5.1 gate, cheap first check).
 *       The full RFC-3820 chain-trust half of the gate runs next in
 *       brix_vfs_deleg_chain_is_trusted (P90-70.4); DN-match is enforced at
 *       capture (deleg_capture.c / gsi_promote_fullproxy).
 *
 * HOW:  BIO over the bytes → PEM_read_bio_X509; a single successful parse is
 *       enough to prove the bytes are a PEM certificate. Frees the cert + BIO. */
int
brix_vfs_deleg_pem_is_valid(const u_char *pem, size_t len)
{
    BIO  *bio;
    X509 *cert;

    if (pem == NULL || len == 0) {
        return 0;
    }

    bio = BIO_new_mem_buf(pem, (int) len);
    if (bio == NULL) {
        return 0;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (cert == NULL) {
        return 0;
    }

    X509_free(cert);
    return 1;
}

/* ---- brix_vfs_deleg_deny ---------------------------------------------------
 *
 * WHAT: Terminal decision for a missing/invalid live cred: EACCES→deny in
 *       fallback-deny mode, else service-credential fallback.
 *
 * WHY:  §6 no-wrong-identity-fallback — a passthrough failure must never reach
 *       the origin under the service cred when the operator set deny.
 *
 * HOW:  Deny mode: errno/err_out=EACCES, use_cred=0, NGX_ERROR. Otherwise leave
 *       use_cred=0 and return NGX_OK so the caller falls to the service cred.
 *       Bumps the P90-70.6 outcome + failure-reason counters (skipped on a
 *       NULL ctx — no proto to attribute to). */
ngx_int_t
brix_vfs_deleg_deny(brix_vfs_ctx_t *ctx, int *use_cred, int *err_out,
    brix_cred_fail_t reason)
{
    *use_cred = 0;

    if (ctx != NULL) {
        brix_metric_cred_fail(brix_vfs_metrics_proto(ctx), reason);
        brix_metric_cred_deleg(brix_vfs_metrics_proto(ctx),
            (ngx_uint_t) brix_vfs_backend_mode(ctx),
            ctx->storage_cred_deny ? BRIX_CRED_OUTCOME_DENY
                                   : BRIX_CRED_OUTCOME_FALLBACK);
    }

    /* A NULL ctx (no VFS context bound — brix_vfs_deleg_live_cred forwards it
     * here verbatim) means the operator's deny/fallback choice is unknowable:
     * fail closed rather than silently fall back to the service credential. */
    if (ctx == NULL || ctx->storage_cred_deny) {
        errno = EACCES;
        if (err_out != NULL) {
            *err_out = EACCES;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ---- brix_vfs_deleg_bearer -------------------------------------------------
 *
 * WHAT: Materialise a PASSTHROUGH bearer: copy the raw JWT text into cred->bearer
 *       and stamp the mode.
 *
 * WHY:  A bearer needs no temp file — the byte string is handed straight to the
 *       origin ZTN presenter (§5.4 zero-provisioning path).
 *
 * HOW:  The bytes are owned by the request pool (via the bag) and outlive the
 *       op, so the pointer is borrowed rather than copied. */
static ngx_int_t
brix_vfs_deleg_bearer(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred)
{
    cred->bearer = (const char *) ctx->deleg_live->bearer.data;
    cred->mode   = BRIX_CRED_PASSTHROUGH;
    *use_cred    = 1;

    brix_metric_cred_deleg(brix_vfs_metrics_proto(ctx),
        (ngx_uint_t) brix_vfs_backend_mode(ctx), BRIX_CRED_OUTCOME_USER);
    return NGX_OK;
}

/* ---- brix_vfs_deleg_exchange -----------------------------------------------
 *
 * WHAT: Materialise an EXCHANGE bearer: trade the live subject JWT for a
 *       backend-audienced token via brix_token_exchange() and stamp the result
 *       onto cred->bearer (mode EXCHANGE).
 *
 * WHY:  §5.4 — when a backend audience is node-bound the cache must mint an
 *       origin-specific token rather than replay the client's verbatim. The
 *       minted token is then presented to the origin ZTN leg exactly like a
 *       passthrough bearer.
 *
 * HOW:  Requires a configured exchange endpoint (live->tx.endpoint) — the caller
 *       (brix_vfs_deleg_live_cred) has already applied the "endpoint unset ⇒
 *       verbatim passthrough" fallback, so reaching here means the endpoint is
 *       set. The per-worker minted-token cache (exchange_cache.c, keyed on the
 *       FULL subject token + audience, TTL-clamped) is consulted first — lazily
 *       created into the conf slot the capture site handed over — so repeated
 *       ops on one request/token do not re-POST the RFC-8693 grant. On a miss
 *       brix_token_exchange() POSTs using the first backend audience
 *       (live->tx_audience); on NGX_OK the pool-copied token is borrowed into
 *       cred->bearer and cached. On failure → deny (never the service cred in
 *       fallback-deny mode). The subject/minted tokens are never logged. */
static ngx_int_t
brix_vfs_deleg_exchange(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    brix_deleg_live_t *live = ctx->deleg_live;
    ngx_str_t          minted = ngx_null_string;
    ngx_str_t          hit = ngx_null_string;
    const ngx_str_t   *aud;
    brix_tx_cache_t   *txc = NULL;
    time_t             now = time(NULL);

    aud = (live->tx_audience.len > 0) ? &live->tx_audience : NULL;

    if (live->tx_cache_slot != NULL) {
        if (*live->tx_cache_slot == NULL) {
            *live->tx_cache_slot = brix_tx_cache_create(ngx_cycle->pool,
                                                        BRIX_TX_CACHE_SLOTS);
        }
        txc = *live->tx_cache_slot;
    }

    if (brix_tx_cache_lookup(txc, &live->bearer, aud, now, &hit)) {
        /* Borrowed slot bytes can be evicted by a later store; pin the token
         * to the request pool like a fresh mint. */
        minted.data = ngx_pnalloc(ctx->pool, hit.len + 1);
        if (minted.data != NULL) {
            ngx_memcpy(minted.data, hit.data, hit.len + 1);
            minted.len = hit.len;
        }
    }

    if (minted.len == 0) {
        if (brix_token_exchange(ctx->pool, &live->bearer, aud, NULL,
                &live->tx, &minted, ctx->log) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
                "brix: backend token-exchange failed - denying (no service-cred "
                "fallback for EXCHANGE)");
            return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                       BRIX_CRED_FAIL_EXCHANGE);
        }
        brix_tx_cache_store(txc, &live->bearer, aud, &minted, now);
    }

    cred->bearer = (const char *) minted.data;
    cred->mode   = BRIX_CRED_EXCHANGE;
    *use_cred    = 1;

    brix_metric_cred_deleg(brix_vfs_metrics_proto(ctx),
        (ngx_uint_t) brix_vfs_backend_mode(ctx), BRIX_CRED_OUTCOME_USER);
    return NGX_OK;
}


/* ---- brix_vfs_deleg_sss ----------------------------------------------------
 *
 * WHAT: SSS identity injection (phase-70 §5.6 / P90-70.3): fill *cred so the
 *       backend asserts the CALLER's authenticated principal to the origin via
 *       an SSS credential signed with the export's brix_backend_sss_keytab.
 * WHY:  The keytab's own principal must never act at the origin (the shared-
 *       identity hole this closes): no authenticated identity → FAIL_MISSING;
 *       principal over the SSS NAME TLV bound (63 bytes) → FAIL_MATERIALISE —
 *       the credential builder would otherwise silently truncate, colliding
 *       long principals that share a 63-byte prefix into one origin identity.
 * HOW:  Accept-gate on BRIX_SD_CRED_SSS; extract + bound-check + pool-copy the
 *       principal; the driver's fill task does the in-process mint at boot. */
static ngx_int_t
brix_vfs_deleg_sss(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    brix_deleg_live_t *live = ctx->deleg_live;
    char                princ[512];
    size_t              len;
    char               *copy;

    if (!(brix_sd_cred_accept(brix_vfs_ns_leaf(ctx->sd))
          & BRIX_SD_CRED_SSS)) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_KIND);
    }

    if (brix_sd_ucred_principal(ctx->identity, princ, sizeof(princ))
        != NGX_OK) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_MISSING);
    }

    len = ngx_strlen(princ);
    if (len > 63) {           /* SSS NAME TLV bound — truncation = collision */
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_MATERIALISE);
    }

    copy = ngx_pnalloc(ctx->pool, len + 1);
    if (copy == NULL) {
        brix_metric_cred_fail(brix_vfs_metrics_proto(ctx),
                              BRIX_CRED_FAIL_MATERIALISE);
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        *use_cred = 0;
        return NGX_ERROR;
    }
    ngx_memcpy(copy, princ, len + 1);

    cred->principal  = copy;
    cred->sss_keytab = (const char *) live->sss_keytab.data;
    cred->mode       = live->mode;
    *use_cred        = 1;

    brix_metric_cred_deleg(brix_vfs_metrics_proto(ctx),
        (ngx_uint_t) brix_vfs_backend_mode(ctx), BRIX_CRED_OUTCOME_USER);
    return NGX_OK;
}

/* ---- brix_vfs_deleg_krb5 ---------------------------------------------------
 *
 * WHAT: krb5 EXCHANGE (phase-70 §5.7): fill *cred so the origin leg
 *       authenticates AS the caller by forwarding the caller's delegated TGT.
 *       The production origin leg is the RAW AP-REQ exchange
 *       (brix_cache_origin_auth_krb5_raw, origin_protocol_bootstrap.c) — stock
 *       XRootD krb5 speaks raw krb5_rd_req, not a GSSAPI init-token negotiation
 *       (the GSSAPI variant brix_cache_origin_auth_krb5 is retained-unused
 *       reference; phase-88 UPDATE (iv), phase-92 §5).
 * WHY:  A live gss_cred_id_t is request-scoped and cannot ride the async fill
 *       task, so the front door serialised the delegated TGT to a 0600 FILE
 *       ccache and bound only its PATH (krb5_ccache) plus the origin service
 *       principal (krb5_origin_princ). This materialiser just carries those two
 *       borrowed request-pool strings onto the POD cred — the origin leg
 *       re-imports the cred from the path via brix_krb5_cred_from_ccache.
 * HOW:  Accept-gate happens in the caller (before this is reached). Both strings
 *       are NUL-terminated request-pool bytes owned by the ctx; carry them
 *       verbatim, stamp EXCHANGE, and mark the cred present. */
static ngx_int_t
brix_vfs_deleg_krb5(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred, int *use_cred)
{
    brix_deleg_live_t *live = ctx->deleg_live;

    cred->krb5_ccache = (const char *) live->krb5_ccache.data;
    cred->krb5_princ  = (const char *) live->krb5_origin_princ.data;
    cred->mode        = BRIX_CRED_EXCHANGE;
    *use_cred         = 1;

    brix_metric_cred_deleg(brix_vfs_metrics_proto(ctx),
        (ngx_uint_t) brix_vfs_backend_mode(ctx), BRIX_CRED_OUTCOME_USER);
    return NGX_OK;
}

/* Which forwardable bytes did the front door actually bind? Each predicate
 * requires BOTH a non-NULL buffer and a non-zero length — a bag may carry a
 * zero-length placeholder for a kind that was offered but never materialised. */
static int
brix_deleg_has_proxy(const brix_deleg_live_t *live)
{
    return live->have_proxy_pem && live->proxy_pem.len > 0
           && live->proxy_pem.data != NULL;
}

static int
brix_deleg_has_krb5(const brix_deleg_live_t *live)
{
    return live->krb5_ccache.len > 0 && live->krb5_ccache.data != NULL;
}

static int
brix_deleg_has_bearer(const brix_deleg_live_t *live)
{
    return live->bearer.len > 0 && live->bearer.data != NULL;
}

static int
brix_deleg_has_sss(const brix_deleg_live_t *live)
{
    return live->sss_keytab.len > 0 && live->sss_keytab.data != NULL;
}


/* Proven forwardable USER credentials — a full x509 proxy, or a forwarded krb5
 * TGT (GSSAPI EXCHANGE, §5.7). Both outrank the STS/bearer/SSS fallbacks below:
 * they are the caller's own delegable credential, not an identity assertion.
 * Each is denied (EACCES, before any origin contact) when the leaf backend does
 * not consume that kind — phase-71's credential-kind accept gate.
 * Returns 1 when this tier handled the request (verdict in *rc), 0 to fall on. */
static int
brix_deleg_user_cred(brix_vfs_ctx_t *ctx, const brix_deleg_live_t *live,
    uint32_t accept, brix_sd_cred_t *cred, int *use_cred, int *err_out,
    ngx_int_t *rc)
{
    if (brix_deleg_has_proxy(live)) {
        *rc = (accept & BRIX_SD_CRED_PROXY_PEM)
            ? brix_vfs_deleg_proxy(ctx, cred, use_cred, err_out)
            : brix_vfs_deleg_deny(ctx, use_cred, err_out, BRIX_CRED_FAIL_KIND);
        return 1;
    }
    if (brix_deleg_has_krb5(live)) {
        *rc = (accept & BRIX_SD_CRED_GSS_KRB5)
            ? brix_vfs_deleg_krb5(ctx, cred, use_cred)
            : brix_vfs_deleg_deny(ctx, use_cred, err_out, BRIX_CRED_FAIL_KIND);
        return 1;
    }
    return 0;
}


/* Origin-scoped SERVICE credentials, in precedence order.
 *
 * S3-origin STS EXCHANGE (§5.5) is decided BEFORE the bearer branch when the
 * operator armed STS and the leaf accepts an S3 credential. Rationale: a WLCG
 * bearer is the caller's IDENTITY, never an S3-consumable secret — an S3 SigV4
 * origin leg cannot be authenticated by forwarding the JWT verbatim (the origin
 * rejects it, or the driver falls back to the static service key, defeating
 * per-caller scoping). So when STS is armed a bound bearer supplies only
 * identity (RoleSessionName, already on ctx->identity) and STS mints the
 * temporary (ak/sk/session) origin cred. With STS unarmed (live->sts == NULL)
 * this is skipped and a bearer for a genuinely bearer-consuming origin
 * (xroot/https) is forwarded below.
 *
 * Bearer: EXCHANGE with a configured endpoint trades the subject token for a
 * backend-audienced one; EXCHANGE with no endpoint (documented §5.4 fallback)
 * and plain PASSTHROUGH forward the bearer verbatim.
 *
 * SSS: no forwardable bytes at all, but an armed keytab (§5.6) — assert the
 * caller's principal via a keytab-signed SSS cred. Proven bytes always win.
 * Returns 1 when this tier handled the request (verdict in *rc), 0 to fall on. */
static int
brix_deleg_service_cred(brix_vfs_ctx_t *ctx, const brix_deleg_live_t *live,
    uint32_t accept, brix_sd_cred_t *cred, int *use_cred, int *err_out,
    ngx_int_t *rc)
{
    if (live->sts != NULL && (accept & BRIX_SD_CRED_S3)) {
        *rc = brix_vfs_deleg_sts_cred(ctx,
            (const brix_s3_sts_conf_t *) live->sts, cred, use_cred, err_out);
        return 1;
    }
    if (brix_deleg_has_bearer(live)) {
        if (!(accept & BRIX_SD_CRED_BEARER)) {
            *rc = brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                      BRIX_CRED_FAIL_KIND);
            return 1;
        }
        *rc = (live->mode == BRIX_CRED_EXCHANGE && live->tx.endpoint.len > 0)
            ? brix_vfs_deleg_exchange(ctx, cred, use_cred, err_out)
            : brix_vfs_deleg_bearer(ctx, cred, use_cred);
        return 1;
    }
    if (brix_deleg_has_sss(live)) {
        *rc = brix_vfs_deleg_sss(ctx, cred, use_cred, err_out);
        return 1;
    }
    return 0;
}


/* ---- brix_vfs_deleg_live_cred ----------------------------------------------
 *
 * WHAT: Validate + materialise the ctx's bound PASSTHROUGH live cred into *cred.
 *       See the vfs_internal.h doc block for the full contract.
 *
 * WHY:  The cred gate delegates here when brix_vfs_backend_mode() is PASSTHROUGH,
 *       so all the "bytes → cred form (or deny/fallback)" logic is in one place.
 *
 * HOW:  Dispatch on which byte field the front door filled: a full proxy PEM
 *       (have_proxy_pem) routes to brix_vfs_deleg_proxy; a bound krb5 ccache path
 *       routes to brix_vfs_deleg_krb5 (GSSAPI forwarding, §5.7); an armed STS
 *       conf on an S3 leaf routes to brix_vfs_deleg_sts_cred; a bearer routes to
 *       brix_vfs_deleg_bearer; no bytes but an armed sss_keytab routes to
 *       brix_vfs_deleg_sss (identity injection, §5.6); nothing at all is a
 *       missing cred → deny/fallback. */
ngx_int_t
brix_vfs_deleg_live_cred(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    const brix_deleg_live_t *live;
    uint32_t                 accept;
    ngx_int_t                rc = NGX_OK;

    *use_cred = 0;

    if (ctx == NULL || ctx->deleg_live == NULL) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                                   BRIX_CRED_FAIL_MISSING);
    }
    live = ctx->deleg_live;

    /* phase-71: credential-kind accept gate. Deny (EACCES, before any origin
     * contact) when the live credential kind is not one the leaf backend can
     * consume — e.g. a bearer-only backend handed a full x509 proxy, or vice
     * versa. cred_accept==0 (no delegation support) rejects both kinds. */
    accept = brix_sd_cred_accept(brix_vfs_ns_leaf(ctx->sd));

    if (brix_deleg_user_cred(ctx, live, accept, cred, use_cred, err_out, &rc)) {
        return rc;
    }
    if (brix_deleg_service_cred(ctx, live, accept, cred, use_cred, err_out,
                                &rc))
    {
        return rc;
    }
    return brix_vfs_deleg_deny(ctx, use_cred, err_out,
                               BRIX_CRED_FAIL_MISSING);
}
