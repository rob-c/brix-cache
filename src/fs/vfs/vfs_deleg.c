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
 *       rejects non-PEM bytes before materialising; the full RFC-3820 chain-trust
 *       + DN-match gate is a documented TODO (§5.1) — the capture agent supplies
 *       validated bytes for now.
 */
#include "vfs_internal.h"
#include "net/proxy/gsi_upstream.h"
#include "auth/s3/sts.h"                 /* brix_s3_sts_assume  (§5.5, call-ready) */
#include "auth/krb5/forward.h"           /* brix_krb5_deleg_to_origin (§5.7)       */

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Cleanup payload: the pool-allocated 0600 temp path materialised for a
 * PASSTHROUGH proxy. On pool destruction the file is removed and the path
 * string is zeroed so it cannot linger in freed-but-reused pool memory. */
typedef struct {
    char *path;   /* NUL-terminated temp path, owned by the request pool */
} brix_deleg_temp_t;

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
static void
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
 *       handing the path to the GSI presenter (§5.1 gate, minimal form). The
 *       full RFC-3820 chain-trust + DN-match validation is a documented TODO
 *       below.
 *
 * HOW:  BIO over the bytes → PEM_read_bio_X509; a single successful parse is
 *       enough to prove the bytes are a PEM certificate. Frees the cert + BIO. */
static int
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
 *       use_cred=0 and return NGX_OK so the caller falls to the service cred. */
static ngx_int_t
brix_vfs_deleg_deny(brix_vfs_ctx_t *ctx, int *use_cred, int *err_out)
{
    *use_cred = 0;

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
 *       set. brix_token_exchange() POSTs the RFC-8693 grant using the first
 *       backend audience (live->tx_audience); on NGX_OK the pool-copied token is
 *       borrowed into cred->bearer. On failure → deny (never the service cred in
 *       fallback-deny mode). The subject/minted tokens are never logged. */
static ngx_int_t
brix_vfs_deleg_exchange(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    brix_deleg_live_t *live = ctx->deleg_live;
    ngx_str_t          minted = ngx_null_string;
    const ngx_str_t   *aud;

    aud = (live->tx_audience.len > 0) ? &live->tx_audience : NULL;

    if (brix_token_exchange(ctx->pool, &live->bearer, aud, NULL,
            &live->tx, &minted, ctx->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: backend token-exchange failed - denying (no service-cred "
            "fallback for EXCHANGE)");
        return brix_vfs_deleg_deny(ctx, use_cred, err_out);
    }

    cred->bearer = (const char *) minted.data;
    cred->mode   = BRIX_CRED_EXCHANGE;
    *use_cred    = 1;

    return NGX_OK;
}

/* ---- brix_vfs_deleg_proxy --------------------------------------------------
 *
 * WHAT: Materialise a PASSTHROUGH full x509 proxy: validate the PEM, write it to
 *       a 0600 temp, register the unlink+zero cleanup, and point cred->x509_proxy
 *       at the temp path.
 *
 * WHY:  brix_cache_origin_auth_gsi() authenticates from a proxy FILE path, so
 *       any strategy that materialises a proxy PEM at a 0600 path reuses the
 *       origin leg unchanged (§5.1). The private key must never be logged and
 *       must be unlinked on pool teardown.
 *
 * HOW:  brix_vfs_deleg_pem_is_valid() rejects non-PEM bytes → deny. Otherwise
 *       brix_proxy_gsi_write_pem_temp() creates the owner-only temp; the path is
 *       copied onto the pool and a cleanup registered to unlink+zero it.
 *
 * RFC-3820 chain-trust (phase-70 §5.1): the full gate is (1) chain parses AND is
 *       unexpired; (2) leaf DN EQUALS the front-door authenticated DN (no
 *       privilege swap); (3) chain is RFC-3820-valid AND trusted by the export's
 *       CA store via brix_gsi_verify_chain(..., client_purpose=0); (4) TLS-only
 *       transport. Steps (2)-(4) are enforced at CAPTURE (webdav auth_cert.c /
 *       delegation.c already run brix_gsi_verify_chain against conf->ca_store and
 *       match the DN before stashing the bytes), so only already-validated PEM
 *       reaches this seam. The trust check cannot be RE-run here because
 *       brix_gsi_verify_chain requires an X509_STORE* and brix_vfs_ctx_t carries
 *       no CA store — the store lives on the protocol conf (webdav conf->ca_store)
 *       and reaching it needs a new ctx-bind at the capture sites (owned by other
 *       agents). DEFERRED: add a `const void *ca_store` field to brix_vfs_ctx_t +
 *       a brix_vfs_ctx_bind_ca_store() call at each deleg capture site, then
 *       re-verify the chain here before materialising. Until then this seam
 *       enforces PEM well-formedness and relies on the capture-side gate. */
static ngx_int_t
brix_vfs_deleg_proxy(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    brix_deleg_live_t   *live = ctx->deleg_live;
    char                  tmp[NGX_MAX_PATH];
    char                 *path;
    size_t                path_len;
    brix_deleg_temp_t   *payload;
    ngx_pool_cleanup_t   *cln;
    ngx_str_t             princ = ngx_string("");

    if (!brix_vfs_deleg_pem_is_valid(live->proxy_pem.data,
                                     live->proxy_pem.len)) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out);
    }

    if (brix_proxy_gsi_write_pem_temp(live->proxy_pem.data,
            live->proxy_pem.len, tmp, sizeof(tmp)) != 0) {
        if (ctx->identity != NULL) {
            princ = ctx->identity->subject;
        }
        ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
            "brix: failed to materialise PASSTHROUGH proxy temp for "
            "principal=\"%V\"", &princ);
        return brix_vfs_deleg_deny(ctx, use_cred, err_out);
    }

    path_len = ngx_strlen(tmp);
    path = ngx_pnalloc(ctx->pool, path_len + 1);
    if (path == NULL) {
        (void) unlink(tmp);   /* vfs-seam-allow: config-domain PASSTHROUGH proxy credential temp (not export storage) */
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        *use_cred = 0;
        return NGX_ERROR;
    }
    ngx_memcpy(path, tmp, path_len);
    path[path_len] = '\0';

    cln = ngx_pool_cleanup_add(ctx->pool, sizeof(*payload));
    if (cln == NULL) {
        (void) unlink(path);  /* vfs-seam-allow: config-domain PASSTHROUGH proxy credential temp (not export storage) */
        ngx_memzero(path, path_len);
        errno = ENOMEM;
        if (err_out != NULL) {
            *err_out = ENOMEM;
        }
        *use_cred = 0;
        return NGX_ERROR;
    }
    payload = cln->data;
    payload->path = path;
    cln->handler = brix_vfs_deleg_temp_cleanup;

    cred->x509_proxy = path;
    cred->mode       = BRIX_CRED_PASSTHROUGH;
    *use_cred        = 1;

    return NGX_OK;
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
 *       (have_proxy_pem) routes to brix_vfs_deleg_proxy; a bearer routes to
 *       brix_vfs_deleg_bearer; neither present is a missing cred → deny/fallback. */
ngx_int_t
brix_vfs_deleg_live_cred(brix_vfs_ctx_t *ctx, brix_sd_cred_t *cred,
    int *use_cred, int *err_out)
{
    brix_deleg_live_t *live;

    *use_cred = 0;

    if (ctx == NULL || ctx->deleg_live == NULL) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out);
    }
    live = ctx->deleg_live;

    {
        /* phase-71: credential-kind accept gate. Deny (EACCES, before any origin
         * contact) when the live credential kind is not one the leaf backend can
         * consume — e.g. a bearer-only backend handed a full x509 proxy, or vice
         * versa. cred_accept==0 (no delegation support) rejects both kinds. */
        uint32_t accept = brix_sd_cred_accept(brix_vfs_ns_leaf(ctx->sd));

        if (live->have_proxy_pem && live->proxy_pem.len > 0
            && live->proxy_pem.data != NULL) {
            if (!(accept & BRIX_SD_CRED_PROXY_PEM)) {
                return brix_vfs_deleg_deny(ctx, use_cred, err_out);
            }
            return brix_vfs_deleg_proxy(ctx, cred, use_cred, err_out);
        }

        if (live->bearer.len > 0 && live->bearer.data != NULL) {
            if (!(accept & BRIX_SD_CRED_BEARER)) {
                return brix_vfs_deleg_deny(ctx, use_cred, err_out);
            }
            /* EXCHANGE with a configured endpoint trades the subject token for a
             * backend-audienced one; EXCHANGE with no endpoint (documented §5.4
             * fallback) and plain PASSTHROUGH forward the bearer verbatim. */
            if (live->mode == BRIX_CRED_EXCHANGE
                && live->tx.endpoint.len > 0) {
                return brix_vfs_deleg_exchange(ctx, cred, use_cred, err_out);
            }
            return brix_vfs_deleg_bearer(ctx, cred, use_cred);
        }
    }

    return brix_vfs_deleg_deny(ctx, use_cred, err_out);
}

/* ---- brix_vfs_deleg_sts_cred (call-ready hook, §5.5) -----------------------
 *
 * WHAT: Exchange the node's S3 service credential for temporary credentials
 *       scoped to the inbound identity via brix_s3_sts_assume(), and stamp the
 *       result onto cred->s3_ak/s3_sk/s3_region (mode EXCHANGE).
 *
 * WHY:  An S3 SigV4 secret is never transmitted, so the origin cannot be handed
 *       the caller's key; STS is the EXCHANGE path (§5.5). This helper is the
 *       single seam where the STS result becomes the sd_remote-consumable cred
 *       form, mirroring brix_vfs_deleg_exchange for bearers.
 *
 * HOW:  Calls brix_s3_sts_assume() with the ctx identity and the caller-supplied
 *       conf; on NGX_OK borrows the pool-copied ak/sk/region onto *cred. On
 *       failure → deny (never the service cred under fallback-deny). Secrets are
 *       never logged.
 *
 * DEFERRED (full origin-leg invocation): this compiles and is call-ready, but is
 *       NOT yet driven from brix_vfs_deleg_live_cred because (a) the STS conf
 *       (brix_s3_sts_conf_t: endpoint/region/role_arn + the node's svc_ak/svc_sk)
 *       is not reachable from brix_vfs_ctx_t — conf->common.backend_sts_endpoint/
 *       _role are set, but the SigV4 SERVICE key pair still needs a config source
 *       + a brix_vfs_ctx_bind_backend_sts() at the S3 capture site (owned by
 *       another agent); and (b) sd_remote's open_cred must map s3_ak/sk/session
 *       through to the origin keys. Wire (a)+(b), then call this from the
 *       EXCHANGE branch when the leaf backend accepts S3 creds. */
ngx_int_t
brix_vfs_deleg_sts_cred(brix_vfs_ctx_t *ctx, const brix_s3_sts_conf_t *cf,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    ngx_str_t ak = ngx_null_string;
    ngx_str_t sk = ngx_null_string;
    ngx_str_t session = ngx_null_string;
    brix_s3_sts_out_t out = { &ak, &sk, &session };

    *use_cred = 0;

    if (ctx == NULL || cf == NULL) {
        return brix_vfs_deleg_deny(ctx, use_cred, err_out);
    }

    if (brix_s3_sts_assume(ctx->pool, ctx->identity, cf, &out, ctx->log)
        != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
            "brix: S3 STS exchange failed - denying (no service-cred fallback "
            "for EXCHANGE)");
        return brix_vfs_deleg_deny(ctx, use_cred, err_out);
    }

    cred->s3_ak     = (const char *) ak.data;
    cred->s3_sk     = (const char *) sk.data;
    cred->s3_region = (cf->region.len > 0) ? (const char *) cf->region.data
                                           : NULL;
    cred->mode      = BRIX_CRED_EXCHANGE;
    *use_cred       = 1;

    return NGX_OK;
}

/* ---- brix_vfs_deleg_krb5_token (call-ready hook, §5.7) ---------------------
 *
 * WHAT: Initiate the first GSSAPI leg to the origin AS the inbound user, using a
 *       forwardable delegated GSS credential, via brix_krb5_deleg_to_origin().
 *
 * WHY:  krb5 is only backend-usable by GSSAPI forwarding (§5.7); this seam turns
 *       the captured delegated cred + origin service principal into the first-leg
 *       token the origin-auth caller then drives to completion.
 *
 * HOW:  Guarded by brix_krb5_forward_available() so a build without krb5, or a
 *       request without a forwardable ticket, cleanly reports unavailable (the
 *       caller falls back to SELECT). On success *out_token holds the first-leg
 *       GSS token (pool-copied).
 *
 * DEFERRED (full origin-leg invocation): compiles + is call-ready, but NOT yet
 *       driven because (a) the captured delegated gss_cred_id_t and the origin
 *       service principal are not carried on brix_vfs_ctx_t (root:// krb5 auth
 *       captures them in the session ctx — reaching them needs a bind at the
 *       stream capture site, owned by another agent); and (b) the multi-leg GSS
 *       negotiation belongs to origin_auth.c, which must feed origin replies back
 *       through gss_init_sec_context. Thread the delegated cred onto the ctx and
 *       add the origin-auth krb5-forward leg, then call this from the gate. */
ngx_int_t
brix_vfs_deleg_krb5_token(brix_vfs_ctx_t *ctx, void *deleg_gss_cred,
    const char *origin_service_princ, ngx_str_t *out_token)
{
    if (ctx == NULL || out_token == NULL) {
        return NGX_ERROR;
    }

    if (!brix_krb5_forward_available()) {
        ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
            "brix: krb5 credential forwarding unavailable - falling back to "
            "SELECT");
        return NGX_ERROR;
    }

    return brix_krb5_deleg_to_origin(ctx->pool, deleg_gss_cred,
        origin_service_princ, out_token, ctx->log);
}
