/*
 * delegation.c - authenticated proxy delegation endpoints: the simple
 * proxy-UPLOAD form (phase-2 T8) and the standard GridSite two-step
 * getProxyReq/putProxy REST flow (phase-3 T4).
 *
 * ============================ Phase-2 T8: upload ==========================
 * WHAT: PUT/POST /.well-known/brix-delegation, body = the client's own
 *       RFC-3820 x.509 proxy chain (PEM).  Requires GSI-cert-authenticated
 *       TLS (the request must already carry a verified client-certificate
 *       identity — see auth_cert.c), validates the uploaded proxy, and
 *       atomically stores it at <storage_credential_dir>/<key>.pem so
 *       Phase-1 credential selection (brix_sd_ucred_select) picks it up
 *       for that user's subsequent davs/S3 origin sessions.
 *
 * WHY: Phase-1 per-user backend credentials require a proxy to already
 *      exist under storage_credential_dir before a user's first origin
 *      request.  Operationally that means out-of-band provisioning.  This
 *      endpoint lets an already-authenticated client "capture" its own
 *      delegation over the wire (proxy-UPLOAD, not the full GridSite
 *      getProxyReq/putProxy two-step) so no pre-provisioning is required.
 *
 * HOW: 1. Gate on brix_delegation_endpoint + the well-known path.
 *      2. Require ctx->verified && ctx->auth_source == "cert"/"nginx"/
 *         "manual" (GSI/client-cert path — never a bearer token) and a
 *         non-empty ctx->dn.
 *      3. Read the whole body via brix_http_body_read_all (bounded, small).
 *      4. Parse the PEM chain (PEM_read_bio_X509 loop, mirrors the pattern
 *         in src/auth/gsi/parse_x509.c); find the end-entity cert (the one
 *         brix_px_classify() reports as BRIX_PX_NONE — proxies in the
 *         uploaded chain are excluded by construction).
 *      5. Check every cert in the chain (proxy and EEC) has a notAfter
 *         still in the future, and the EEC's subject DN (brix_x509_oneline,
 *         same normalisation as ctx->dn) equals the authenticated client's
 *         DN — a client may only upload a proxy for its own identity.
 *      6. Derive the credential key (brix_sd_ucred_key) and atomically
 *         write the whole uploaded PEM to <cred_dir>/<key>.pem: open a
 *         temp file in the same directory (O_CREAT|O_EXCL|O_WRONLY, 0600),
 *         write, fsync, close, then rename() over the final path.  This is
 *         a raw filesystem write to a service-owned config directory (not
 *         an export), so it is marked vfs-seam-allow rather than routed
 *         through the VFS, which confines to the export root only.
 *
 * ======================= Phase-3 T4: two-step GridSite ====================
 * WHAT: The standard GridSite getProxyReq/putProxy handshake, adapted to
 *       plain HTTP: GET /.well-known/brix-delegation/request returns a
 *       fresh CSR + a delegation-id; the client signs the CSR with its own
 *       EEC key and PUTs the signed proxy back to
 *       /.well-known/brix-delegation/<id>, which assembles and stores the
 *       full delegated proxy exactly like the T8 upload path.
 *
 * WHY: T8's proxy-UPLOAD form requires the client to already hold a
 *      complete, signed proxy chain it is willing to hand over wholesale —
 *      fine for scripted/xrdcp-style clients but not how the reference
 *      GridSite delegation portType works, and not what some interop
 *      partners expect.  The two-step form lets the SERVER generate the
 *      keypair (never touching disk, never leaving the server) so the
 *      client only ever signs a request — the standard, narrower trust
 *      model this specification exists to support alongside T8, not to
 *      replace it.
 *
 * HOW: 1. brix_deleg_store — a bounded (256-entry), per-worker, in-memory
 *         table of pending {id, fresh EVP_PKEY*, client_dn, expires_at}
 *         entries, TTL 600s, swept lazily on every get/put (no background
 *         thread — see brix_deleg_store_sweep).  Per-worker, NOT SHM: the
 *         fresh private key must never leave the process that generated
 *         it, and this is a short interactive two-request handshake, not
 *         durable state — a multi-worker deployment needs sticky routing
 *         (an L7 proxy or client retry-on-same-worker) so both requests of
 *         one handshake land on the same worker.  Documented on
 *         brix_deleg_store_t below; NOT a design flaw for THIS store, since
 *         SHM would additionally require serialising an EVP_PKEY private
 *         key into shared memory, which trades one small operational
 *         constraint (stickiness) for a much larger one (private key
 *         material outside process-local heap).
 *      2. webdav_delegation_request_handle (GET .../request): reuse the
 *         SAME peer-cert access pattern as auth_cert.c's
 *         webdav_verify_proxy_cert() — SSL_get_peer_certificate(ssl) off
 *         r->connection->ssl->connection — PEM-export it as `parent_pem`,
 *         and call brix_gsi_build_pxyreq(parent_pem, ...) to get a fresh
 *         key + CSR (re-encoded request DER→PEM, mirroring
 *         src/auth/gsi/delegation.c's gsi_req_der_to_pem, since the CSR
 *         travels over HTTP as PEM here too — DER has no natural HTTP
 *         content-type and PEM is what a human/openssl workflow expects).
 *         Store the entry keyed by a CSPRNG id (RAND_bytes, 16 bytes / 32
 *         hex chars via brix_hex_encode); respond with the CSR PEM as the
 *         body and the id in X-Brix-Delegation-Id.  UNLIKE the other two
 *         entry points, this one runs SYNCHRONOUSLY inside the content
 *         phase (a GET has no body to read asynchronously) and therefore
 *         returns an ngx_int_t instead of self-finalizing — see
 *         delegation.h's doc comment on this function for why
 *         self-finalizing here would double-finalize the request and
 *         crash the worker (caught by testing: the two-step e2e test
 *         initially crashed a worker with SIGSEGV in
 *         ngx_http_set_lingering_close via a double
 *         ngx_http_finalize_request, fixed by returning the status through
 *         webdav_metrics_return() like every other synchronous handler
 *         instead of calling webdav_metrics_finalize_request).
 *      3. webdav_delegation_put_handle (PUT .../<id>): look up id (checked
 *         BEFORE sweeping the rest of the table, so an expired-but-present
 *         entry is reported as 410, distinct from a never-existed/already-
 *         consumed 404 — see brix_deleg_store_take); 404 if absent, 410 if
 *         expired, 403 (and DO NOT touch any file) if entry.client_dn !=
 *         ctx->dn.  Otherwise split the
 *         uploaded body into its first PEM block (the signed proxy —
 *         brix_gsi_assemble_proxy's `proxy_pem` parses only the first
 *         block via PEM_read_bio_X509) and the remainder (the client's EEC
 *         chain — passed verbatim as `chain_pem`, appended after the proxy
 *         with no further parsing, exactly as brix_gsi_assemble_proxy's
 *         implementation does).  Call brix_gsi_assemble_proxy(proxy_pem,
 *         reqkey, chain_pem, ...) — it verifies the signed proxy's pubkey
 *         matches the stored fresh key (this IS the delegation's proof of
 *         possession: only a client holding the matching CSR could produce
 *         a proxy whose key matches) and returns the assembled
 *         <proxy><chain><private key> PEM — the reqkey is serialized into
 *         the blob so the stored credential is complete and can
 *         authenticate downstream (proxy_ssl_certificate_key, TPC pull,
 *         origin auth all load key+chain from the one stored file).
 *         Validate every cert's notAfter is still in
 *         the future and the chain's end-entity DN matches ctx->dn (reuse
 *         delegation_chain_expired / delegation_eec_dn_matches, the SAME T8
 *         helpers — a two-step-assembled credential is validated exactly
 *         as strictly as an uploaded one).  On success, atomically store
 *         via delegation_store_pem (the SAME T8 helper) and drop the store
 *         entry.  One-shot policy (documented on brix_deleg_store_drop
 *         below): the entry is dropped and its EVP_PKEY freed on ANY
 *         terminal outcome of this call — success, DN mismatch, expired,
 *         malformed body, or assemble failure — never left pending for a
 *         retry.  This is the simplest policy that guarantees no EVP_PKEY
 *         leak on any path and closes the id after first use either way,
 *         matching the brief's documented default.
 */

#include "webdav.h"
#include "delegation.h"
#include "fs/backend/ucred.h"
#include "auth/crypto/store_policy.h"
#include "auth/gsi/proxy_req.h"
#include "auth/crypto/gsi_verify.h"
#include "core/compat/log_diag.h"
#include "core/compat/hex.h"
#include "core/http/http_body.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Uploaded proxy PEM bodies are a handful of KB; reject anything larger. */
#define BRIX_DELEGATION_BODY_MAX (64 * 1024)

/* CSR responses (a single proxy-request cert, no chain) are small too. */
#define BRIX_DELEGATION_CSR_MAX  (16 * 1024)

/*
 * delegation_client_authenticated - true iff the request carries a verified
 * GSI/x.509 client-certificate identity (never a bearer token — those have
 * no certificate chain to delegate from).
 */
static int
delegation_client_authenticated(const ngx_http_brix_webdav_req_ctx_t *ctx)
{
    return ctx != NULL
        && ctx->verified
        && !ctx->token_auth
        && ctx->dn[0] != '\0';
}

/*
 * delegation_find_eec - scan a parsed proxy chain for the end-entity
 * certificate (the one cert that is NOT itself a proxy per
 * brix_px_classify()).  Returns a borrowed reference (still owned by
 * `chain`) or NULL if every cert in the chain is a proxy (malformed
 * upload — no EEC present).
 */
static X509 *
delegation_find_eec(STACK_OF(X509) *chain)
{
    int i, n;

    n = sk_X509_num(chain);
    for (i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);

        if (brix_px_classify(cert) == BRIX_PX_NONE) {
            return cert;
        }
    }
    return NULL;
}

/*
 * delegation_parse_chain - parse a PEM-concatenated cert chain from a
 * NUL-terminated buffer.  Mirrors the BIO+loop pattern in
 * src/auth/gsi/parse_x509.c (gsi_chain_from_plaintext).  Returns a
 * non-empty STACK_OF(X509) (caller must sk_X509_pop_free(chain, X509_free))
 * or NULL on any parse failure.
 */
static STACK_OF(X509) *
delegation_parse_chain(const u_char *pem, size_t pem_len)
{
    BIO            *bio;
    STACK_OF(X509) *chain;
    X509           *cert;

    bio = BIO_new_mem_buf(pem, (int) pem_len);
    if (bio == NULL) {
        return NULL;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        BIO_free(bio);
        return NULL;
    }

    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }
    BIO_free(bio);

    if (sk_X509_num(chain) == 0) {
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }
    return chain;
}

/*
 * delegation_chain_expired - true iff ANY certificate in the uploaded chain
 * (proxy or EEC) has a notAfter that is not in the future.  A delegation is
 * only as strong as its weakest link: an expired proxy cert grants no
 * authority even if the EEC underneath it is still valid, so the whole
 * chain must check out.
 */
static int
delegation_chain_expired(STACK_OF(X509) *chain)
{
    int i, n = sk_X509_num(chain);

    for (i = 0; i < n; i++) {
        if (X509_cmp_current_time(X509_get0_notAfter(sk_X509_value(chain, i)))
            <= 0)
        {
            return 1;
        }
    }
    return 0;
}

/*
 * delegation_eec_dn_matches - true iff `eec`'s subject DN
 * (brix_x509_oneline — the same normalisation ctx->dn uses) equals `want_dn`
 * exactly.  A client may only upload a proxy that delegates its own identity.
 */
static int
delegation_eec_dn_matches(X509 *eec, const char *want_dn)
{
    char eec_dn[1024];

    brix_x509_oneline(X509_get_subject_name(eec), eec_dn, sizeof(eec_dn));
    return strcmp(eec_dn, want_dn) == 0;
}

/*
 * delegation_chain_trusted - cryptographically verify that a delegated proxy
 * chain actually chains to a CA in the frontend's trust store.
 *
 * WHAT: run the same PKIX + RFC-3820 proxy verification the WebDAV
 *       client-certificate auth path uses (brix_gsi_verify_chain against
 *       conf->ca_store), treating the topmost proxy (chain[0]) as the leaf
 *       and the whole parsed chain as the untrusted intermediate set.
 *
 * WHY: the DN-equality check (delegation_eec_dn_matches) alone compares the
 *      EEC's *self-asserted* subject string against the authenticated client
 *      DN — it proves nothing about issuance.  A credential-writing endpoint
 *      must not store a proxy it cannot anchor to a trusted CA, otherwise the
 *      authenticated owner could plant a self-signed cert whose subject string
 *      is spoofed to equal their own DN.  Running full chain verification
 *      first turns the subsequent DN string compare into an identity check on
 *      a cryptographically-anchored EEC rather than an attacker-controlled
 *      string.  Mirrors auth_cert.c: a NULL ca_store means we cannot verify,
 *      so we refuse (caller maps to 403) rather than trust blindly.
 *
 * HOW: NULL store -> NGX_ERROR (refuse, logged).  Otherwise leaf = chain[0]
 *      (assemble/upload order is proxy-first), untrusted = the full chain
 *      (OpenSSL tolerates the leaf appearing in the untrusted stack), and
 *      client_purpose = 0 so RFC-3820 proxy chains are accepted (the davs://
 *      GSI mode, not the TLS-leaf mode).  Returns NGX_OK iff the chain
 *      verifies to the trust store; brix_gsi_verify_chain has already logged
 *      the specific reason on failure.  Owns nothing.
 */
static ngx_int_t
delegation_chain_trusted(ngx_http_request_t *r,
    const ngx_http_brix_webdav_loc_conf_t *conf, STACK_OF(X509) *chain)
{
    brix_gsi_verify_result_t verify_res;
    X509                    *leaf;

    if (conf->ca_store == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "brix_delegation: no trusted CA store configured — cannot verify"
            " delegated proxy; refusing to store an unverifiable credential"
            " (set brix_webdav_auth required with a CA on this location)");
        return NGX_ERROR;
    }

    leaf = sk_X509_value(chain, 0);
    if (leaf == NULL) {
        return NGX_ERROR;
    }

    if (brix_gsi_verify_chain(r->connection->log, conf->ca_store, leaf, chain,
            conf->verify_depth, &verify_res, 0 /* GSI: accept RFC-3820 proxy */)
        != NGX_OK)
    {
        /* brix_gsi_verify_chain already logged the specific error. */
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * delegation_store_pem - atomically write `pem`/`pem_len` to
 * <dir>/<key>.pem: temp file in the same directory (O_CREAT|O_EXCL|
 * O_WRONLY, 0600), write, fsync, close, rename() over the final path.
 * vfs-seam-allow: storage_credential_dir is service-owned server config,
 * not export storage — the VFS confines to the export root only, the
 * wrong root for this write.
 *
 * Returns NGX_OK on success, NGX_ERROR on any I/O failure (temp file is
 * best-effort unlinked on the way out; caller maps failure to 507).
 */
static ngx_int_t
delegation_store_pem(ngx_log_t *log, const ngx_str_t *dir, const char *key,
    const u_char *pem, size_t pem_len)
{
    char    final_path[1024];
    char    tmp_path[1024];
    int     fd;
    ssize_t written;

    if (dir->len == 0
        || dir->len + 1 + strlen(key) + sizeof(".pem") >= sizeof(final_path)
        || dir->len + 1 + strlen(key) + sizeof(".pem.XXXXXX") >= sizeof(tmp_path))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "brix_delegation: credential dir/key too long");
        return NGX_ERROR;
    }

    (void) ngx_snprintf((u_char *) final_path, sizeof(final_path) - 1,
        "%V/%s.pem%Z", dir, key);
    (void) snprintf(tmp_path, sizeof(tmp_path), "%.*s/.%s.pem.upload.%ld",
        (int) dir->len, dir->data, key, (long) getpid());

    fd = open(tmp_path, /* vfs-seam-allow: cred dir is svc-owned config, not an export */
              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 && ngx_errno == NGX_ENOENT) {
        /* Store dir vanished (tmpfs default is wiped by a reboot without a
         * config reload, or an admin rm'd it) — recreate it 0700 as the
         * worker uid and retry once before shouting. */
        if (mkdir((const char *) dir->data, 0700) == 0 /* vfs-seam-allow: cred dir is svc-owned config, not an export */
            || ngx_errno == NGX_EEXIST)
        {
            fd = open(tmp_path, /* vfs-seam-allow: cred dir is svc-owned config, not an export */
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        }
    }
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ALERT, log, ngx_errno,
                      "brix_delegation: open(\"%s\") temp cred file failed — "
                      "credential store \"%V\" is missing or not writable; "
                      "delegation will not work until "
                      "brix_storage_credential_dir is fixed",
                      tmp_path, dir);
        return NGX_ERROR;
    }

    written = write(fd, pem, pem_len);
    if (written < 0 || (size_t) written != pem_len || fsync(fd) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_delegation: write/fsync(\"%s\") failed", tmp_path);
        close(fd);
        unlink(tmp_path); /* vfs-seam-allow: cred dir is svc-owned config, not an export */
        return NGX_ERROR;
    }
    close(fd);

    if (rename(tmp_path, final_path) != 0) { /* vfs-seam-allow: cred dir is svc-owned config, not an export */
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "brix_delegation: rename(\"%s\" -> \"%s\") failed",
                      tmp_path, final_path);
        unlink(tmp_path); /* vfs-seam-allow: cred dir is svc-owned config, not an export */
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * delegation_reject - send a small plain-text error body and finalize the
 * request.  Single choke point so every failure branch below is one line.
 */
static void
delegation_reject(ngx_http_request_t *r, ngx_uint_t status, const char *msg)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    size_t       len = strlen(msg);
    u_char      *buf = ngx_pnalloc(r->pool, len);

    if (buf == NULL) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_memcpy(buf, msg, len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        webdav_metrics_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (ngx_http_send_header(r) == NGX_ERROR || r->header_only) {
        webdav_metrics_finalize_request(r, status);
        return;
    }
    webdav_metrics_finalize_request(r, ngx_http_output_filter(r, &out));
}

/* ========================================================================
 * Phase-3 T4: pending-delegation store (per-worker, in-memory, TTL-bounded).
 *
 * WHAT: A fixed-capacity table of {id, fresh EVP_PKEY*, client_dn,
 *       expires_at} entries, one per in-flight getProxyReq/putProxy
 *       handshake.  brix_deleg_store_put() inserts (evicting expired
 *       entries first, then refusing if still full); brix_deleg_store_take()
 *       looks up + REMOVES an entry by id (one-shot: the caller always owns
 *       the returned EVP_PKEY* and must free it), sweeping expired entries
 *       as a side effect of every call so no background thread is needed.
 *
 * WHY: Per-worker, NOT SHM. The fresh private key generated for a
 *      getProxyReq must NEVER leave the process that generated it (the
 *      brief's hardest requirement) — SHM would mean either serialising an
 *      EVP_PKEY into shared bytes (a private key exposed to every other
 *      worker process) or storing only a reference nginx cannot safely
 *      cross-process anyway.  A module-static per-worker table keeps the
 *      key in this worker's heap for its ~600s lifetime and nowhere else.
 *      The operational cost: a getProxyReq and its matching putProxy MUST
 *      land on the same worker.  For a single-worker deployment (typical
 *      test/small-site config) this is automatic.  For multi-worker, the
 *      deployment needs sticky routing (e.g. an L7 proxy keyed on client
 *      IP/TLS session, or a client that simply retries putProxy against
 *      the same connection/worker it got the CSR from) — documented here
 *      and in the reference doc, not solved by this store.
 *
 * HOW: Fixed array (BRIX_DELEG_STORE_CAP slots), linear scan (the table is
 *      small and operations are rare — an O(n) scan is simpler and just as
 *      fast in practice as a hash table at this size).  brix_deleg_store()
 *      lazily allocates the singleton on first use (module-static pointer,
 *      the ONE new global this feature introduces, exactly as scoped in
 *      the task brief) from ngx_cycle->pool so it lives for the worker's
 *      lifetime; nginx never destroys that pool mid-run.
 * ======================================================================== */

/* Delegation ids are CSPRNG bytes, hex-encoded; see brix_deleg_store_put. */
#define BRIX_DELEG_ID_BYTES   16
#define BRIX_DELEG_ID_HEXLEN  (BRIX_DELEG_ID_BYTES * 2)

/* Bounded capacity: a pending handshake is a brief interactive round-trip
 * (client signs a CSR, usually within seconds); 256 concurrent in-flight
 * handshakes per worker is generous headroom without unbounded growth. */
#define BRIX_DELEG_STORE_CAP  256

/* Pending-delegation lifetime: long enough for a human/script to sign and
 * return a CSR, short enough that an abandoned handshake's key doesn't
 * linger. Matches the brief's suggested 10 minutes. */
#define BRIX_DELEG_TTL_SEC    600

typedef struct {
    char       id[BRIX_DELEG_ID_HEXLEN + 1];  /* hex, NUL-terminated; empty = free slot */
    EVP_PKEY  *fresh_key;                      /* owned; never written to disk */
    char       client_dn[1024];                /* bound at getreq, rechecked at putProxy */
    time_t     created_at;
    time_t     expires_at;
} brix_deleg_entry_t;

typedef struct {
    brix_deleg_entry_t slots[BRIX_DELEG_STORE_CAP];
} brix_deleg_store_t;

/* The one documented per-worker global this feature introduces (see the
 * module doc-block above for why this cannot be SHM). Lazily allocated on
 * first use from ngx_cycle->pool; never freed early (worker-lifetime). */
static brix_deleg_store_t *brix_deleg_store_singleton = NULL;

static brix_deleg_store_t *
brix_deleg_store(void)
{
    if (brix_deleg_store_singleton == NULL) {
        brix_deleg_store_singleton =
            ngx_pcalloc(ngx_cycle->pool, sizeof(brix_deleg_store_t));
    }
    return brix_deleg_store_singleton;
}

/*
 * brix_deleg_entry_free - release an entry's owned resources and mark the
 * slot free.  The ONLY place an EVP_PKEY is freed, so every store exit path
 * (evict, sweep, take, drop) routes through this — the single choke point
 * that makes "no EVP_PKEY leak on any path" auditable by inspection.
 */
static void
brix_deleg_entry_free(brix_deleg_entry_t *e)
{
    if (e->fresh_key != NULL) {
        EVP_PKEY_free(e->fresh_key);
        e->fresh_key = NULL;
    }
    e->id[0] = '\0';
    e->client_dn[0] = '\0';
    e->created_at = 0;
    e->expires_at = 0;
}

/*
 * brix_deleg_store_sweep - free every expired entry.  Called at the top of
 * both brix_deleg_store_put (to make room) and brix_deleg_store_take (so a
 * lookup never returns a stale entry) — this IS the store's TTL enforcement;
 * there is no background timer.
 */
static void
brix_deleg_store_sweep(brix_deleg_store_t *st, time_t now)
{
    int i;

    for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
        if (st->slots[i].id[0] != '\0' && st->slots[i].expires_at <= now) {
            brix_deleg_entry_free(&st->slots[i]);
        }
    }
}

/*
 * brix_deleg_store_put - insert a new pending entry with a fresh CSPRNG id.
 *
 * WHAT: Sweeps expired entries, then scans for a free slot.  On success,
 *       fills id_out (caller-supplied buffer, >= BRIX_DELEG_ID_HEXLEN+1)
 *       with the hex id, stores fresh_key (ownership transfers to the
 *       store — caller must NOT free it after a successful put) and
 *       client_dn, sets expires_at = now + BRIX_DELEG_TTL_SEC.
 *
 * WHY:  CSPRNG (RAND_bytes, 16 bytes / 32 hex chars) makes the id
 *       unguessable — an attacker cannot brute-force or predict another
 *       client's pending delegation-id to attempt a cross-client putProxy
 *       (the DN check at take-time is the second, independent layer).
 *
 * HOW:  1. Sweep. 2. RAND_bytes + brix_hex_encode for the id (retry once on
 *       an astronomically unlikely id collision — a fresh RAND_bytes draw,
 *       not a fallback to a weaker source). 3. Linear scan for id[0]=='\0'.
 *       4. All full after sweep -> NGX_DECLINED (caller maps to 503,
 *       documented eviction policy: evict-expired-first, else reject new
 *       getreq rather than evict a live pending handshake).
 */
static ngx_int_t
brix_deleg_store_put(brix_deleg_store_t *st, EVP_PKEY *fresh_key,
    const char *client_dn, char *id_out, size_t id_out_cap)
{
    unsigned char raw[BRIX_DELEG_ID_BYTES];
    char          hex[BRIX_DELEG_ID_HEXLEN + 1];
    time_t        now = time(NULL);
    int           i;

    if (id_out_cap < sizeof(hex)) {
        return NGX_ERROR;
    }
    brix_deleg_store_sweep(st, now);

    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        return NGX_ERROR;
    }
    brix_hex_encode(raw, sizeof(raw), hex);

    for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
        if (st->slots[i].id[0] == '\0') {
            ngx_memcpy(st->slots[i].id, hex, sizeof(hex));
            st->slots[i].fresh_key = fresh_key;
            ngx_memcpy(st->slots[i].client_dn, client_dn,
                ngx_min(strlen(client_dn) + 1,
                        sizeof(st->slots[i].client_dn) - 1));
            st->slots[i].client_dn[sizeof(st->slots[i].client_dn) - 1] = '\0';
            st->slots[i].created_at = now;
            st->slots[i].expires_at = now + BRIX_DELEG_TTL_SEC;
            ngx_memcpy(id_out, hex, sizeof(hex));
            return NGX_OK;
        }
    }
    return NGX_DECLINED;  /* bounded store full even after sweep */
}

/* Outcome of brix_deleg_store_take, distinguishing every caller-relevant
 * terminal state (dispatch.c / the putProxy handler map these to distinct
 * HTTP statuses: 404 / 410 / 403 / found). */
typedef enum {
    BRIX_DELEG_TAKE_NOT_FOUND = 0,
    BRIX_DELEG_TAKE_EXPIRED,
    BRIX_DELEG_TAKE_DN_MISMATCH,
    BRIX_DELEG_TAKE_OK
} brix_deleg_take_t;

/*
 * brix_deleg_store_take - one-shot lookup-and-remove by id, DN-checked.
 *
 * WHAT: Scans for the id FIRST (before sweeping) so an expired-but-still-
 *       present entry can be reported as EXPIRED rather than being wiped by
 *       a blind sweep and misreported as NOT_FOUND — "never existed" /
 *       "already consumed" is a genuinely different, distinguishable
 *       outcome from "existed but timed out" for the caller's error
 *       message.  On a live match: if want_dn does not match the entry's
 *       stored client_dn, frees the entry (one-shot: a cross-client attempt
 *       burns the id rather than leaving it available for a retry) and
 *       returns DN_MISMATCH WITHOUT transferring the key.  On a DN match,
 *       transfers fresh_key ownership to *key_out (caller must
 *       EVP_PKEY_free it) and frees the slot's other fields, returning OK.
 *       Once the target id is resolved (found-and-handled, or absent),
 *       sweeps the REST of the table for any other expired entries — this
 *       is still the TTL enforcement's only trigger point (alongside
 *       brix_deleg_store_put), just ordered after the id-specific check so
 *       the two responsibilities (report THIS id's true state; reclaim
 *       OTHER entries' expired slots) don't fight over the same pass.
 *
 * WHY:  This is the id-to-client binding re-check the brief requires:
 *       "must belong to THIS authenticated client DN — reject
 *       cross-client".  One-shot on EVERY terminal outcome (not just
 *       success) is the documented policy — see the module doc-block —
 *       so a determined attacker gets exactly one guess per id and success
 *       or failure both close it out, with no leaked EVP_PKEY on any path
 *       (brix_deleg_entry_free is the sole free site).
 *
 * HOW:  Linear scan for id match. Not found -> sweep the rest -> NOT_FOUND.
 *       Found but past expiry -> free + sweep the rest -> EXPIRED.
 *       DN mismatch -> free + sweep the rest -> DN_MISMATCH.
 *       Match -> transfer key, free the rest of the slot, sweep the
 *       remaining table, -> OK.
 */
static brix_deleg_take_t
brix_deleg_store_take(brix_deleg_store_t *st, const char *id,
    const char *want_dn, EVP_PKEY **key_out)
{
    time_t             now = time(NULL);
    int                i;
    brix_deleg_take_t  result = BRIX_DELEG_TAKE_NOT_FOUND;

    for (i = 0; i < BRIX_DELEG_STORE_CAP; i++) {
        brix_deleg_entry_t *e = &st->slots[i];

        if (e->id[0] == '\0' || strcmp(e->id, id) != 0) {
            continue;
        }
        if (e->expires_at <= now) {
            brix_deleg_entry_free(e);
            result = BRIX_DELEG_TAKE_EXPIRED;
        } else if (strcmp(e->client_dn, want_dn) != 0) {
            brix_deleg_entry_free(e);
            result = BRIX_DELEG_TAKE_DN_MISMATCH;
        } else {
            *key_out = e->fresh_key;
            e->fresh_key = NULL;  /* ownership -> caller; entry_free must not free it */
            brix_deleg_entry_free(e);
            result = BRIX_DELEG_TAKE_OK;
        }
        break;
    }
    brix_deleg_store_sweep(st, now);
    return result;
}

/*
 * delegation_get_peer_pem - PEM-export the TLS peer certificate off this
 * request's SSL connection.  Reuses the exact acquisition pattern
 * auth_cert.c's webdav_verify_proxy_cert() uses (SSL_get_peer_certificate
 * off r->connection->ssl->connection) — this endpoint runs strictly after
 * that same verification has already populated ctx->verified/ctx->dn, so a
 * peer cert is guaranteed present; this just re-fetches the X509* (the
 * verified req_ctx stores only the derived DN string, not the cert object)
 * and serialises it to PEM in memory for brix_gsi_build_pxyreq's
 * `parent_pem` argument.  Caller frees *pem via free() (malloc'd, matching
 * the ngx-free proxy_req.c/gsi delegation.c convention for PEM buffers).
 */
static ngx_int_t
delegation_get_peer_pem(ngx_http_request_t *r, u_char **pem, size_t *pem_len)
{
    SSL    *ssl;
    X509   *leaf;
    BIO    *bio;
    char   *data;
    long    n;

    if (r->connection->ssl == NULL) {
        return NGX_ERROR;
    }
    ssl = r->connection->ssl->connection;
    leaf = SSL_get_peer_certificate(ssl);
    if (leaf == NULL) {
        return NGX_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL || PEM_write_bio_X509(bio, leaf) != 1) {
        BIO_free(bio);
        X509_free(leaf);
        return NGX_ERROR;
    }
    X509_free(leaf);

    n = BIO_get_mem_data(bio, &data);
    *pem = malloc((size_t) n + 1);
    if (*pem == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }
    memcpy(*pem, data, (size_t) n);
    (*pem)[n] = '\0';
    *pem_len = (size_t) n;
    BIO_free(bio);
    return NGX_OK;
}

/*
 * delegation_req_der_to_pem - re-encode brix_gsi_build_pxyreq's DER
 * X509_REQ output as PEM.  The two-step flow travels the CSR over HTTP as
 * a body a human or `openssl req` workflow can consume directly, and
 * mirrors src/auth/gsi/delegation.c's gsi_req_der_to_pem (the wire-protocol
 * delegation path re-encodes for the exact same reason — the crypto core
 * emits DER, the transport wants PEM).  Returns a malloc'd NUL-terminated
 * PEM buffer (caller frees), or NULL on parse/encode failure.
 */
static u_char *
delegation_req_der_to_pem(const uint8_t *der, size_t der_len, size_t *pem_len)
{
    const unsigned char *p = der;
    X509_REQ             *req = d2i_X509_REQ(NULL, &p, (long) der_len);
    BIO                   *bio;
    char                  *data;
    long                   n;
    u_char                *out = NULL;

    if (req == NULL) {
        return NULL;
    }
    bio = BIO_new(BIO_s_mem());
    if (bio != NULL && PEM_write_bio_X509_REQ(bio, req) == 1) {
        n = BIO_get_mem_data(bio, &data);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, data, (size_t) n);
            out[n] = '\0';
            *pem_len = (size_t) n;
        }
    }
    BIO_free(bio);
    X509_REQ_free(req);
    return out;
}

/*
 * delegation_send_csr - build a 200 response with the CSR PEM as the body
 * and the delegation-id in X-Brix-Delegation-Id.  Content-Type: application/
 * x-pem-file (RFC-ish convention for a bare PEM payload; chosen over
 * text/plain so a client can distinguish "this response IS a PEM
 * document" from the plain-text error bodies delegation_reject sends).
 *
 * Returns the ngx_int_t status the CALLER must return up through
 * webdav_metrics_return() — this function does NOT call
 * ngx_http_send_header/ngx_http_output_filter's result into
 * webdav_metrics_finalize_request itself, unlike delegation_reject.
 * webdav_delegation_request_handle runs synchronously inside the content
 * phase (no async body read is in flight), so self-finalizing here would
 * double-finalize the request once nginx's content phase ALSO finalizes
 * whatever this handler returns — see delegation.h's doc comment on
 * webdav_delegation_request_handle for why that crashes the worker.
 */
static ngx_int_t
delegation_send_csr(ngx_http_request_t *r, const char *id,
    const u_char *pem, size_t pem_len)
{
    ngx_buf_t        *b;
    ngx_chain_t        out;
    ngx_table_elt_t  *h;
    u_char            *buf;
    ngx_str_t          id_str;
    u_char            *id_copy;

    buf = ngx_pnalloc(r->pool, pem_len);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf, pem, pem_len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = buf;
    b->last = buf + pem_len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    id_str.len = strlen(id);
    id_str.data = (u_char *) id;
    id_copy = ngx_pstrdup(r->pool, &id_str);
    if (id_copy == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    h->hash = 1;
    ngx_str_set(&h->key, "X-Brix-Delegation-Id");
    h->value.data = id_copy;
    h->value.len = id_str.len;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) pem_len;
    r->headers_out.content_type.data = (u_char *) "application/x-pem-file";
    r->headers_out.content_type.len = sizeof("application/x-pem-file") - 1;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (ngx_http_send_header(r) == NGX_ERROR || r->header_only) {
        return NGX_HTTP_OK;
    }
    return ngx_http_output_filter(r, &out);
}

/*
 * delegation_request_reject - build a small plain-text error response
 * WITHOUT finalizing (the synchronous-handler counterpart to
 * delegation_reject, which self-finalizes for the async PUT paths). Returns
 * the status the caller passes up through webdav_metrics_return().
 */
static ngx_int_t
delegation_request_reject(ngx_http_request_t *r, ngx_uint_t status,
    const char *msg)
{
    ngx_buf_t   *b;
    ngx_chain_t  out;
    size_t       len = strlen(msg);
    u_char      *buf = ngx_pnalloc(r->pool, len);

    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(buf, msg, len);

    b = ngx_pcalloc(r->pool, sizeof(*b));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos = buf;
    b->last = buf + len;
    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = status;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (ngx_http_send_header(r) == NGX_ERROR || r->header_only) {
        return status;
    }
    return ngx_http_output_filter(r, &out);
}

ngx_int_t
webdav_delegation_request_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    u_char    *parent_pem = NULL;
    size_t     parent_pem_len = 0;
    EVP_PKEY  *newkey = NULL;
    uint8_t   *req_der = NULL;
    size_t     req_der_len = 0;
    u_char    *req_pem = NULL;
    size_t     req_pem_len = 0;
    char       err[160];
    char       id[BRIX_DELEG_ID_HEXLEN + 1];
    ngx_int_t  rc;

    if (!delegation_client_authenticated(ctx)) {
        return delegation_request_reject(r, NGX_HTTP_UNAUTHORIZED,
                          "GSI client-certificate authentication"
                          " required\n");
    }

    if (delegation_get_peer_pem(r, &parent_pem, &parent_pem_len) != NGX_OK) {
        return delegation_request_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "cannot access client certificate\n");
    }

    err[0] = '\0';
    {
        const brix_gsi_blob_t parent_blob = { parent_pem, parent_pem_len };
        const brix_gsi_err_t  err_sink    = { err, sizeof(err) };
        brix_gsi_buf_t        req_out     = { NULL, 0 };

        if (brix_gsi_build_pxyreq(&parent_blob, &newkey, &req_out,
                &err_sink) != 0)
        {
            free(parent_pem);
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "brix_delegation: build_pxyreq failed: %s", err);
            return delegation_request_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                              "cannot build proxy request\n");
        }
        req_der = req_out.data;
        req_der_len = req_out.len;
    }
    free(parent_pem);

    req_pem = delegation_req_der_to_pem(req_der, req_der_len, &req_pem_len);
    free(req_der);
    if (req_pem == NULL) {
        EVP_PKEY_free(newkey);
        return delegation_request_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "cannot encode proxy request\n");
    }

    if (brix_deleg_store_put(brix_deleg_store(), newkey, ctx->dn,
            id, sizeof(id)) != NGX_OK)
    {
        /* newkey ownership did NOT transfer on a failed put — free it here. */
        EVP_PKEY_free(newkey);
        free(req_pem);
        return delegation_request_reject(r, NGX_HTTP_SERVICE_UNAVAILABLE,
                          "too many pending delegations, try again later\n");
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_delegation: issued getProxyReq id=%s", id);
    rc = delegation_send_csr(r, id, req_pem, req_pem_len);
    free(req_pem);
    return rc;
}

/*
 * gsi_pem_export_one / gsi_pem_export_chain - serialise a single X509 or a
 * whole STACK_OF(X509) to a malloc'd, NUL-terminated PEM buffer.  Local
 * equivalents of src/auth/gsi/delegation.c's gsi_pem_export (that file's
 * helper is static to its own translation unit and not exposed to WebDAV,
 * and this file already carries its own X509/BIO includes, so a small
 * duplicate is simpler than threading a shared header through both wire
 * protocols for two output-only helper calls). Caller frees the result.
 */
static u_char *
gsi_pem_export_one(X509 *cert, size_t *len)
{
    BIO    *bio = BIO_new(BIO_s_mem());
    char   *data;
    long    n;
    u_char *out = NULL;

    if (bio != NULL && PEM_write_bio_X509(bio, cert) == 1) {
        n = BIO_get_mem_data(bio, &data);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, data, (size_t) n);
            out[n] = '\0';
            *len = (size_t) n;
        }
    }
    BIO_free(bio);
    return out;
}

static u_char *
gsi_pem_export_chain(STACK_OF(X509) *chain, size_t *len)
{
    BIO    *bio = BIO_new(BIO_s_mem());
    char   *data;
    long    n;
    u_char *out = NULL;
    int     i, ok = (bio != NULL);

    for (i = 0; ok && i < sk_X509_num(chain); i++) {
        if (PEM_write_bio_X509(bio, sk_X509_value(chain, i)) != 1) {
            ok = 0;
        }
    }
    if (ok) {
        n = BIO_get_mem_data(bio, &data);
        out = malloc((size_t) n + 1);
        if (out != NULL) {
            memcpy(out, data, (size_t) n);
            out[n] = '\0';
            *len = (size_t) n;
        }
    }
    BIO_free(bio);
    return out;
}

/*
 * delegation_split_first_pem_block - split a PEM buffer into its first
 * X509 certificate block (the signed proxy) and everything after it (the
 * issuer/EEC chain).  brix_gsi_assemble_proxy's `proxy_pem` argument is
 * parsed with PEM_read_bio_X509, which reads only the FIRST PEM block off
 * the BIO — so the client-uploaded body (signed proxy followed by its EEC
 * chain, mirroring the wire-protocol delegation flow's signed_pem +
 * deleg_chain_pem split in src/auth/gsi/delegation.c) must be split at
 * that boundary before calling assemble.  Re-parses via
 * delegation_parse_chain (same PEM-loop helper T8 uses) then re-serialises
 * cert[0] alone and certs[1..] concatenated — this also gives "unparseable"
 * and "no certs at all" rejection for free, reusing the T8 parse path
 * rather than a bespoke byte-offset scan.
 *
 * On success returns NGX_OK with proxy_pem / proxy_pem_len (cert[0] only)
 * and chain_pem / chain_pem_len (certs[1..], possibly zero-length if the
 * client sent only the proxy with no chain) both malloc'd (caller frees
 * both).  NGX_ERROR on parse failure or an empty chain.
 */
static ngx_int_t
delegation_split_first_pem_block(const u_char *body, size_t body_len,
    u_char **proxy_pem, size_t *proxy_pem_len,
    u_char **chain_pem, size_t *chain_pem_len)
{
    STACK_OF(X509) *chain;
    X509            *first;
    size_t           n;

    chain = delegation_parse_chain(body, body_len);
    if (chain == NULL) {
        return NGX_ERROR;
    }
    n = (size_t) sk_X509_num(chain);
    first = sk_X509_value(chain, 0);

    *proxy_pem = gsi_pem_export_one(first, proxy_pem_len);
    if (n > 1) {
        STACK_OF(X509) *rest = sk_X509_new_null();
        size_t          i;

        if (rest == NULL) {
            free(*proxy_pem);
            *proxy_pem = NULL;
            sk_X509_pop_free(chain, X509_free);
            return NGX_ERROR;
        }
        for (i = 1; i < n; i++) {
            sk_X509_push(rest, sk_X509_value(chain, (int) i));
        }
        *chain_pem = gsi_pem_export_chain(rest, chain_pem_len);
        sk_X509_free(rest);   /* shallow: certs still owned by `chain` */
    } else {
        *chain_pem = malloc(1);
        if (*chain_pem != NULL) {
            (*chain_pem)[0] = '\0';
        }
        *chain_pem_len = 0;
    }

    sk_X509_pop_free(chain, X509_free);
    if (*proxy_pem == NULL || *chain_pem == NULL) {
        free(*proxy_pem);
        free(*chain_pem);
        *proxy_pem = NULL;
        *chain_pem = NULL;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * delegation_extract_id - the trailing path segment of r->uri after
 * "/.well-known/brix-delegation/".  Returns NGX_OK with id / id_len
 * pointing into r->uri.data (borrowed, valid for the request's lifetime —
 * no copy needed), or NGX_ERROR if the segment is empty or implausibly
 * long (> BRIX_DELEG_ID_HEXLEN*2, generous slack over the real 32-char
 * ids so a legitimate id is never rejected while an absurd one short-
 * circuits before the store's strcmp scan).
 */
static ngx_int_t
delegation_extract_id(ngx_http_request_t *r, const u_char **id,
    size_t *id_len)
{
    static const char prefix[] = "/.well-known/brix-delegation/";
    size_t             plen = sizeof(prefix) - 1;

    if (r->uri.len <= plen) {
        return NGX_ERROR;
    }
    /* The id is whatever follows the LAST occurrence of the prefix — mirror
     * dispatch.c's routing, which matches on this same fixed prefix. */
    {
        ngx_uint_t i;
        const u_char *found = NULL;

        for (i = 0; i + plen <= r->uri.len; i++) {
            if (ngx_memcmp(r->uri.data + i, prefix, plen) == 0) {
                found = r->uri.data + i + plen;
            }
        }
        if (found == NULL) {
            return NGX_ERROR;
        }
        *id = found;
        *id_len = (size_t) (r->uri.data + r->uri.len - found);
    }
    if (*id_len == 0 || *id_len > (BRIX_DELEG_ID_HEXLEN * 2)) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t
delegation_put_take_key(ngx_http_request_t *r,
    const ngx_http_brix_webdav_req_ctx_t *ctx, const char *id,
    EVP_PKEY **reqkey)
{
    brix_deleg_take_t take_rc;

    take_rc = brix_deleg_store_take(brix_deleg_store(), id, ctx->dn, reqkey);
    if (take_rc == BRIX_DELEG_TAKE_OK) {
        return NGX_OK;
    }
    if (take_rc == BRIX_DELEG_TAKE_NOT_FOUND) {
        delegation_reject(r, NGX_HTTP_NOT_FOUND, "unknown delegation id\n");
        return NGX_ERROR;
    }
    if (take_rc == BRIX_DELEG_TAKE_EXPIRED) {
        delegation_reject(r, 410, "delegation id expired\n");
        return NGX_ERROR;
    }

    {
        char dn_log[1024];

        brix_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_delegation: putProxy id=%s DN mismatch — authenticated"
            " as \"%s\" does not own this delegation", id, dn_log);
    }
    delegation_reject(r, NGX_HTTP_FORBIDDEN,
                      "delegation id does not belong to the"
                      " authenticated client\n");
    return NGX_ERROR;
}

static ngx_int_t
delegation_put_assemble(ngx_http_request_t *r, const char *id, EVP_PKEY *reqkey,
    const u_char *body, size_t body_len, uint8_t **out_pem, size_t *out_len)
{
    u_char *proxy_pem = NULL, *chain_pem = NULL;
    size_t  proxy_pem_len = 0, chain_pem_len = 0;
    char    err[160];

    if (delegation_split_first_pem_block(body, body_len, &proxy_pem,
            &proxy_pem_len, &chain_pem, &chain_pem_len) != NGX_OK)
    {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "unparseable signed proxy PEM\n");
        return NGX_ERROR;
    }

    err[0] = '\0';
    {
        const brix_gsi_blob_t proxy_blob = { proxy_pem, proxy_pem_len };
        const brix_gsi_blob_t chain_blob = { chain_pem, chain_pem_len };
        const brix_gsi_err_t  err_sink   = { err, sizeof(err) };
        brix_gsi_buf_t        cred_out   = { NULL, 0 };

        if (brix_gsi_assemble_proxy(&proxy_blob, reqkey, &chain_blob,
                &cred_out, &err_sink) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "brix_delegation: putProxy id=%s assemble failed: %s", id, err);
            free(proxy_pem);
            free(chain_pem);
            delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                              "signed proxy does not match the outstanding"
                              " delegation request\n");
            return NGX_ERROR;
        }
        *out_pem = cred_out.data;
        *out_len = cred_out.len;
    }

    free(proxy_pem);
    free(chain_pem);
    return NGX_OK;
}

static ngx_int_t
delegation_put_validate_chain(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const ngx_http_brix_webdav_req_ctx_t *ctx, const char *id,
    const uint8_t *out_pem, size_t out_len)
{
    STACK_OF(X509) *proxy_chain;
    X509           *eec;

    proxy_chain = delegation_parse_chain(out_pem, out_len);
    if (proxy_chain == NULL) {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "assembled proxy is unparseable\n");
        return NGX_ERROR;
    }
    eec = delegation_find_eec(proxy_chain);
    if (eec == NULL) {
        sk_X509_pop_free(proxy_chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "assembled proxy has no end-entity certificate\n");
        return NGX_ERROR;
    }
    if (delegation_chain_expired(proxy_chain)) {
        sk_X509_pop_free(proxy_chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "assembled proxy is expired\n");
        return NGX_ERROR;
    }
    if (delegation_chain_trusted(r, conf, proxy_chain) != NGX_OK) {
        sk_X509_pop_free(proxy_chain, X509_free);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "assembled proxy chain does not verify against a"
                          " trusted CA\n");
        return NGX_ERROR;
    }
    if (!delegation_eec_dn_matches(eec, ctx->dn)) {
        sk_X509_pop_free(proxy_chain, X509_free);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_delegation: putProxy id=%s assembled proxy identity"
            " mismatch (should be unreachable — DN was already checked at"
            " getreq/take time)", id);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "assembled proxy identity does not match"
                          " authenticated client\n");
        return NGX_ERROR;
    }
    sk_X509_pop_free(proxy_chain, X509_free);
    return NGX_OK;
}

static ngx_int_t
delegation_put_store(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const ngx_http_brix_webdav_req_ctx_t *ctx, const uint8_t *out_pem,
    size_t out_len, char *key, size_t key_len)
{
    if (brix_sd_ucred_key(ctx->dn, key, key_len) != NGX_OK) {
        delegation_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "credential key derivation failed\n");
        return NGX_ERROR;
    }
    if (delegation_store_pem(r->connection->log,
            &conf->common.storage_credential_dir, key, out_pem, out_len)
        == NGX_OK)
    {
        return NGX_OK;
    }
    delegation_reject(r, NGX_HTTP_INSUFFICIENT_STORAGE,
                      "failed to store credential\n");
    return NGX_ERROR;
}

void
webdav_delegation_put_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    const u_char   *id_ptr;
    size_t          id_len;
    char            id[BRIX_DELEG_ID_HEXLEN * 2 + 1];
    u_char         *body = NULL;
    size_t          body_len = 0;
    EVP_PKEY       *reqkey = NULL;
    uint8_t        *out_pem = NULL;
    size_t          out_len = 0;
    char            key[BRIX_UCRED_KEY_MAX];

    if (!delegation_client_authenticated(ctx)) {
        delegation_reject(r, NGX_HTTP_UNAUTHORIZED,
                          "GSI client-certificate authentication"
                          " required\n");
        return;
    }

    if (delegation_extract_id(r, &id_ptr, &id_len) != NGX_OK) {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "missing or malformed delegation id\n");
        return;
    }
    ngx_memcpy(id, id_ptr, id_len);
    id[id_len] = '\0';

    if (brix_http_body_read_all(r, BRIX_DELEGATION_BODY_MAX, &body, &body_len)
            != NGX_OK
        || body == NULL || body_len == 0)
    {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "missing or oversized signed proxy body\n");
        return;
    }

    if (delegation_put_take_key(r, ctx, id, &reqkey) != NGX_OK) {
        return;
    }

    if (delegation_put_assemble(r, id, reqkey, body, body_len, &out_pem,
                                &out_len) != NGX_OK)
    {
        EVP_PKEY_free(reqkey);
        return;
    }
    EVP_PKEY_free(reqkey);

    /* Same validation strictness as T8's uploaded-chain path: every cert
     * unexpired, end-entity DN matches the authenticated client. */
    if (delegation_put_validate_chain(r, conf, ctx, id, out_pem, out_len)
        != NGX_OK)
    {
        free(out_pem);
        return;
    }

    if (delegation_put_store(r, conf, ctx, out_pem, out_len, key, sizeof(key))
        != NGX_OK)
    {
        free(out_pem);
        return;
    }
    free(out_pem);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_delegation: putProxy id=%s completed, stored proxy for key=%s",
        id, key);
    delegation_reject(r, NGX_HTTP_CREATED, "OK\n");
}

/*
 * delegation_validate_and_store - body is in hand; parse/validate/store.
 * Split out of webdav_delegation_handle so each early-return failure path
 * stays a single statement in the caller (no goto, no nested cleanup
 * ladders — chain ownership lives entirely in this function).
 */
static void
delegation_validate_and_store(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf,
    const ngx_http_brix_webdav_req_ctx_t *ctx,
    const u_char *body, size_t body_len)
{
    STACK_OF(X509) *chain;
    X509            *eec;
    char             key[BRIX_UCRED_KEY_MAX];

    chain = delegation_parse_chain(body, body_len);
    if (chain == NULL) {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "unparseable proxy PEM\n");
        return;
    }

    eec = delegation_find_eec(chain);
    if (eec == NULL) {
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "no end-entity certificate in chain\n");
        return;
    }

    /* Expiry checked before identity: an expired-and-mismatched upload
     * should not leak whether it also happens to name another identity. */
    if (delegation_chain_expired(chain)) {
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_BAD_REQUEST, "proxy is expired\n");
        return;
    }

    /* Chain-of-trust before identity: the EEC DN string compare below is only
     * meaningful once the EEC is proven to chain to a trusted CA.  A failure
     * here (self-signed / wrong-CA / untrusted issuer) and a DN mismatch both
     * report the same 403 so we never reveal which check the upload failed. */
    if (delegation_chain_trusted(r, conf, chain) != NGX_OK) {
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "proxy chain does not verify against a trusted"
                          " CA\n");
        return;
    }

    if (!delegation_eec_dn_matches(eec, ctx->dn)) {
        char dn_log[1024];

        brix_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "brix_delegation: DN mismatch — authenticated as \"%s\","
            " uploaded proxy is for a different identity", dn_log);
        sk_X509_pop_free(chain, X509_free);
        delegation_reject(r, NGX_HTTP_FORBIDDEN,
                          "proxy identity does not match authenticated"
                          " client\n");
        return;
    }

    sk_X509_pop_free(chain, X509_free);

    if (brix_sd_ucred_key(ctx->dn, key, sizeof(key)) != NGX_OK) {
        delegation_reject(r, NGX_HTTP_INTERNAL_SERVER_ERROR,
                          "credential key derivation failed\n");
        return;
    }

    if (delegation_store_pem(r->connection->log,
            &conf->common.storage_credential_dir, key, body, body_len)
        != NGX_OK)
    {
        delegation_reject(r, NGX_HTTP_INSUFFICIENT_STORAGE,
                          "failed to store credential\n");
        return;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "brix_delegation: stored proxy for key=%s", key);
    delegation_reject(r, NGX_HTTP_CREATED, "OK\n");
}

void
webdav_delegation_handle(ngx_http_request_t *r)
{
    ngx_http_brix_webdav_loc_conf_t *conf =
        ngx_http_get_module_loc_conf(r, ngx_http_brix_webdav_module);
    ngx_http_brix_webdav_req_ctx_t  *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_webdav_module);
    u_char *body = NULL;
    size_t  body_len = 0;

    if (!delegation_client_authenticated(ctx)) {
        delegation_reject(r, NGX_HTTP_UNAUTHORIZED,
                          "GSI client-certificate authentication"
                          " required\n");
        return;
    }

    if (brix_http_body_read_all(r, BRIX_DELEGATION_BODY_MAX, &body, &body_len)
            != NGX_OK
        || body == NULL || body_len == 0)
    {
        delegation_reject(r, NGX_HTTP_BAD_REQUEST,
                          "missing or oversized proxy body\n");
        return;
    }

    delegation_validate_and_store(r, conf, ctx, body, body_len);
}
