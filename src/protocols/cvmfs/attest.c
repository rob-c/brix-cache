/* attest.c — runtime provenance / SLSA-style attestation (phase-87 G15).
 *
 * WHAT: since this proxy VERIFIES every CAS byte it serves (phase-85 F1),
 *       it can attest exactly which content hashes a job consumed. A data
 *       request tagged with an `X-Brix-Attest: <session-label>` header has
 *       its served CAS hashes recorded under that session; the signed
 *       record is queryable at GET <loc>/.cvmfs-attest?session=<label> as a
 *       DSSE envelope over an in-toto v1 Statement (subject = the consumed
 *       digests), signed with the key named by `brix_cvmfs_attest`.
 * WHY:  "this result was produced against precisely these bytes" — supply-
 *       chain provenance and perfect reproducibility, uniquely enabled by a
 *       verifying proxy (the stock stack trusts, it cannot attest).
 * HOW:  the gate captures the (validated, bounded) session label into ctx;
 *       the request-finalization observer — the one place every serve path
 *       converges — records the CAS hash on success. Zero hot-path work:
 *       nothing runs when the directive is unset, and recording happens at
 *       request teardown.
 *
 * HONEST LIMITS (by design, documented):
 *   - The session table is PER-WORKER (same documented-exception idiom as
 *     the T13 negative memo): a session's requests and its record query
 *     must reach the same worker. Deployments with worker_processes > 1
 *     want keep-alive (one connection = one worker) or a per-worker query.
 *   - The label is a client-chosen capability, not an identity: anyone who
 *     knows a session label can read that session's record (hashes only —
 *     no payload content). Bind labels to jobs out of band. EXCEPTION: a
 *     session that touched an F3 token-gated repo is itself gated — its
 *     record serves only under a gated repo's name with a valid read token
 *     (location-coarse: any gated repo's reader in the location qualifies).
 *   - Bounded store, never silent: evicting the oldest session and
 *     truncating an over-long session both NOTICE-log exactly what dropped.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "cvmfs.h"
#include "cvmfs_module_internal.h"
#include "core/http/http_headers.h"

#define CVMFS_ATTEST_TAIL        "/.cvmfs-attest"
#define CVMFS_ATTEST_HEADER      "x-brix-attest"
#define CVMFS_ATTEST_SESSIONS    32   /* concurrent sessions per worker     */
#define CVMFS_ATTEST_HASHES      256  /* distinct hashes per session        */
#define CVMFS_ATTEST_LABEL_MAX   64
#define CVMFS_ATTEST_HEX_MAX     64   /* sha1 = 40; room for longer algos   */

#define CVMFS_ATTEST_PAYLOAD_TYPE  "application/vnd.in-toto+json"

typedef struct {
    char        label[CVMFS_ATTEST_LABEL_MAX + 1];
    char        hex[CVMFS_ATTEST_HASHES][CVMFS_ATTEST_HEX_MAX + 1];
    ngx_uint_t  nhex;
    uint64_t    seq;                  /* recency for oldest-first eviction  */
    unsigned    used:1;
    unsigned    truncated:1;
    unsigned    gated:1;              /* touched an F3 token-gated repo —
                                         record readable only through that
                                         gate (fail-closed, see endpoint)  */
} cvmfs_attest_session_t;

/* Per-worker session table — the same documented exception to the no-new-
 * globals rule as the T13 negative memo and the G12 swarm state: worker-
 * private observability state with no cross-worker consistency requirement
 * (the per-worker scope is part of the feature's stated contract above). */
static cvmfs_attest_session_t  cvmfs_attest_tab[CVMFS_ATTEST_SESSIONS];
static uint64_t                cvmfs_attest_seq;

/* ---- label validation ---------------------------------------------------- */

/* A session label is BOUND before use (phase-83 lesson: names are never
 * spliced raw): 1..64 chars of [A-Za-z0-9._-]. Returns 0 on invalid. */
static int
cvmfs_attest_label_ok(const u_char *p, size_t len)
{
    size_t  i;

    if (len == 0 || len > CVMFS_ATTEST_LABEL_MAX) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        u_char c = p[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
        {
            return 0;
        }
    }
    return 1;
}

/* ---- session store ------------------------------------------------------- */

static cvmfs_attest_session_t *
cvmfs_attest_find(const u_char *label, size_t len)
{
    ngx_uint_t  i;

    for (i = 0; i < CVMFS_ATTEST_SESSIONS; i++) {
        cvmfs_attest_session_t *s = &cvmfs_attest_tab[i];
        if (s->used && ngx_strlen(s->label) == len
            && ngx_memcmp(s->label, label, len) == 0)
        {
            return s;
        }
    }
    return NULL;
}

static cvmfs_attest_session_t *
cvmfs_attest_claim(const u_char *label, size_t len, ngx_log_t *log)
{
    cvmfs_attest_session_t *victim = NULL;
    ngx_uint_t              i;

    for (i = 0; i < CVMFS_ATTEST_SESSIONS; i++) {
        cvmfs_attest_session_t *s = &cvmfs_attest_tab[i];
        if (!s->used) {
            victim = s;
            break;
        }
        if (victim == NULL || s->seq < victim->seq) {
            victim = s;
        }
    }
    if (victim->used) {
        /* no silent caps: say exactly which record was dropped */
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
            "cvmfs-attest: event=session-evicted session=%s hashes=%ui "
            "hint=\"per-worker table full (%d sessions) — oldest record "
            "dropped to admit a new session\"",
            victim->label, victim->nhex, CVMFS_ATTEST_SESSIONS);
    }
    ngx_memzero(victim, sizeof(*victim));
    ngx_memcpy(victim->label, label, len);
    victim->used = 1;
    return victim;
}

static void
cvmfs_attest_record(const ngx_str_t *label, const char *hex, size_t hex_len,
    ngx_uint_t gated, ngx_log_t *log)
{
    cvmfs_attest_session_t *s;
    ngx_uint_t              i;

    s = cvmfs_attest_find(label->data, label->len);
    if (s == NULL) {
        s = cvmfs_attest_claim(label->data, label->len, log);
    }
    s->seq = ++cvmfs_attest_seq;
    if (gated) {
        s->gated = 1;      /* sticky: one gated hash gates the whole record */
    }

    for (i = 0; i < s->nhex; i++) {           /* consumed = a set, not a log */
        if (ngx_strlen(s->hex[i]) == hex_len
            && ngx_memcmp(s->hex[i], hex, hex_len) == 0)
        {
            return;
        }
    }
    if (s->nhex >= CVMFS_ATTEST_HASHES) {
        if (!s->truncated) {
            s->truncated = 1;
            ngx_log_error(NGX_LOG_NOTICE, log, 0,
                "cvmfs-attest: event=session-truncated session=%s "
                "hint=\"more than %d distinct hashes — record marked "
                "truncated=true, further hashes dropped\"",
                s->label, CVMFS_ATTEST_HASHES);
        }
        return;
    }
    ngx_memcpy(s->hex[s->nhex], hex, hex_len);
    s->hex[s->nhex][hex_len] = '\0';
    s->nhex++;
}

/* ---- finalize observer --------------------------------------------------- */

/* Record the served CAS hash under the request's session tag. Fires from the
 * request-finalization observer, so every serve path (inline hit, off-loop
 * fill, G16 member walk) converges here with the FINAL status — a 404'd or
 * rejected request never enters the record. */
void
brix_cvmfs_attest_observe(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    ngx_uint_t status)
{
    if (lcf->attest_pkey == NULL || ctx->attest_label.len == 0) {
        return;
    }
    if (status != NGX_HTTP_OK && status != NGX_HTTP_PARTIAL_CONTENT) {
        return;
    }
    if (ctx->url.cls != CVMFS_URL_CAS || ctx->url.cas_hex_len == 0) {
        return;                    /* only CAS objects carry a content hash */
    }
    if (ctx->url.cas_hex_len > CVMFS_ATTEST_HEX_MAX) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "cvmfs-attest: event=hash-dropped session=%V "
            "hint=\"CAS hash longer than %d hex chars — not recorded\"",
            &ctx->attest_label, CVMFS_ATTEST_HEX_MAX);
        return;
    }
    /* An F3-gated repo's consumption record is itself gated content: the
     * request that put the hash here passed the token gate, so its record
     * must not become anonymously readable through the endpoint. */
    cvmfs_attest_record(&ctx->attest_label, ctx->url.cas_hex,
                        ctx->url.cas_hex_len,
                        brix_cvmfs_repo_authz_gated(lcf, ctx->url.repo,
                                                    ctx->url.repo_len),
                        r->connection->log);
}

/* ---- signed record emission (DSSE over an in-toto v1 Statement) ---------- */

/* DSSE PAE(payloadType, payload) = "DSSEv1 <len> <type> <len> <payload>". */
static u_char *
cvmfs_attest_pae(ngx_http_request_t *r, const u_char *payload, size_t plen,
    size_t *out_len)
{
    size_t   max = sizeof("DSSEv1  " CVMFS_ATTEST_PAYLOAD_TYPE) + 40 + plen;
    u_char  *pae, *p;

    pae = ngx_pnalloc(r->pool, max);
    if (pae == NULL) {
        return NULL;
    }
    p = ngx_sprintf(pae, "DSSEv1 %uz %s %uz ",
                    sizeof(CVMFS_ATTEST_PAYLOAD_TYPE) - 1,
                    CVMFS_ATTEST_PAYLOAD_TYPE, plen);
    p = ngx_cpymem(p, payload, plen);
    *out_len = (size_t) (p - pae);
    return pae;
}

static ngx_int_t
cvmfs_attest_sign(ngx_http_request_t *r, EVP_PKEY *pkey,
    const u_char *msg, size_t mlen, u_char **sig_out, size_t *slen_out)
{
    EVP_MD_CTX  *md;
    u_char      *sig;
    size_t       slen;

    slen = (size_t) EVP_PKEY_size(pkey);
    sig  = ngx_pnalloc(r->pool, slen);
    if (sig == NULL) {
        return NGX_ERROR;
    }
    md = EVP_MD_CTX_new();
    if (md == NULL) {
        return NGX_ERROR;
    }
    if (EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, pkey) != 1
        || EVP_DigestSign(md, sig, &slen, msg, mlen) != 1)
    {
        EVP_MD_CTX_free(md);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "cvmfs-attest: EVP_DigestSign failed");
        return NGX_ERROR;
    }
    EVP_MD_CTX_free(md);
    *sig_out  = sig;
    *slen_out = slen;
    return NGX_OK;
}

static ngx_int_t
cvmfs_attest_serve_record(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, cvmfs_attest_session_t *s)
{
    u_char      *payload, *p, *pae, *sig, *body, *q;
    size_t       pmax, plen, pae_len, slen, bmax, blen;
    ngx_str_t    b64p, b64s, src;
    ngx_uint_t   i;
    ngx_buf_t   *b;
    ngx_chain_t  out;
    ngx_int_t    rc;

    /* in-toto v1 Statement: subject = the consumed digest set. 40 hex =
     * sha1 (the CVMFS default); anything else is labeled with the neutral
     * DigestSet key "cvmfs" rather than guessing an algorithm. */
    pmax = 256 + (size_t) s->nhex * (CVMFS_ATTEST_HEX_MAX + 40)
               + ngx_strlen(s->label);
    payload = ngx_pnalloc(r->pool, pmax);
    if (payload == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p = ngx_sprintf(payload,
            "{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[");
    for (i = 0; i < s->nhex; i++) {
        p = ngx_sprintf(p, "%s{\"digest\":{\"%s\":\"%s\"}}",
                        i ? "," : "",
                        ngx_strlen(s->hex[i]) == 40 ? "sha1" : "cvmfs",
                        s->hex[i]);
    }
    p = ngx_sprintf(p,
            "],\"predicateType\":\"https://brix.dev/cvmfs-attest/v1\","
            "\"predicate\":{\"session\":\"%s\",\"count\":%ui,"
            "\"truncated\":%s}}",
            s->label, s->nhex, s->truncated ? "true" : "false");
    plen = (size_t) (p - payload);

    pae = cvmfs_attest_pae(r, payload, plen, &pae_len);
    if (pae == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (cvmfs_attest_sign(r, (EVP_PKEY *) lcf->attest_pkey, pae, pae_len,
                          &sig, &slen) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b64p.len  = ngx_base64_encoded_length(plen);
    b64p.data = ngx_pnalloc(r->pool, b64p.len);
    b64s.len  = ngx_base64_encoded_length(slen);
    b64s.data = ngx_pnalloc(r->pool, b64s.len);
    if (b64p.data == NULL || b64s.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    src.data = payload;  src.len = plen;   ngx_encode_base64(&b64p, &src);
    src.data = sig;      src.len = slen;   ngx_encode_base64(&b64s, &src);

    bmax = 128 + sizeof(CVMFS_ATTEST_PAYLOAD_TYPE) + b64p.len + b64s.len;
    body = ngx_pnalloc(r->pool, bmax);
    if (body == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    q = ngx_sprintf(body,
            "{\"payloadType\":\"%s\",\"payload\":\"%V\","
            "\"signatures\":[{\"sig\":\"%V\"}]}",
            CVMFS_ATTEST_PAYLOAD_TYPE, &b64p, &b64s);
    blen = (size_t) (q - body);

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) blen;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->pos      = body;
    b->last     = body + blen;
    b->memory   = 1;
    b->last_buf = (r == r->main);
    out.buf  = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}

/* ---- gate hook: endpoint + label capture --------------------------------- */

/* A data (non-endpoint) request: capture (and BIND) the session tag, if
 * present. NGX_DECLINED = proceed with normal gating. */
static ngx_int_t
cvmfs_attest_capture_label(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_ctx_t *ctx)
{
    ngx_table_elt_t *h;

    h = brix_http_find_header(r, CVMFS_ATTEST_HEADER,
                              sizeof(CVMFS_ATTEST_HEADER) - 1);
    if (h == NULL || ctx == NULL) {
        return NGX_DECLINED;
    }

    if (!cvmfs_attest_label_ok(h->value.data, h->value.len)) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
            "cvmfs-attest: event=label-rejected client=%V "
            "hint=\"X-Brix-Attest must be 1..%d chars of "
            "[A-Za-z0-9._-] — request served untagged\"",
            &r->connection->addr_text, CVMFS_ATTEST_LABEL_MAX);
        return NGX_DECLINED;
    }

    ctx->attest_label.data = ngx_pnalloc(r->pool, h->value.len);
    if (ctx->attest_label.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(ctx->attest_label.data, h->value.data, h->value.len);
    ctx->attest_label.len = h->value.len;
    return NGX_DECLINED;
}

/* Fail-closed (phase-85 F3 contract: ALL of a gated repo's traffic sits
 * behind its gate): a session that touched gated content serves its record
 * only under a GATED repo's name with a valid READ-scope bearer for it —
 * never anonymously, and never through an ungated sibling name (that would
 * be a gate bypass). Gating is location-coarse: any gated repo's reader in
 * this location may read gated session records here (see HONEST LIMITS).
 * NGX_DECLINED = authorized. */
static ngx_int_t
cvmfs_attest_gated_authz(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf, ngx_http_brix_cvmfs_ctx_t *ctx,
    size_t tail_len)
{
    size_t end = r->uri.len - tail_len;           /* "…/<repo>" */
    size_t i   = end;

    while (i > 0 && r->uri.data[i - 1] != '/') {
        i--;
    }
    if (ctx == NULL || end == i
        || !brix_cvmfs_repo_authz_gated(lcf,
                (const char *) r->uri.data + i, end - i))
    {
        return NGX_HTTP_UNAUTHORIZED;
    }
    ctx->url.repo     = (const char *) r->uri.data + i;
    ctx->url.repo_len = end - i;
    return brix_cvmfs_repo_authz_eval(r, lcf);
    /* NGX_DECLINED authorized; 401 bad/missing bearer, 400 cleartext */
}

/* Serve GET <anything>/.cvmfs-attest?session=<label>, or capture a data
 * request's X-Brix-Attest label into ctx. NGX_DECLINED = not the endpoint
 * (the gate then classifies as usual). Pre-classification, like the swarm
 * roster: ".cvmfs-attest" is not a CVMFS traffic shape. The record is
 * metadata-plane: content hashes only, readable by whoever holds the
 * session label (see HONEST LIMITS above). */
ngx_int_t
brix_cvmfs_attest_gate(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    static const size_t         tail_len = sizeof(CVMFS_ATTEST_TAIL) - 1;
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    cvmfs_attest_session_t     *s;
    ngx_int_t                   rc;

    if (r->method != NGX_HTTP_GET
        || r->uri.len < tail_len
        || ngx_memcmp(r->uri.data + r->uri.len - tail_len,
                      CVMFS_ATTEST_TAIL, tail_len) != 0)
    {
        return cvmfs_attest_capture_label(r, ctx);
    }

    /* the record endpoint: ?session=<label> */
    if (r->args.len <= sizeof("session=") - 1
        || ngx_strncmp(r->args.data, "session=", sizeof("session=") - 1) != 0)
    {
        return NGX_HTTP_BAD_REQUEST;
    }
    {
        u_char  *label = r->args.data + sizeof("session=") - 1;
        size_t   len   = r->args.len - (sizeof("session=") - 1);

        if (!cvmfs_attest_label_ok(label, len)) {
            return NGX_HTTP_BAD_REQUEST;
        }
        s = cvmfs_attest_find(label, len);
    }
    if (s == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (s->gated) {
        rc = cvmfs_attest_gated_authz(r, lcf, ctx, tail_len);
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }
    return cvmfs_attest_serve_record(r, lcf, s);
}

/* ---- directive: brix_cvmfs_attest <private-key.pem> ---------------------- */

static void
cvmfs_attest_key_cleanup(void *data)
{
    EVP_PKEY_free((EVP_PKEY *) data);
}

/* Load the signing key at config time — an attesting proxy with an
 * unloadable key must not start (same fail-fast contract as the F1 trust
 * anchor). cf->pool cleanup frees the key on reload. */
char *
cvmfs_conf_attest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    void               **slot = (void **) ((char *) conf + cmd->offset);
    ngx_str_t           *value = cf->args->elts;
    char                 pathz[1024];
    u_char              *buf;
    ssize_t              n;
    off_t                size;
    ngx_fd_t             fd;
    ngx_file_info_t      fi;
    BIO                 *bio;
    EVP_PKEY            *pkey;
    ngx_pool_cleanup_t  *cln;

    if (*slot != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }
    if (value[1].len >= sizeof(pathz)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_attest: key path too long");
        return NGX_CONF_ERROR;
    }
    ngx_cpystrn((u_char *) pathz, value[1].data, value[1].len + 1);

    fd = open(pathz, O_RDONLY | O_CLOEXEC);   /* vfs-seam-allow: DOMAIN_CONFIG — config-domain signing-key PEM (not export storage) */
    if (fd == -1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_cvmfs_attest: cannot open \"%s\"", pathz);
        return NGX_CONF_ERROR;
    }
    if (ngx_fd_info(fd, &fi) == -1
        || (size = ngx_file_size(&fi)) <= 0 || size > 65536)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_attest: \"%s\" is empty, unreadable or larger "
            "than 64KB", pathz);
        (void) close(fd);
        return NGX_CONF_ERROR;
    }
    buf = ngx_palloc(cf->temp_pool, (size_t) size);
    if (buf == NULL) {
        (void) close(fd);
        return NGX_CONF_ERROR;
    }
    n = read(fd, buf, (size_t) size);   /* vfs-seam-allow: DOMAIN_CONFIG — config-domain signing-key PEM (not export storage) */
    (void) close(fd);
    if (n != (ssize_t) size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "brix_cvmfs_attest: short read on \"%s\"", pathz);
        return NGX_CONF_ERROR;
    }

    bio = BIO_new_mem_buf(buf, (int) size);
    if (bio == NULL) {
        return NGX_CONF_ERROR;
    }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (pkey == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_attest: \"%s\" holds no usable PEM private key",
            pathz);
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_CONF_ERROR;
    }
    cln->handler = cvmfs_attest_key_cleanup;
    cln->data    = pkey;

    *slot = pkey;
    return NGX_CONF_OK;
}
