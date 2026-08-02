/* Unit test for the VFS delegation PASSTHROUGH proxy gate (P90-70.4):
 * brix_vfs_deleg_live_cred's in-gate RFC-3820 chain-trust re-verify.
 *
 * Links the REAL vfs_deleg.o + vfs_deleg_bind.o + gsi_verify.o (+ the x509
 * policy sources and cred_stage/gsi_upstream for the temp materialiser); the
 * nginx pool/log surface and the unreached exchange leg + its cache are stubbed
 * below. Fixtures (forged via tests/x509forge.py) come from the directory in
 * $BRIX_DELEG_FIXTURES:
 *   ca.pem         — trusted CA (loaded into the X509_STORE)
 *   good_grid.pem  — grid-format proxy: proxy cert, PRIVATE KEY, EEC (CA-signed)
 *   rogue_grid.pem — same shape, chained to a DIFFERENT (untrusted) CA
 *   garbage.pem    — not PEM at all
 *
 * Ritual: success (trusted chain materialises; grid key block must not break
 * chain assembly) + error (garbage PEM denied EACCES) + security-negative
 * (rogue-CA chain denied EACCES; no service-cred fallback under deny).
 *
 * Also covers SSS identity injection (phase-70 §5.6 / P90-70.3): success
 * (caller's principal asserted, keytab passed through), error (no identity →
 * FAIL_MISSING deny), security-negative (>63-byte principal → never truncated;
 * SSS-refusing backend → FAIL_KIND; proven bytes always beat injection). */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "fs/vfs/vfs_internal.h"
#include "auth/token/exchange.h"
#include "auth/token/exchange_cache.h"

/* ---- nginx surface stubs (no nginx core objects are linked) --------------- */

static ngx_log_t test_log;   /* log_level 0: ngx_log_error() bodies are skipped */

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return malloc(size);
}

void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    return calloc(1, size);
}

/* Record registered cleanups so the test can run the unlink+zero handler. */
static ngx_pool_cleanup_t *last_cleanup;

ngx_pool_cleanup_t *
ngx_pool_cleanup_add(ngx_pool_t *p, size_t size)
{
    ngx_pool_cleanup_t *c;

    (void) p;
    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    if (size) {
        c->data = calloc(1, size);
        if (c->data == NULL) {
            free(c);
            return NULL;
        }
    }
    last_cleanup = c;
    return c;
}

u_char *
ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }
    while (--n && (*dst = *src) != '\0') {
        dst++;
        src++;
    }
    *dst = '\0';
    return dst;
}

/* ---- unreached delegation legs / sd accessors ----------------------------- */

ngx_int_t
brix_token_exchange(ngx_pool_t *pool, const ngx_str_t *subject_token,
    const ngx_str_t *audience, const ngx_str_t *scope,
    const brix_token_exchange_conf_t *cf, ngx_str_t *out_token, ngx_log_t *log)
{
    (void) pool; (void) subject_token; (void) audience; (void) scope;
    (void) cf; (void) out_token; (void) log;
    return NGX_ERROR;
}

/* The S3-STS origin leg (§5.5): an observable stub keeps vfs_deleg_hooks.o and
 * its brix_s3_sts_assume / libcurl / libxml2 chain out of the link while still
 * resolving vfs_deleg.o's reference. sts_stub_calls counts entries so a case can
 * prove the STS branch was (or was not) taken; sts_stub_succeed flips it between
 * a minted-temp-cred success (marker ak) and the default deny. */
static int sts_stub_calls;
static int sts_stub_succeed;

ngx_int_t
brix_vfs_deleg_sts_cred(brix_vfs_ctx_t *ctx, const brix_s3_sts_conf_t *cf,
    brix_sd_cred_t *cred, int *use_cred, int *err_out)
{
    (void) ctx; (void) cf; (void) err_out;
    sts_stub_calls++;
    if (use_cred != NULL) {
        *use_cred = 0;
    }
    if (!sts_stub_succeed) {
        return NGX_ERROR;
    }
    if (cred != NULL) {
        cred->s3_ak = "STS-TEMP-AK";
        cred->mode  = BRIX_CRED_EXCHANGE;
    }
    if (use_cred != NULL) {
        *use_cred = 1;
    }
    return NGX_OK;
}

/* The exchange leg's minted-token cache: this unit never reaches a cache hit
 * (no bag sets tx_cache_slot), so miss/no-op stubs keep exchange_cache.o and
 * its json/b64url/sha256 dependencies out of the link. ngx_cycle likewise
 * exists only to satisfy the lazy-create branch's reference. */
volatile ngx_cycle_t *ngx_cycle;

brix_tx_cache_t *
brix_tx_cache_create(ngx_pool_t *pool, ngx_uint_t slots)
{
    (void) pool; (void) slots;
    return NULL;
}

int
brix_tx_cache_lookup(brix_tx_cache_t *cache, const ngx_str_t *subject,
    const ngx_str_t *aud, time_t now, ngx_str_t *out)
{
    (void) cache; (void) subject; (void) aud; (void) now; (void) out;
    return 0;
}

void
brix_tx_cache_store(brix_tx_cache_t *cache, const ngx_str_t *subject,
    const ngx_str_t *aud, const ngx_str_t *minted, time_t now)
{
    (void) cache; (void) subject; (void) aud; (void) minted; (void) now;
}

/* ---- metric recording stubs (P90-70.6) ------------------------------------
 * vfs_deleg.o's terminals now emit the mode×outcome cube + failure reasons;
 * the unit records the last call of each so every case can assert the exact
 * label pair instead of linking the SHM-backed unified_record.o. */

static int         deleg_metric_calls;
static ngx_uint_t  last_deleg_mode;
static int         last_deleg_outcome;
static int         fail_metric_calls;
static int         last_fail_reason;

static void
reset_metrics(void)
{
    deleg_metric_calls = 0;
    fail_metric_calls  = 0;
    last_deleg_mode    = (ngx_uint_t) -1;
    last_deleg_outcome = -1;
    last_fail_reason   = -1;
}

void
brix_metric_cred_deleg(brix_proto_t proto, ngx_uint_t mode,
    brix_cred_outcome_t outcome)
{
    (void) proto;
    deleg_metric_calls++;
    last_deleg_mode    = mode;
    last_deleg_outcome = (int) outcome;
}

void
brix_metric_cred_fail(brix_proto_t proto, brix_cred_fail_t reason)
{
    (void) proto;
    fail_metric_calls++;
    last_fail_reason = (int) reason;
}

/* Toggled per-case so the SSS injection accept-gate deny is exercisable. */
static uint32_t accept_mask =
    BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM | BRIX_SD_CRED_SSS;

uint32_t
brix_sd_cred_accept(const brix_sd_instance_t *inst)
{
    (void) inst;
    return accept_mask;
}

/* Faithful stub of backend/ucred.o's principal extractor (linking the real
 * object drags in its sibling reader TUs): dn if non-empty, else subject;
 * unauthenticated / both-empty → NGX_ERROR. */
ngx_int_t
brix_sd_ucred_principal(const brix_identity_t *id, char *buf, size_t cap)
{
    ngx_str_t src;

    if (id == NULL || !id->is_authenticated) {
        return NGX_ERROR;
    }
    if (id->dn.len > 0) {
        src = id->dn;
    } else if (id->subject.len > 0) {
        src = id->subject;
    } else {
        return NGX_ERROR;
    }
    if (src.len >= cap) {
        return NGX_ERROR;
    }
    memcpy(buf, src.data, src.len);
    buf[src.len] = '\0';
    return NGX_OK;
}

brix_sd_instance_t *
brix_vfs_ns_leaf(brix_sd_instance_t *top)
{
    return top;
}

/* ---- helpers -------------------------------------------------------------- */

static u_char *
read_file(const char *dir, const char *name, size_t *len)
{
    char    path[1024];
    FILE   *f;
    u_char *buf;
    long    n;

    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "rb");
    assert(f != NULL);
    assert(fseek(f, 0, SEEK_END) == 0);
    n = ftell(f);
    assert(n > 0);
    rewind(f);
    buf = malloc((size_t) n);
    assert(buf != NULL);
    assert(fread(buf, 1, (size_t) n, f) == (size_t) n);
    fclose(f);
    *len = (size_t) n;
    return buf;
}

static X509_STORE *
load_store(const char *dir)
{
    char        path[1024];
    X509_STORE *store;

    snprintf(path, sizeof(path), "%s/ca.pem", dir);
    store = X509_STORE_new();
    assert(store != NULL);
    assert(X509_STORE_load_locations(store, path, NULL) == 1);
    return store;
}

static void
make_ctx(brix_vfs_ctx_t *ctx, brix_deleg_live_t *bag, u_char *pem,
    size_t len, X509_STORE *store, unsigned deny)
{
    memset(ctx, 0, sizeof(*ctx));
    memset(bag, 0, sizeof(*bag));

    bag->have_proxy_pem  = 1;
    bag->proxy_pem.data  = pem;
    bag->proxy_pem.len   = len;
    bag->mode            = BRIX_CRED_PASSTHROUGH;
    bag->ca_store        = store;
    bag->ca_verify_depth = 10;

    ctx->pool              = (ngx_pool_t *) ctx;   /* opaque to the stubs */
    ctx->log               = &test_log;
    ctx->deleg_live        = bag;
    ctx->storage_cred_deny = deny ? 1 : 0;
}

int
main(void)
{
    const char       *dir = getenv("BRIX_DELEG_FIXTURES");
    brix_vfs_ctx_t     ctx;
    brix_deleg_live_t  bag;
    brix_sd_cred_t     cred;
    X509_STORE        *store;
    u_char            *good, *rogue, *garbage;
    size_t             good_len, rogue_len, garbage_len;
    int                use_cred, err;
    ngx_int_t          rc;
    struct stat        st;

    assert(dir != NULL && "BRIX_DELEG_FIXTURES must point at the forge dir");

    good    = read_file(dir, "good_grid.pem", &good_len);
    rogue   = read_file(dir, "rogue_grid.pem", &rogue_len);
    garbage = read_file(dir, "garbage.pem", &garbage_len);
    store   = load_store(dir);

    /* 1. SUCCESS: trusted grid-format chain (cert, PRIVATE KEY, EEC)
     *    materialises to a 0600 temp whose bytes round-trip — proving the
     *    chain parser skips the key block instead of losing the EEC. */
    make_ctx(&ctx, &bag, good, good_len, store, 1);
    memset(&cred, 0, sizeof(cred));
    use_cred = 0; err = 0; last_cleanup = NULL;
    reset_metrics();
    rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
    assert(rc == NGX_OK);
    assert(use_cred == 1);
    assert(cred.mode == BRIX_CRED_PASSTHROUGH);
    assert(cred.x509_proxy != NULL);
    assert(stat(cred.x509_proxy, &st) == 0);
    assert((st.st_mode & 0777) == 0600);
    assert((size_t) st.st_size == good_len);
    assert(deleg_metric_calls == 1);
    assert(last_deleg_mode == (ngx_uint_t) BRIX_CRED_PASSTHROUGH);
    assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_USER);
    assert(fail_metric_calls == 0);

    /* …and the registered pool cleanup unlinks + scrubs the temp (§6). */
    assert(last_cleanup != NULL && last_cleanup->handler != NULL);
    {
        char kept[1024];
        ngx_cpystrn((u_char *) kept, (u_char *) cred.x509_proxy, sizeof(kept));
        last_cleanup->handler(last_cleanup->data);
        assert(stat(kept, &st) != 0 && errno == ENOENT);
    }

    /* 2. SUCCESS (back-compat): no store bound — capture-side gate applies,
     *    the materialiser still accepts a well-formed PEM. */
    make_ctx(&ctx, &bag, good, good_len, NULL, 1);
    memset(&cred, 0, sizeof(cred));
    use_cred = 0; err = 0;
    rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
    assert(rc == NGX_OK && use_cred == 1 && cred.x509_proxy != NULL);
    if (last_cleanup != NULL && last_cleanup->handler != NULL) {
        last_cleanup->handler(last_cleanup->data);
    }

    /* 3. SECURITY-NEG: chain rooted in an untrusted CA is denied EACCES with
     *    fallback-deny — never falls back to the service credential. */
    make_ctx(&ctx, &bag, rogue, rogue_len, store, 1);
    memset(&cred, 0, sizeof(cred));
    use_cred = 1; err = 0;
    reset_metrics();
    rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
    assert(rc == NGX_ERROR);
    assert(use_cred == 0);
    assert(err == EACCES);
    assert(cred.x509_proxy == NULL);
    assert(fail_metric_calls == 1);
    assert(last_fail_reason == (int) BRIX_CRED_FAIL_CHAIN);
    assert(deleg_metric_calls == 1);
    assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_DENY);

    /* 4. SECURITY-NEG: same rogue chain WITHOUT fallback-deny → NGX_OK but
     *    use_cred stays 0 (service-cred fallback, wrong identity never used). */
    make_ctx(&ctx, &bag, rogue, rogue_len, store, 0);
    memset(&cred, 0, sizeof(cred));
    use_cred = 1; err = 0;
    reset_metrics();
    rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
    assert(rc == NGX_OK && use_cred == 0 && cred.x509_proxy == NULL);
    assert(last_fail_reason == (int) BRIX_CRED_FAIL_CHAIN);
    assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_FALLBACK);

    /* 5. ERROR: non-PEM bytes are denied EACCES before any temp is written. */
    make_ctx(&ctx, &bag, garbage, garbage_len, store, 1);
    memset(&cred, 0, sizeof(cred));
    use_cred = 1; err = 0;
    reset_metrics();
    rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
    assert(rc == NGX_ERROR && use_cred == 0 && err == EACCES);
    assert(last_fail_reason == (int) BRIX_CRED_FAIL_PEM);
    assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_DENY);

    /* 6. Setter guards: NULL vctx / no bag / NULL store are silent no-ops. */
    brix_vfs_deleg_set_ca_store(NULL, store, 10);
    memset(&ctx, 0, sizeof(ctx));
    brix_vfs_deleg_set_ca_store(&ctx, store, 10);   /* no bag bound */
    make_ctx(&ctx, &bag, good, good_len, NULL, 1);
    brix_vfs_deleg_set_ca_store(&ctx, NULL, 10);
    assert(bag.ca_store == NULL);
    brix_vfs_deleg_set_ca_store(&ctx, store, 7);
    assert(bag.ca_store == store && bag.ca_verify_depth == 7);

    /* ---- SSS identity injection (phase-70 §5.6 / P90-70.3) ---------------- */
    {
        ngx_str_t        keytab = ngx_string("/etc/brix/backend.keytab");
        brix_identity_t  id;
        char             longname[65];

        /* 7. SUCCESS: no forwardable bytes + armed keytab + authenticated
         *    identity → SSS cred asserting the CALLER's dn, keytab passed
         *    through, USER outcome on the PASSTHROUGH mode label. */
        make_ctx(&ctx, &bag, NULL, 0, NULL, 1);
        bag.have_proxy_pem = 0;
        bag.sss_keytab     = keytab;
        memset(&id, 0, sizeof(id));
        ngx_str_set(&id.dn, "CN=Alice Adams");
        id.is_authenticated = 1;
        ctx.identity = &id;
        memset(&cred, 0, sizeof(cred));
        use_cred = 0; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_OK && use_cred == 1);
        assert(cred.principal != NULL
               && strcmp(cred.principal, "CN=Alice Adams") == 0);
        assert(cred.sss_keytab != NULL
               && strcmp(cred.sss_keytab, (const char *) keytab.data) == 0);
        assert(cred.mode == BRIX_CRED_PASSTHROUGH);
        assert(cred.x509_proxy == NULL);
        assert(deleg_metric_calls == 1);
        assert(last_deleg_mode == (ngx_uint_t) BRIX_CRED_PASSTHROUGH);
        assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_USER);
        assert(fail_metric_calls == 0);

        /* 8. ERROR: no authenticated identity → FAIL_MISSING deny; the shared
         *    keytab identity is never substituted. */
        make_ctx(&ctx, &bag, NULL, 0, NULL, 1);
        bag.have_proxy_pem = 0;
        bag.sss_keytab     = keytab;
        ctx.identity       = NULL;
        memset(&cred, 0, sizeof(cred));
        use_cred = 1; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_ERROR && use_cred == 0 && err == EACCES);
        assert(cred.principal == NULL && cred.sss_keytab == NULL);
        assert(last_fail_reason == (int) BRIX_CRED_FAIL_MISSING);
        assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_DENY);

        /* 9. SECURITY-NEG: principal over the SSS NAME TLV bound (63 bytes)
         *    → FAIL_MATERIALISE deny, never silently truncated (a 63-byte
         *    prefix collision would merge two identities at the origin). */
        memset(longname, 'A', 64);
        longname[64] = '\0';
        make_ctx(&ctx, &bag, NULL, 0, NULL, 1);
        bag.have_proxy_pem = 0;
        bag.sss_keytab     = keytab;
        memset(&id, 0, sizeof(id));
        id.dn.data = (u_char *) longname;
        id.dn.len  = 64;
        id.is_authenticated = 1;
        ctx.identity = &id;
        memset(&cred, 0, sizeof(cred));
        use_cred = 1; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_ERROR && use_cred == 0 && err == EACCES);
        assert(cred.principal == NULL);
        assert(last_fail_reason == (int) BRIX_CRED_FAIL_MATERIALISE);
        assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_DENY);

        /* 10. SECURITY-NEG: backend that does not accept SSS → FAIL_KIND deny
         *     (no service fallback under deny). */
        accept_mask = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM;
        make_ctx(&ctx, &bag, NULL, 0, NULL, 1);
        bag.have_proxy_pem = 0;
        bag.sss_keytab     = keytab;
        memset(&id, 0, sizeof(id));
        ngx_str_set(&id.dn, "CN=Alice Adams");
        id.is_authenticated = 1;
        ctx.identity = &id;
        memset(&cred, 0, sizeof(cred));
        use_cred = 1; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_ERROR && use_cred == 0 && err == EACCES);
        assert(last_fail_reason == (int) BRIX_CRED_FAIL_KIND);
        accept_mask =
            BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM | BRIX_SD_CRED_SSS;

        /* 11. Proven bytes win: a bag carrying BOTH a proxy PEM and an armed
         *     keytab takes the proxy leg — injection never shadows real
         *     credential bytes. */
        make_ctx(&ctx, &bag, good, good_len, store, 1);
        bag.sss_keytab = keytab;
        memset(&id, 0, sizeof(id));
        ngx_str_set(&id.dn, "CN=Alice Adams");
        id.is_authenticated = 1;
        ctx.identity = &id;
        memset(&cred, 0, sizeof(cred));
        use_cred = 0; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_OK && use_cred == 1);
        assert(cred.x509_proxy != NULL);       /* proxy leg, not injection */
        assert(cred.sss_keytab == NULL && cred.principal == NULL);
        if (last_cleanup != NULL && last_cleanup->handler != NULL) {
            last_cleanup->handler(last_cleanup->data);
        }

        /* 12. brix_vfs_deleg_set_sss: allocates the bag when none is bound
         *     (the injection-only capture path); SELECT mode and an empty
         *     keytab stay no-ops. */
        memset(&ctx, 0, sizeof(ctx));
        ctx.pool = (ngx_pool_t *) &ctx;
        brix_vfs_deleg_set_sss(NULL, BRIX_CRED_PASSTHROUGH, &keytab);
        brix_vfs_deleg_set_sss(&ctx, BRIX_CRED_SELECT, &keytab);
        assert(ctx.deleg_live == NULL);
        {
            ngx_str_t empty = ngx_null_string;
            brix_vfs_deleg_set_sss(&ctx, BRIX_CRED_PASSTHROUGH, &empty);
            assert(ctx.deleg_live == NULL);
        }
        brix_vfs_deleg_set_sss(&ctx, BRIX_CRED_PASSTHROUGH, &keytab);
        assert(ctx.deleg_live != NULL);
        assert(ctx.deleg_live->mode == BRIX_CRED_PASSTHROUGH);
        assert(ctx.deleg_live->sss_keytab.data == keytab.data);
        free(ctx.deleg_live);
    }

    /* ---- S3-STS precedence over a bound bearer (phase-70 §5.5) ------------- */
    {
        brix_deleg_live_t  bag2;
        ngx_str_t          bearer = ngx_string("eyJ0.stub.jwt");

        /* 13. PRECEDENCE (SUCCESS): a bag carrying BOTH a bearer AND an armed STS
         *     conf, on an S3-accepting leaf, takes the STS branch — a WLCG bearer
         *     is the caller's identity, never an S3-consumable secret, so it must
         *     NOT be forwarded verbatim while STS is armed. Proves STS wins the
         *     ordering ahead of brix_vfs_deleg_bearer. */
        accept_mask = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_S3;
        memset(&ctx, 0, sizeof(ctx));
        memset(&bag2, 0, sizeof(bag2));
        ctx.pool = (ngx_pool_t *) &ctx;
        ctx.log  = &test_log;
        ctx.deleg_live   = &bag2;
        bag2.have_proxy_pem = 0;
        bag2.bearer         = bearer;
        bag2.mode           = BRIX_CRED_EXCHANGE;
        bag2.sts            = (const void *) &bag2;   /* non-NULL: STS armed */
        sts_stub_calls = 0; sts_stub_succeed = 1;
        memset(&cred, 0, sizeof(cred));
        use_cred = 0; err = 0;
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_OK && use_cred == 1);
        assert(sts_stub_calls == 1);                  /* STS branch taken */
        assert(cred.s3_ak != NULL
               && strcmp(cred.s3_ak, "STS-TEMP-AK") == 0);
        assert(cred.bearer == NULL);                  /* NOT bearer-verbatim */
        assert(cred.mode == BRIX_CRED_EXCHANGE);

        /* 14. REGRESSION GUARD: same bearer, STS UNARMED (live->sts == NULL) on a
         *     bearer+S3 leaf → the STS branch is skipped and the bearer is
         *     forwarded verbatim (the genuine xroot/https-origin case). Proves the
         *     reorder narrows to armed-STS only and never steals a plain bearer. */
        memset(&ctx, 0, sizeof(ctx));
        memset(&bag2, 0, sizeof(bag2));
        ctx.pool = (ngx_pool_t *) &ctx;
        ctx.log  = &test_log;
        ctx.deleg_live   = &bag2;
        bag2.have_proxy_pem = 0;
        bag2.bearer         = bearer;
        bag2.mode           = BRIX_CRED_PASSTHROUGH;
        bag2.sts            = NULL;                    /* STS disarmed */
        sts_stub_calls = 0; sts_stub_succeed = 1;
        memset(&cred, 0, sizeof(cred));
        use_cred = 0; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_OK && use_cred == 1);
        assert(sts_stub_calls == 0);                  /* STS branch NOT taken */
        assert(cred.bearer != NULL
               && strcmp(cred.bearer, (const char *) bearer.data) == 0);
        assert(cred.s3_ak == NULL);
        sts_stub_succeed = 0;
    }

    /* ---- krb5 GSSAPI EXCHANGE selection (phase-70 §5.7) -------------------- */
    {
        brix_deleg_live_t  bag3;
        ngx_str_t          cc  = ngx_string("/tmp/brix-krb5-fwd.ccache");
        ngx_str_t          spn = ngx_string("host/origin.example.org@EXAMPLE.ORG");

        /* 15. SUCCESS: a bag carrying a bound krb5 ccache PATH on a krb5-accepting
         *     leaf takes the krb5 branch — the ccache path + origin principal are
         *     carried verbatim onto the POD cred as an EXCHANGE, USER outcome. The
         *     origin leg re-imports the delegated TGT from the path at fill time. */
        accept_mask = BRIX_SD_CRED_GSS_KRB5;
        memset(&ctx, 0, sizeof(ctx));
        memset(&bag3, 0, sizeof(bag3));
        ctx.pool = (ngx_pool_t *) &ctx;
        ctx.log  = &test_log;
        ctx.deleg_live         = &bag3;
        bag3.have_proxy_pem    = 0;
        bag3.mode              = BRIX_CRED_EXCHANGE;
        bag3.krb5_ccache       = cc;
        bag3.krb5_origin_princ = spn;
        memset(&cred, 0, sizeof(cred));
        use_cred = 0; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_OK && use_cred == 1);
        assert(cred.krb5_ccache != NULL
               && strcmp(cred.krb5_ccache, (const char *) cc.data) == 0);
        assert(cred.krb5_princ != NULL
               && strcmp(cred.krb5_princ, (const char *) spn.data) == 0);
        assert(cred.mode == BRIX_CRED_EXCHANGE);
        assert(cred.x509_proxy == NULL && cred.bearer == NULL);
        assert(deleg_metric_calls == 1);
        assert(last_deleg_outcome == (int) BRIX_CRED_OUTCOME_USER);
        assert(fail_metric_calls == 0);

        /* 16. SECURITY-NEG: a leaf that does not consume a krb5 GSSAPI cred →
         *     FAIL_KIND deny (EACCES, before any origin contact); the ccache path
         *     is never carried and no service fallback happens under deny. */
        accept_mask = BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM;
        memset(&ctx, 0, sizeof(ctx));
        memset(&bag3, 0, sizeof(bag3));
        ctx.pool = (ngx_pool_t *) &ctx;
        ctx.log  = &test_log;
        ctx.deleg_live         = &bag3;
        ctx.storage_cred_deny  = 1;                    /* no wrong-identity fallback */
        bag3.have_proxy_pem    = 0;
        bag3.mode              = BRIX_CRED_EXCHANGE;
        bag3.krb5_ccache       = cc;
        bag3.krb5_origin_princ = spn;
        memset(&cred, 0, sizeof(cred));
        use_cred = 1; err = 0;
        reset_metrics();
        rc = brix_vfs_deleg_live_cred(&ctx, &cred, &use_cred, &err);
        assert(rc == NGX_ERROR && use_cred == 0 && err == EACCES);
        assert(cred.krb5_ccache == NULL);
        assert(last_fail_reason == (int) BRIX_CRED_FAIL_KIND);

        /* 17. brix_vfs_deleg_set_krb5: allocates the bag when none is bound (the
         *     krb5-only capture path); SELECT mode and empty strings stay no-ops. */
        accept_mask = BRIX_SD_CRED_GSS_KRB5;
        memset(&ctx, 0, sizeof(ctx));
        ctx.pool = (ngx_pool_t *) &ctx;
        brix_vfs_deleg_set_krb5(NULL, BRIX_CRED_EXCHANGE, &cc, &spn);
        brix_vfs_deleg_set_krb5(&ctx, BRIX_CRED_SELECT, &cc, &spn);
        assert(ctx.deleg_live == NULL);
        {
            ngx_str_t empty = ngx_null_string;
            brix_vfs_deleg_set_krb5(&ctx, BRIX_CRED_EXCHANGE, &empty, &spn);
            assert(ctx.deleg_live == NULL);
            brix_vfs_deleg_set_krb5(&ctx, BRIX_CRED_EXCHANGE, &cc, &empty);
            assert(ctx.deleg_live == NULL);
        }
        brix_vfs_deleg_set_krb5(&ctx, BRIX_CRED_EXCHANGE, &cc, &spn);
        assert(ctx.deleg_live != NULL);
        assert(ctx.deleg_live->mode == BRIX_CRED_EXCHANGE);
        assert(ctx.deleg_live->krb5_ccache.data == cc.data);
        assert(ctx.deleg_live->krb5_origin_princ.data == spn.data);
        free(ctx.deleg_live);
        accept_mask =
            BRIX_SD_CRED_BEARER | BRIX_SD_CRED_PROXY_PEM | BRIX_SD_CRED_SSS;
    }

    X509_STORE_free(store);
    free(good);
    free(rogue);
    free(garbage);
    printf("deleg_gate_test: all checks passed\n");
    return 0;
}
