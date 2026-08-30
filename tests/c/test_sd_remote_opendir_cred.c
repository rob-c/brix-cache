/* test_sd_remote_opendir_cred.c — unit test for the credential-scoped directory
 * listing on the remote-origin (s3://) driver: opendir_cred (sd_remote_dir.c).
 *
 * The driver already signed every object op and every namespace op — open,
 * staged_open, stat, unlink, mkdir, rename, and (since the metadata-read fix)
 * getxattr/listxattr — with the requesting user's SigV4 keys. opendir had no
 * *_cred sibling, so brix_sd_opendir_maybe_cred fell through to the plain slot
 * and ran ListObjectsV2 AS THE EXPORT: a user whose own keys are scoped to one
 * prefix saw the whole bucket, and the entries looked entirely normal.
 *
 * Two things make this slot different from the read slots:
 *
 *   - opendir performs NO I/O. It only derives the key prefix; the first
 *     ListObjectsV2 request is issued lazily from readdir, and continuation
 *     pages later still. The credential therefore has to be COPIED onto the
 *     handle — brix_sd_cred_t is borrowed only for the duration of the opendir
 *     call. Test 1 frees the credential strings AND scribbles over the struct
 *     between opendir and the first readdir, so a driver that kept the pointer
 *     would read freed memory rather than quietly pass.
 *   - the STS session token has no small bound, so an over-long one is REFUSED
 *     (E2BIG) rather than truncated: a clipped token signs a request the store
 *     rejects with an opaque SignatureDoesNotMatch pages into the listing.
 *
 * The signing identity is observable — SigV4 puts the access key id in
 * `Authorization: ... Credential=<AK>/<date>/...` — so every assertion here is
 * about WHICH KEY SIGNED THE LIST, never merely about the entries returned.
 *
 * Coverage: the user's key signs both pages of a paged listing and the entries
 * surface (success); an over-long session token and a NULL/no-S3 credential
 * (error); a fallback_deny credential this backend cannot use refused with
 * EACCES before any wire I/O, on a half-credential too, with the service key
 * proven absent from the wire (security-neg).
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_opendir_cred`.
 */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/sd_cred_types.h"    /* brix_sd_cred_t */
#include "core/compat/crypto.h"          /* brix_crypto_init: SigV4 sign path */

#define SERVICE_AK  "SERVICE-AK-STATIC"
#define USER_AK     "USER-AK-ALICE"

/* ---- scripted fake transport -------------------------------------------- */

static int  g_get_calls = 0;
static char g_last_path[512];
static char g_ak[4][128];                /* signing key id, per request */

static const char BODY_PAGE1[] =
    "<ListBucketResult><IsTruncated>true</IsTruncated>"
    "<NextContinuationToken>TOKEN123</NextContinuationToken>"
    "<Contents><Key>sub/p1.txt</Key></Contents></ListBucketResult>";

static const char BODY_PAGE2[] =
    "<ListBucketResult><IsTruncated>false</IsTruncated>"
    "<Contents><Key>sub/p2.txt</Key></Contents>"
    "<CommonPrefixes><Prefix>sub/d1/</Prefix></CommonPrefixes>"
    "</ListBucketResult>";

static const char *g_cur_body = NULL;
static size_t      g_cur_len  = 0;

static void
reset_capture(void)
{
    int i;

    g_get_calls  = 0;
    g_last_path[0] = '\0';
    for (i = 0; i < 4; i++) {
        g_ak[i][0] = '\0';
    }
}

/* Lift the access key id out of the SigV4 Authorization line:
 * "...Credential=<AK>/<yyyymmdd>/<region>/s3/aws4_request,...". Leaves the slot
 * empty when the request carried no credential scope at all. */
static void
capture_signing_ak(const char *headers, char *out, size_t cap)
{
    static const char tag[] = "Credential=";
    const char       *p = (headers != NULL) ? strstr(headers, tag) : NULL;
    size_t            n;

    out[0] = '\0';
    if (p == NULL) {
        return;
    }
    p += sizeof(tag) - 1;
    n = strcspn(p, "/");
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(out, p, n);
    out[n] = '\0';
}

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls;
    (void) body; (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    assert(strcmp(method, "GET") == 0);   /* listing is a GET on the bucket root */
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    if (g_get_calls < 4) {
        capture_signing_ak(headers, g_ak[g_get_calls], sizeof(g_ak[0]));
    }
    g_get_calls++;

    resp->opaque = NULL;
    resp->status = 200;
    g_cur_body = (g_get_calls == 1) ? BODY_PAGE1 : BODY_PAGE2;
    g_cur_len  = strlen(g_cur_body);
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp; (void) name; (void) out; (void) outcap;
    return -1;
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (len != NULL) { *len = g_cur_len; }
    return g_cur_body;
}

static void
fake_resp_free(brix_s3_resp_t *resp)
{
    (void) resp;
}

static const brix_s3_transport_t g_fake_transport = {
    .request     = fake_request,
    .resp_header = fake_resp_header,
    .resp_body   = fake_resp_body,
    .resp_free   = fake_resp_free,
};

static brix_sd_instance_t *
build_instance(void)
{
    brix_sd_remote_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.scheme = BRIX_SD_REMOTE_S3;
    snprintf(cfg.host, sizeof(cfg.host), "127.0.0.1");
    cfg.port = 9999;
    cfg.tls  = 0;
    snprintf(cfg.bucket, sizeof(cfg.bucket), "test-bucket");
    snprintf(cfg.access_key, sizeof(cfg.access_key), SERVICE_AK);
    snprintf(cfg.secret_key, sizeof(cfg.secret_key), "SERVICE-SK-STATIC");
    snprintf(cfg.region, sizeof(cfg.region), "us-east-1");
    cfg.timeout_ms = 2000;
    cfg.transport  = &g_fake_transport;
    cfg.tctx       = NULL;

    return brix_sd_remote_create(&cfg, NULL);
}

/* Drain a dir into caller arrays; returns the entry count and the terminal rc. */
static size_t
drain(brix_sd_dir_t *d, char names[][256], size_t cap, ngx_int_t *term_rc)
{
    size_t           n = 0;
    brix_sd_dirent_t e;
    ngx_int_t        rc;

    for ( ;; ) {
        rc = d->inst->driver->readdir(d, &e);
        if (rc != NGX_OK) {
            break;
        }
        assert(n < cap);
        snprintf(names[n], 256, "%s", e.name);
        n++;
    }
    *term_rc = rc;
    return n;
}

static int
has_name(char names[][256], size_t n, const char *want)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (strcmp(names[i], want) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ---- success ------------------------------------------------------------- */

/* Test 1: every page of a cred-scoped listing signs with the USER's key, and it
 * keeps doing so after the caller's credential is gone — the strings are freed
 * and the struct scribbled over between opendir and the first readdir, which is
 * exactly the window a borrowed-pointer implementation would fall into. */
static void
test_opendir_cred_signs_every_page_as_user(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    brix_sd_dir_t      *d;
    char                names[16][256];
    ngx_int_t           term = NGX_OK;
    int                 err = 0;
    size_t              n;
    char               *ak, *sk, *region;

    assert(inst != NULL);
    assert(inst->driver->opendir_cred != NULL);   /* the slot exists at all */

    ak     = strdup(USER_AK);
    sk     = strdup("USER-SK-ALICE");
    region = strdup("us-east-1");
    assert(ak != NULL && sk != NULL && region != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.s3_ak     = ak;
    cred.s3_sk     = sk;
    cred.s3_region = region;

    reset_capture();
    d = inst->driver->opendir_cred(inst, "/sub", &err, &cred);
    assert(d != NULL);
    assert(g_get_calls == 0);            /* opendir is lazy: no I/O yet */

    /* The credential's lifetime ends here, before a single byte is listed. */
    memset(ak, 'X', strlen(ak));
    memset(sk, 'X', strlen(sk));
    free(ak);
    free(sk);
    free(region);
    memset(&cred, 0xAA, sizeof(cred));

    n = drain(d, names, 16, &term);

    assert(term == NGX_DONE);
    assert(g_get_calls == 2);                          /* both pages fetched */
    assert(n == 3);
    assert(has_name(names, n, "p1.txt"));
    assert(has_name(names, n, "p2.txt"));
    assert(has_name(names, n, "d1"));
    assert(strstr(g_last_path, "continuation-token=TOKEN123") != NULL);
    /* the point of the slot: neither page was signed by the export */
    assert(strcmp(g_ak[0], USER_AK) == 0);
    assert(strcmp(g_ak[1], USER_AK) == 0);

    inst->driver->closedir(d);
    printf("  ok   1: cred listing -> both pages signed as the user, credential "
           "freed before the first page\n");
    brix_sd_remote_destroy(inst);
}

/* Test 2: the no-credential paths are unchanged — a NULL cred through the cred
 * slot, and the plain slot, both still sign with the export's service key. */
static void
test_no_cred_still_signs_as_export(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    char                names[16][256];
    ngx_int_t           term = NGX_OK;
    int                 err = 0;

    assert(inst != NULL);

    reset_capture();
    d = inst->driver->opendir_cred(inst, "/sub", &err, NULL);
    assert(d != NULL);
    (void) drain(d, names, 16, &term);
    assert(term == NGX_DONE);
    assert(strcmp(g_ak[0], SERVICE_AK) == 0);
    inst->driver->closedir(d);

    reset_capture();
    d = inst->driver->opendir(inst, "/sub", &err);
    assert(d != NULL);
    (void) drain(d, names, 16, &term);
    assert(term == NGX_DONE);
    assert(strcmp(g_ak[0], SERVICE_AK) == 0);
    inst->driver->closedir(d);

    printf("  ok   2: NULL cred and the plain slot -> service key, unchanged\n");
    brix_sd_remote_destroy(inst);
}

/* ---- error --------------------------------------------------------------- */

/* Test 3: an over-long session token is refused at opendir (E2BIG), not clipped
 * — a truncated token would surface as an opaque signature failure a page in.
 * A credential carrying no S3 material at all, with fallback_deny unset, still
 * lists under the service key (the documented fallback), and an over-long path
 * is still ENAMETOOLONG through the cred slot. */
static void
test_error_contract(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    brix_sd_dir_t      *d;
    char                names[16][256];
    ngx_int_t           term = NGX_OK;
    char                longpath[1200];
    char               *big;
    int                 err;

    assert(inst != NULL);

    big = malloc(8192);
    assert(big != NULL);
    memset(big, 's', 8191);
    big[8191] = '\0';

    memset(&cred, 0, sizeof(cred));
    cred.s3_ak      = USER_AK;
    cred.s3_sk      = "USER-SK-ALICE";
    cred.s3_region  = "us-east-1";
    cred.s3_session = big;

    reset_capture();
    err = 0;
    d = inst->driver->opendir_cred(inst, "/sub", &err, &cred);
    assert(d == NULL);
    assert(err == E2BIG);                  /* refused, never truncated */
    assert(g_get_calls == 0);              /* and refused before any wire I/O */
    free(big);

    /* No S3 material, deny not set -> the documented service-key fallback. */
    memset(&cred, 0, sizeof(cred));
    cred.bearer = "eyJhbGciOi.stub.token";
    reset_capture();
    err = 0;
    d = inst->driver->opendir_cred(inst, "/sub", &err, &cred);
    assert(d != NULL);
    (void) drain(d, names, 16, &term);
    assert(term == NGX_DONE);
    assert(strcmp(g_ak[0], SERVICE_AK) == 0);
    inst->driver->closedir(d);

    /* A path that cannot become a key prefix is refused the same either way. */
    memset(longpath, 'a', sizeof(longpath) - 1);
    longpath[0] = '/';
    longpath[sizeof(longpath) - 1] = '\0';
    memset(&cred, 0, sizeof(cred));
    cred.s3_ak = USER_AK;
    cred.s3_sk = "USER-SK-ALICE";
    reset_capture();
    err = 0;
    d = inst->driver->opendir_cred(inst, longpath, &err, &cred);
    assert(d == NULL);
    assert(err == ENAMETOOLONG);
    assert(g_get_calls == 0);

    printf("  ok   3: over-long session token -> E2BIG (not truncated); no-S3 "
           "cred -> service fallback; long path -> ENAMETOOLONG\n");
    brix_sd_remote_destroy(inst);
}

/* ---- security-negative --------------------------------------------------- */

/* Test 4: under fallback_deny a credential this S3-only backend cannot use must
 * be REFUSED, never quietly listed with the export's shared key — including a
 * half credential (an access key with no secret). Nothing may reach the wire,
 * and in particular the service key must never appear on it. */
static void
test_cred_deny_refuses_listing(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    brix_sd_dir_t      *d;
    char                names[16][256];
    ngx_int_t           term = NGX_OK;
    int                 err;

    assert(inst != NULL);

    /* bearer-only + deny */
    memset(&cred, 0, sizeof(cred));
    cred.bearer        = "eyJhbGciOi.stub.token";
    cred.fallback_deny = 1;
    reset_capture();
    err = 0;
    d = inst->driver->opendir_cred(inst, "/sub", &err, &cred);
    assert(d == NULL);
    assert(err == EACCES);
    assert(g_get_calls == 0);
    assert(g_ak[0][0] == '\0');            /* the service key never signed */

    /* x509-proxy-only + deny */
    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy    = "/tmp/x509up_u1000";
    cred.fallback_deny = 1;
    reset_capture();
    err = 0;
    d = inst->driver->opendir_cred(inst, "/sub", &err, &cred);
    assert(d == NULL);
    assert(err == EACCES);
    assert(g_get_calls == 0);

    /* HALF a keypair + deny: an access key with no secret cannot sign, so it is
     * refused rather than completed from the export's secret. */
    memset(&cred, 0, sizeof(cred));
    cred.s3_ak         = USER_AK;
    cred.fallback_deny = 1;
    reset_capture();
    err = 0;
    d = inst->driver->opendir_cred(inst, "/sub", &err, &cred);
    assert(d == NULL);
    assert(err == EACCES);
    assert(g_get_calls == 0);

    /* The gate is scoped to the credential path: the plain slot still serves. */
    reset_capture();
    err = 0;
    d = inst->driver->opendir(inst, "/sub", &err);
    assert(d != NULL);
    (void) drain(d, names, 16, &term);
    assert(term == NGX_DONE);
    assert(strcmp(g_ak[0], SERVICE_AK) == 0);
    inst->driver->closedir(d);

    printf("  ok   4: fallback_deny -> EACCES with zero wire I/O (bearer, x509, "
           "half keypair); plain slot unaffected\n");
    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_opendir_cred_signs_every_page_as_user();
    test_no_cred_still_signs_as_export();
    test_error_contract();
    test_cred_deny_refuses_listing();
    printf("test_sd_remote_opendir_cred: ALL PASS\n");
    return 0;
}
