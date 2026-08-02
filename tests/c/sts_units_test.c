/* Unit test for the S3 STS exchange seam (phase-70 §5.5 origin leg):
 * the non-static functions declared in src/auth/s3/sts_internal.h —
 *   - sts_parse_response()  (sts_http.c)  XML → temporary-credential triple
 *   - sts_build_action_qs() (sts_sign.c)  canonical AssumeRole/GetSessionToken query
 *   - sts_sign_query()      (sts_sign.c)  SigV4 signature append
 *
 * Links the REAL sts_http.o + sts_sign.o + crypto.o + sigv4.o and the real
 * ngx_snprintf (ngx_string.o) — the signer's canonical string is byte-sensitive,
 * so we exercise the production formatter, not a re-implementation. Response
 * bodies are canned XML and every input is fixed, so there is no network and no
 * wall clock (sidesteps the WSL2 clock-backwards issue).
 *
 * Ritual: success (well-formed AssumeRole/GetSessionToken parse + build + a
 * stable 64-hex signature) + error (unparseable body, missing/empty secret,
 * over-tight output buffers all fail closed) + security-negative (a body that
 * omits the secret NEVER leaves a partial secret in the caller's buffer, and an
 * oversized secret field is truncated within bounds — no overflow). */

#include <ngx_config.h>
#include <ngx_core.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth/s3/sts_internal.h"   /* sts_req_t, sts_creds_buf_t, seam fns */
#include "core/compat/crypto.h"     /* brix_crypto_init: prefetch the EVP_MD */

/* ---- nginx surface stubs -------------------------------------------------- */

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
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) log;
    return malloc(size);
}

volatile ngx_cycle_t  *ngx_cycle;   /* ngx_string.o references it; unused here */

/* A zeroed log: log_level 0 < NGX_LOG_ERR, so every ngx_log_error() the parser
 * runs on a fault short-circuits before dereferencing anything real. */
static ngx_log_t  log_ = { 0 };

/* ---- fixtures ------------------------------------------------------------- */

#define CREDS_XML(AK, SK, EXTRA)                                              \
    "<AssumeRoleResponse><AssumeRoleResult><Credentials>"                    \
    "<AccessKeyId>" AK "</AccessKeyId>"                                       \
    "<SecretAccessKey>" SK "</SecretAccessKey>" EXTRA                         \
    "</Credentials></AssumeRoleResult></AssumeRoleResponse>"

static void
init_creds(sts_creds_buf_t *c, char *ak, size_t aksz, char *sk, size_t sksz,
    char *sess, size_t sesssz)
{
    c->ak = ak; c->aksz = aksz;
    c->sk = sk; c->sksz = sksz;
    c->session = sess; c->sesssz = sesssz;
}

/* ---- parser: success ------------------------------------------------------ */

static void
test_parse_full(void)
{
    char ak[128], sk[256], sess[512];
    sts_creds_buf_t c;
    const char *xml = CREDS_XML("AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "<SessionToken>FQoGZXIvYXdzEExampleSessionTokenABC123</SessionToken>");

    init_creds(&c, ak, sizeof ak, sk, sizeof sk, sess, sizeof sess);
    assert(sts_parse_response((const u_char *) xml, strlen(xml), &c, &log_)
           == NGX_OK);
    assert(strcmp(ak, "AKIAIOSFODNN7EXAMPLE") == 0);
    assert(strcmp(sk, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") == 0);
    assert(strcmp(sess, "FQoGZXIvYXdzEExampleSessionTokenABC123") == 0);
}

static void
test_parse_no_session(void)
{
    char ak[128], sk[256], sess[512];
    sts_creds_buf_t c;
    /* AK + SK present, SessionToken absent — session is optional (NGX_OK). */
    const char *xml = CREDS_XML("AKIAEXAMPLE2", "secretvalue2", "");

    init_creds(&c, ak, sizeof ak, sk, sizeof sk, sess, sizeof sess);
    assert(sts_parse_response((const u_char *) xml, strlen(xml), &c, &log_)
           == NGX_OK);
    assert(strcmp(ak, "AKIAEXAMPLE2") == 0);
    assert(strcmp(sk, "secretvalue2") == 0);
    assert(sess[0] == '\0');
}

/* ---- parser: error + security-negative ------------------------------------ */

static void
test_parse_missing_secret(void)
{
    char ak[128], sk[256], sess[512];
    sts_creds_buf_t c;
    /* AccessKeyId only — no SecretAccessKey element. */
    const char *xml =
        "<AssumeRoleResponse><AssumeRoleResult><Credentials>"
        "<AccessKeyId>AKIAEXAMPLE3</AccessKeyId>"
        "</Credentials></AssumeRoleResult></AssumeRoleResponse>";

    init_creds(&c, ak, sizeof ak, sk, sizeof sk, sess, sizeof sess);
    assert(sts_parse_response((const u_char *) xml, strlen(xml), &c, &log_)
           == NGX_ERROR);
    /* Security: the fail path must never leave a partial secret behind. */
    assert(sk[0] == '\0');
    assert(sess[0] == '\0');
}

static void
test_parse_empty_access_key(void)
{
    char ak[128], sk[256], sess[512];
    sts_creds_buf_t c;
    /* Present but empty AccessKeyId value — must be rejected, not accepted. */
    const char *xml = CREDS_XML("", "secretvalue4", "");

    init_creds(&c, ak, sizeof ak, sk, sizeof sk, sess, sizeof sess);
    assert(sts_parse_response((const u_char *) xml, strlen(xml), &c, &log_)
           == NGX_ERROR);
}

static void
test_parse_garbage(void)
{
    char ak[128], sk[256], sess[512];
    sts_creds_buf_t c;
    const char *body = "this is not xml at all { <<< >>>";

    init_creds(&c, ak, sizeof ak, sk, sizeof sk, sess, sizeof sess);
    assert(sts_parse_response((const u_char *) body, strlen(body), &c, &log_)
           == NGX_ERROR);
    assert(ak[0] == '\0' && sk[0] == '\0' && sess[0] == '\0');
}

static void
test_parse_oversized_secret_bounded(void)
{
    /* A canary immediately after a deliberately tiny secret buffer: a secret
     * field far longer than sk[8] must be truncated INTO the buffer, never
     * written past it. (ngx_snprintf bounds the copy at outsz; it does not
     * over-run — production buffers are large, so this only ever exercises the
     * bound.) */
    struct { char sk[8]; char canary; } g;
    char ak[128], sess[512];
    sts_creds_buf_t c;
    const char *xml = CREDS_XML("AKIAEXAMPLE5",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "");

    g.canary = 0x7e;
    init_creds(&c, ak, sizeof ak, g.sk, sizeof g.sk, sess, sizeof sess);
    /* AK + SK both non-empty → NGX_OK, but the write stayed within sk[8]. */
    assert(sts_parse_response((const u_char *) xml, strlen(xml), &c, &log_)
           == NGX_OK);
    assert(g.canary == 0x7e);   /* no overflow past the secret buffer */
}

/* ---- signer: request building --------------------------------------------- */

static void
fill_req(sts_req_t *req, brix_s3_sts_conf_t *cf)
{
    memset(req, 0, sizeof *req);
    memset(cf, 0, sizeof *cf);
    ngx_str_set(&cf->region, "us-east-1");
    ngx_str_set(&cf->role_arn, "arn:aws:iam::123456789012:role/BrixTest");
    ngx_str_set(&cf->svc_ak, "AKIDEXAMPLE");
    ngx_str_set(&cf->svc_sk, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    req->cf = cf;
    req->host = "sts.amazonaws.com";
    memcpy(req->amzdate, "20260728T000000Z", sizeof "20260728T000000Z");
    memcpy(req->datestamp, "20260728", sizeof "20260728");
    memcpy(req->rsn, "alice", sizeof "alice");
    memcpy(req->credential,
        "AKIDEXAMPLE%2F20260728%2Fus-east-1%2Fsts%2Faws4_request",
        sizeof "AKIDEXAMPLE%2F20260728%2Fus-east-1%2Fsts%2Faws4_request");
    req->ttl = 3600;
}

static void
test_build_assume_role(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf; char qs[2048];

    fill_req(&req, &cf);
    assert(sts_build_action_qs(&req, qs, sizeof qs) == NGX_OK);
    assert(strstr(qs, "Action=AssumeRole") != NULL);
    assert(strstr(qs, "DurationSeconds=3600") != NULL);
    assert(strstr(qs, "RoleArn=arn:aws:iam::123456789012:role/BrixTest")
           != NULL);
    assert(strstr(qs, "RoleSessionName=alice") != NULL);
    assert(strstr(qs, "Version=2011-06-15") != NULL);
}

static void
test_build_get_session_token(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf; char qs[2048];

    fill_req(&req, &cf);
    cf.role_arn.len = 0;   /* no role ARN → GetSessionToken variant */
    assert(sts_build_action_qs(&req, qs, sizeof qs) == NGX_OK);
    assert(strstr(qs, "Action=GetSessionToken") != NULL);
    assert(strstr(qs, "RoleArn=") == NULL);
    assert(strstr(qs, "RoleSessionName=") == NULL);
}

static void
test_build_overflow(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf; char tiny[16];

    fill_req(&req, &cf);
    assert(sts_build_action_qs(&req, tiny, sizeof tiny) == NGX_ERROR);
}

/* ---- signer: SigV4 signature ---------------------------------------------- */

static void
test_sign_query_deterministic(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf;
    char qs[2048], signed_a[4096], signed_b[4096];
    const char *sig;

    fill_req(&req, &cf);
    assert(sts_build_action_qs(&req, qs, sizeof qs) == NGX_OK);

    assert(sts_sign_query(&req, qs, signed_a, sizeof signed_a) == NGX_OK);
    sig = strstr(signed_a, "&X-Amz-Signature=");
    assert(sig != NULL);
    sig += sizeof("&X-Amz-Signature=") - 1;
    assert(strlen(sig) == 64);          /* SHA-256 HMAC → 64 lowercase hex */
    for (const char *p = sig; *p; p++) {
        assert((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'));
    }

    /* Identical inputs → identical signature: proves the signer is a pure,
     * reproducible function of (config, identity, timestamp). */
    assert(sts_sign_query(&req, qs, signed_b, sizeof signed_b) == NGX_OK);
    assert(strcmp(signed_a, signed_b) == 0);
}

static void
test_sign_overflow(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf;
    char qs[2048], tiny[16];

    fill_req(&req, &cf);
    assert(sts_build_action_qs(&req, qs, sizeof qs) == NGX_OK);
    assert(sts_sign_query(&req, qs, tiny, sizeof tiny) == NGX_ERROR);
}

/* ---- MinIO dialect: header-auth POST builder (phase-70 §5.5) --------------- */

static int
is_hex64(const char *s)
{
    if (strlen(s) != 64) { return 0; }
    for (const char *p = s; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static void
test_build_post_minio(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf; sts_post_t pd;

    fill_req(&req, &cf);
    memset(&pd, 0, sizeof pd);
    assert(sts_build_post(&req, &pd) == NGX_OK);

    /* Body: MinIO always AssumeRole, form-encoded, versioned. */
    assert(strstr(pd.body, "Action=AssumeRole") != NULL);
    assert(strstr(pd.body, "DurationSeconds=3600") != NULL);
    assert(strstr(pd.body, "RoleSessionName=alice") != NULL);
    assert(strstr(pd.body, "Version=2011-06-15") != NULL);
    /* The role ARN's ':' and '/' are form delimiters — must be percent-encoded
     * in the body (the signature is over these raw bytes). */
    assert(strstr(pd.body, "RoleArn=arn%3Aaws%3Aiam%3A%3A") != NULL);
    assert(strstr(pd.body, "RoleArn=arn:aws") == NULL);

    /* x-amz-content-sha256 is the lowercase-hex SHA-256 of the body. */
    assert(is_hex64(pd.content_sha256));

    /* amzdate is copied from the request (it is a signed header). */
    assert(strcmp(pd.amzdate, "20260728T000000Z") == 0);

    /* Authorization: header-auth SigV4 over the "sts" service, literal-'/'
     * scope, the exact four signed headers, and a 64-hex signature. */
    assert(strncmp(pd.authorization, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/",
        sizeof("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") - 1) == 0);
    assert(strstr(pd.authorization, "/20260728/us-east-1/sts/aws4_request")
           != NULL);
    assert(strstr(pd.authorization,
        "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
           != NULL);
    const char *sig = strstr(pd.authorization, "Signature=");
    assert(sig != NULL);
    assert(is_hex64(sig + sizeof("Signature=") - 1));
}

static void
test_build_post_no_role(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf; sts_post_t pd;

    fill_req(&req, &cf);
    cf.role_arn.len = 0;   /* MinIO: no ARN still AssumeRole (inherits policy) */
    memset(&pd, 0, sizeof pd);
    assert(sts_build_post(&req, &pd) == NGX_OK);
    assert(strstr(pd.body, "Action=AssumeRole") != NULL);
    assert(strstr(pd.body, "RoleArn=") == NULL);
    assert(strstr(pd.body, "RoleSessionName=alice") != NULL);
    assert(is_hex64(pd.content_sha256));
}

static void
test_build_post_deterministic(void)
{
    sts_req_t req; brix_s3_sts_conf_t cf; sts_post_t a, b;

    fill_req(&req, &cf);
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    assert(sts_build_post(&req, &a) == NGX_OK);
    assert(sts_build_post(&req, &b) == NGX_OK);
    /* Pure function of (config, identity, timestamp): identical bytes out. */
    assert(strcmp(a.body, b.body) == 0);
    assert(strcmp(a.content_sha256, b.content_sha256) == 0);
    assert(strcmp(a.authorization, b.authorization) == 0);
}

int
main(void)
{
    /* Production calls this once at process init; brix_sha256/HMAC fail closed
     * without the prefetched EVP_MD, which would break the signer. */
    assert(brix_crypto_init() == 1);

    test_parse_full();
    test_parse_no_session();
    test_parse_missing_secret();
    test_parse_empty_access_key();
    test_parse_garbage();
    test_parse_oversized_secret_bounded();

    test_build_assume_role();
    test_build_get_session_token();
    test_build_overflow();

    test_sign_query_deterministic();
    test_sign_overflow();

    test_build_post_minio();
    test_build_post_no_role();
    test_build_post_deterministic();

    printf("sts_units: all assertions passed\n");
    return 0;
}
