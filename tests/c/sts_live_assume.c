/* Live harness for the S3 STS origin leg (phase-70 §5.5), MinIO dialect.
 *
 * Calls the REAL brix_s3_sts_assume() with flavor=MINIO against a live STS
 * endpoint and prints the temporary credential triple, so a pytest can then
 * drive a token-signed S3 GET with those creds and prove MinIO accepted our
 * exact on-the-wire bytes (POST + form body + header-auth SigV4 AssumeRole).
 *
 * Unlike sts_units_test.c (offline, canned), this exercises the transport
 * (sts_http.o) end-to-end over a real socket — it is invoked only by the live
 * pytest, which owns the MinIO lifecycle and skips when Docker is unavailable.
 *
 * Usage:  sts_live_assume <endpoint> <access_key> <secret_key> <region> [role_arn]
 * Output: on success, three lines "<ak>\n<sk>\n<session>" to stdout, exit 0.
 *         on failure, "ERR\n" to stdout, exit 1. Secrets appear on stdout by
 *         design (the test needs them); nothing is logged.
 */
#include <ngx_config.h>
#include <ngx_core.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auth/s3/sts.h"
#include "core/compat/crypto.h"

/* ---- nginx surface stubs (pool → malloc, as the offline STS unit does) ---- */

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

volatile ngx_cycle_t  *ngx_cycle;

int
main(int argc, char **argv)
{
    brix_s3_sts_conf_t cf;
    brix_identity_t    id;
    brix_s3_sts_out_t  out;
    ngx_str_t          ak = ngx_null_string;
    ngx_str_t          sk = ngx_null_string;
    ngx_str_t          session = ngx_null_string;
    ngx_log_t          log_ = { 0 };
    /* A non-NULL sentinel: sts_validate() rejects a NULL pool, and the pool-alloc
     * stubs above ignore the pointer's target (they malloc), so any non-NULL
     * address satisfies the guard without a real nginx pool. */
    ngx_pool_t        *pool = (ngx_pool_t *) &log_;

    if (argc < 5) {
        fprintf(stderr, "usage: %s <endpoint> <ak> <sk> <region> [role]\n",
            argv[0]);
        return 2;
    }
    if (brix_crypto_init() != 1) {
        printf("ERR\n");
        return 1;
    }

    memset(&cf, 0, sizeof cf);
    cf.endpoint.data = (u_char *) argv[1];
    cf.endpoint.len  = ngx_strlen(argv[1]);
    cf.svc_ak.data   = (u_char *) argv[2];
    cf.svc_ak.len    = ngx_strlen(argv[2]);
    cf.svc_sk.data   = (u_char *) argv[3];
    cf.svc_sk.len    = ngx_strlen(argv[3]);
    cf.region.data   = (u_char *) argv[4];
    cf.region.len    = ngx_strlen(argv[4]);
    if (argc >= 6) {
        cf.role_arn.data = (u_char *) argv[5];
        cf.role_arn.len  = ngx_strlen(argv[5]);
    }
    cf.ttl_secs = 3600;
    cf.flavor   = BRIX_STS_FLAVOR_MINIO;

    memset(&id, 0, sizeof id);
    ngx_str_set(&id.subject, "brix-live-tester");

    out.ak = &ak;
    out.sk = &sk;
    out.session = &session;

    if (brix_s3_sts_assume(pool, &id, &cf, &out, &log_) != NGX_OK) {
        printf("ERR\n");
        return 1;
    }

    printf("%.*s\n%.*s\n%.*s\n",
        (int) ak.len, ak.data,
        (int) sk.len, sk.data,
        (int) session.len, session.data);
    return 0;
}
