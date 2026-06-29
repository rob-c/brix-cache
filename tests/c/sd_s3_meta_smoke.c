/*
 * sd_s3_meta_smoke.c — live smoke test for the shared sd_s3 driver's object
 * metadata surface (get_meta / set_meta / advisory unix-attr). Runs against a
 * live S3 endpoint (the module's own anonymous S3 server in the wrapper).
 *
 * Usage: sd_s3_meta_smoke <host> <port> </bucket/key>
 * The wrapper pre-PUTs the object with x-amz-meta-foo: bar.
 */
#include "fs/backend/s3/sd_s3.h"
#include "compat/crypto.h"   /* xrootd_crypto_init — fetch the HMAC/SHA handles */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The client-side HTTP transport for the shared S3 driver (libxrdc.a). */
extern const xrootd_s3_transport_t xrdc_s3_http_transport;

static int fails = 0;
static void check(int cond, const char *msg)
{
    printf(cond ? "  ok   %s\n" : "  FAIL %s\n", msg);
    if (!cond) {
        fails = 1;
    }
}

int
main(int argc, char **argv)
{
    char                   eb[256];
    sd_s3_open_params      p;
    sd_s3_file            *f;
    char                   val[256];
    ssize_t                n;
    int                    rc;
    sd_s3_meta_kv          kv;
    xrootd_meta_advisory_t a, got;

    if (argc != 4) {
        fprintf(stderr, "usage: %s <host> <port> </bucket/key>\n", argv[0]);
        return 2;
    }
    /* Standalone consumer: fetch the OpenSSL HMAC/SHA handles SigV4 needs (the
     * module/client do this in their worker init). */
    if (!xrootd_crypto_init()) {
        fprintf(stderr, "crypto init failed\n");
        return 2;
    }

    memset(&p, 0, sizeof(p));
    p.host       = argv[1];
    p.port       = atoi(argv[2]);
    p.tls        = 0;
    p.key        = argv[3];
    p.ak         = "anon";          /* anonymous server ignores the signature */
    p.sk         = "anonsecret";
    p.region     = "us-east-1";
    p.transport  = &xrdc_s3_http_transport;
    p.tctx       = NULL;
    p.timeout_ms = 10000;

    /* 1. get_meta reads what the server stored (wrapper PUT x-amz-meta-foo: bar). */
    f = sd_s3_open_read(&p, eb, sizeof(eb));
    if (f == NULL) {
        fprintf(stderr, "open_read failed: %s\n", eb);
        return 2;
    }
    n = sd_s3_get_meta(f, "foo", val, sizeof(val), eb, sizeof(eb));
    check(n == 3 && strcmp(val, "bar") == 0,
          "get_meta reads server-stored x-amz-meta-foo=bar");
    n = sd_s3_get_meta(f, "absent", val, sizeof(val), eb, sizeof(eb));
    check(n == 0, "get_meta returns 0 for an absent attribute");
    sd_s3_close(f);

    /* 2. set_meta (copy-self REPLACE + SigV4 over the meta headers) changes it. */
    kv.name  = "foo";
    kv.value = "baz";
    rc = sd_s3_set_meta(&p, &kv, 1, eb, sizeof(eb));
    check(rc == 0, "set_meta (copy-self REPLACE) succeeds");
    if (rc != 0) {
        fprintf(stderr, "  set_meta: %s\n", eb);
    }
    f = sd_s3_open_read(&p, eb, sizeof(eb));
    n = sd_s3_get_meta(f, "foo", val, sizeof(val), eb, sizeof(eb));
    check(n == 3 && strcmp(val, "baz") == 0,
          "get_meta reflects the set_meta change (foo=baz)");
    sd_s3_close(f);

    /* 3. advisory unix-attrs (mode/uid/gid) round-trip through x-amz-meta-xrd-unixattr.
     *    Note: set replaces the user-metadata set (S3 semantics), so foo is gone. */
    memset(&a, 0, sizeof(a));
    a.mode = 0640; a.have_mode = 1;
    a.uid = 1000; a.gid = 2000; a.have_owner = 1;
    rc = sd_s3_set_unixattr(&p, &a, eb, sizeof(eb));
    check(rc == 0, "set_unixattr (advisory mode/uid/gid) succeeds");
    if (rc != 0) {
        fprintf(stderr, "  set_unixattr: %s\n", eb);
    }
    f = sd_s3_open_read(&p, eb, sizeof(eb));
    memset(&got, 0, sizeof(got));
    rc = sd_s3_get_unixattr(f, &got, eb, sizeof(eb));
    check(rc == 1 && got.have_mode && (got.mode & 07777) == 0640
          && got.have_owner && got.uid == 1000 && got.gid == 2000,
          "get_unixattr round-trips mode=0640 uid=1000 gid=2000");
    sd_s3_close(f);

    printf(fails ? "sd_s3_meta_smoke: FAILURES\n"
                 : "sd_s3_meta_smoke: ALL PASS\n");
    return fails;
}
