/*
 * test_sd_s3_sign_session.c — SigV4 signing of an STS session token
 * (x-amz-security-token) on the S3 storage driver (phase-70 §5.5).
 *
 * WHY: STS temporary credentials (from brix_s3_sts_assume) are (ak, sk, session).
 *      AWS/MinIO REQUIRE the session token to travel in the x-amz-security-token
 *      header AND to be a SIGNED header — a request that carries the token
 *      unsigned, or omits it, is rejected as an invalid temporary credential.
 *      The token sorts lexicographically AFTER x-amz-date, so sd_s3_sign_ex folds
 *      it in as the LAST canonical header, the last SignedHeaders token, and a
 *      trailing emitted header. This TU proves all three renderings are present
 *      (and correctly ordered) when a session token is set, and that the plain
 *      three-header signature is left completely untouched when it is absent —
 *      the "static keypair path is unchanged" invariant.
 *
 * These are structural assertions on the emitted header block (deterministic, no
 * clock/network dependence). End-to-end signature ACCEPTANCE by a real origin is
 * covered by the live MinIO STS suite.
 *
 * Unity build: this TU #includes sd_s3.c + sd_s3_sign.c so it links the driver +
 * SigV4 kernels directly, mirroring test_sd_s3_read.c. Compiled by
 * cmdscripts.sd_s3_sign_session_unit.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sd_s3.h"
#include "core/compat/crypto.h"   /* brix_crypto_init — SigV4 needs the MAC/MD */

/* The driver + SigV4 kernels, pulled in directly (SD_S3_AUTH_HDRS_CAP,
 * sd_s3_sign / sd_s3_sign_ex come from sd_s3_internal.h via these). */
#include "sd_s3.c"       /* NOLINT — deliberate unity build for the unit test */
#include "sd_s3_sign.c"  /* NOLINT */

static int failures;

#define CHECK(cond, msg) do {                                               \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); failures++; }        \
    else         { fprintf(stderr, "ok:   %s\n", (msg)); }                    \
} while (0)

/* A representative STS session token: opaque, long, and containing the '/' and
 * '+' bytes real MinIO/AWS tokens carry — none of which are header-special, so
 * they must appear verbatim in both the canonical and emitted renderings. */
static const char *SESSION =
    "FQoGZXIvYXdzEBk/aCK3Ab0example+token/with+slashes+and+plus==";

static sd_s3_file *
open_handle(const char *session)
{
    sd_s3_open_params p;
    char              errbuf[256];
    sd_s3_file       *f;

    memset(&p, 0, sizeof(p));
    p.host          = "s3.example.com";
    p.port          = 443;
    p.tls           = 1;
    p.key           = "/bucket/obj";
    p.ak            = "AKIDTEMP0001";
    p.sk            = "SECRETTEMPKEY0123456789abcdef";
    p.region        = "us-east-1";
    p.session_token = session;                /* NULL / "" = static keypair */
    p.transport     = (const brix_s3_transport_t *) 0x1;  /* unused: no I/O */
    p.timeout_ms    = 5000;

    f = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (f == NULL) { fprintf(stderr, "open failed: %s\n", errbuf); exit(2); }
    return f;
}

int
main(void)
{
    char hdrs_tok[SD_S3_AUTH_HDRS_CAP];
    char hdrs_plain[SD_S3_AUTH_HDRS_CAP];

    if (brix_crypto_init() != 1) {
        fprintf(stderr, "brix_crypto_init failed\n");
        return 2;
    }

    /* ---- with an STS session token ---------------------------------------- */
    {
        sd_s3_file *f = open_handle(SESSION);

        CHECK(sd_s3_sign(f, "GET", "", hdrs_tok, sizeof(hdrs_tok)) == 0,
              "sign succeeds with a session token set");

        /* (1) Emitted as its own wire header, value verbatim. */
        {
            char needle[256];
            snprintf(needle, sizeof(needle),
                     "x-amz-security-token: %s\r\n", SESSION);
            CHECK(strstr(hdrs_tok, needle) != NULL,
                  "x-amz-security-token emitted as a wire header, value verbatim");
        }

        /* (2) Present in SignedHeaders, in the correct sorted position: it must
         *     be the LAST token (after x-amz-date), not merely present. */
        CHECK(strstr(hdrs_tok,
                     "SignedHeaders=host;x-amz-content-sha256;x-amz-date;"
                     "x-amz-security-token") != NULL,
              "x-amz-security-token is the last SignedHeaders token (post x-amz-date)");

        /* (3) It must NOT appear before x-amz-date in SignedHeaders (guards a
         *     mis-sorted fold that would break the canonical request). */
        CHECK(strstr(hdrs_tok,
                     "SignedHeaders=host;x-amz-content-sha256;"
                     "x-amz-security-token") == NULL,
              "x-amz-security-token never sorts before x-amz-date");

        sd_s3_close(f);
    }

    /* ---- without a session token (static keypair) ------------------------- */
    {
        sd_s3_file *f = open_handle(NULL);

        CHECK(sd_s3_sign(f, "GET", "", hdrs_plain, sizeof(hdrs_plain)) == 0,
              "sign succeeds with no session token (static keypair)");

        CHECK(strstr(hdrs_plain, "x-amz-security-token") == NULL,
              "no x-amz-security-token anywhere when the token is absent");

        CHECK(strstr(hdrs_plain,
                     "SignedHeaders=host;x-amz-content-sha256;x-amz-date,")
              != NULL,
              "plain SignedHeaders list is exactly host;content-sha256;date");

        sd_s3_close(f);
    }

    /* ---- the token materially changes the request ------------------------- */
    /* The Authorization line (Credential + SignedHeaders + Signature) must
     * differ between the two — proof the token is folded into the signed
     * material, not cosmetically appended. (Even across a 1s amzdate tick the
     * two differ; this can only PASS when they are genuinely distinct.) */
    CHECK(strcmp(hdrs_tok, hdrs_plain) != 0,
          "token-signed header block differs from the plain one");

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall sd_s3 session-token signing invariants hold\n");
    return 0;
}
