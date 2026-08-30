/* test_sd_remote_checksum.c — unit test for the sd_remote checksum-offload slot:
 * the s3:// driver's `query_checksum` (src/fs/backend/remote/sd_remote_checksum.c).
 *
 * A checksum request against an s3:// export used to have exactly one answer:
 * Range-GET the whole object back and hash it locally — paying for the entire
 * transfer a second time to recompute a digest the store already holds. The slot
 * replaces that with one signed HEAD carrying `x-amz-checksum-mode: ENABLED`,
 * and DECLINES to the byte-reading fallback whenever the store's answer is not
 * authoritative for exactly the algorithm that was asked for.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_remote_create with an
 * injected fake transport that answers the open's size HEAD and then a scripted
 * set of checksum headers. It proves:
 *   1 (success)      — a base64 x-amz-checksum-sha256/crc32/crc32c/crc64nvme
 *                      comes back as lowercase hex of the right width, and a
 *                      single-part ETag answers "md5" with its quotes stripped.
 *                      Every probe is a HEAD asking for checksum mode.
 *   2 (error)        — an object uploaded without the requested checksum, an
 *                      algorithm S3 does not compute (asked with ZERO wire
 *                      calls), a caller buffer too small and a NULL object all
 *                      DECLINE; a transport fault and a non-200 are NGX_ERROR.
 *   3 (security-neg) — a MULTIPART ETag ("<hex>-<n>", an md5 of the part digests
 *                      and not of the object) is never handed back as the md5;
 *                      neither is a non-md5-width or non-hex ETag; a corrupt
 *                      base64 value is refused whole rather than half-decoded;
 *                      and a value in the WRONG algorithm's header cannot be
 *                      relabelled, because each algorithm reads only its own.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_checksum`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "core/compat/crypto.h"   /* brix_crypto_init: the SigV4 sign path */

/* ---- scripted fake transport -------------------------------------------- */

#define CK_MAX 6

static int         g_calls;
static int         g_fail;                  /* 1 = transport fault           */
static int         g_status = 200;
static char        g_last_hdrs[2048];
static const char *g_ck_name[CK_MAX];       /* scripted response headers      */
static const char *g_ck_val[CK_MAX];
static int         g_ckn;

static void
script_reset(void)
{
    g_ckn = 0;
    g_fail = 0;
    g_status = 200;
    g_calls = 0;
}

static void
script_add(const char *name, const char *val)
{
    assert(g_ckn < CK_MAX);
    g_ck_name[g_ckn] = name;
    g_ck_val[g_ckn]  = val;
    g_ckn++;
}

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) method;
    (void) path_and_query; (void) body; (void) body_len; (void) timeout_ms;

    g_calls++;
    snprintf(g_last_hdrs, sizeof(g_last_hdrs), "%s", headers ? headers : "");
    resp->opaque = NULL;
    if (g_fail) {
        snprintf(errbuf, errcap, "stub: refused (test double, no network)");
        return -1;
    }
    resp->status = g_status;
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    int i;

    (void) resp;
    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "1024");
        return 0;
    }
    for (i = 0; i < g_ckn; i++) {
        if (strcasecmp(name, g_ck_name[i]) == 0) {
            snprintf(out, outcap, "%s", g_ck_val[i]);
            return 0;
        }
    }
    return -1;                              /* header absent */
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (len) { *len = 0; }
    return NULL;
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
    snprintf(cfg.bucket, sizeof(cfg.bucket), "test-bucket");
    snprintf(cfg.access_key, sizeof(cfg.access_key), "SERVICE-AK-STATIC");
    snprintf(cfg.secret_key, sizeof(cfg.secret_key), "SERVICE-SK-STATIC");
    snprintf(cfg.region, sizeof(cfg.region), "us-east-1");
    cfg.timeout_ms = 2000;
    cfg.transport  = &g_fake_transport;

    return brix_sd_remote_create(&cfg, NULL);
}

static brix_sd_obj_t *
open_obj(brix_sd_instance_t *inst)
{
    int            err = 0;
    brix_sd_obj_t *obj;

    script_reset();
    obj = inst->driver->open(inst, "/probe.bin", BRIX_SD_O_READ, 0, &err);
    assert(obj != NULL);
    return obj;
}

/* Query with the output pre-poisoned, so a decline is observably "the caller's
 * buffer is untouched" and not "a shorter string that still looks like a
 * digest". */
static ngx_int_t
probe(brix_sd_obj_t *obj, const char *algo, char *out, size_t cap)
{
    memset(out, 'Z', cap - 1);
    out[cap - 1] = '\0';
    return obj->inst->driver->query_checksum(obj, algo, out, cap);
}

static void
expect_ok(brix_sd_obj_t *obj, const char *algo, const char *hdr,
    const char *val, const char *want_hex)
{
    char hex[160];

    script_reset();
    script_add(hdr, val);
    assert(probe(obj, algo, hex, sizeof(hex)) == NGX_OK);
    assert(strcmp(hex, want_hex) == 0);
    assert(g_calls == 1);                   /* one HEAD, no object read-back */
}

static void
expect_declined(brix_sd_obj_t *obj, const char *algo, const char *hdr,
    const char *val)
{
    char hex[160];

    script_reset();
    if (hdr != NULL) {
        script_add(hdr, val);
    }
    assert(probe(obj, algo, hex, sizeof(hex)) == NGX_DECLINED);
    assert(hex[0] == 'Z');                  /* caller's buffer left alone */
}

/* Test 1 (success): the store's own digest answers the request. */
static void
test_checksum_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_obj_t      *obj;
    char                hex[160];

    assert(inst != NULL);
    assert(inst->driver->query_checksum != NULL);
    obj = open_obj(inst);

    /* S3 additional checksums ride as base64 of the raw digest bytes. */
    expect_ok(obj, "sha256", "x-amz-checksum-sha256",
              "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_ok(obj, "crc32", "x-amz-checksum-crc32", "AAAAAA==", "00000000");
    expect_ok(obj, "crc32c", "x-amz-checksum-crc32c", "GtHtsA==", "1ad1edb0");
    expect_ok(obj, "crc64nvme", "x-amz-checksum-crc64nvme", "AAAAAAAAAAA=",
              "0000000000000000");

    /* A single-part ETag is the object's md5, quoted, in hex. */
    expect_ok(obj, "md5", "ETag", "\"d41d8cd98f00b204e9800998ecf8427e\"",
              "d41d8cd98f00b204e9800998ecf8427e");

    /* The probe must actually ASK for the stored checksums — HeadObject omits
     * them otherwise — and AWS requires every x-amz-* header it carries to be in
     * the SIGNED set, so the mode header and the signature travel together. */
    assert(strstr(g_last_hdrs, "x-amz-checksum-mode: ENABLED") != NULL);
    assert(strstr(g_last_hdrs, "SignedHeaders=") != NULL);
    assert(strstr(g_last_hdrs, "x-amz-checksum-mode") != NULL);

    /* A short value from a store that trimmed leading zeros is re-padded to the
     * algorithm's width — the digest is handed on as authoritative and compared
     * literally against a local compute. */
    script_reset();
    script_add("x-amz-checksum-crc32", "Gg==");
    assert(probe(obj, "crc32", hex, sizeof(hex)) == NGX_OK);
    assert(strcmp(hex, "0000001a") == 0);

    inst->driver->close(obj);
    brix_sd_remote_destroy(inst);
    printf("  ok   1: base64 sha256/crc32/crc32c/crc64nvme -> hex, single-part"
           " ETag -> md5, checksum-mode asked and signed, short value re-padded\n");
}

/* Test 2 (error): every way the store can fail to answer falls back. */
static void
test_checksum_error(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_obj_t      *obj;
    char                hex[160];

    assert(inst != NULL);
    obj = open_obj(inst);

    /* Uploaded without the requested checksum: the header is simply absent. */
    expect_declined(obj, "sha256", NULL, NULL);

    /* An algorithm S3 does not compute declines BEFORE any wire I/O — asking
     * would cost a round trip for an answer that cannot exist. */
    script_reset();
    assert(probe(obj, "adler32", hex, sizeof(hex)) == NGX_DECLINED);
    assert(g_calls == 0);
    script_reset();
    assert(probe(obj, "sha512", hex, sizeof(hex)) == NGX_DECLINED);
    assert(g_calls == 0);

    /* A caller buffer that cannot hold the whole value declines rather than
     * truncating a digest. */
    script_reset();
    script_add("x-amz-checksum-sha256",
               "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    {
        char small[8];
        assert(probe(obj, "sha256", small, sizeof(small)) == NGX_DECLINED);
    }

    /* A transport fault and a refusing origin are NGX_ERROR: the caller hashes
     * the bytes, exactly as for a decline. */
    script_reset();
    g_fail = 1;
    assert(probe(obj, "sha256", hex, sizeof(hex)) == NGX_ERROR);
    script_reset();
    g_status = 403;
    assert(probe(obj, "sha256", hex, sizeof(hex)) == NGX_ERROR);

    script_reset();
    assert(inst->driver->query_checksum(NULL, "sha256", hex, sizeof(hex))
           == NGX_DECLINED);
    assert(inst->driver->query_checksum(obj, NULL, hex, sizeof(hex))
           == NGX_DECLINED);
    assert(inst->driver->query_checksum(obj, "sha256", hex, 0) == NGX_DECLINED);
    assert(g_calls == 0);

    inst->driver->close(obj);
    brix_sd_remote_destroy(inst);
    printf("  ok   2: checksum absent / algorithm S3 never computes (0 wire"
           " calls) / buffer too small / NULL args -> DECLINED; transport fault"
           " and 403 -> ERROR\n");
}

/* An ETag is an md5 of the OBJECT only for a single-part upload. Everything
 * else that can appear there must decline, because the caller republishes this
 * value as the object's authoritative checksum. */
static void
check_etag_not_an_md5(brix_sd_obj_t *obj)
{
    /* Multipart: md5 of the concatenated PART digests, "-<nparts>" suffixed. */
    expect_declined(obj, "md5", "ETag",
                    "\"9bb58f26192e4ba00f01e2e7b136bbd8-42\"");
    expect_declined(obj, "md5", "ETag", "9bb58f26192e4ba00f01e2e7b136bbd8-2");
    /* SSE-KMS / a store that puts something else there entirely. */
    expect_declined(obj, "md5", "ETag", "\"not-a-digest\"");
    expect_declined(obj, "md5", "ETag", "\"d41d8cd98f00b204e9800998ecf842\"");
    expect_declined(obj, "md5", "ETag", "\"d41d8cd98f00b204e9800998ecf8427g\"");
    expect_declined(obj, "md5", "ETag", "\"\"");
}

/* Test 3 (security-negative). */
static void
test_checksum_security_neg(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_obj_t      *obj;

    assert(inst != NULL);
    obj = open_obj(inst);

    check_etag_not_an_md5(obj);

    /* A value that is not usable base64 is refused WHOLE — a half-decoded
     * prefix would still look like a digest to the caller. */
    expect_declined(obj, "sha256", "x-amz-checksum-sha256", "!!!not base64!!!");
    expect_declined(obj, "sha256", "x-amz-checksum-sha256", "");

    /* Each algorithm reads ONLY its own header, so a store that holds a digest
     * in a different function cannot have it relabelled: a crc32 present while
     * sha256 was asked for is a decline, not a mislabelled crc32. */
    expect_declined(obj, "sha256", "x-amz-checksum-crc32", "GtHtsA==");
    expect_declined(obj, "md5", "x-amz-checksum-sha256",
                    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    /* ...and crc32 is not crc32c, nor crc64nvme a crc64 (invariant #9). */
    expect_declined(obj, "crc32c", "x-amz-checksum-crc32", "GtHtsA==");
    expect_declined(obj, "crc64", "x-amz-checksum-crc64nvme", "AAAAAAAAAAA=");

    inst->driver->close(obj);
    brix_sd_remote_destroy(inst);
    printf("  ok   3: multipart/SSE/short/non-hex ETag never becomes an md5;"
           " unusable base64 refused whole; no algorithm is relabelled from"
           " another's header\n");
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_checksum_success();
    test_checksum_error();
    test_checksum_security_neg();
    printf("test_sd_remote_checksum: ALL PASS\n");
    return 0;
}
