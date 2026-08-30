/* test_sd_http_digest.c — unit test for the sd_http checksum-offload slot: the
 * HTTP/WebDAV-origin driver's `query_checksum` (src/fs/backend/http/sd_http_digest.c).
 *
 * A checksum request against an http:// primary used to have exactly one
 * answer: pread the whole object across the network and hash it locally. The
 * slot replaces that with one RFC-3230 round trip — a HEAD carrying
 * `Want-Digest: <token>`, answered from the origin's `Digest:` reply header —
 * and DECLINES to the byte-reading fallback whenever the origin's answer is not
 * authoritative for exactly the algorithm that was asked for.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create (pure config
 * copy, no network) with an injected fake transport returning a scripted
 * `Digest:` header. It proves:
 *   1 (success)      — an unpadded hex adler32 comes back zero-padded to the
 *                      algorithm width; a base64 md5 comes back as lowercase
 *                      hex; a canonical "sha256" is ASKED for in the registered
 *                      hyphenated spelling and picked out of a multi-valued
 *                      header. Every probe is a HEAD on the object's own key.
 *   2 (error)        — no Digest header, a non-200 probe, and a caller buffer
 *                      too small all DECLINE; a transport fault is NGX_ERROR;
 *                      an algorithm with no registered RFC-3230 token declines
 *                      with ZERO wire calls; a NULL object declines.
 *   3 (security-neg) — an origin answering in a DIFFERENT algorithm than was
 *                      requested is never relabelled (decline, output buffer
 *                      untouched); an unusable value is refused rather than
 *                      half-parsed; and the probe presents the PER-OPEN user
 *                      bearer, never the instance service credential, so the
 *                      digest handed back is the one the origin shows to the
 *                      identity that opened the object.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_digest`.
 */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/http/sd_http.h"
#include "core/compat/digest_header.h"

/* The whole-object sha-256 and md5 the scripted origin advertises: bytes
 * 0x00..0x1f and 0x00..0x0f, base64 on the wire per RFC 3230. Fixed vectors,
 * not real digests of anything — the slot never hashes, it only transcodes. */
#define B64_MD5     "AAECAwQFBgcICQoLDA0ODw=="
#define HEX_MD5     "000102030405060708090a0b0c0d0e0f"
#define B64_SHA256  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
#define HEX_SHA256  "000102030405060708090a0b0c0d0e0f" \
                    "101112131415161718191a1b1c1d1e1f"

/* ---- ngx + brix link stubs -------------------------------------------------
 * Instances are built with log=NULL, so sd_http_live_log() short-circuits to
 * NULL and every ngx_log_error site is skipped — these definitions only satisfy
 * the linker; they are never executed on the tested paths. (nginx's own string
 * kernel IS linked here, for ngx_decode_base64, so no ngx_string.c function may
 * be stubbed locally.) */
volatile ngx_cycle_t *ngx_cycle = NULL;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

size_t
brix_sanitize_log_string(const char *in, char *out, size_t outsz)
{
    size_t n = 0;

    if (outsz == 0) { return 0; }
    while (in != NULL && in[n] != '\0' && n + 1 < outsz) {
        out[n] = in[n];
        n++;
    }
    out[n] = '\0';
    return n;
}

/* ---- scripted fake transport -------------------------------------------- */

static int         g_calls;
static int         g_fail;             /* 1 = transport fault on the probe    */
static int         g_status = 200;     /* origin status for the probe         */
static const char *g_digest;           /* Digest: value (NULL = no header)    */
static char        g_last_method[16];
static char        g_last_path[512];
static char        g_last_hdrs[1024];

/* The open-time size HEAD and the digest probe both land here; only the probe
 * carries a Want-Digest request header, so the script keys on that rather than
 * on a call counter (the open must stay scriptable independently). */
static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    int is_probe;

    (void) tctx; (void) host; (void) port; (void) tls;
    (void) body; (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    g_calls++;
    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    snprintf(g_last_hdrs, sizeof(g_last_hdrs), "%s", headers ? headers : "");

    is_probe = (headers != NULL && strstr(headers, "Want-Digest:") != NULL);
    resp->opaque = NULL;
    if (!is_probe) {
        resp->status = 200;                  /* open-time size HEAD succeeds */
        return 0;
    }
    if (g_fail) {
        return -1;
    }
    resp->status = g_status;
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp;
    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "4096");
        return 0;
    }
    if (strcasecmp(name, "Digest") == 0 && g_digest != NULL) {
        snprintf(out, outcap, "%s", g_digest);
        return 0;
    }
    return -1;
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
build_instance(const char *service_bearer)
{
    brix_sd_http_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host         = "127.0.0.1";
    cfg.port         = 9999;
    cfg.base_path    = "/base";
    cfg.transport    = &g_fake_transport;
    cfg.timeout_ms   = 2000;
    cfg.bearer_token = service_bearer;

    return brix_sd_http_create(&cfg, NULL);  /* log=NULL -> logging inert */
}

static brix_sd_obj_t *
open_obj(brix_sd_instance_t *inst, const brix_sd_cred_t *cred)
{
    brix_sd_obj_t *obj;
    int            err = 0;

    if (cred != NULL) {
        obj = inst->driver->open_cred(inst, "/o.dat", BRIX_SD_O_READ, 0, cred,
                                      &err);
    } else {
        obj = inst->driver->open(inst, "/o.dat", BRIX_SD_O_READ, 0, &err);
    }
    assert(obj != NULL);
    return obj;
}

/* Probe with the output buffer pre-poisoned, so "did the slot write anything?"
 * is observable on every non-OK answer (the contract lets the caller keep its
 * own value and fall back to computing). */
static ngx_int_t
probe(brix_sd_obj_t *obj, const char *algo, char *hex, size_t sz)
{
    memset(hex, 'Z', sz);
    hex[sz - 1] = '\0';
    return obj->inst->driver->query_checksum(obj, algo, hex, sz);
}

static void
expect_ok(brix_sd_obj_t *obj, const char *algo, const char *want_hex,
    const char *want_token)
{
    char hex[BRIX_DIGEST_HEX_MAX];
    char want[64];

    assert(probe(obj, algo, hex, sizeof(hex)) == NGX_OK);
    assert(strcmp(hex, want_hex) == 0);
    assert(strcmp(g_last_method, "HEAD") == 0);
    assert(strstr(g_last_path, "/base/o.dat") != NULL);
    snprintf(want, sizeof(want), "Want-Digest: %s\r\n", want_token);
    assert(strstr(g_last_hdrs, want) != NULL);
}

static void
expect_rc(brix_sd_obj_t *obj, const char *algo, ngx_int_t want_rc)
{
    char hex[BRIX_DIGEST_HEX_MAX];

    assert(probe(obj, algo, hex, sizeof(hex)) == want_rc);
    assert(hex[0] == 'Z');            /* nothing written unless it is a digest */
}

/* Test 1 (success): the origin's own digest answers the request. */
static void
test_digest_success(void)
{
    brix_sd_instance_t *inst = build_instance(NULL);
    brix_sd_obj_t      *obj;

    assert(inst != NULL);
    obj = open_obj(inst, NULL);

    /* dCache and friends trim the leading zeros off an adler32; the value we
     * hand back is compared literally by clients against a padded compute. */
    g_digest = "adler32=1a2b3c";
    expect_ok(obj, "adler32", "001a2b3c", "adler32");

    /* md5 rides as base64 on the wire (RFC 3230 / RFC 1864). */
    g_digest = "MD5=" B64_MD5;
    expect_ok(obj, "md5", HEX_MD5, "md5");

    /* Canonical "sha256" must be ASKED for in the registered hyphenated form,
     * and found in a multi-valued header beside another algorithm. */
    g_digest = "adler32=deadbeef,SHA-256=" B64_SHA256;
    expect_ok(obj, "sha256", HEX_SHA256, "sha-256");

    inst->driver->close(obj);
    brix_sd_http_destroy(inst);
    printf("  ok   1: unpadded adler32 re-padded, base64 md5 -> hex, sha256 asked"
           " as sha-256 and picked from a list\n");
}

/* Test 2 (error): every way the origin can fail to answer is a fallback, and a
 * transport fault is distinguishable from a refusal. */
static void
test_digest_error(void)
{
    brix_sd_instance_t *inst = build_instance(NULL);
    brix_sd_obj_t      *obj;
    char                small[5];
    int                 before;

    assert(inst != NULL);
    obj = open_obj(inst, NULL);

    g_digest = NULL;                            /* origin advertises no digest */
    expect_rc(obj, "adler32", NGX_DECLINED);

    g_digest = "adler32=1a2b3c";
    g_status = 404;                             /* probe refused by the origin */
    expect_rc(obj, "adler32", NGX_DECLINED);
    g_status = 200;

    g_fail = 1;                                 /* transport fault             */
    expect_rc(obj, "adler32", NGX_ERROR);
    g_fail = 0;

    /* An algorithm with no registered RFC-3230 token is declined BEFORE any
     * I/O — we never invent a wire spelling and never ask blind. */
    before = g_calls;
    expect_rc(obj, "crc64nvme", NGX_DECLINED);
    assert(g_calls == before);

    /* A caller buffer too small for the algorithm's width: decline whole
     * rather than hand back a truncated digest. */
    memset(small, 'Z', sizeof(small));
    small[sizeof(small) - 1] = '\0';
    assert(inst->driver->query_checksum(obj, "adler32", small,
                                        sizeof(small)) == NGX_DECLINED);
    assert(small[0] == 'Z');

    assert(inst->driver->query_checksum(NULL, "md5", small,
                                        sizeof(small)) == NGX_DECLINED);

    inst->driver->close(obj);
    brix_sd_http_destroy(inst);
    printf("  ok   2: no header / 404 / small buffer / NULL obj -> DECLINED,"
           " transport fault -> ERROR, unknown alg -> no wire call\n");
}

/* An origin digest in some other algorithm, or in an unusable encoding, must
 * never become the answer to what was asked. */
static void
check_never_relabelled(brix_sd_obj_t *obj)
{
    g_digest = "md5=" B64_MD5;
    expect_rc(obj, "sha256", NGX_DECLINED);

    g_digest = "adler32=zz!!";
    expect_rc(obj, "adler32", NGX_DECLINED);

    g_digest = "SHA-256=not-base64!!";
    expect_rc(obj, "sha256", NGX_DECLINED);
}

/* The probe must re-present the identity the object was opened with, not the
 * instance's service credential: a digest is only authoritative for the
 * requester the origin authorized. */
static void
check_identity_not_downgraded(void)
{
    brix_sd_instance_t *inst = build_instance("SVCTOK");
    brix_sd_cred_t      cred;
    brix_sd_obj_t      *obj;
    char                hex[BRIX_DIGEST_HEX_MAX];

    assert(inst != NULL);
    memset(&cred, 0, sizeof(cred));
    cred.bearer = "USERTOK";
    obj = open_obj(inst, &cred);

    g_digest = "adler32=00112233";
    assert(probe(obj, "adler32", hex, sizeof(hex)) == NGX_OK);
    assert(strstr(g_last_hdrs, "Authorization: Bearer USERTOK") != NULL);
    assert(strstr(g_last_hdrs, "SVCTOK") == NULL);

    inst->driver->close(obj);
    brix_sd_http_destroy(inst);
}

/* Test 3 (security-negative). */
static void
test_digest_security_neg(void)
{
    brix_sd_instance_t *inst = build_instance(NULL);
    brix_sd_obj_t      *obj;

    assert(inst != NULL);
    obj = open_obj(inst, NULL);
    check_never_relabelled(obj);
    inst->driver->close(obj);
    brix_sd_http_destroy(inst);

    check_identity_not_downgraded();
    printf("  ok   3: wrong-algorithm and unusable digests are never relabelled;"
           " the probe carries the per-open bearer, not the service one\n");
}

int
main(void)
{
    test_digest_success();
    test_digest_error();
    test_digest_security_neg();
    printf("test_sd_http_digest: ALL PASS\n");
    return 0;
}
