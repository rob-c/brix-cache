/* test_sd_http_space.c — unit test for the sd_http capacity slot: the
 * HTTP/WebDAV-origin driver's `space` (src/fs/backend/http/sd_http_space.c).
 *
 * Without this slot, kXR_statvfs / kXR_Qspace / kXR_QFSinfo / SRR against an
 * http:// primary answered from a statvfs(2) of the gateway's own export
 * directory — which for an http origin holds nothing, so a client sizing a
 * transfer read the gateway's spool instead of the storage it was about to
 * write to. The slot answers from the ORIGIN's RFC-4331 quota pair
 * (`DAV:quota-available-bytes` / `DAV:quota-used-bytes`) over one Depth:0
 * PROPFIND, and reports NGX_ERROR — deliberately, so the caller falls back to
 * that local statvfs — for every origin that does not answer.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create (pure config
 * copy, no network) with an injected fake transport returning a scripted 207.
 * It proves:
 *   1 (success)      — the pair is read and total is used+available; the request
 *                      is a Depth:0 PROPFIND on the export root carrying a
 *                      named-prop body for BOTH properties and its own
 *                      Content-Type; the reader is namespace-prefix-agnostic and
 *                      tolerates whitespace and a multi-propstat reply.
 *   2 (error)        — a reply with no quota properties, one that lists them as
 *                      EMPTY elements (the 404-propstat spelling of "not
 *                      supported"), a half-answer, a non-207 status, a transport
 *                      fault, an empty body and NULL arguments are all NGX_ERROR
 *                      with the caller's brix_sd_space_t left untouched.
 *   3 (security-neg) — a value that is not a bare integer is refused WHOLE
 *                      rather than read up to the first bad byte; a value that
 *                      would overflow uint64 is refused; a total that would
 *                      overflow is refused; and the property is only ever read
 *                      from a real element — an href or a filename containing
 *                      the property name verbatim cannot spoof a capacity, and
 *                      a near-miss element name is not a match.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_space`.
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

/* ---- ngx + brix link stubs -------------------------------------------------
 * Instances are built with log=NULL, so sd_http_live_log() short-circuits to
 * NULL and every ngx_log_error site is skipped — these definitions only satisfy
 * the linker. (nginx's own string kernel IS linked into the sd_http closure, so
 * no ngx_string.c function may be stubbed locally.) */
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
static int         g_fail;              /* 1 = transport fault                 */
static int         g_status = 207;      /* origin status                       */
static const char *g_xml;               /* 207 body (NULL = empty body)        */
static char        g_last_method[16];
static char        g_last_path[512];
static char        g_last_hdrs[1024];
static char        g_last_body[4096];
static size_t      g_last_body_len;

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls;
    (void) timeout_ms; (void) errbuf; (void) errcap;

    g_calls++;
    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    snprintf(g_last_hdrs, sizeof(g_last_hdrs), "%s", headers ? headers : "");
    g_last_body_len = 0;
    g_last_body[0] = '\0';
    if (body != NULL && body_len > 0 && body_len < sizeof(g_last_body)) {
        memcpy(g_last_body, body, body_len);
        g_last_body[body_len] = '\0';
        g_last_body_len = body_len;
    }
    resp->opaque = NULL;
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
    (void) resp; (void) name; (void) out; (void) outcap;
    return -1;
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (g_xml == NULL) {
        if (len) { *len = 0; }
        return NULL;
    }
    if (len) { *len = strlen(g_xml); }
    return g_xml;
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

/* Query with the out-struct pre-poisoned, so "did the slot write anything?" is
 * observable on every failure — the contract is that the caller keeps its own
 * value and falls back to the local statvfs. */
#define POISON  0xEEEEEEEEEEEEEEEEull

static ngx_int_t
query(brix_sd_instance_t *inst, brix_sd_space_t *out)
{
    out->total_bytes = POISON;
    out->used_bytes  = POISON;
    out->free_bytes  = POISON;
    return inst->driver->space(inst, out);
}

/* Every failure answer is the same answer: NGX_ERROR, nothing written. */
static void
expect_error(brix_sd_instance_t *inst, const char *xml)
{
    brix_sd_space_t sp;

    g_xml = xml;
    assert(query(inst, &sp) == NGX_ERROR);
    assert(sp.total_bytes == POISON);
    assert(sp.used_bytes == POISON);
    assert(sp.free_bytes == POISON);
}

static void
expect_ok(brix_sd_instance_t *inst, const char *xml, uint64_t avail,
    uint64_t used)
{
    brix_sd_space_t sp;

    g_xml = xml;
    assert(query(inst, &sp) == NGX_OK);
    assert(sp.free_bytes == avail);
    assert(sp.used_bytes == used);
    assert(sp.total_bytes == avail + used);
}

/* Test 1 (success): the origin's own quota answers the request. */
static void
test_space_success(void)
{
    brix_sd_instance_t *inst = build_instance(NULL);

    assert(inst != NULL);

    g_calls = 0;
    expect_ok(inst,
        "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">"
        "<D:response><D:href>/base/</D:href><D:propstat><D:prop>"
        "<D:quota-available-bytes>1000</D:quota-available-bytes>"
        "<D:quota-used-bytes>24</D:quota-used-bytes>"
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
        "</D:response></D:multistatus>",
        1000, 24);

    /* The request itself: Depth:0 PROPFIND on the export root, a named-prop
     * body naming BOTH properties (an empty "allprop" body is not obliged to
     * carry either — they are live properties outside RFC 4918), and the
     * entity's own Content-Type. */
    assert(g_calls == 1);                  /* one round trip, not a walk */
    assert(strcmp(g_last_method, "PROPFIND") == 0);
    assert(strstr(g_last_path, "/base/") != NULL);
    assert(strstr(g_last_hdrs, "Depth: 0\r\n") != NULL);
    assert(strstr(g_last_hdrs, "Content-Type: application/xml\r\n") != NULL);
    assert(g_last_body_len > 0);
    assert(strstr(g_last_body, "quota-available-bytes") != NULL);
    assert(strstr(g_last_body, "quota-used-bytes") != NULL);

    /* A different namespace prefix, whitespace around the values, and a second
     * (404) propstat for properties the origin does not hold: all the shapes a
     * real WebDAV origin sends. */
    expect_ok(inst,
        "<multistatus xmlns=\"DAV:\"><response><href>/base/</href>"
        "<propstat><prop>"
        "<ns1:quota-available-bytes xmlns:ns1=\"DAV:\">  8589934592  "
        "</ns1:quota-available-bytes>"
        "<quota-used-bytes>\n 1073741824 \n</quota-used-bytes>"
        "</prop><status>HTTP/1.1 200 OK</status></propstat>"
        "<propstat><prop><getcontentlanguage/></prop>"
        "<status>HTTP/1.1 404 Not Found</status></propstat>"
        "</response></multistatus>",
        8589934592ull, 1073741824ull);

    /* Zero available is a real answer — a full backend, not a missing one. */
    expect_ok(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>0</D:quota-available-bytes>"
        "<D:quota-used-bytes>512</D:quota-used-bytes>"
        "</D:prop></D:multistatus>",
        0, 512);

    brix_sd_http_destroy(inst);
    printf("  ok   1: quota pair -> free/used/total over a Depth:0 named-prop"
           " PROPFIND, any namespace prefix, whitespace and multi-propstat\n");
}

/* Test 2 (error): every way the origin can fail to answer falls back. */
static void
test_space_error(void)
{
    brix_sd_instance_t *inst = build_instance(NULL);
    brix_sd_space_t     sp;

    assert(inst != NULL);

    /* An origin that speaks WebDAV but reports no quota at all. */
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>/base/</D:href>"
        "<D:propstat><D:prop><D:getcontentlength>7</D:getcontentlength>"
        "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
        "</D:response></D:multistatus>");

    /* RFC 4918 lists an unsupported property as an EMPTY element inside a 404
     * propstat. "The tag is present" is not "there is a value", and must never
     * be read as a zero — a zero total would look like a full backend. */
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:propstat><D:prop>"
        "<D:quota-available-bytes/><D:quota-used-bytes/>"
        "</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"
        "</D:multistatus>");

    /* Half an answer is no answer: there is no `total` property to fall back
     * on, so a missing half cannot be derived. */
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>1000</D:quota-available-bytes>"
        "</D:prop></D:multistatus>");
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-used-bytes>1000</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");

    expect_error(inst, NULL);                   /* 207 with an empty body      */

    g_status = 405;                             /* origin speaks no WebDAV     */
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>1</D:quota-available-bytes>"
        "<D:quota-used-bytes>1</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");
    g_status = 207;

    g_fail = 1;                                 /* transport fault             */
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>1</D:quota-available-bytes>"
        "<D:quota-used-bytes>1</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");
    g_fail = 0;

    assert(inst->driver->space(inst, NULL) == NGX_ERROR);
    assert(inst->driver->space(NULL, &sp) == NGX_ERROR);

    brix_sd_http_destroy(inst);
    printf("  ok   2: no quota / empty elements / half an answer / non-207 /"
           " transport fault / empty body / NULL args -> ERROR, out untouched\n");
}

/* A capacity is a number a client sizes a transfer against. Anything that is
 * not exactly one non-negative integer must be refused whole — reading a value
 * up to its first bad byte would turn "1024junk" into a 1024-byte backend. */
static void
check_values_refused_whole(brix_sd_instance_t *inst)
{
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>1024junk</D:quota-available-bytes>"
        "<D:quota-used-bytes>16</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");

    expect_error(inst,                          /* RFC 4331 has no negatives  */
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>-1</D:quota-available-bytes>"
        "<D:quota-used-bytes>16</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");

    expect_error(inst,                          /* wider than uint64          */
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>99999999999999999999999"
        "</D:quota-available-bytes>"
        "<D:quota-used-bytes>16</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");

    expect_error(inst,                          /* used+available overflows    */
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>18446744073709551615"
        "</D:quota-available-bytes>"
        "<D:quota-used-bytes>1</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");
}

/* The property is read from a real ELEMENT, never from text that merely spells
 * its name — otherwise a file an unprivileged user can create would dictate the
 * capacity this server reports. */
static void
check_not_spoofable_by_text(brix_sd_instance_t *inst)
{
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:response>"
        "<D:href>/base/quota-available-bytes>999&lt;</D:href>"
        "<D:displayname>quota-used-bytes>7</D:displayname>"
        "</D:response></D:multistatus>");

    /* A close-tag is not an open-tag, and a longer local name is not a match. */
    expect_error(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "</D:quota-available-bytes>4096"
        "<D:quota-available-bytes-x>4096</D:quota-available-bytes-x>"
        "<D:quota-used-bytes>16</D:quota-used-bytes>"
        "</D:prop></D:multistatus>");
}

/* Test 3 (security-negative). */
static void
test_space_security_neg(void)
{
    brix_sd_instance_t *inst = build_instance("SVCTOK");

    assert(inst != NULL);
    check_values_refused_whole(inst);
    check_not_spoofable_by_text(inst);

    /* The slot is instance-scoped, so it presents the instance's own service
     * credential — there is no per-open user identity at this level to borrow,
     * and inventing one would ask the origin a question as the wrong principal. */
    expect_ok(inst,
        "<D:multistatus xmlns:D=\"DAV:\"><D:prop>"
        "<D:quota-available-bytes>4</D:quota-available-bytes>"
        "<D:quota-used-bytes>4</D:quota-used-bytes>"
        "</D:prop></D:multistatus>", 4, 4);
    assert(strstr(g_last_hdrs, "Authorization: Bearer SVCTOK") != NULL);

    brix_sd_http_destroy(inst);
    printf("  ok   3: non-integer / oversize / overflowing values refused whole;"
           " href and displayname text cannot spoof a capacity\n");
}

int
main(void)
{
    test_space_success();
    test_space_error();
    test_space_security_neg();
    printf("test_sd_http_space: ALL PASS\n");
    return 0;
}
