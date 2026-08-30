/* test_sd_http_xattr.c — unit test for the sd_http xattr slots: extended
 * attributes on an HTTP/WebDAV origin carried as RFC 4918 §15 dead properties
 * (src/fs/backend/http/sd_http_xattr.c + sd_http_xattr_write.c).
 *
 * `http` was the only namespace-capable driver with no xattr support at all, so
 * everything the gateway layers on a per-object key/value store went dark behind
 * an http origin: WebDAV LOCK tokens, WebDAV PROPPATCH dead properties, S3 object
 * tagging, S3 user metadata and root:// kXR_fattr. One xattr becomes one element
 * `bxa<hex(name)>` in the BriX xattr namespace, with a hex-encoded value.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_http_create (pure config
 * copy, no network) with an injected fake transport returning scripted replies.
 * It proves:
 *   1 (success)      — set/get/list round-trip: the PROPPATCH carries the name
 *                      AND the value as hex, the named-prop PROPFIND asks for the
 *                      same element at Depth:0, the value comes back byte-exact
 *                      including embedded NULs, bufsz==0 reports the size without
 *                      writing, and listxattr enumerates every `bxa` property
 *                      whatever namespace prefix the origin used.
 *   2 (error)        — an absent property is ENODATA (both the missing-element
 *                      and the 404-propstat spellings), a short buffer is ERANGE
 *                      with nothing written, an over-long value is E2BIG and an
 *                      over-long name ERANGE — both refused before any wire op —
 *                      XATTR_CREATE on an existing attribute is EEXIST and
 *                      XATTR_REPLACE on an absent one ENODATA, removing an absent
 *                      attribute is ENODATA (not the WebDAV success), a 405/409
 *                      origin is ENOTSUP, and a transport fault is EIO.
 *   3 (security-neg) — a deny-mode proxy-only credential is refused BEFORE any
 *                      request reaches the transport, on all four ops; and a name
 *                      or value full of XML metacharacters cannot inject markup,
 *                      because neither ever reaches the body as itself.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_http_xattr`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

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

/* ---- scripted fake transport --------------------------------------------
 * `g_xml` answers a PROPFIND; a PROPPATCH gets `g_patch_status` and no body, so
 * one script drives a whole round trip. */

static int         g_calls;
static int         g_fail;
static int         g_pf_status    = 207;
static int         g_patch_status = 207;
static const char *g_xml;
static const char *g_patch_xml;
static char        g_last_method[16];
static char        g_last_path[512];
static char        g_last_hdrs[1024];
static char        g_last_body[70000];
static size_t      g_last_body_len;
static int         g_last_was_patch;

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
    g_last_was_patch = (strcmp(method, "PROPPATCH") == 0);
    g_last_body_len  = 0;
    g_last_body[0]   = '\0';
    if (body != NULL && body_len > 0 && body_len < sizeof(g_last_body)) {
        memcpy(g_last_body, body, body_len);
        g_last_body[body_len] = '\0';
        g_last_body_len = body_len;
    }
    resp->opaque = NULL;
    if (g_fail) {
        return -1;
    }
    resp->status = g_last_was_patch ? g_patch_status : g_pf_status;
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
    const char *b = g_last_was_patch ? g_patch_xml : g_xml;

    (void) resp;
    if (b == NULL) {
        if (len) { *len = 0; }
        return NULL;
    }
    if (len) { *len = strlen(b); }
    return b;
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
    brix_sd_http_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.host       = "127.0.0.1";
    cfg.port       = 9999;
    cfg.base_path  = "/base";
    cfg.transport  = &g_fake_transport;
    cfg.timeout_ms = 2000;

    return brix_sd_http_create(&cfg, NULL);  /* log=NULL -> logging inert */
}

/* Wrap one value in the 207 a WebDAV origin sends for a named-prop PROPFIND
 * that FOUND the property (a 200 propstat). `elem` is the element local name. */
static const char *
found_xml(char *out, size_t cap, const char *elem, const char *hexval)
{
    snprintf(out, cap,
             "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">"
             "<D:response><D:href>/base/f</D:href><D:propstat><D:prop>"
             "<B:%s xmlns:B=\"https://brix.dev/ns/xattr\">%s</B:%s>"
             "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
             "</D:response></D:multistatus>", elem, hexval, elem);
    return out;
}

/* The whole answer for "there is no such property": RFC 4918 returns the element
 * EMPTY inside a 404 propstat, which must never read as an empty value. */
static const char *g_absent_xml =
    "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\">"
    "<D:response><D:href>/base/f</D:href><D:propstat><D:prop>"
    "<B:bxa757365722e78 xmlns:B=\"https://brix.dev/ns/xattr\"/>"
    "</D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat>"
    "</D:response></D:multistatus>";

/* Test 1 (success): a set/get/list round trip over the wire spelling. */
static void
test_xattr_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    char                xmlbuf[1024];
    char                got[64];
    ssize_t             n;

    assert(inst != NULL);

    /* set: one PROPPATCH whose body carries the NAME as hex ("user.x" ==
     * 757365722e78) and the VALUE as hex ("hi" == 6869). */
    g_calls = 0;
    g_patch_status = 207;
    g_patch_xml = "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:propstat>"
                  "<D:prop><B:bxa757365722e78 xmlns:B=\"https://brix.dev/ns/"
                  "xattr\"/></D:prop><D:status>HTTP/1.1 200 OK</D:status>"
                  "</D:propstat></D:response></D:multistatus>";
    assert(inst->driver->setxattr(inst, "/f", "user.x", "hi", 2, 0) == NGX_OK);
    assert(g_calls == 1);                    /* no flags -> no probe read */
    assert(strcmp(g_last_method, "PROPPATCH") == 0);
    assert(strstr(g_last_path, "/base/") != NULL);
    assert(strstr(g_last_hdrs, "Content-Type: application/xml\r\n") != NULL);
    assert(strstr(g_last_body, "<D:set>") != NULL);
    assert(strstr(g_last_body, "bxa757365722e78") != NULL);
    assert(strstr(g_last_body, ">6869<") != NULL);
    assert(strstr(g_last_body, "hi") == NULL);   /* the value never travels raw */

    /* get: a Depth:0 named-prop PROPFIND for the same element. */
    g_calls = 0;
    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78", "6869");
    n = inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got));
    assert(n == 2 && memcmp(got, "hi", 2) == 0);
    assert(g_calls == 1);
    assert(strcmp(g_last_method, "PROPFIND") == 0);
    assert(strstr(g_last_hdrs, "Depth: 0\r\n") != NULL);
    assert(strstr(g_last_body, "<D:propfind") != NULL);
    assert(strstr(g_last_body, "bxa757365722e78") != NULL);

    /* bufsz == 0 is the size enquiry: it reports, it does not write. */
    memset(got, 'Z', sizeof(got));
    assert(inst->driver->getxattr(inst, "/f", "user.x", NULL, 0) == 2);
    assert(got[0] == 'Z');

    /* A value is arbitrary BYTES, embedded NULs included — the round trip is
     * over hex, so nothing here is string-shaped. */
    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78", "00ff0041");
    n = inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got));
    assert(n == 4 && memcmp(got, "\x00\xff\x00" "A", 4) == 0);

    /* list: every bxa property on the resource, whatever prefix the origin
     * chose, and nothing that is not one of ours. */
    g_xml = "<multistatus xmlns=\"DAV:\"><response><href>/base/f</href>"
            "<propstat><prop>"
            "<ns7:bxa757365722e78 xmlns:ns7=\"https://brix.dev/ns/xattr\"/>"
            "<getcontentlength/>"
            "<bxa757365722e79 xmlns=\"https://brix.dev/ns/xattr\"/>"
            "</prop><status>HTTP/1.1 200 OK</status></propstat>"
            "</response></multistatus>";
    memset(got, 0, sizeof(got));
    n = inst->driver->listxattr(inst, "/f", got, sizeof(got));
    assert(n == (ssize_t) (sizeof("user.x") + sizeof("user.y")));
    assert(strcmp(got, "user.x") == 0);
    assert(strcmp(got + 7, "user.y") == 0);
    assert(strstr(g_last_body, "<D:propname/>") != NULL);
    assert(inst->driver->listxattr(inst, "/f", NULL, 0) == n);

    brix_sd_http_destroy(inst);
    printf("  ok   1: set/get/list round-trip — name and value hex on the wire,"
           " Depth:0 named-prop read, byte-exact values, size enquiries\n");
}

/* The absent-attribute family: both spellings an origin uses, on both the read
 * and the remove path. */
static void
check_absent(brix_sd_instance_t *inst)
{
    char got[16];

    g_xml = g_absent_xml;                       /* empty element, 404 propstat */
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got)) < 0);
    assert(errno == ENODATA);

    g_xml = "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>/base/f"
            "</D:href></D:response></D:multistatus>";   /* no element at all */
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got)) < 0);
    assert(errno == ENODATA);

    /* RFC 4918 §9.2 makes removing an absent property a SUCCESS; POSIX demands
     * ENODATA, so the driver asks before it patches — and never patches. */
    g_calls = 0;
    errno = 0;
    assert(inst->driver->removexattr(inst, "/f", "user.x") == NGX_ERROR);
    assert(errno == ENODATA);
    assert(g_calls == 1 && strcmp(g_last_method, "PROPFIND") == 0);
}

/* The two POSIX flags PROPPATCH has no native equivalent for. */
static void
check_flag_gate(brix_sd_instance_t *inst)
{
    char xmlbuf[1024];

    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78", "6869");
    g_calls = 0;
    errno = 0;
    assert(inst->driver->setxattr(inst, "/f", "user.x", "z", 1,
                                  XATTR_CREATE) == NGX_ERROR);
    assert(errno == EEXIST);
    assert(g_calls == 1);                       /* probed, never patched */

    g_xml = g_absent_xml;
    g_calls = 0;
    errno = 0;
    assert(inst->driver->setxattr(inst, "/f", "user.x", "z", 1,
                                  XATTR_REPLACE) == NGX_ERROR);
    assert(errno == ENODATA);
    assert(g_calls == 1);
}

/* Test 2 (error). */
static void
test_xattr_error(void)
{
    brix_sd_instance_t *inst = build_instance();
    char                xmlbuf[1024];
    char                got[4];
    char                bigname[512];
    char                bigval[16385];       /* one past the 16 KiB value cap */

    assert(inst != NULL);
    check_absent(inst);
    check_flag_gate(inst);

    /* A buffer that cannot hold the value is ERANGE, and nothing is written —
     * a truncated xattr handed back as the stored one is a silent corruption. */
    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78", "4142434445");
    memset(got, 'Z', sizeof(got));
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got)) < 0);
    assert(errno == ERANGE);
    assert(got[0] == 'Z');

    /* Over-long name and over-long value are refused BEFORE any request. */
    memset(bigname, 'n', sizeof(bigname) - 1);
    bigname[sizeof(bigname) - 1] = '\0';
    memset(bigval, 'v', sizeof(bigval));
    g_calls = 0;
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", bigname, got, sizeof(got)) < 0);
    assert(errno == ERANGE);
    errno = 0;
    assert(inst->driver->setxattr(inst, "/f", "user.x", bigval, sizeof(bigval),
                                  0) == NGX_ERROR);
    assert(errno == E2BIG);
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", "", got, sizeof(got)) < 0);
    assert(errno == EINVAL);
    assert(g_calls == 0);

    /* An origin that keeps no dead properties: ENOTSUP, so the tier above can
     * fall back rather than read it as "the file is gone" or "already there". */
    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78", "6869");
    g_patch_status = 405;
    errno = 0;
    assert(inst->driver->setxattr(inst, "/f", "user.x", "z", 1, 0) == NGX_ERROR);
    assert(errno == ENOTSUP);
    g_patch_status = 409;
    errno = 0;
    assert(inst->driver->setxattr(inst, "/f", "user.x", "z", 1, 0) == NGX_ERROR);
    assert(errno == ENOTSUP);
    /* A 207 whose PROPSTAT says the property was rejected is a failure too —
     * reading only the outer status would report a write that never landed. */
    g_patch_status = 207;
    g_patch_xml = "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:propstat>"
                  "<D:prop><B:bxa757365722e78 xmlns:B=\"https://brix.dev/ns/"
                  "xattr\"/></D:prop><D:status>HTTP/1.1 403 Forbidden</D:status>"
                  "</D:propstat></D:response></D:multistatus>";
    errno = 0;
    assert(inst->driver->setxattr(inst, "/f", "user.x", "z", 1, 0) == NGX_ERROR);
    assert(errno == ENOTSUP);

    g_fail = 1;
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got)) < 0);
    assert(errno == EIO);
    g_fail = 0;

    assert(inst->driver->getxattr(NULL, "/f", "user.x", got, 4) < 0);
    assert(inst->driver->listxattr(inst, NULL, got, 4) < 0);

    brix_sd_http_destroy(inst);
    printf("  ok   2: absent -> ENODATA (both spellings, get and remove),"
           " short buffer -> ERANGE untouched, oversize refused pre-wire,"
           " CREATE/REPLACE honoured, 405/409/propstat-403 -> ENOTSUP\n");
}

/* A deny-mode proxy-only credential the transport cannot present must be
 * refused BEFORE the request leaves this host — falling back to the service
 * identity would run a per-user property write as the gateway. */
static void
check_deny_mode_refused(brix_sd_instance_t *inst)
{
    brix_sd_cred_t cred;
    char           got[16];

    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy    = "/tmp/nonexistent-proxy.pem";
    cred.fallback_deny = 1;

    g_calls = 0;
    errno = 0;
    assert(inst->driver->getxattr_cred(inst, "/f", "user.x", got, sizeof(got),
                                       &cred) < 0);
    assert(errno == EACCES);
    errno = 0;
    assert(inst->driver->listxattr_cred(inst, "/f", got, sizeof(got),
                                        &cred) < 0);
    assert(errno == EACCES);
    errno = 0;
    assert(inst->driver->setxattr_cred(inst, "/f", "user.x", "z", 1, 0,
                                       &cred) == NGX_ERROR);
    assert(errno == EACCES);
    errno = 0;
    assert(inst->driver->removexattr_cred(inst, "/f", "user.x",
                                          &cred) == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_calls == 0);                   /* nothing ever reached the wire */
}

/* Names and values are attacker-chosen bytes. Hex on both halves is what makes
 * that safe: neither ever appears in the request body as itself, so no choice of
 * bytes can close a tag, open one, or end the CDATA the body is not using. */
static void
check_no_markup_injection(brix_sd_instance_t *inst)
{
    static const char evil[] = "]]></B:x></D:prop></D:set><D:remove><D:prop>";
    char xmlbuf[1024];
    char got[16];

    g_patch_status = 200;                   /* a plain PROPPATCH success */
    assert(inst->driver->setxattr(inst, "/f", "user.<&\"'>", evil,
                                  sizeof(evil) - 1, 0) == NGX_OK);
    /* Neither the name nor the value reaches the body as itself, so no choice
     * of bytes can close a tag, open one, or end a CDATA section. */
    assert(strstr(g_last_body, "]]>") == NULL);
    assert(strstr(g_last_body, "D:remove") == NULL);
    assert(strstr(g_last_body, "&") == NULL);
    assert(strstr(g_last_body, "\"'") == NULL);
    assert(strstr(g_last_body, "<B:bxa757365722e3c2622273e>") != NULL);

    /* And the same in the other direction: a property's text is only ever read
     * as hex, so markup in it decodes to nothing — never to markup — and text
     * that is not hex at all is refused whole rather than salvaged. */
    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78",
                      "<D:evil>41</D:evil>");
    assert(inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got)) == 0);
    g_xml = found_xml(xmlbuf, sizeof(xmlbuf), "bxa757365722e78", "41zz");
    errno = 0;
    assert(inst->driver->getxattr(inst, "/f", "user.x", got, sizeof(got)) < 0);
    assert(errno == EIO);
}

/* Test 3 (security-negative). */
static void
test_xattr_security_neg(void)
{
    brix_sd_instance_t *inst = build_instance();

    assert(inst != NULL);
    check_deny_mode_refused(inst);
    check_no_markup_injection(inst);

    brix_sd_http_destroy(inst);
    printf("  ok   3: deny-mode proxy cred refused on all four ops before any"
           " wire op; markup in a name or value cannot escape the hex\n");
}

int
main(void)
{
    test_xattr_success();
    test_xattr_error();
    test_xattr_security_neg();
    printf("test_sd_http_xattr: ALL PASS\n");
    return 0;
}
