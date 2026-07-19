/*
 * test_sd_s3_read.c — in-path integrity guards on the S3 storage-driver read
 * path (sd_s3_pread).
 *
 * WHY: sd_s3_pread issues a signed `Range: bytes=off-end` GET and copies the
 *      response body into the caller's buffer at logical offset `off`.  The HTTP
 *      transport (libcurl) validates framing and Content-Length but NOTHING about
 *      whether the bytes are the ones we asked for.  A meddling middlebox on a
 *      hostile network can therefore hand back a *well-formed* response that is
 *      shifted, whole-object'd, or emptied — and the naive read would silently
 *      land the wrong bytes at `off` (corruption) or stop short (truncation).
 *      These are exactly the faults brix must survive on networks run by admins
 *      who will not even admit a link is broken.
 *
 * This drives sd_s3_pread through a MOCK transport (no live S3) so each hostile
 * response shape is deterministic:
 *   1 GOOD             206 + Content-Range starting at off + full body -> bytes
 *   2 SHIFTED RANGE    206 + Content-Range starting elsewhere         -> EIO
 *   3 EMPTY MID-OBJECT 206/200 + empty body, off < obj_size           -> EIO
 *   4 WHOLE-FOR-RANGE  200 for a ranged request at off>0              -> EIO
 *   5 GENUINE EOF      empty body at/after obj end, and 416           -> 0
 *
 * Unity build: this TU #includes sd_s3.c + sd_s3_sign.c so the mock transport
 * and the driver share one link.  Compiled by cmdscripts.unit_tests.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sd_s3.h"
#include "core/compat/crypto.h"   /* brix_crypto_init — SigV4 needs the MAC/MD */

/* The driver + SigV4 kernels, pulled in directly. */
#include "sd_s3.c"       /* NOLINT — deliberate unity build for the unit test */
#include "sd_s3_sign.c"  /* NOLINT */

/* ---- mock transport ------------------------------------------------------ */

typedef struct {
    int         status;          /* HTTP status to report                     */
    const char *body;            /* body bytes (may be NULL)                  */
    size_t      body_len;
    const char *content_range;   /* Content-Range header value, or NULL       */
} mock_scenario;

static mock_scenario g_scn;

static int
mock_request(void *tctx, const char *host, int port, int tls,
             const char *method, const char *path_and_query,
             const char *headers, const void *body, size_t body_len,
             int timeout_ms, brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) method;
    (void) path_and_query; (void) headers; (void) body; (void) body_len;
    (void) timeout_ms; (void) errbuf; (void) errcap;
    resp->status = g_scn.status;
    resp->opaque = &g_scn;
    return 0;
}

static int
mock_resp_header(const brix_s3_resp_t *resp, const char *name,
                 char *out, size_t outcap)
{
    const mock_scenario *s = resp->opaque;
    if (strcasecmp(name, "Content-Range") == 0 && s->content_range != NULL) {
        snprintf(out, outcap, "%s", s->content_range);
        return 0;
    }
    return -1;
}

static const void *
mock_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    const mock_scenario *s = resp->opaque;
    if (len) { *len = s->body_len; }
    return s->body;
}

static void mock_resp_free(brix_s3_resp_t *resp) { (void) resp; }

static const brix_s3_transport_t mock_transport = {
    .request      = mock_request,
    .request_cred = NULL,
    .resp_header  = mock_resp_header,
    .resp_body    = mock_resp_body,
    .resp_free    = mock_resp_free,
};

/* ---- harness ------------------------------------------------------------- */

static int failures;

#define CHECK(cond, msg) do {                                               \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); failures++; }       \
    else         { fprintf(stderr, "ok:   %s\n", (msg)); }                   \
} while (0)

static sd_s3_file *
open_handle(int64_t obj_size)
{
    sd_s3_open_params p;
    char errbuf[256];
    sd_s3_file *f;

    memset(&p, 0, sizeof(p));
    p.host = "s3.example.com";
    p.port = 443;
    p.tls  = 1;
    p.key  = "/bucket/obj";
    p.ak   = "AKIDTEST";
    p.sk   = "SECRETTESTKEY0123456789";
    p.region = "us-east-1";
    p.transport = &mock_transport;
    p.timeout_ms = 5000;

    f = sd_s3_open_read(&p, errbuf, sizeof(errbuf));
    if (f == NULL) { fprintf(stderr, "open failed: %s\n", errbuf); exit(2); }
    f->obj_size = obj_size;   /* as if HEAD already ran */
    return f;
}

int
main(void)
{
    char    buf[8192];
    char    errbuf[256];
    ssize_t n;

    if (brix_crypto_init() != 1) {   /* returns 1 on success, 0 on failure */
        fprintf(stderr, "brix_crypto_init failed\n");
        return 2;
    }

    /* Deterministic 4 KiB "object". */
    char obj[4096];
    for (size_t i = 0; i < sizeof(obj); i++) { obj[i] = (char) (i & 0xff); }
    const int64_t OBJ = (int64_t) sizeof(obj);

    /* 1 GOOD: a compliant 206 for bytes=0- with a matching Content-Range. */
    {
        sd_s3_file *f = open_handle(OBJ);
        g_scn = (mock_scenario){ .status = 206, .body = obj, .body_len = 1024,
                                 .content_range = "bytes 0-1023/4096" };
        n = sd_s3_pread(f, buf, 1024, 0, errbuf, sizeof(errbuf));
        CHECK(n == 1024 && memcmp(buf, obj, 1024) == 0,
              "compliant 206 range delivers the requested bytes");
        sd_s3_close(f);
    }

    /* 2 SHIFTED RANGE: 206 whose Content-Range starts at the wrong offset must
     *   be refused (would land bytes[512..] where the caller expects [0..]). */
    {
        sd_s3_file *f = open_handle(OBJ);
        g_scn = (mock_scenario){ .status = 206, .body = obj + 512, .body_len = 1024,
                                 .content_range = "bytes 512-1535/4096" };
        n = sd_s3_pread(f, buf, 1024, 0, errbuf, sizeof(errbuf));
        CHECK(n < 0, "misaligned Content-Range is refused (EIO), not copied");
        sd_s3_close(f);
    }

    /* 3 EMPTY MID-OBJECT: an empty body at off=0 with obj_size=4096 is a forged
     *   truncation, NOT EOF — must fault so the fill aborts. */
    {
        sd_s3_file *f = open_handle(OBJ);
        g_scn = (mock_scenario){ .status = 206, .body = NULL, .body_len = 0,
                                 .content_range = "bytes 0-4095/4096" };
        n = sd_s3_pread(f, buf, 4096, 0, errbuf, sizeof(errbuf));
        CHECK(n < 0, "empty body before object end is a fault, not EOF");
        sd_s3_close(f);
    }

    /* 4 WHOLE-OBJECT-FOR-RANGE: a 200 (range ignored) for a request at off>0
     *   must be refused — its body starts at 0, not at off. */
    {
        sd_s3_file *f = open_handle(OBJ);
        g_scn = (mock_scenario){ .status = 200, .body = obj, .body_len = 4096,
                                 .content_range = NULL };
        n = sd_s3_pread(f, buf, 1024, 1024, errbuf, sizeof(errbuf));
        CHECK(n < 0, "200 whole-object reply to a ranged read at off>0 is refused");
        sd_s3_close(f);
    }

    /* 5a GENUINE EOF: reading an EMPTY object (obj_size 0) at off 0 gets a 200
     *   with an empty body — that IS real EOF (0), not a forged truncation. */
    {
        sd_s3_file *f = open_handle(0);
        g_scn = (mock_scenario){ .status = 200, .body = NULL, .body_len = 0,
                                 .content_range = NULL };
        n = sd_s3_pread(f, buf, 1024, 0, errbuf, sizeof(errbuf));
        CHECK(n == 0, "empty body for an empty object reports EOF (0)");
        sd_s3_close(f);
    }

    /* 5b GENUINE EOF: a 416 Range-Not-Satisfiable is EOF (0). */
    {
        sd_s3_file *f = open_handle(OBJ);
        g_scn = (mock_scenario){ .status = 416, .body = NULL, .body_len = 0,
                                 .content_range = NULL };
        n = sd_s3_pread(f, buf, 1024, OBJ, errbuf, sizeof(errbuf));
        CHECK(n == 0, "416 past object end reports EOF (0)");
        sd_s3_close(f);
    }

    if (failures) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall sd_s3 read-path integrity guards hold\n");
    return 0;
}
