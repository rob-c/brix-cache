/* test_sd_remote_opendir.c — unit test for finding #4 (phase-92): the
 * remote-origin (s3://) driver's directory-listing slots.
 *
 * sd_remote_opendir/readdir/closedir (src/fs/backend/remote/sd_remote.c) turn an
 * S3 ListObjectsV2 (delimited, paged) into a POSIX-shaped directory level over
 * the shared sd_s3_list_page primitive (src/fs/backend/s3/sd_s3_list.c):
 * <Contents> under the prefix are files, <CommonPrefixes> are sub-directories.
 * Before this change opendir on an s3:// export hit the NULL slot -> ENOTSUP.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_remote_create (pure
 * config copy, no network) with an injected fake transport that returns scripted
 * ListObjectsV2 XML. It proves:
 *   1 (success)      — one page yields files + a sub-dir with the right d_type,
 *                      the request carries the derived prefix, an XML-escaped key
 *                      is unescaped, the directory-marker object (Key==prefix) is
 *                      skipped, and the stream ends with NGX_DONE.
 *   2 (pagination)   — a truncated first page threads its NextContinuationToken
 *                      into the second request and both pages' entries surface.
 *   3 (error/sec-neg)— a 403 LIST surfaces as NGX_ERROR/EACCES on readdir (an
 *                      auth refusal is never masked as an empty directory), and
 *                      NULL arguments to sd_s3_list_page are rejected with EINVAL
 *                      before any wire I/O.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_opendir`.
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
#include "fs/backend/s3/sd_s3.h"  /* sd_s3_open_params, sd_s3_list_page (bad-arg) */
#include "core/compat/crypto.h"   /* brix_crypto_init: SigV4 sign path */

/* ---- scripted fake transport ------------------------------------------- */

enum { MODE_SINGLE, MODE_PAGED, MODE_ERR };

static int  g_mode        = MODE_SINGLE;
static int  g_get_calls   = 0;
static char g_last_path[512];
static const char *g_cur_body = NULL;
static size_t      g_cur_len  = 0;

static const char BODY_SINGLE[] =
    "<?xml version=\"1.0\"?>\n"
    "<ListBucketResult><Name>test-bucket</Name><Prefix>sub/</Prefix>"
    "<IsTruncated>false</IsTruncated>"
    "<Contents><Key>sub/</Key><Size>0</Size></Contents>"          /* marker */
    "<Contents><Key>sub/file1.txt</Key><Size>10</Size></Contents>"
    "<Contents><Key>sub/a&amp;b.txt</Key><Size>5</Size></Contents>" /* escaped */
    "<CommonPrefixes><Prefix>sub/dir1/</Prefix></CommonPrefixes>"
    "</ListBucketResult>";

static const char BODY_PAGE1[] =
    "<ListBucketResult><IsTruncated>true</IsTruncated>"
    "<NextContinuationToken>TOKEN123</NextContinuationToken>"
    "<Contents><Key>p1.txt</Key></Contents></ListBucketResult>";

static const char BODY_PAGE2[] =
    "<ListBucketResult><IsTruncated>false</IsTruncated>"
    "<Contents><Key>p2.txt</Key></Contents></ListBucketResult>";

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) headers;
    (void) body; (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    g_get_calls++;
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    assert(strcmp(method, "GET") == 0);   /* listing is a GET on the bucket root */

    resp->opaque = NULL;
    if (g_mode == MODE_ERR) {
        resp->status = 403;
        g_cur_body = NULL;
        g_cur_len  = 0;
        return 0;
    }
    resp->status = 200;
    if (g_mode == MODE_PAGED) {
        g_cur_body = (g_get_calls == 1) ? BODY_PAGE1 : BODY_PAGE2;
    } else {
        g_cur_body = BODY_SINGLE;
    }
    g_cur_len = strlen(g_cur_body);
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
    if (len) { *len = g_cur_len; }
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
    snprintf(cfg.access_key, sizeof(cfg.access_key), "SERVICE-AK-STATIC");
    snprintf(cfg.secret_key, sizeof(cfg.secret_key), "SERVICE-SK-STATIC");
    snprintf(cfg.region, sizeof(cfg.region), "us-east-1");
    cfg.timeout_ms = 2000;
    cfg.transport  = &g_fake_transport;
    cfg.tctx       = NULL;

    return brix_sd_remote_create(&cfg, NULL);
}

/* Drain a dir into caller arrays; returns the entry count and the terminal rc. */
static size_t
drain(brix_sd_instance_t *inst, brix_sd_dir_t *d, char names[][256],
    unsigned char *types, size_t cap, ngx_int_t *term_rc)
{
    size_t          n = 0;
    brix_sd_dirent_t e;
    ngx_int_t       rc;

    (void) inst;
    for ( ;; ) {
        rc = d->inst->driver->readdir(d, &e);
        if (rc != NGX_OK) {
            break;
        }
        assert(n < cap);
        snprintf(names[n], 256, "%s", e.name);
        types[n] = e.d_type;
        n++;
    }
    *term_rc = rc;
    return n;
}

static int
find_name(char names[][256], size_t n, const char *want, unsigned char *types,
    unsigned char *type_out)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (strcmp(names[i], want) == 0) {
            if (type_out) { *type_out = types[i]; }
            return 1;
        }
    }
    return 0;
}

/* Test 1 (success): a single-page listing of "/sub". */
static void
test_list_single_page(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    char                names[16][256];
    unsigned char       types[16];
    unsigned char       t;
    int                 err = 0;
    ngx_int_t           term = NGX_OK;
    size_t              n;

    assert(inst != NULL);
    assert(inst->driver->opendir != NULL);   /* slots registered (#4) */
    assert(inst->driver->readdir != NULL);
    assert(inst->driver->closedir != NULL);

    g_mode = MODE_SINGLE;
    g_get_calls = 0;

    d = inst->driver->opendir(inst, "/sub", &err);
    assert(d != NULL);

    n = drain(inst, d, names, types, 16, &term);

    assert(term == NGX_DONE);                 /* clean end-of-stream */
    assert(n == 3);                           /* marker skipped, 2 files + 1 dir */
    assert(strstr(g_last_path, "prefix=sub%2F") != NULL);  /* derived prefix */
    assert(find_name(names, n, "file1.txt", types, &t) && t == DT_REG);
    assert(find_name(names, n, "a&b.txt", types, &t) && t == DT_REG); /* unescaped */
    assert(find_name(names, n, "dir1", types, &t) && t == DT_DIR);    /* no slash */
    assert(!find_name(names, n, "", types, NULL));   /* marker never surfaced */

    inst->driver->closedir(d);
    printf("  ok   1: single page -> 3 entries (marker skipped, &amp; decoded, "
           "dir1 as DT_DIR), NGX_DONE\n");
    brix_sd_remote_destroy(inst);
}

/* Test 2 (pagination): a truncated first page threads its continuation token. */
static void
test_list_paginated(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    char                names[16][256];
    unsigned char       types[16];
    int                 err = 0;
    ngx_int_t           term = NGX_OK;
    size_t              n;

    assert(inst != NULL);
    g_mode = MODE_PAGED;
    g_get_calls = 0;

    d = inst->driver->opendir(inst, "/", &err);   /* root -> empty prefix */
    assert(d != NULL);

    n = drain(inst, d, names, types, 16, &term);

    assert(term == NGX_DONE);
    assert(g_get_calls == 2);                     /* two pages fetched */
    assert(n == 2);
    assert(find_name(names, n, "p1.txt", types, NULL));
    assert(find_name(names, n, "p2.txt", types, NULL));
    /* the SECOND request carried the first page's NextContinuationToken */
    assert(strstr(g_last_path, "continuation-token=TOKEN123") != NULL);

    inst->driver->closedir(d);
    printf("  ok   2: pagination -> token threaded, both pages' entries surfaced\n");
    brix_sd_remote_destroy(inst);
}

/* Test 3 (error / security-neg): a 403 LIST is surfaced, never masked as an
 * empty directory; NULL args to sd_s3_list_page are rejected before any I/O. */
static void
test_list_forbidden_and_bad_args(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_dir_t      *d;
    brix_sd_dirent_t    e;
    int                 err = 0;
    ngx_int_t           rc;

    assert(inst != NULL);
    g_mode = MODE_ERR;
    g_get_calls = 0;

    d = inst->driver->opendir(inst, "/sub", &err);
    assert(d != NULL);                            /* opendir is lazy (no I/O) */

    errno = 0;
    rc = inst->driver->readdir(d, &e);
    assert(rc == NGX_ERROR);                      /* NOT NGX_DONE (empty dir) */
    assert(errno == EACCES);                      /* auth refusal surfaced */
    assert(g_get_calls == 1);

    inst->driver->closedir(d);

    /* Bad-arg guard on the raw primitive: NULL cb -> EINVAL, no wire I/O. */
    {
        char              errbuf[128];
        char              cont[64];
        sd_s3_open_params p;
        int               trunc = 0;
        int               prc;

        memset(&p, 0, sizeof(p));
        p.host = "127.0.0.1"; p.port = 9999; p.key = "/test-bucket/";
        p.ak = "AK"; p.sk = "SK"; p.region = "us-east-1";
        p.transport = &g_fake_transport; p.timeout_ms = 2000;

        g_get_calls = 0;
        errno = 0;
        prc = sd_s3_list_page(&p, "", "", NULL, NULL, &trunc, cont,
                              sizeof(cont), errbuf, sizeof(errbuf));
        assert(prc == -1);
        assert(errno == EINVAL);
        assert(g_get_calls == 0);                 /* rejected before any request */
    }

    printf("  ok   3: 403 LIST -> NGX_ERROR/EACCES (not empty); NULL cb -> "
           "EINVAL (no wire I/O)\n");
    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_list_single_page();
    test_list_paginated();
    test_list_forbidden_and_bad_args();
    printf("test_sd_remote_opendir: ALL PASS\n");
    return 0;
}
