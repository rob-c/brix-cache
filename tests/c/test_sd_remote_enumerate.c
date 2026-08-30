/* test_sd_remote_enumerate.c — the s3:// backend-catalog verb.
 *
 * sd_remote_enumerate (src/fs/backend/remote/sd_remote_enum.c) answers
 * driver->enumerate by paging an UNDELIMITED ListObjectsV2
 * (sd_s3_list_flat_page) and reporting one brix_sd_catalog_ent_t per stored
 * object. Before it, an S3 export had no catalog verb at all, so inventory and
 * the background scrub fell back to recursing the synthetic namespace: one
 * signed delimited LIST per pseudo-directory plus a HEAD per entry to stat it.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_remote_create (pure
 * config copy, no network) with an injected fake transport returning scripted
 * ListObjectsV2 XML. It proves:
 *   1 (success)      — every key at EVERY depth is reported exactly once with
 *                      the size and mtime carried in the listing itself (no
 *                      extra request), `key` is the S3 key and `path` the
 *                      export-relative logical path, an XML-escaped key is
 *                      unescaped, the request carries no `delimiter` and an
 *                      empty prefix, CAP_CATALOG is advertised, and a truncated
 *                      page threads its NextContinuationToken into the next
 *                      request.
 *   2 (error)        — a 403 LIST surfaces as NGX_ERROR/EACCES rather than an
 *                      empty catalog (an auth refusal that read as "the bucket
 *                      holds nothing" would let a scrub evict a live store), a
 *                      NULL callback is rejected with EINVAL before any wire
 *                      I/O, and an unparsable <LastModified> yields have_stat=0
 *                      rather than a guessed epoch.
 *   3 (security-neg) — the directory-marker object (a key ending in '/') is NOT
 *                      reported as stored content; a callback abort stops the
 *                      enumeration AND stops paging (no further requests); and
 *                      a page that claims truncation but supplies no
 *                      continuation token terminates instead of re-listing the
 *                      same page forever.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_enumerate`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/s3/sd_s3.h"
#include "core/compat/crypto.h"   /* brix_crypto_init: SigV4 sign path */

/* ---- scripted fake transport ------------------------------------------- */

enum { MODE_SINGLE, MODE_PAGED, MODE_ERR, MODE_BADTIME, MODE_NOTOKEN };

static int  g_mode      = MODE_SINGLE;
static int  g_get_calls = 0;
static char g_last_path[1024];
static const char *g_cur_body = NULL;
static size_t      g_cur_len  = 0;

/* One flat page: keys at three depths, an escaped key, and a directory marker.
 * <Size>/<LastModified> ride in the listing, which is the whole point. */
static const char BODY_SINGLE[] =
    "<?xml version=\"1.0\"?>\n"
    "<ListBucketResult><Name>test-bucket</Name><Prefix></Prefix>"
    "<IsTruncated>false</IsTruncated>"
    "<Contents><Key>top.bin</Key><Size>100</Size>"
        "<LastModified>2009-10-12T17:50:30.000Z</LastModified></Contents>"
    "<Contents><Key>sub/</Key><Size>0</Size>"
        "<LastModified>2009-10-12T17:50:30.000Z</LastModified></Contents>"
    "<Contents><Key>sub/one.bin</Key><Size>200</Size>"
        "<LastModified>2020-01-02T03:04:05.000Z</LastModified></Contents>"
    "<Contents><Key>sub/deep/two.bin</Key><Size>300</Size>"
        "<LastModified>2020-01-02T03:04:05.000Z</LastModified></Contents>"
    "<Contents><Key>a&amp;b.bin</Key><Size>7</Size>"
        "<LastModified>2020-01-02T03:04:05.000Z</LastModified></Contents>"
    "</ListBucketResult>";

static const char BODY_PAGE1[] =
    "<ListBucketResult><IsTruncated>true</IsTruncated>"
    "<NextContinuationToken>TOKEN123</NextContinuationToken>"
    "<Contents><Key>p1.bin</Key><Size>11</Size>"
        "<LastModified>2020-01-02T03:04:05.000Z</LastModified></Contents>"
    "</ListBucketResult>";

static const char BODY_PAGE2[] =
    "<ListBucketResult><IsTruncated>false</IsTruncated>"
    "<Contents><Key>p2.bin</Key><Size>22</Size>"
        "<LastModified>2020-01-02T03:04:05.000Z</LastModified></Contents>"
    "</ListBucketResult>";

/* A key whose timestamp is garbage, and one with no <LastModified> at all. */
static const char BODY_BADTIME[] =
    "<ListBucketResult><IsTruncated>false</IsTruncated>"
    "<Contents><Key>bad.bin</Key><Size>5</Size>"
        "<LastModified>not-a-date</LastModified></Contents>"
    "<Contents><Key>none.bin</Key><Size>6</Size></Contents>"
    "</ListBucketResult>";

/* Truncated, but the token is missing — a broken proxy, not real S3. */
static const char BODY_NOTOKEN[] =
    "<ListBucketResult><IsTruncated>true</IsTruncated>"
    "<Contents><Key>loop.bin</Key><Size>1</Size></Contents>"
    "</ListBucketResult>";

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
    assert(strcmp(method, "GET") == 0);

    resp->opaque = NULL;
    if (g_mode == MODE_ERR) {
        resp->status = 403;
        g_cur_body = NULL;
        g_cur_len  = 0;
        return 0;
    }
    resp->status = 200;
    switch (g_mode) {
    case MODE_PAGED:   g_cur_body = (g_get_calls == 1) ? BODY_PAGE1 : BODY_PAGE2;
                       break;
    case MODE_BADTIME: g_cur_body = BODY_BADTIME; break;
    case MODE_NOTOKEN: g_cur_body = BODY_NOTOKEN; break;
    default:           g_cur_body = BODY_SINGLE;  break;
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
    snprintf(cfg.bucket, sizeof(cfg.bucket), "test-bucket");
    snprintf(cfg.access_key, sizeof(cfg.access_key), "SERVICE-AK-STATIC");
    snprintf(cfg.secret_key, sizeof(cfg.secret_key), "SERVICE-SK-STATIC");
    snprintf(cfg.region, sizeof(cfg.region), "us-east-1");
    cfg.timeout_ms = 2000;
    cfg.transport  = &g_fake_transport;
    cfg.tctx       = NULL;

    return brix_sd_remote_create(&cfg, NULL);
}

/* ---- collector ---------------------------------------------------------- */

#define MAX_ENT 16

typedef struct {
    size_t n;
    char   key [MAX_ENT][256];
    char   path[MAX_ENT][256];
    int    have_path[MAX_ENT];
    int    have_stat[MAX_ENT];
    off_t  size [MAX_ENT];
    time_t mtime[MAX_ENT];
    int    stop_after;    /* >0: abort once n reaches it */
} coll_t;

static int
collect(void *ctx, const brix_sd_catalog_ent_t *ent)
{
    coll_t *c = ctx;

    assert(c->n < MAX_ENT);
    assert(ent->key != NULL);            /* key is ALWAYS present per the contract */
    snprintf(c->key[c->n], sizeof(c->key[0]), "%s", ent->key);
    c->have_path[c->n] = (ent->path != NULL);
    if (ent->path != NULL) {
        snprintf(c->path[c->n], sizeof(c->path[0]), "%s", ent->path);
    }
    c->have_stat[c->n] = ent->have_stat;
    c->size [c->n] = ent->size;
    c->mtime[c->n] = ent->mtime;
    c->n++;
    return (c->stop_after > 0 && c->n >= (size_t) c->stop_after) ? 1 : 0;
}

static int
find_key(const coll_t *c, const char *want)
{
    size_t i;

    for (i = 0; i < c->n; i++) {
        if (strcmp(c->key[i], want) == 0) {
            return (int) i;
        }
    }
    return -1;
}

static void
reset(int mode)
{
    g_mode      = mode;
    g_get_calls = 0;
    g_last_path[0] = '\0';
}

/* ---- 1: success --------------------------------------------------------- */

static void
test_success(void)
{
    brix_sd_instance_t *inst = build_instance();
    coll_t              c;
    int                 i;

    assert(inst != NULL);
    assert(inst->driver->enumerate != NULL);            /* slot registered */
    assert((inst->caps & BRIX_SD_CAP_CATALOG) != 0);    /* and advertised */

    reset(MODE_SINGLE);
    memset(&c, 0, sizeof(c));
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_OK);

    /* One request served the whole tree: three depths, no per-directory LIST. */
    assert(g_get_calls == 1);
    assert(strstr(g_last_path, "list-type=2") != NULL);
    assert(strstr(g_last_path, "delimiter") == NULL);   /* flat, by construction */
    assert(strstr(g_last_path, "prefix=") != NULL);

    assert(c.n == 4);            /* 5 <Contents> minus the directory marker */

    i = find_key(&c, "top.bin");
    assert(i >= 0);
    assert(c.have_path[i] && strcmp(c.path[i], "/top.bin") == 0);
    assert(c.have_stat[i]);
    assert(c.size[i] == 100);
    assert(c.mtime[i] == (time_t) 1255369830);   /* 2009-10-12T17:50:30Z */

    i = find_key(&c, "sub/deep/two.bin");        /* depth is irrelevant */
    assert(i >= 0);
    assert(c.have_path[i] && strcmp(c.path[i], "/sub/deep/two.bin") == 0);
    assert(c.have_stat[i] && c.size[i] == 300);

    i = find_key(&c, "a&b.bin");                 /* XML-unescaped */
    assert(i >= 0);
    assert(c.have_path[i] && strcmp(c.path[i], "/a&b.bin") == 0);

    /* want_stat == 0: the same entries, no stat claimed. */
    reset(MODE_SINGLE);
    memset(&c, 0, sizeof(c));
    assert(inst->driver->enumerate(inst, 0, collect, &c) == NGX_OK);
    assert(c.n == 4);
    for (i = 0; (size_t) i < c.n; i++) {
        assert(!c.have_stat[i]);
    }

    /* pagination: the token threads into the second request */
    reset(MODE_PAGED);
    memset(&c, 0, sizeof(c));
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_OK);
    assert(g_get_calls == 2);
    assert(strstr(g_last_path, "continuation-token=TOKEN123") != NULL);
    assert(c.n == 2);
    assert(find_key(&c, "p1.bin") >= 0 && find_key(&c, "p2.bin") >= 0);

    brix_sd_remote_destroy(inst);
    printf("ok success\n");
}

/* ---- 2: error ----------------------------------------------------------- */

static void
test_error(void)
{
    brix_sd_instance_t *inst = build_instance();
    coll_t              c;
    int                 truncated = 0;
    char                cont[64];
    char                errbuf[128];
    int                 i;

    assert(inst != NULL);

    /* A refused LIST is an ERROR, never an empty catalog: a scrub that read a
     * 403 as "this store holds nothing" would evict every live object. */
    reset(MODE_ERR);
    memset(&c, 0, sizeof(c));
    errno = 0;
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_ERROR);
    assert(errno == EACCES);
    assert(c.n == 0);

    /* Bad arguments are refused before any wire I/O. */
    reset(MODE_SINGLE);
    memset(&c, 0, sizeof(c));
    errno = 0;
    assert(inst->driver->enumerate(inst, 1, NULL, &c) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_get_calls == 0);

    errno = 0;
    assert(inst->driver->enumerate(NULL, 1, collect, &c) == NGX_ERROR);
    assert(errno == EINVAL);
    assert(g_get_calls == 0);

    errno = 0;
    assert(sd_s3_list_flat_page(NULL, "", "", NULL, NULL, &truncated, cont,
               sizeof(cont), errbuf, sizeof(errbuf)) == -1);
    assert(errno == EINVAL);
    assert(g_get_calls == 0);

    /* An unparsable or absent <LastModified> is NOT a stat. Reporting a
     * fabricated epoch would make an inventory believe every such object was
     * last modified in 1970 and a drift check treat it as stale. */
    reset(MODE_BADTIME);
    memset(&c, 0, sizeof(c));
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_OK);
    assert(c.n == 2);
    for (i = 0; (size_t) i < c.n; i++) {
        assert(!c.have_stat[i]);
        assert(c.mtime[i] == 0);
    }

    brix_sd_remote_destroy(inst);
    printf("ok error\n");
}

/* ---- 3: security-negative ----------------------------------------------- */

static void
test_security_negative(void)
{
    brix_sd_instance_t *inst = build_instance();
    coll_t              c;

    assert(inst != NULL);

    /* The directory-marker object is namespace scaffolding this driver's own
     * mkdir wrote, not stored content. Reporting it would have an inventory
     * count a folder as a file and a drift check call every folder an orphan. */
    reset(MODE_SINGLE);
    memset(&c, 0, sizeof(c));
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_OK);
    assert(find_key(&c, "sub/") < 0);
    assert(find_key(&c, "") < 0);

    /* A callback abort stops the enumeration AND stops PAGING: an early stop
     * that kept fetching would issue unbounded signed requests against the
     * origin for a caller that already has what it wanted. */
    reset(MODE_PAGED);
    memset(&c, 0, sizeof(c));
    c.stop_after = 1;
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_OK);
    assert(c.n == 1);
    assert(g_get_calls == 1);       /* page 2 never requested */

    /* Truncated with no continuation token: the cursor cannot advance, so the
     * loop must terminate rather than re-list the same page forever and wedge a
     * scrub thread on a broken proxy. */
    reset(MODE_NOTOKEN);
    memset(&c, 0, sizeof(c));
    assert(inst->driver->enumerate(inst, 1, collect, &c) == NGX_OK);
    assert(g_get_calls == 1);
    assert(c.n == 1);

    brix_sd_remote_destroy(inst);
    printf("ok security-negative\n");
}

int
main(void)
{
    brix_crypto_init();
    test_success();
    test_error();
    test_security_negative();
    printf("PASS test_sd_remote_enumerate\n");
    return 0;
}
