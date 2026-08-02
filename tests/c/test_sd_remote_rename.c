/* test_sd_remote_rename.c — unit test for finding #4-rest (phase-92): the
 * remote-origin (s3://) driver's namespace-mutation slots — mkdir, rename,
 * rmdir (unlink is_dir) and directory-aware stat.
 *
 * S3 has no directories, so BriX models a folder as a zero-byte "path/" marker
 * object (src/fs/backend/remote/sd_remote_meta.c + sd_remote_write.c):
 *   - mkdir   PUTs the marker (idempotent: an existing marker is EEXIST);
 *   - rename  copies+deletes (S3 has no atomic move) a file, or an EMPTY
 *             directory marker; a NON-empty directory reports ENOTSUP;
 *   - rmdir   (unlink is_dir=1) DELETEs the "path/" marker, not a file key;
 *   - stat    recognises the marker as a directory and the export root always.
 *
 * The test builds a real brix_sd_instance_t via brix_sd_remote_create with an
 * injected fake transport. HEAD existence is driven by a registry of "existing"
 * object paths; the ListObjectsV2 GET returns a scripted one-page body. It
 * proves success + error + security-neg for each slot, including that a
 * fallback_deny credential of a non-S3 kind is refused with EACCES before any
 * wire I/O.
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_rename`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/sd_cred_types.h"   /* brix_sd_cred_t (deny-gate leg) */
#include "core/compat/crypto.h"         /* brix_crypto_init: SigV4 sign path */

/* ---- scripted fake transport ------------------------------------------- */

static int  g_put_status = 200;   /* status for object/copy/marker PUTs      */
static int  g_del_status = 200;   /* status for DELETE                       */
static int  g_list_child = 0;     /* 1 => the ListObjectsV2 page has a child  */
static int  g_put_calls, g_del_calls, g_head_calls, g_get_calls;
static char g_last_method[16];
static char g_last_path[512];
static char g_copy_source[256];   /* captured x-amz-copy-source (rename copy) */
static size_t g_last_body_len;

/* object paths that "exist" (HEAD -> 200); everything else 404. */
static const char *g_exist[16];
static int         g_nexist;

static const char *XML_EMPTY =
    "<?xml version=\"1.0\"?><ListBucketResult>"
    "<IsTruncated>false</IsTruncated></ListBucketResult>";
static const char *XML_CHILD =
    "<?xml version=\"1.0\"?><ListBucketResult><IsTruncated>false</IsTruncated>"
    "<Contents><Key>olddir/child.bin</Key></Contents></ListBucketResult>";

static void
exist_reset(void)
{
    g_nexist = 0;
}

static void
exist_add(const char *objpath)
{
    g_exist[g_nexist++] = objpath;
}

/* Exact-match the request path (query stripped) against a registered key so a
 * file key "/b/f" and its marker "/b/f/" are distinguished. */
static int
exist_has(const char *path)
{
    char        bare[512];
    const char *q = strchr(path, '?');
    size_t      n = (q != NULL) ? (size_t) (q - path) : strlen(path);
    int         i;

    if (n >= sizeof(bare)) { n = sizeof(bare) - 1; }
    memcpy(bare, path, n);
    bare[n] = '\0';
    for (i = 0; i < g_nexist; i++) {
        if (strcmp(bare, g_exist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static const char *
hdr_value(const char *headers, const char *name, char *out, size_t outcap)
{
    const char *p = strstr(headers, name);
    const char *v, *e;
    size_t      n;

    if (p == NULL) {
        return NULL;
    }
    v = p + strlen(name);
    while (*v == ':' || *v == ' ') { v++; }
    e = v;
    while (*e != '\0' && *e != '\r' && *e != '\n') { e++; }
    n = (size_t) (e - v);
    if (n >= outcap) { n = outcap - 1; }
    memcpy(out, v, n);
    out[n] = '\0';
    return out;
}

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) body;
    (void) timeout_ms; (void) errbuf; (void) errcap;

    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    g_last_body_len = body_len;
    resp->opaque = NULL;

    if (strcmp(method, "HEAD") == 0) {
        g_head_calls++;
        resp->status = exist_has(path_and_query) ? 200 : 404;
        return 0;
    }
    if (strcmp(method, "GET") == 0) {          /* ListObjectsV2 */
        g_get_calls++;
        resp->status = 200;
        return 0;
    }
    if (strcmp(method, "DELETE") == 0) {
        g_del_calls++;
        resp->status = g_del_status;
        return 0;
    }
    /* PUT (marker / copy). */
    g_put_calls++;
    g_copy_source[0] = '\0';
    hdr_value(headers, "x-amz-copy-source", g_copy_source, sizeof(g_copy_source));
    resp->status = g_put_status;
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp;
    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "0");    /* markers/files are 0-byte for the probe */
        return 0;
    }
    return -1;
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    const char *xml = g_list_child ? XML_CHILD : XML_EMPTY;
    (void) resp;
    if (len) { *len = strlen(xml); }
    return xml;
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

static void
reset_capture(void)
{
    g_put_calls = g_del_calls = g_head_calls = g_get_calls = 0;
    g_last_method[0] = '\0';
    g_last_path[0] = '\0';
    g_copy_source[0] = '\0';
    g_last_body_len = 0;
    g_list_child = 0;
    exist_reset();
    errno = 0;
}

/* ---- mkdir --------------------------------------------------------------- */

/* Test 1 (success): mkdir on an absent path PUTs the zero-byte "path/" marker
 * (one existence HEAD that 404s, then one 0-byte PUT to the marker key). */
static void
test_mkdir_creates_marker(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->mkdir != NULL);            /* slot registered (#4) */
    assert(inst->driver->caps & BRIX_SD_CAP_DIRS_WRITE);

    reset_capture();
    rc = inst->driver->mkdir(inst, "/newdir", 0755);

    assert(rc == NGX_OK);
    assert(g_head_calls == 1);                       /* idempotency probe */
    assert(g_put_calls == 1);                        /* the marker PUT */
    assert(strcmp(g_last_method, "PUT") == 0);
    assert(strstr(g_last_path, "/test-bucket/newdir/") != NULL);  /* trailing / */
    assert(g_last_body_len == 0);                    /* zero-byte marker */

    printf("  ok   1: mkdir -> 0-byte PUT to %s\n", g_last_path);
    brix_sd_remote_destroy(inst);
}

/* Test 2 (error): mkdir on an existing marker is EEXIST — no PUT (MKCOL on an
 * existing collection; brix_vfs_backend_mkpath tolerates it per component). */
static void
test_mkdir_existing_eexist(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    reset_capture();
    exist_add("/test-bucket/have/");                 /* marker already present */
    rc = inst->driver->mkdir(inst, "/have", 0755);

    assert(rc == NGX_ERROR);
    assert(errno == EEXIST);
    assert(g_head_calls == 1);
    assert(g_put_calls == 0);                         /* never overwrites */

    printf("  ok   2: mkdir on existing marker -> EEXIST, no PUT\n");
    brix_sd_remote_destroy(inst);
}

/* ---- rename -------------------------------------------------------------- */

/* Test 3 (success): rename of a file copies src->dst then deletes src (S3 has
 * no atomic move) — one HEAD (src exists), one CopyObject PUT to dst carrying
 * x-amz-copy-source: /bucket/src, one DELETE of src. */
static void
test_rename_file(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->rename != NULL);

    reset_capture();
    exist_add("/test-bucket/a.txt");                 /* src is a real file */
    rc = inst->driver->rename(inst, "/a.txt", "/b.txt", 0 /* replace */);

    assert(rc == NGX_OK);
    assert(g_put_calls == 1);                         /* the copy */
    assert(strstr(g_copy_source, "/test-bucket/a.txt") != NULL);
    assert(g_del_calls == 1);                         /* delete the source */
    assert(strcmp(g_last_method, "DELETE") == 0);
    assert(strstr(g_last_path, "/test-bucket/a.txt") != NULL);
    assert(g_get_calls == 0);                         /* file path: no LIST */

    printf("  ok   3: rename file -> copy(%s)+delete\n", g_copy_source);
    brix_sd_remote_destroy(inst);
}

/* Test 4 (error): a non-empty directory has no atomic prefix move -> ENOTSUP
 * (never a partial in-store shuffle); a missing source -> ENOENT. */
static void
test_rename_dir_notsup_and_missing(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    /* NON-empty directory: src is not a file, the LIST page reports a child. */
    reset_capture();
    g_list_child = 1;
    rc = inst->driver->rename(inst, "/olddir", "/newdir", 0);
    assert(rc == NGX_ERROR);
    assert(errno == ENOTSUP);
    assert(g_put_calls == 0 && g_del_calls == 0);     /* nothing moved */
    assert(g_get_calls == 1);                          /* the child probe */

    /* Missing source: not a file, empty prefix, no marker -> ENOENT. */
    reset_capture();
    rc = inst->driver->rename(inst, "/gone.txt", "/b.txt", 0);
    assert(rc == NGX_ERROR);
    assert(errno == ENOENT);
    assert(g_put_calls == 0 && g_del_calls == 0);

    printf("  ok   4: rename non-empty dir -> ENOTSUP; missing src -> ENOENT\n");
    brix_sd_remote_destroy(inst);
}

/* Test 5 (error): noreplace refuses when the destination already exists
 * (POSC/O_EXCL) — a HEAD-before-move existence check, no copy/delete. */
static void
test_rename_noreplace_eexist(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    reset_capture();
    exist_add("/test-bucket/a.txt");                  /* src exists */
    exist_add("/test-bucket/b.txt");                  /* dst already exists */
    rc = inst->driver->rename(inst, "/a.txt", "/b.txt", 1 /* noreplace */);

    assert(rc == NGX_ERROR);
    assert(errno == EEXIST);
    assert(g_put_calls == 0 && g_del_calls == 0);

    printf("  ok   5: rename noreplace over existing dst -> EEXIST\n");
    brix_sd_remote_destroy(inst);
}

/* ---- rmdir + directory-aware stat --------------------------------------- */

/* Test 6 (success): rmdir (unlink is_dir=1) DELETEs the "path/" marker object,
 * not a same-named file key; stat recognises a marker as a directory and the
 * export root as a directory with no backing object. */
static void
test_rmdir_marker_and_dir_stat(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_stat_t      st;
    ngx_int_t           rc;

    assert(inst != NULL);

    /* rmdir -> DELETE the marker key. */
    reset_capture();
    rc = inst->driver->unlink(inst, "/somedir", 1 /* is_dir */);
    assert(rc == NGX_OK);
    assert(g_del_calls == 1);
    assert(strcmp(g_last_method, "DELETE") == 0);
    assert(strstr(g_last_path, "/test-bucket/somedir/") != NULL);

    /* stat of a marker -> directory. */
    reset_capture();
    exist_add("/test-bucket/mydir/");                 /* only the marker exists */
    memset(&st, 0xff, sizeof(st));
    rc = inst->driver->stat(inst, "/mydir", &st);
    assert(rc == NGX_OK);
    assert(st.is_dir);
    assert((st.mode & S_IFMT) == S_IFDIR);
    assert(g_head_calls == 2);                         /* file miss, marker hit */

    /* stat of the export root -> directory with no I/O. */
    reset_capture();
    rc = inst->driver->stat(inst, "/", &st);
    assert(rc == NGX_OK);
    assert(st.is_dir);
    assert(g_head_calls == 0 && g_get_calls == 0);     /* synthesised */

    printf("  ok   6: rmdir deletes marker; marker+root stat as dir\n");
    brix_sd_remote_destroy(inst);
}

/* ---- security-neg: fallback_deny credential ----------------------------- */

/* Test 7 (security-neg): a fallback_deny credential of a kind this S3 backend
 * cannot use (no s3_ak/s3_sk) is refused with EACCES before any origin contact
 * — the cred slot must never silently fall back to the shared service key. */
static void
test_cred_deny_refuses(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->mkdir_cred != NULL);
    assert(inst->driver->rename_cred != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.bearer        = "eyJ.deny.token";   /* a non-S3 kind */
    cred.fallback_deny = 1;

    reset_capture();
    rc = inst->driver->mkdir_cred(inst, "/x", 0755, &cred);
    assert(rc == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_head_calls == 0 && g_put_calls == 0);     /* no wire I/O */

    reset_capture();
    rc = inst->driver->rename_cred(inst, "/x", "/y", 0, &cred);
    assert(rc == NGX_ERROR);
    assert(errno == EACCES);
    assert(g_head_calls == 0 && g_put_calls == 0 && g_del_calls == 0);

    printf("  ok   7: fallback_deny cred -> EACCES (no wire I/O)\n");
    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_mkdir_creates_marker();
    test_mkdir_existing_eexist();
    test_rename_file();
    test_rename_dir_notsup_and_missing();
    test_rename_noreplace_eexist();
    test_rmdir_marker_and_dir_stat();
    test_cred_deny_refuses();
    printf("test_sd_remote_rename: ALL PASS\n");
    return 0;
}
