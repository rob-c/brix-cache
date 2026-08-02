/* test_sd_remote_setattr.c — unit test for finding #4 (phase-92): the remote-
 * origin (s3://) driver's metadata-MUTATION slots — setxattr, removexattr and
 * setattr (sd_remote_xattr.c).
 *
 * S3 has no in-place metadata edit: a write REPLACES the object's entire
 * user-metadata set via a copy-onto-self (x-amz-metadata-directive: REPLACE).
 * Each slot must therefore READ the complete current set, apply the single
 * change, and REWRITE the whole set — otherwise every co-existing attribute
 * (including the advisory unix-attr blob) is silently dropped. This test proves
 * that read-merge-write contract with an injected fake transport that carries a
 * real per-object metadata store:
 *   - HEAD  reports the object's current x-amz-meta-* headers (raw block for the
 *           listxattr enumeration + single-header lookups for get);
 *   - the REPLACE PUT re-populates the store from the request's x-amz-meta-*
 *           headers, exactly as a real bucket would.
 * so the assertions can inspect what actually survived the rewrite.
 *
 * Coverage: setxattr add/replace preserving siblings + the advisory blob
 * (success); XATTR_CREATE/REPLACE flag semantics, a non-user namespace, an
 * invalid value, and a missing attribute (error); setattr chmod patching the
 * advisory blob (success) incl. the directory-marker fallback; a fallback_deny
 * credential refused with EACCES before any wire I/O and a transport that cannot
 * enumerate headers degrading to ENOTSUP (security-neg / degradation).
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_setattr`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/sd_cred_types.h"    /* brix_sd_cred_t (deny-gate leg) */
#include "fs/backend/meta_advisory.h"    /* advisory blob encode/decode */
#include "core/compat/crypto.h"          /* brix_crypto_init: SigV4 sign path */

/* ---- per-object metadata store ----------------------------------------- *
 * One object under test carries a set of bare (unprefixed, lowercased) user-
 * metadata name=value pairs — the advisory blob rides here too, under its
 * reserved key. The fake transport reads from and (on a REPLACE PUT) rewrites
 * this store, so the test observes the true post-rewrite state.               */
#define MSTORE_MAX 40
static char g_sname[MSTORE_MAX][160];
static char g_sval [MSTORE_MAX][2048];
static int  g_sn;
static char g_store_key[512];            /* object path that owns the store */

static int  g_put_calls, g_head_calls, g_get_calls, g_del_calls;
static char g_last_method[16];
static char g_last_path[512];

static void
store_reset(void)
{
    g_sn = 0;
    g_store_key[0] = '\0';
}

/* Seed the store for `key` with one bare name=value pair (repeat to add more). */
static void
store_seed(const char *key, const char *name, const char *val)
{
    snprintf(g_store_key, sizeof(g_store_key), "%s", key);
    assert(g_sn < MSTORE_MAX);
    snprintf(g_sname[g_sn], sizeof(g_sname[g_sn]), "%s", name);
    snprintf(g_sval[g_sn], sizeof(g_sval[g_sn]), "%s", val);
    g_sn++;
}

static int
store_find(const char *name)
{
    int i;

    for (i = 0; i < g_sn; i++) {
        if (strcmp(g_sname[i], name) == 0) {
            return i;
        }
    }
    return -1;
}

static const char *
store_get(const char *name)
{
    int i = store_find(name);
    return (i >= 0) ? g_sval[i] : NULL;
}

/* Query-strip a request path for exact key comparison. */
static void
bare_path(const char *path, char *out, size_t cap)
{
    const char *q = strchr(path, '?');
    size_t      n = (q != NULL) ? (size_t) (q - path) : strlen(path);

    if (n >= cap) { n = cap - 1; }
    memcpy(out, path, n);
    out[n] = '\0';
}

/* Rebuild the store from a REPLACE PUT's x-amz-meta-* header lines (verbatim S3
 * REPLACE semantics: the new set is exactly the headers on the copy request).
 * "x-amz-metadata-directive" does NOT match the "x-amz-meta-" prefix (the char
 * after "x-amz-meta" is 'd', not '-'), so it is not mistaken for an attribute. */
static void
store_apply_replace(const char *key, const char *headers)
{
    static const char pfx[] = "x-amz-meta-";
    const size_t      pfxlen = sizeof(pfx) - 1;
    const char       *p;

    snprintf(g_store_key, sizeof(g_store_key), "%s", key);
    g_sn = 0;
    for (p = headers; *p != '\0'; ) {
        const char *eol = p + strcspn(p, "\r\n");
        const char *colon;

        if ((size_t) (eol - p) > pfxlen
            && strncasecmp(p, pfx, pfxlen) == 0
            && (colon = memchr(p, ':', (size_t) (eol - p))) != NULL
            && colon > p + pfxlen)
        {
            const char *name = p + pfxlen;
            size_t      nlen = (size_t) (colon - name);
            const char *v = colon + 1;
            size_t      vlen;

            while (*v == ' ') { v++; }
            vlen = (size_t) (eol - v);
            if (g_sn < MSTORE_MAX && nlen < sizeof(g_sname[0])
                && vlen < sizeof(g_sval[0]))
            {
                memcpy(g_sname[g_sn], name, nlen);
                g_sname[g_sn][nlen] = '\0';
                memcpy(g_sval[g_sn], v, vlen);
                g_sval[g_sn][vlen] = '\0';
                g_sn++;
            }
        }
        p = eol + strspn(eol, "\r\n");
    }
}

static int
fake_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    char bare[512];

    (void) tctx; (void) host; (void) port; (void) tls; (void) body;
    (void) body_len; (void) timeout_ms; (void) errbuf; (void) errcap;

    snprintf(g_last_method, sizeof(g_last_method), "%s", method);
    snprintf(g_last_path, sizeof(g_last_path), "%s", path_and_query);
    bare_path(path_and_query, bare, sizeof(bare));
    resp->opaque = NULL;

    if (strcmp(method, "HEAD") == 0) {
        g_head_calls++;
        if (g_store_key[0] != '\0' && strcmp(bare, g_store_key) == 0) {
            resp->status = 200;
            resp->opaque = (void *) 1;    /* store owner: emit its metadata */
        } else {
            resp->status = 404;
        }
        return 0;
    }
    if (strcmp(method, "GET") == 0) {     /* ListObjectsV2 (unused here) */
        g_get_calls++;
        resp->status = 200;
        return 0;
    }
    if (strcmp(method, "DELETE") == 0) {
        g_del_calls++;
        resp->status = 200;
        return 0;
    }
    /* PUT: a metadata REPLACE copy-onto-self rewrites the store. */
    g_put_calls++;
    if (strstr(headers, "x-amz-metadata-directive") != NULL) {
        store_apply_replace(bare, headers);
    }
    resp->status = 200;
    return 0;
}

static int
fake_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    static const char pfx[] = "x-amz-meta-";
    const size_t      pfxlen = sizeof(pfx) - 1;

    if (strcasecmp(name, "Content-Length") == 0) {
        snprintf(out, outcap, "0");
        return 0;
    }
    if (resp->opaque != NULL && strncasecmp(name, pfx, pfxlen) == 0) {
        const char *v = store_get(name + pfxlen);
        if (v != NULL) {
            snprintf(out, outcap, "%s", v);
            return 0;
        }
    }
    return -1;                             /* header absent */
}

static const char *
fake_resp_headers_raw(const brix_s3_resp_t *resp)
{
    static char buf[MSTORE_MAX * 2240];
    size_t      off;
    int         i;

    if (resp->opaque == NULL) {
        return "Content-Length: 0\r\n";
    }
    off = (size_t) snprintf(buf, sizeof(buf), "Content-Length: 0\r\n");
    for (i = 0; i < g_sn && off < sizeof(buf); i++) {
        off += (size_t) snprintf(buf + off, sizeof(buf) - off,
                                 "x-amz-meta-%s: %s\r\n", g_sname[i], g_sval[i]);
    }
    return buf;
}

static const void *
fake_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    static const char *empty =
        "<?xml version=\"1.0\"?><ListBucketResult>"
        "<IsTruncated>false</IsTruncated></ListBucketResult>";
    (void) resp;
    if (len) { *len = strlen(empty); }
    return empty;
}

static void
fake_resp_free(brix_s3_resp_t *resp)
{
    (void) resp;
}

static const brix_s3_transport_t g_fake_transport = {
    .request          = fake_request,
    .resp_header      = fake_resp_header,
    .resp_headers_raw = fake_resp_headers_raw,
    .resp_body        = fake_resp_body,
    .resp_free        = fake_resp_free,
};

/* A transport with NO raw-header enumeration — metadata mutation must degrade
 * to ENOTSUP (it cannot read the current set to merge). */
static const brix_s3_transport_t g_fake_transport_noraw = {
    .request     = fake_request,
    .resp_header = fake_resp_header,
    .resp_body   = fake_resp_body,
    .resp_free   = fake_resp_free,
};

static brix_sd_instance_t *
build_instance_tp(const brix_s3_transport_t *tp)
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
    cfg.transport  = tp;
    cfg.tctx       = NULL;

    return brix_sd_remote_create(&cfg, NULL);
}

static brix_sd_instance_t *
build_instance(void)
{
    return build_instance_tp(&g_fake_transport);
}

static void
reset_capture(void)
{
    g_put_calls = g_head_calls = g_get_calls = g_del_calls = 0;
    g_last_method[0] = '\0';
    g_last_path[0] = '\0';
    errno = 0;
}

/* A known advisory blob (mode 0644) for seeding co-existing POSIX attrs. */
static void
seed_advisory_mode(char *out, size_t cap, mode_t mode)
{
    brix_meta_advisory_t a;

    memset(&a, 0, sizeof(a));
    a.have_mode = 1;
    a.mode = mode;
    assert(brix_meta_advisory_encode(&a, out, cap) > 0);
}

/* ---- setxattr ----------------------------------------------------------- */

/* Test 1 (success): setxattr adds a new user.<name> while PRESERVING every
 * co-existing user attribute AND the advisory blob — the read-merge-write that
 * a naive single-attribute REPLACE would destroy. */
static void
test_setxattr_preserves_siblings(void)
{
    brix_sd_instance_t *inst = build_instance();
    char                blob[256];
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->setxattr != NULL);
    assert(inst->driver->caps & BRIX_SD_CAP_XATTR_WRITE);

    seed_advisory_mode(blob, sizeof(blob), 0644);
    reset_capture();
    store_reset();
    store_seed("/test-bucket/a.txt", "keep", "original");
    store_seed("/test-bucket/a.txt", BRIX_META_ADVISORY_S3META, blob);

    rc = inst->driver->setxattr(inst, "/a.txt", "user.new", "hello", 5, 0);
    assert(rc == NGX_OK);
    assert(g_put_calls == 1);                 /* exactly one REPLACE */
    assert(strcmp(g_last_method, "PUT") == 0);

    /* All three survive the rewrite, with the new value applied. */
    assert(store_get("new") != NULL && strcmp(store_get("new"), "hello") == 0);
    assert(store_get("keep") != NULL && strcmp(store_get("keep"), "original") == 0);
    assert(store_get(BRIX_META_ADVISORY_S3META) != NULL);   /* blob preserved */

    printf("  ok   1: setxattr adds user.new; keep + advisory blob preserved\n");
    brix_sd_remote_destroy(inst);
}

/* Test 2 (error): XATTR_CREATE over an existing name is EEXIST and XATTR_REPLACE
 * over an absent name is ENODATA — both before any write. */
static void
test_setxattr_flag_semantics(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    reset_capture();
    store_reset();
    store_seed("/test-bucket/a.txt", "have", "v");

    rc = inst->driver->setxattr(inst, "/a.txt", "user.have", "x", 1,
                                XATTR_CREATE);
    assert(rc == NGX_ERROR && errno == EEXIST);
    assert(g_put_calls == 0);

    reset_capture();
    rc = inst->driver->setxattr(inst, "/a.txt", "user.missing", "x", 1,
                                XATTR_REPLACE);
    assert(rc == NGX_ERROR && errno == ENODATA);
    assert(g_put_calls == 0);

    printf("  ok   2: XATTR_CREATE->EEXIST, XATTR_REPLACE(absent)->ENODATA\n");
    brix_sd_remote_destroy(inst);
}

/* Test 3 (error): a non-user namespace is ENOTSUP (only user.* maps to
 * x-amz-meta-*) and a value carrying a header-breaking byte is EINVAL — both
 * rejected before any origin contact. */
static void
test_setxattr_rejects_bad_input(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);

    reset_capture();
    store_reset();
    store_seed("/test-bucket/a.txt", "keep", "v");

    rc = inst->driver->setxattr(inst, "/a.txt", "system.posix_acl", "x", 1, 0);
    assert(rc == NGX_ERROR && errno == ENOTSUP);
    assert(g_head_calls == 0 && g_put_calls == 0);

    reset_capture();
    rc = inst->driver->setxattr(inst, "/a.txt", "user.bad", "a\nb", 3, 0);
    assert(rc == NGX_ERROR && errno == EINVAL);
    assert(g_head_calls == 0 && g_put_calls == 0);

    printf("  ok   3: non-user ns->ENOTSUP; CR/LF value->EINVAL (no I/O)\n");
    brix_sd_remote_destroy(inst);
}

/* ---- removexattr -------------------------------------------------------- */

/* Test 4 (success + error): removexattr drops the named attribute, preserving
 * the others; removing an absent attribute is ENODATA with no write. */
static void
test_removexattr(void)
{
    brix_sd_instance_t *inst = build_instance();
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->removexattr != NULL);

    reset_capture();
    store_reset();
    store_seed("/test-bucket/a.txt", "drop", "gone");
    store_seed("/test-bucket/a.txt", "keep", "stay");

    rc = inst->driver->removexattr(inst, "/a.txt", "user.drop");
    assert(rc == NGX_OK);
    assert(g_put_calls == 1);
    assert(store_get("drop") == NULL);        /* removed */
    assert(store_get("keep") != NULL);        /* sibling preserved */

    reset_capture();
    rc = inst->driver->removexattr(inst, "/a.txt", "user.notthere");
    assert(rc == NGX_ERROR && errno == ENODATA);
    assert(g_put_calls == 0);

    printf("  ok   4: removexattr drops target, keeps sibling; absent->ENODATA\n");
    brix_sd_remote_destroy(inst);
}

/* ---- setattr (advisory unix-attr blob) ---------------------------------- */

/* Test 5 (success): setattr chmod patches the advisory blob so the new mode
 * round-trips, while a co-existing user xattr survives the rewrite. */
static void
test_setattr_chmod_patches_blob(void)
{
    brix_sd_instance_t  *inst = build_instance();
    brix_sd_setattr_t    attr;
    brix_meta_advisory_t got;
    char                 blob[256];
    const char          *stored;
    ngx_int_t            rc;

    assert(inst != NULL);
    assert(inst->driver->setattr != NULL);

    seed_advisory_mode(blob, sizeof(blob), 0644);
    reset_capture();
    store_reset();
    store_seed("/test-bucket/f.dat", "keep", "v");
    store_seed("/test-bucket/f.dat", BRIX_META_ADVISORY_S3META, blob);

    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = 0700;
    rc = inst->driver->setattr(inst, "/f.dat", &attr);
    assert(rc == NGX_OK);
    assert(g_put_calls == 1);

    stored = store_get(BRIX_META_ADVISORY_S3META);
    assert(stored != NULL);
    memset(&got, 0, sizeof(got));
    assert(brix_meta_advisory_decode(stored, strlen(stored), &got) == 0);
    assert(got.have_mode && (got.mode & 0777) == 0700);   /* new mode stuck */
    assert(store_get("keep") != NULL);                     /* xattr preserved */

    printf("  ok   5: setattr chmod 0700 patches advisory blob; xattr kept\n");
    brix_sd_remote_destroy(inst);
}

/* Test 6 (success): setattr on a directory falls back to the "path/" marker
 * when no same-named file key exists, patching the marker's blob. */
static void
test_setattr_dir_marker_fallback(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_setattr_t   attr;
    char                blob[256];
    ngx_int_t           rc;

    assert(inst != NULL);

    seed_advisory_mode(blob, sizeof(blob), 0755);
    reset_capture();
    store_reset();
    /* Only the directory marker exists (file key /test-bucket/d 404s). */
    store_seed("/test-bucket/d/", BRIX_META_ADVISORY_S3META, blob);

    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = 0750;
    rc = inst->driver->setattr(inst, "/d", &attr);
    assert(rc == NGX_OK);
    assert(g_put_calls == 1);
    assert(strstr(g_last_path, "/test-bucket/d/") != NULL);   /* marker key */

    printf("  ok   6: setattr on dir patches the /path/ marker blob\n");
    brix_sd_remote_destroy(inst);
}

/* ---- security-neg / degradation ----------------------------------------- */

/* Test 7 (security-neg): a fallback_deny credential of a kind this S3 backend
 * cannot sign with is refused with EACCES before any origin contact — the cred
 * slots must never silently reach the origin under the shared service key. */
static void
test_cred_deny_refuses(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_setattr_t   attr;
    brix_sd_cred_t      cred;
    ngx_int_t           rc;

    assert(inst != NULL);
    assert(inst->driver->setxattr_cred != NULL);
    assert(inst->driver->removexattr_cred != NULL);
    assert(inst->driver->setattr_cred != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.bearer = "eyJ.deny.token";          /* a non-S3 credential kind */
    cred.fallback_deny = 1;

    reset_capture();
    store_reset();
    store_seed("/test-bucket/a.txt", "keep", "v");

    rc = inst->driver->setxattr_cred(inst, "/a.txt", "user.x", "y", 1, 0, &cred);
    assert(rc == NGX_ERROR && errno == EACCES);
    assert(g_head_calls == 0 && g_put_calls == 0);

    reset_capture();
    rc = inst->driver->removexattr_cred(inst, "/a.txt", "user.keep", &cred);
    assert(rc == NGX_ERROR && errno == EACCES);
    assert(g_head_calls == 0 && g_put_calls == 0);

    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = 0700;
    reset_capture();
    rc = inst->driver->setattr_cred(inst, "/a.txt", &attr, &cred);
    assert(rc == NGX_ERROR && errno == EACCES);
    assert(g_head_calls == 0 && g_put_calls == 0);

    printf("  ok   7: fallback_deny cred -> EACCES for all 3 verbs (no I/O)\n");
    brix_sd_remote_destroy(inst);
}

/* Test 8 (degradation): a transport that cannot enumerate raw headers cannot
 * read the current set to merge, so every mutation reports ENOTSUP rather than
 * blindly clobbering the object's other metadata. */
static void
test_noraw_transport_notsup(void)
{
    brix_sd_instance_t *inst = build_instance_tp(&g_fake_transport_noraw);
    brix_sd_setattr_t   attr;
    ngx_int_t           rc;

    assert(inst != NULL);

    reset_capture();
    store_reset();
    store_seed("/test-bucket/a.txt", "keep", "v");

    rc = inst->driver->setxattr(inst, "/a.txt", "user.x", "y", 1, 0);
    assert(rc == NGX_ERROR && errno == ENOTSUP);
    assert(g_put_calls == 0);

    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode = 0700;
    reset_capture();
    rc = inst->driver->setattr(inst, "/a.txt", &attr);
    assert(rc == NGX_ERROR && errno == ENOTSUP);
    assert(g_put_calls == 0);

    printf("  ok   8: no raw-header transport -> ENOTSUP, never a blind write\n");
    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_setxattr_preserves_siblings();
    test_setxattr_flag_semantics();
    test_setxattr_rejects_bad_input();
    test_removexattr();
    test_setattr_chmod_patches_blob();
    test_setattr_dir_marker_fallback();
    test_cred_deny_refuses();
    test_noraw_transport_notsup();
    printf("test_sd_remote_setattr: ALL PASS\n");
    return 0;
}
