/* test_sd_remote_xattr_cred.c — unit test for the credential-scoped metadata
 * READ slots on the remote-origin (s3://) driver: getxattr_cred and
 * listxattr_cred (sd_remote_meta.c).
 *
 * The driver already ran every metadata WRITE (setxattr/removexattr/setattr) and
 * every namespace op (stat/mkdir/rename/unlink) under the requesting user's
 * SigV4 keys. The two READ slots had no *_cred sibling at all, so
 * brix_sd_{get,list}xattr_maybe_cred fell through to the plain slot for every
 * caller it could not outright refuse, and the HEAD was signed with the export's
 * shared SERVICE key — a user presenting perfectly good S3 keys had their
 * metadata read authorised as the export, returning attributes their own keys
 * would have been denied. (The forwarder's fallback_deny arm already refused a
 * credential it could not route; that arm was never the hole. Test 5 pins it so
 * it stays closed now that the slots exist to route to.)
 *
 * The signing identity is observable: SigV4 puts the access key id in the
 * request's `Authorization: ... Credential=<AK>/<date>/...` line, which the fake
 * transport captures verbatim. Every assertion below is therefore about WHICH
 * KEY SIGNED THE HEAD, not merely about the returned bytes.
 *
 * Coverage: the user's key signs the read and the value/name list comes back
 * (success); absent attribute, absent object, a non-user. name, a short buffer
 * and a size probe (error); a fallback_deny credential refused with EACCES
 * before any wire I/O — on both slots — plus the proof that the service key
 * never appears on the wire during those attempts (security-neg).
 *
 * Run via `python3 -m cmdscripts.c_regression_units sd_remote_xattr_cred`.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "fs/backend/sd_cred_types.h"    /* brix_sd_cred_t */
#include "core/compat/crypto.h"          /* brix_crypto_init: SigV4 sign path */

#define SERVICE_AK  "SERVICE-AK-STATIC"
#define USER_AK     "USER-AK-ALICE"

/* ---- per-object metadata store ------------------------------------------ *
 * One object under test carries a set of bare (unprefixed) user-metadata pairs;
 * the fake transport serves them on HEAD. Reads never rewrite the store, so
 * unlike the mutation unit there is no REPLACE-PUT path here.                */
#define MSTORE_MAX 8
static char g_sname[MSTORE_MAX][160];
static char g_sval [MSTORE_MAX][256];
static int  g_sn;
static char g_store_key[512];            /* object path that owns the store */

static int  g_requests;                  /* every wire request, any method */
static char g_last_ak[128];              /* Credential=<AK> off the last sign */

static void
store_reset(void)
{
    g_sn = 0;
    g_store_key[0] = '\0';
}

static void
store_seed(const char *key, const char *name, const char *val)
{
    snprintf(g_store_key, sizeof(g_store_key), "%s", key);
    assert(g_sn < MSTORE_MAX);
    snprintf(g_sname[g_sn], sizeof(g_sname[g_sn]), "%s", name);
    snprintf(g_sval[g_sn], sizeof(g_sval[g_sn]), "%s", val);
    g_sn++;
}

static const char *
store_get(const char *name)
{
    int i;

    for (i = 0; i < g_sn; i++) {
        if (strcmp(g_sname[i], name) == 0) {
            return g_sval[i];
        }
    }
    return NULL;
}

static void
reset_capture(void)
{
    g_requests = 0;
    g_last_ak[0] = '\0';
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

/* Lift the access key id out of the SigV4 Authorization line:
 * "...Credential=<AK>/<yyyymmdd>/<region>/s3/aws4_request,...". Leaves g_last_ak
 * empty when the request carried no credential scope at all. */
static void
capture_signing_ak(const char *headers)
{
    static const char tag[] = "Credential=";
    const char       *p = (headers != NULL) ? strstr(headers, tag) : NULL;
    size_t            n;

    g_last_ak[0] = '\0';
    if (p == NULL) {
        return;
    }
    p += sizeof(tag) - 1;
    n = strcspn(p, "/");
    if (n >= sizeof(g_last_ak)) {
        n = sizeof(g_last_ak) - 1;
    }
    memcpy(g_last_ak, p, n);
    g_last_ak[n] = '\0';
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
    (void) method;

    g_requests++;
    capture_signing_ak(headers);
    bare_path(path_and_query, bare, sizeof(bare));

    resp->opaque = NULL;
    if (g_store_key[0] != '\0' && strcmp(bare, g_store_key) == 0) {
        resp->status = 200;
        resp->opaque = (void *) 1;        /* store owner: emit its metadata */
    } else {
        resp->status = 404;
    }
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
    static char buf[MSTORE_MAX * 448];
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
    (void) resp;
    if (len != NULL) { *len = 0; }
    return "";
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

/* A transport with NO raw-header enumeration: listxattr cannot enumerate and
 * must say so (ENOTSUP) rather than report an empty attribute set. */
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
    snprintf(cfg.access_key, sizeof(cfg.access_key), SERVICE_AK);
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

/* A usable per-user S3 credential. */
static void
user_cred(brix_sd_cred_t *cred)
{
    memset(cred, 0, sizeof(*cred));
    cred->s3_ak     = USER_AK;
    cred->s3_sk     = "USER-SK-ALICE";
    cred->s3_region = "us-east-1";
}

/* Seed one object with two attributes and clear the capture counters. */
static void
seed_object(void)
{
    store_reset();
    store_seed("/test-bucket/a.txt", "colour", "amber");
    store_seed("/test-bucket/a.txt", "owner", "alice");
    reset_capture();
}

/* ---- success ------------------------------------------------------------- */

/* Test 1: the user's key — not the export's service key — signs a cred-scoped
 * read, and the value still comes back. This is the whole point of the slot. */
static void
test_getxattr_cred_signs_as_user(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    char                buf[64];
    ssize_t             n;

    assert(inst != NULL);
    assert(inst->driver->getxattr_cred != NULL);
    assert(inst->driver->listxattr_cred != NULL);

    user_cred(&cred);
    seed_object();

    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.colour",
                                    buf, sizeof(buf), &cred);
    assert(n == 5 && memcmp(buf, "amber", 5) == 0);
    assert(g_requests == 1);
    assert(strcmp(g_last_ak, USER_AK) == 0);

    /* The same read with no credential keeps the pre-change behaviour: the
     * instance's static service key signs it. */
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.colour",
                                    buf, sizeof(buf), NULL);
    assert(n == 5);
    assert(strcmp(g_last_ak, SERVICE_AK) == 0);

    reset_capture();
    n = inst->driver->getxattr(inst, "/a.txt", "user.owner", buf, sizeof(buf));
    assert(n == 5 && memcmp(buf, "alice", 5) == 0);
    assert(strcmp(g_last_ak, SERVICE_AK) == 0);

    printf("  ok   1: getxattr_cred signs as the user; plain slot unchanged\n");
    brix_sd_remote_destroy(inst);
}

/* Test 2: listxattr_cred enumerates under the user's key, and a credential of a
 * kind this backend cannot use falls back to the service key when — and only
 * when — the operator has not set fallback_deny. */
static void
test_listxattr_cred_signs_as_user(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    char                buf[512];
    ssize_t             n;

    assert(inst != NULL);

    user_cred(&cred);
    seed_object();

    n = inst->driver->listxattr_cred(inst, "/a.txt", buf, sizeof(buf), &cred);
    assert(n > 0);
    assert(strcmp(g_last_ak, USER_AK) == 0);
    /* NUL-separated "user.<name>" keys, both attributes present. */
    {
        const char *p;
        int         seen_colour = 0, seen_owner = 0;

        for (p = buf; p < buf + n && *p != '\0'; p += strlen(p) + 1) {
            if (strcmp(p, "user.colour") == 0) { seen_colour = 1; }
            if (strcmp(p, "user.owner") == 0)  { seen_owner = 1; }
        }
        assert(seen_colour && seen_owner);
    }

    /* Bearer-only cred, fallback permitted: the service key signs, as before. */
    memset(&cred, 0, sizeof(cred));
    cred.bearer = "eyJ.allowed.token";
    reset_capture();
    n = inst->driver->listxattr_cred(inst, "/a.txt", buf, sizeof(buf), &cred);
    assert(n > 0);
    assert(strcmp(g_last_ak, SERVICE_AK) == 0);

    printf("  ok   2: listxattr_cred signs as the user; permitted fallback OK\n");
    brix_sd_remote_destroy(inst);
}

/* ---- error --------------------------------------------------------------- */

/* Test 3: the error contract is the plain slot's, unchanged, and every failure
 * still runs under the caller's identity rather than escaping to the service
 * key on the way to reporting it. */
static void
test_error_contract(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    char                buf[64];
    ssize_t             n;

    assert(inst != NULL);
    user_cred(&cred);
    seed_object();

    /* attribute absent on a present object */
    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.missing",
                                    buf, sizeof(buf), &cred);
    assert(n == -1 && errno == ENODATA);
    assert(strcmp(g_last_ak, USER_AK) == 0);

    /* a name outside the user. namespace never reaches the wire */
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/a.txt", "trusted.root",
                                    buf, sizeof(buf), &cred);
    assert(n == -1 && errno == ENODATA);
    assert(g_requests == 0);

    /* "user." with an empty remainder is equally not an attribute name */
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.",
                                    buf, sizeof(buf), &cred);
    assert(n == -1 && errno == ENODATA);
    assert(g_requests == 0);

    /* absent object: the HEAD 404s and no attribute can be reported */
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/nope.txt", "user.colour",
                                    buf, sizeof(buf), &cred);
    assert(n == -1);
    assert(g_requests == 1);
    assert(strcmp(g_last_ak, USER_AK) == 0);

    /* size probe (cap 0) reports the length without touching the buffer */
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.colour", NULL, 0,
                                    &cred);
    assert(n == 5);

    /* a buffer one byte short is ERANGE, not a truncated value */
    memset(buf, '#', sizeof(buf));
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.colour", buf, 4,
                                    &cred);
    assert(n == -1 && errno == ERANGE);
    assert(buf[0] == '#');

    printf("  ok   3: ENODATA / 404 / ERANGE / size probe contract preserved\n");
    brix_sd_remote_destroy(inst);
}

/* Test 4 (degradation): without the transport's raw-header slot the driver
 * cannot enumerate metadata; listxattr must report ENOTSUP rather than an empty
 * set, which a caller would read as "this object has no attributes". */
static void
test_noraw_transport_notsup(void)
{
    brix_sd_instance_t *inst = build_instance_tp(&g_fake_transport_noraw);
    brix_sd_cred_t      cred;
    char                buf[512];
    ssize_t             n;

    assert(inst != NULL);
    user_cred(&cred);
    seed_object();

    n = inst->driver->listxattr_cred(inst, "/a.txt", buf, sizeof(buf), &cred);
    assert(n == -1 && errno == ENOTSUP);

    printf("  ok   4: no raw-header transport -> ENOTSUP, never an empty set\n");
    brix_sd_remote_destroy(inst);
}

/* ---- security-negative --------------------------------------------------- */

/* Test 5: a fallback_deny identity that carries no usable S3 keys must be
 * refused with EACCES before any origin contact. The cred forwarder enforced
 * this while the slots were missing; now that they exist the refusal moved INTO
 * them, so it is re-pinned here at the driver. Asserted on both slots, and
 * against the signing key itself: g_last_ak stays empty, so no request was
 * signed at all — not merely "signed with the wrong key". */
static void
test_cred_deny_refuses_reads(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t      cred;
    char                buf[512];
    ssize_t             n;

    assert(inst != NULL);
    seed_object();

    memset(&cred, 0, sizeof(cred));
    cred.bearer = "eyJ.deny.token";          /* a non-S3 credential kind */
    cred.fallback_deny = 1;

    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.colour",
                                    buf, sizeof(buf), &cred);
    assert(n == -1 && errno == EACCES);
    assert(g_requests == 0 && g_last_ak[0] == '\0');

    reset_capture();
    n = inst->driver->listxattr_cred(inst, "/a.txt", buf, sizeof(buf), &cred);
    assert(n == -1 && errno == EACCES);
    assert(g_requests == 0 && g_last_ak[0] == '\0');

    /* An x509 proxy is equally unusable for SigV4 and equally refused. */
    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy = "/tmp/x509up_u1000";
    cred.fallback_deny = 1;
    reset_capture();
    n = inst->driver->getxattr_cred(inst, "/a.txt", "user.colour",
                                    buf, sizeof(buf), &cred);
    assert(n == -1 && errno == EACCES);
    assert(g_requests == 0);

    /* A HALF credential (access key with no secret) cannot sign either, and
     * must not be quietly completed from the service key under deny. */
    memset(&cred, 0, sizeof(cred));
    cred.s3_ak = USER_AK;
    cred.fallback_deny = 1;
    reset_capture();
    n = inst->driver->listxattr_cred(inst, "/a.txt", buf, sizeof(buf), &cred);
    assert(n == -1 && errno == EACCES);
    assert(g_requests == 0);

    /* The deny gate is scoped to the credential path: the plain slot still
     * serves the export's own service identity. */
    reset_capture();
    n = inst->driver->getxattr(inst, "/a.txt", "user.colour", buf, sizeof(buf));
    assert(n == 5);
    assert(strcmp(g_last_ak, SERVICE_AK) == 0);

    printf("  ok   5: fallback_deny -> EACCES on both reads, zero signed I/O\n");
    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — SigV4 sign path. */
    test_getxattr_cred_signs_as_user();
    test_listxattr_cred_signs_as_user();
    test_error_contract();
    test_noraw_transport_notsup();
    test_cred_deny_refuses_reads();
    printf("test_sd_remote_xattr_cred: ALL PASS\n");
    return 0;
}
