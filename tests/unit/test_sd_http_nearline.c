/*
 * test_sd_http_nearline.c — the http driver's nearline pair (residency/recall,
 * WLCG Tape REST API) and its advisory-metadata setattr, driven with no origin.
 *
 * WHY: three of the decisions in these slots are only visible from the outside
 *      as an absence of harm, so nothing else would catch them regressing:
 *
 *      1. An UNKNOWN locality token must be an error, never ONLINE. The Tape
 *         REST API's vocabulary is closed, so a token this build has not seen
 *         means we are not talking to that API — answering ONLINE would hand a
 *         caller a file that is still on tape.
 *      2. The object key is the only caller-controlled text in either request
 *         body. A key carrying a quote or a backslash must not be able to close
 *         the JSON string and turn a request for one path into a request for
 *         several; an over-long key must be REFUSED, because a truncated path
 *         names a different object.
 *      3. setattr must not treat a FAILED attribute read as "no attributes yet".
 *         Doing so would take a 403 from the origin and answer it by writing a
 *         fresh blob — i.e. a denied read becoming a successful write.
 *
 * Unity build: this TU #includes sd_http_nearline.c + sd_http_setattr.c and
 * supplies the three externs they call (the namespace sender, the WebDAV status
 * verdict, the xattr read/write pair) as mocks, so every scenario is
 * deterministic and no HTTP happens. Compiled by cmdscripts.sd_http_nearline_unit.
 */
#define XRDPROTO_NO_NGX 1

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "fs/backend/http/sd_http_internal.h"
#include "fs/backend/meta_advisory.h"

static int failures;

static void
check(int ok, const char *what)
{
    if (!ok) {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

/* ---- mocked wire ---------------------------------------------------------
 * One scripted reply per POST, plus a capture of the request that produced it
 * so the escaping assertions can look at the bytes that would have gone out. */
typedef struct {
    int    status;         /* status the next POST answers with */
    char   body[512];      /* its body */
    char   sent_path[512]; /* the request path we captured */
    char   sent_body[512]; /* the request body we captured */
    int    posts;          /* how many POSTs were issued */
} mock_wire;

static mock_wire g_wire;

int
sd_http_ns_send(sd_http_inst_state *is, const sd_http_ns_req_t *rq,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) is; (void) errbuf; (void) errcap;

    g_wire.posts++;
    snprintf(g_wire.sent_path, sizeof(g_wire.sent_path), "%s", rq->path);
    snprintf(g_wire.sent_body, sizeof(g_wire.sent_body), "%.*s",
             (int) rq->body_len, (const char *) rq->body);
    resp->status = g_wire.status;
    resp->opaque = &g_wire;
    return 0;
}

int
sd_http_status_to_errno(long status)
{
    if (status == 401 || status == 403) { return EACCES; }
    if (status == 404 || status == 409) { return ENOENT; }
    return EIO;
}

static const void *
mock_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    *len = strlen(g_wire.body);
    return g_wire.body;
}

static void
mock_resp_free(brix_s3_resp_t *resp)
{
    resp->opaque = NULL;
}

static const brix_s3_transport_t mock_transport = {
    .resp_body = mock_resp_body,
    .resp_free = mock_resp_free,
};

/* ---- mocked xattr plane (the setattr slot composes over it) --------------- */
typedef struct {
    const char *stored;    /* current blob, or NULL = absent */
    int         read_err;  /* errno the read fails with, 0 = it succeeds */
    char        written[512];
    int         writes;
    /* Which credential each leg was handed. The setattr slot composes a READ and
     * a WRITE over this plane, and both must carry the SAME identity: a read
     * authorized as the service account and a write authorized as the user (or
     * either the other way round) is a confused deputy with two legs. */
    const brix_sd_cred_t *read_cred;
    const brix_sd_cred_t *write_cred;
    int                   read_calls;
} mock_xattr;

static mock_xattr g_xattr;

ssize_t
sd_http_getxattr_common(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t bufsz, const brix_sd_cred_t *cred)
{
    size_t n;

    (void) inst; (void) path; (void) name;
    g_xattr.read_cred = cred;
    g_xattr.read_calls++;
    if (g_xattr.read_err != 0) {
        errno = g_xattr.read_err;
        return -1;
    }
    if (g_xattr.stored == NULL) {
        errno = ENODATA;
        return -1;
    }
    n = strlen(g_xattr.stored);
    if (n > bufsz) {
        errno = ERANGE;
        return -1;
    }
    memcpy(buf, g_xattr.stored, n);
    return (ssize_t) n;
}

ngx_int_t
sd_http_setxattr_cred(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *value, size_t size, int flags,
    const brix_sd_cred_t *cred)
{
    (void) inst; (void) path; (void) name; (void) flags;
    g_xattr.write_cred = cred;
    g_xattr.writes++;
    snprintf(g_xattr.written, sizeof(g_xattr.written), "%.*s", (int) size,
             (const char *) value);
    return NGX_OK;
}

#include "fs/backend/http/sd_http_nearline.c"   /* NOLINT — unity build */
#include "fs/backend/http/sd_http_setattr.c"    /* NOLINT */

/* ---- fixture ------------------------------------------------------------- */
static sd_http_inst_state  g_state;
static brix_sd_instance_t  g_inst;

static void
fixture_reset(const char *tape_api)
{
    memset(&g_wire, 0, sizeof(g_wire));
    memset(&g_xattr, 0, sizeof(g_xattr));
    memset(&g_state, 0, sizeof(g_state));
    memset(&g_inst, 0, sizeof(g_inst));
    g_state.transport = &mock_transport;
    if (tape_api != NULL) {
        check(sd_http_tape_init(&g_state, tape_api) == 1, "tape_init arms");
    }
    g_inst.state = &g_state;
}

static void
script(int status, const char *body)
{
    g_wire.status = status;
    snprintf(g_wire.body, sizeof(g_wire.body), "%s", body);
}

/* ---- 0. the API base is an allowlist, not a suggestion --------------------
 * The base lands verbatim in a request line. Every byte that could END the path
 * — CR, LF, '?', '#', a space — has to be refused outright rather than stripped,
 * because a sanitised base is one the operator never wrote and cannot see in
 * their config. A refused base leaves the instance un-armed, which is the safe
 * failure: the export keeps serving as plain http. */

static void
test_tape_init(void)
{
    sd_http_inst_state is;

    printf("tape api base\n");

    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, "/api/v1") == 1
          && strcmp(is.tape_api, "/api/v1") == 0, "an absolute base arms");

    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, "/api/v1/") == 1
          && strcmp(is.tape_api, "/api/v1") == 0,
          "a trailing slash is dropped so the composed path never doubles it");

    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, "/a.b_c~d-e") == 1,
          "the unreserved punctuation is accepted");

    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, NULL) == 0 && is.tape_api[0] == '\0',
          "no base leaves the instance un-armed");
    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, "") == 0, "an empty base does not arm");
    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, "api/v1") == 0, "a relative base does not arm");
    memset(&is, 0, sizeof(is));
    check(sd_http_tape_init(&is, "/") == 0,
          "the export root alone is not an API base");

    /* Security-negative: each of these would change what the request line
     * MEANS, and each must leave tape_api empty rather than a sanitised
     * remnant. */
    {
        static const char *hostile[] = {
            "/api\r\nX-Injected: 1",   /* splits the request              */
            "/api\n",                  /* likewise                        */
            "/api?x=1",                /* "/archiveinfo" becomes a query  */
            "/api#frag",               /* …or a fragment                  */
            "/api v1",                 /* ends the request target         */
            "/api%2f",                 /* an escape we would not decode   */
            "/api\\v1",                /* not a path separator here       */
        };
        size_t i;

        for (i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
            memset(&is, 0, sizeof(is));
            check(sd_http_tape_init(&is, hostile[i]) == 0
                  && is.tape_api[0] == '\0',
                  "a base that could end the path is refused, not sanitised");
        }
    }

    /* A base too long to hold is refused rather than truncated: a truncated
     * base names a different endpoint. */
    {
        char big[1024];

        memset(big, 'a', sizeof(big));
        big[0] = '/';
        big[sizeof(big) - 1] = '\0';
        memset(&is, 0, sizeof(is));
        check(sd_http_tape_init(&is, big) == 0 && is.tape_api[0] == '\0',
              "an over-long base is refused, never truncated");
    }
}

/* ---- 1. the JSON quoter is an injection defence --------------------------- */
static void
test_json_quote(void)
{
    char out[64];

    check(sd_http_json_quote("/a/b", out, sizeof(out)) == 0
          && strcmp(out, "\"/a/b\"") == 0, "plain key quotes verbatim");

    check(sd_http_json_quote("/a\"b", out, sizeof(out)) == 0
          && strcmp(out, "\"/a\\\"b\"") == 0, "embedded quote is escaped");

    check(sd_http_json_quote("/a\\b", out, sizeof(out)) == 0
          && strcmp(out, "\"/a\\\\b\"") == 0, "embedded backslash is escaped");

    check(sd_http_json_quote("/a\tb", out, sizeof(out)) == 0
          && strcmp(out, "\"/a\\u0009b\"") == 0, "control byte is \\u-escaped");

    /* Security-negative: an over-long key is REFUSED, not truncated — a
     * truncated path names a different object. */
    check(sd_http_json_quote("/aaaaaaaaaaaaaaaa", out, 8) == -1,
          "overflow is refused, never truncated");
}

/* ---- 2. the locality map --------------------------------------------------*/
static void
test_locality(void)
{
    brix_sd_residency_t r;

    check(sd_http_locality("DISK", &r) == 0 && r == BRIX_SD_RES_ONLINE,
          "DISK is ONLINE");
    check(sd_http_locality("DISK_AND_TAPE", &r) == 0 && r == BRIX_SD_RES_ONLINE,
          "DISK_AND_TAPE is ONLINE (the disk copy serves the read)");
    check(sd_http_locality("TAPE", &r) == 0 && r == BRIX_SD_RES_NEARLINE,
          "TAPE is NEARLINE");
    check(sd_http_locality("UNAVAILABLE", &r) == 0 && r == BRIX_SD_RES_OFFLINE,
          "UNAVAILABLE is OFFLINE");
    check(sd_http_locality("LOST", &r) == 0 && r == BRIX_SD_RES_LOST,
          "LOST is LOST");

    errno = 0;
    check(sd_http_locality("NONE", &r) == -1 && errno == ENOENT,
          "NONE is ENOENT, not a residency class");

    /* Security-negative: a vocabulary this build does not know must never be
     * read as ONLINE. */
    errno = 0;
    check(sd_http_locality("PARTIALLY_ON_DISK", &r) == -1 && errno == EIO,
          "an unknown locality is EIO, never a guess");
}

/* ---- 3. the residency slot ------------------------------------------------*/
static void
test_residency(void)
{
    brix_sd_residency_t r;

    /* Un-armed instance: the slot exists on the vtable but the operator never
     * declared a tape API, so it must decline rather than invent an endpoint. */
    fixture_reset(NULL);
    errno = 0;
    check(sd_http_residency(&g_inst, "/k", &r) == NGX_ERROR && errno == ENOTSUP
          && g_wire.posts == 0, "un-armed instance is ENOTSUP with no request");

    fixture_reset("/api/v1");
    errno = 0;
    check(sd_http_residency(NULL, "/k", &r) == NGX_ERROR && errno == EINVAL,
          "NULL instance is EINVAL");

    fixture_reset("/api/v1");
    script(200, "[{\"path\":\"/k\",\"locality\":\"TAPE\"}]");
    check(sd_http_residency(&g_inst, "/k", &r) == NGX_OK
          && r == BRIX_SD_RES_NEARLINE, "a TAPE reply reads as NEARLINE");
    check(strcmp(g_wire.sent_path, "/api/v1/archiveinfo") == 0,
          "residency posts to {base}/archiveinfo");
    check(strcmp(g_wire.sent_body, "{\"paths\":[\"/k\"]}") == 0,
          "residency sends the documented body");

    fixture_reset("/api/v1");
    script(200, "[]");
    errno = 0;
    check(sd_http_residency(&g_inst, "/k", &r) == NGX_ERROR && errno == ENOENT,
          "an empty array is ENOENT");

    fixture_reset("/api/v1");
    script(403, "");
    errno = 0;
    check(sd_http_residency(&g_inst, "/k", &r) == NGX_ERROR && errno == EACCES,
          "a 403 maps through the shared WebDAV status verdict");

    /* Security-negative, end to end: a key carrying a quote reaches the wire
     * escaped, so the body still describes exactly one path. */
    fixture_reset("/api/v1");
    script(200, "[{\"locality\":\"DISK\"}]");
    (void) sd_http_residency(&g_inst, "/a\",\"/etc/shadow", &r);
    check(strstr(g_wire.sent_body, "\\\",\\\"") != NULL,
          "a quote in the key is escaped on the wire");
    check(strstr(g_wire.sent_body, "\",\"/etc/shadow") == NULL,
          "the key cannot inject a second path");
}

/* ---- 4. the recall slot ---------------------------------------------------*/
static void
test_recall(void)
{
    char reqid[40];

    fixture_reset("/api/v1");
    script(200, "[{\"locality\":\"DISK\"}]");
    check(sd_http_recall(&g_inst, "/k", reqid) == NGX_OK && reqid[0] == '\0'
          && g_wire.posts == 1,
          "an ONLINE path is NGX_OK and stages nothing");

    fixture_reset("/api/v1");
    script(200, "[{\"locality\":\"LOST\"}]");
    errno = 0;
    check(sd_http_recall(&g_inst, "/k", reqid) == NGX_ERROR && errno == ENOENT
          && g_wire.posts == 1,
          "a LOST path is a hard ENOENT and stages nothing");

    fixture_reset("/api/v1");
    script(200, "[{\"locality\":\"UNAVAILABLE\"}]");
    check(sd_http_recall(&g_inst, "/k", reqid) == NGX_AGAIN && reqid[0] == '\0'
          && g_wire.posts == 1,
          "an UNAVAILABLE path is NGX_AGAIN with no request id");

    /* NEARLINE: residency, then the stage submission. The mock answers both
     * POSTs from one script, so the second reply is what the stage sees. */
    fixture_reset("/api/v1");
    script(200, "[{\"locality\":\"TAPE\"}]");
    check(sd_http_recall(&g_inst, "/k", reqid) == NGX_AGAIN
          && g_wire.posts == 2, "a TAPE path stages and parks the open");
    check(strcmp(g_wire.sent_path, "/api/v1/stage") == 0,
          "the stage goes to {base}/stage");
    check(strcmp(g_wire.sent_body, "{\"files\":[{\"path\":\"/k\"}]}") == 0,
          "the stage sends the documented body");
}

/* ---- 5. setattr over the advisory blob ------------------------------------*/
static void
test_setattr(void)
{
    brix_sd_setattr_t attr;

    /* Success: a mode change is persisted into the advisory blob. */
    fixture_reset(NULL);
    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode     = 0640;
    check(sd_http_setattr(&g_inst, "/k", &attr) == NGX_OK && g_xattr.writes == 1,
          "a mode change is written back");
    check(strstr(g_xattr.written, "640") != NULL,
          "the written blob carries the mode");

    /* Nothing representable: success, and NO round trip. An atime-only request
     * has nothing the advisory model can hold. */
    fixture_reset(NULL);
    memset(&attr, 0, sizeof(attr));
    attr.set_times     = 1;
    attr.atime.tv_nsec = 0;
    attr.mtime.tv_nsec = UTIME_OMIT;
    check(sd_http_setattr(&g_inst, "/k", &attr) == NGX_OK && g_xattr.writes == 0,
          "an unrepresentable request succeeds without a write");

    /* Error: a NULL request is rejected before anything is touched. */
    fixture_reset(NULL);
    errno = 0;
    check(sd_http_setattr(&g_inst, "/k", NULL) == NGX_ERROR && errno == EINVAL
          && g_xattr.writes == 0, "a NULL attr is EINVAL");

    /* Security-negative: a DENIED read must not be read as "no blob yet" and
     * answered with a write. Only ENODATA means "absent". */
    fixture_reset(NULL);
    g_xattr.read_err = EACCES;
    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode     = 0777;
    check(sd_http_setattr(&g_inst, "/k", &attr) == NGX_ERROR
          && g_xattr.writes == 0,
          "a denied read never becomes a successful write");
}

/* ---- 6. the per-user twin of the same slot -------------------------------- */
static void
test_setattr_cred(void)
{
    brix_sd_setattr_t attr;
    brix_sd_cred_t    cred;

    memset(&cred, 0, sizeof(cred));

    /* Success: the caller's credential reaches BOTH legs, unchanged. The blob is
     * an ordinary dead property, so the read-modify-write that rewrites a mode
     * has to be authorized end to end as the requesting user. */
    fixture_reset(NULL);
    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode     = 0640;
    check(sd_http_setattr_cred(&g_inst, "/k", &attr, &cred) == NGX_OK,
          "the per-user twin succeeds");
    check(g_xattr.read_cred == &cred && g_xattr.write_cred == &cred,
          "the SAME credential authorizes the read and the write");
    check(g_xattr.writes == 1 && strstr(g_xattr.written, "640") != NULL,
          "and it writes the same blob the plain slot would");

    /* The plain slot is the anonymous case of the same code: it must reach the
     * xattr plane with NO credential, not with a stale one. */
    fixture_reset(NULL);
    check(sd_http_setattr(&g_inst, "/k", &attr) == NGX_OK,
          "the plain slot still succeeds");
    check(g_xattr.read_cred == NULL && g_xattr.write_cred == NULL,
          "the plain slot presents no credential at all");

    /* Error: the argument checks are the shared ones, so a NULL request fails
     * here too — before any credential is presented to anything. */
    fixture_reset(NULL);
    errno = 0;
    check(sd_http_setattr_cred(&g_inst, "/k", NULL, &cred) == NGX_ERROR
          && errno == EINVAL && g_xattr.read_calls == 0 && g_xattr.writes == 0,
          "a NULL attr is EINVAL with no credential presented");

    /* Security-negative 1: a DENIED read is not "no blob yet". This is the whole
     * point of the twin — the user who cannot read the property must not have it
     * rewritten from scratch under their own name. */
    fixture_reset(NULL);
    g_xattr.read_err = EACCES;
    memset(&attr, 0, sizeof(attr));
    attr.set_mode = 1;
    attr.mode     = 0777;
    check(sd_http_setattr_cred(&g_inst, "/k", &attr, &cred) == NGX_ERROR
          && g_xattr.writes == 0,
          "a denied per-user read never becomes a successful write");

    /* Security-negative 2: an unrepresentable request returns before the
     * credential is used for anything. A slot that round-tripped anyway would
     * turn every no-op setattr into a live authorization probe of the origin. */
    fixture_reset(NULL);
    memset(&attr, 0, sizeof(attr));
    attr.set_times     = 1;
    attr.atime.tv_nsec = UTIME_OMIT;
    attr.mtime.tv_nsec = UTIME_OMIT;
    check(sd_http_setattr_cred(&g_inst, "/k", &attr, &cred) == NGX_OK
          && g_xattr.read_calls == 0 && g_xattr.writes == 0,
          "nothing representable means no credentialed round trip");
}

int
main(void)
{
    test_tape_init();
    test_json_quote();
    test_locality();
    test_residency();
    test_recall();
    test_setattr();
    test_setattr_cred();

    if (failures != 0) {
        printf("sd_http nearline/setattr suite: %d FAILURE(S)\n", failures);
        return 1;
    }
    printf("sd_http nearline/setattr suite: all checks passed\n");
    return 0;
}
