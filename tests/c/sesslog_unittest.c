/*
 * sesslog_unittest.c — ngx-free unit tests for session-lifecycle log grammar.
 *
 * Build/run: tests/c/run_sesslog_tests.sh
 */
#include "observability/sesslog/sesslog.h"
#include "protocols/root/protocol/opcodes.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

#define CHECK(cond, msg) do {                                             \
        checks++;                                                         \
        if (!(cond)) {                                                    \
            failures++;                                                   \
            printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);      \
        } else {                                                          \
            printf("  ok: %s\n", msg);                                   \
        }                                                                 \
    } while (0)

static void
seed_session(brix_sess_t *s)
{
    memset(s, 0, sizeof(*s));
    memcpy(s->id, "0123456789abcdef", BRIX_SESSLOG_ID_LEN + 1);
    s->proto = BRIX_SESS_PROTO_ROOT;
    s->dir = BRIX_SESS_DIR_IN;
    s->authmethod = BRIX_SESS_AM_GSI;
    memcpy(s->peer, "10.0.0.5:41234", sizeof("10.0.0.5:41234"));
    s->start_msec = 1000;
}

static void
test_labels(void)
{
    CHECK(strcmp(brix_sesslog_proto_label(BRIX_SESS_PROTO_ROOT), "root") == 0,
          "proto root label");
    CHECK(strcmp(brix_sesslog_proto_label(BRIX_SESS_PROTO_WEBDAV),
                 "webdav") == 0,
          "proto webdav label");
    CHECK(strcmp(brix_sesslog_proto_label(BRIX_SESS_PROTO_FILL), "fill") == 0,
          "proto fill label");
    CHECK(strcmp(brix_sesslog_dir_label(BRIX_SESS_DIR_OUT), "out") == 0,
          "dir out label");
    CHECK(strcmp(brix_sesslog_am_label(BRIX_SESS_AM_SIGV4), "sigv4") == 0,
          "auth method sigv4 label");
    CHECK(strcmp(brix_sesslog_mode_label(BRIX_SESS_MODE_COPY), "copy") == 0,
          "mode copy label");
    CHECK(strcmp(brix_sesslog_xfer_label(BRIX_SESS_XFER_SHUTDOWN),
                 "shutdown") == 0,
          "xfer shutdown label");
    CHECK(strcmp(brix_sesslog_end_label(BRIX_SESS_END_CLIENT),
                 "client-disconnect") == 0,
          "end client label");
}

static void
test_golden_lines(void)
{
    brix_sess_t      s;
    brix_sess_xfer_t x;
    char             line[BRIX_SESSLOG_LINE_MAX];

    seed_session(&s);
    CHECK(brix_sesslog_fmt_connect(line, sizeof(line), &s, NULL) > 0,
          "connect renders");
    CHECK(strcmp(line, "SESS 0123456789abcdef CONNECT proto=root dir=in "
                       "peer=\"10.0.0.5:41234\" authmethod=gsi\n") == 0,
          "connect field order");

    CHECK(brix_sesslog_fmt_auth(line, sizeof(line), &s, 1, BRIX_SESS_AM_GSI,
                                "/DC=ch/CN=alice", "cms", NULL, NULL) > 0,
          "auth renders");
    CHECK(strcmp(line, "SESS 0123456789abcdef AUTH ok method=gsi "
                       "user=\"/DC=ch/CN=alice\" vo=\"cms\"\n") == 0,
          "auth ok field order");

    CHECK(brix_sesslog_fmt_attempt(line, sizeof(line), &s,
                                   "/data/run7/f.root",
                                   BRIX_SESS_MODE_READ, NULL) > 0,
          "attempt renders");
    CHECK(strcmp(line, "SESS 0123456789abcdef ATTEMPT "
                       "path=\"/data/run7/f.root\" mode=read\n") == 0,
          "attempt field order");

    CHECK(brix_sesslog_fmt_result(line, sizeof(line), &s, 0,
                                  "/data/run7/f.root",
                                  BRIX_SESS_MODE_READ, "not-found", NULL) > 0,
          "result renders");
    CHECK(strcmp(line, "SESS 0123456789abcdef RESULT fail "
                       "path=\"/data/run7/f.root\" mode=read "
                       "err=\"not-found\"\n") == 0,
          "result fail field order");

    memset(&x, 0, sizeof(x));
    memcpy(x.path, "/data/run7/f.root", sizeof("/data/run7/f.root"));
    x.mode = BRIX_SESS_MODE_READ;
    x.bytes = 1073741824ULL;
    x.expected = 1073741824LL;
    x.start_msec = 2000;
    CHECK(brix_sesslog_fmt_xfer(line, sizeof(line), &s, &x,
                                BRIX_SESS_XFER_COMPLETE, 4604, NULL) > 0,
          "xfer renders");
    CHECK(strcmp(line, "SESS 0123456789abcdef XFER complete "
                       "path=\"/data/run7/f.root\" mode=read "
                       "bytes=1073741824/1073741824 dur=2604 "
                       "avg=412343250\n") == 0,
          "xfer field order and rate");

    CHECK(brix_sesslog_fmt_end(line, sizeof(line), &s, BRIX_SESS_END_CLIENT,
                               3711, NULL) > 0,
          "end renders");
    CHECK(strcmp(line, "SESS 0123456789abcdef END "
                       "reason=client-disconnect dur=2711\n") == 0,
          "end field order");
}

static void
test_sanitization(void)
{
    brix_sess_t s;
    char        line[BRIX_SESSLOG_LINE_MAX];

    seed_session(&s);
    CHECK(brix_sesslog_fmt_attempt(line, sizeof(line), &s,
                                   "/tmp/x\nSESS "
                                   "0000000000000000 END reason=shutdown",
                                   BRIX_SESS_MODE_READ, NULL) > 0,
          "hostile path renders");
    CHECK(strstr(line, "\\x0aSESS 0000000000000000 END") != NULL,
          "newline escaped inside quoted value");
    CHECK(strchr(line, '\n') == line + strlen(line) - 1,
          "only trailing newline remains");

    CHECK(brix_sesslog_fmt_auth(line, sizeof(line), &s, 1,
                                BRIX_SESS_AM_GSI,
                                "quote\"slash\\ctl\x01utf\xc3\xa9",
                                "-", NULL, NULL) > 0,
          "hostile user renders");
    CHECK(strstr(line, "quote\\\"slash\\\\ctl\\x01utf\\xc3\\xa9") != NULL,
          "quotes, slash, control, and non-ascii escaped");
}

static void
test_truncation_and_rates(void)
{
    brix_sess_t      s;
    brix_sess_xfer_t x;
    char             long_path[5000];
    char             line[BRIX_SESSLOG_LINE_MAX];
    size_t           n;

    memset(long_path, 'a', sizeof(long_path));
    long_path[sizeof(long_path) - 1] = '\0';
    seed_session(&s);
    n = brix_sesslog_fmt_attempt(line, sizeof(line), &s, long_path,
                                 BRIX_SESS_MODE_READ, NULL);
    CHECK(n < sizeof(line), "long attempt stays in line buffer");
    CHECK(strstr(line, "...\" mode=read\n") != NULL,
          "long path truncates inside quoted value");

    memset(&x, 0, sizeof(x));
    memcpy(x.path, "/zero", sizeof("/zero"));
    x.mode = BRIX_SESS_MODE_WRITE;
    x.bytes = 42;
    x.expected = -1;
    x.start_msec = 5000;
    CHECK(brix_sesslog_fmt_xfer(line, sizeof(line), &s, &x,
                                BRIX_SESS_XFER_ABORTED, 5000, NULL) > 0,
          "zero-duration xfer renders");
    CHECK(strstr(line, "bytes=42/- dur=0 avg=42000\n") != NULL,
          "zero-duration rate uses one millisecond floor");
}

static void
test_error_maps(void)
{
    char scratch[BRIX_SESSLOG_ERR_MAX];

    CHECK(strcmp(brix_sesslog_err_from_errno(ENOENT, scratch,
                                             sizeof(scratch)),
                 "not-found") == 0,
          "errno ENOENT maps to not-found");
    CHECK(strcmp(brix_sesslog_err_from_errno(ENOSPC, scratch,
                                             sizeof(scratch)),
                 "no-space") == 0,
          "errno ENOSPC maps to no-space");
    CHECK(strcmp(brix_sesslog_err_from_kxr(kXR_FileLocked, scratch,
                                           sizeof(scratch)),
                 "locked") == 0,
          "kXR file-locked maps to locked");
    CHECK(strcmp(brix_sesslog_err_from_kxr(kXR_Cancelled, scratch,
                                           sizeof(scratch)),
                 "session-closed") == 0,
          "kXR cancelled maps to session-closed");
    CHECK(strcmp(brix_sesslog_err_from_http(504, scratch,
                                            sizeof(scratch)),
                 "timeout") == 0,
          "HTTP 504 maps to timeout");
    CHECK(strcmp(brix_sesslog_err_from_http(599, scratch,
                                            sizeof(scratch)),
                 "code:599") == 0,
          "HTTP fallback maps to code token");
}

int
main(void)
{
    printf("sesslog formatter/unit tests:\n");

    test_labels();
    test_golden_lines();
    test_sanitization();
    test_truncation_and_rates();
    test_error_maps();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
